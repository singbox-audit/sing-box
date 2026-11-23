package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/gofrs/flock"
	"github.com/gofrs/uuid/v5"
	"github.com/klauspost/compress/zstd"
)

type entry struct {
	kind string
	at   time.Time
	data any
}

type Recorder struct {
	directory  string
	runID      string
	minFree    uint64
	spaceError atomic.Pointer[error]
	lowSpace   bool
	peakQueue  int
	maxSyncLag atomic.Int64
	logger     log.ContextLogger
	mu         sync.Mutex // serializes event ordering, session membership and shutdown
	active     map[*session]struct{}
	queries    map[*DNSQuery]struct{}
	queue      chan entry
	stopping   chan struct{}
	done       chan struct{}
	writerDone chan struct{}
	stopped    bool
	failure    atomic.Pointer[error]
	lock       *flock.Flock
	encoder    *zstd.Encoder
	volumes    map[string]*volume
}

type volume struct {
	path      string
	published bool
	file      *os.File
	hour      time.Time
	offset    int64 // end of the last successfully synced frame
}

func NewRecorder(directory string, logger log.ContextLogger) *Recorder {
	return &Recorder{
		directory: directory, logger: logger,
		active: make(map[*session]struct{}), queries: make(map[*DNSQuery]struct{}),
		queue: make(chan entry, 256), stopping: make(chan struct{}),
		done: make(chan struct{}), writerDone: make(chan struct{}),
		volumes: make(map[string]*volume),
	}
}

func (r *Recorder) Name() string { return "connection-audit" }

func (r *Recorder) SetMinFreeBytes(n uint64) { r.minFree = n }

func (r *Recorder) checkSpace() {
	if r.minFree == 0 {
		return
	}
	free, err := freeBytes(r.directory)
	if err == nil {
		low := free/2 < r.minFree
		if low && !r.lowSpace {
			r.logger.Warn("audit disk space low: ", free, " bytes available")
		}
		r.lowSpace = low
	}
	if err == nil && free < r.minFree {
		err = fmt.Errorf("audit disk has %d bytes free, minimum %d", free, r.minFree)
	}
	if err != nil {
		if r.spaceError.Swap(&err) == nil {
			r.logger.Error(err)
		}
	} else if r.spaceError.Swap(nil) != nil {
		r.logger.Info("audit disk space recovered")
	}
}

func (r *Recorder) admissionError() error {
	if err := r.spaceError.Load(); err != nil {
		return *err
	}
	if err := r.failure.Load(); err != nil {
		return *err
	}
	return nil
}

func (r *Recorder) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if err := os.MkdirAll(r.directory, 0o700); err != nil {
		return err
	}
	r.lock = flock.New(filepath.Join(r.directory, ".audit.lock"))
	ok, err := r.lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("audit directory already in use")
	}
	scope.Add(r.lock.Unlock)
	if err = recoverVolumes(r.directory); err != nil {
		return err
	}
	r.encoder, err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return err
	}
	r.checkSpace()
	if err = r.startRun(); err != nil {
		for _, v := range r.volumes {
			if v.file != nil {
				v.file.Close()
			}
		}
		r.encoder.Close()
		return err
	}
	go r.writeLoop()
	go r.snapshots()
	scope.Add(r.close)
	return nil
}

func (r *Recorder) snapshots() {
	defer close(r.done)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-r.stopping:
			return
		case <-t.C:
			r.mu.Lock()
			for s := range r.active {
				if err := r.writeEvent(s.finalEvent("snapshot")); err != nil {
					break
				}
			}
			r.logger.Debug("audit queue peak=", r.peakQueue, " max sync lag=", time.Duration(r.maxSyncLag.Load()))
			r.mu.Unlock()
		}
	}
}

// enqueue is called under mu. A stopped writer releases blocked producers.
func (r *Recorder) enqueue(e entry) error {
	select {
	case <-r.writerDone:
		return os.ErrClosed
	default:
	}
	if r.stopped {
		return os.ErrClosed
	}
	select {
	case r.queue <- e:
		r.peakQueue = max(r.peakQueue, len(r.queue))
		return nil
	default:
	}
	r.peakQueue = cap(r.queue)
	start := time.Now()
	select {
	case r.queue <- e:
		r.logger.Warn("audit queue full, capacity=", cap(r.queue), " wait=", time.Since(start))
		return nil
	case <-r.writerDone:
		return os.ErrClosed
	}
}

func (r *Recorder) writeEvent(e connectionEvent) error {
	now := time.Now()
	e.Time = now.UnixMilli()
	e.RunID = r.runID
	return r.enqueue(entry{"conn", now, e})
}

func (r *Recorder) close() error {
	close(r.stopping)
	<-r.done
	r.mu.Lock()
	for s := range r.active {
		if err := r.writeEvent(s.finalEvent("interrupted")); err != nil {
			break
		}
	}
	for q := range r.queries {
		if err := r.writeDNS(q.initial, "interrupted"); err != nil {
			break
		}
	}
	clear(r.active)
	clear(r.queries)
	r.stopped = true
	close(r.queue)
	r.mu.Unlock()
	<-r.writerDone
	if err := r.failure.Load(); err != nil {
		return *err
	}
	return nil
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func (r *Recorder) seal(kind string) error {
	v := r.volumes[kind]
	if v == nil {
		return nil
	}
	if v.file != nil {
		err := v.file.Close()
		v.file = nil
		if err != nil {
			return err
		}
	}
	if !v.published {
		if err := os.Rename(v.path, strings.TrimSuffix(v.path, ".partial")); err != nil {
			return err
		}
		v.published = true
	}
	if err := syncDirectory(r.directory); err != nil {
		return err
	}
	delete(r.volumes, kind)
	return nil
}

func (r *Recorder) appendFrame(kind string, hour time.Time, frame []byte) error {
	v := r.volumes[kind]
	if v != nil && (v.file == nil || !v.hour.Equal(hour)) {
		if err := r.seal(kind); err != nil {
			return err
		}
		v = nil
	}
	if v == nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		path := filepath.Join(r.directory, kind+"_"+hour.Format("20060102T15Z")+"_"+id.String()+".jsonl.zst.partial")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		v = &volume{path: path, file: file, hour: hour}
		r.volumes[kind] = v
	}
	if v.offset == 0 {
		if err := syncDirectory(r.directory); err != nil {
			return err
		}
	}
	// A short write or failed Sync retries the identical frame at the same offset.
	if _, err := v.file.WriteAt(frame, v.offset); err != nil {
		return err
	}
	if err := v.file.Sync(); err != nil {
		return err
	}
	v.offset += int64(len(frame))
	return nil
}

func (r *Recorder) retryWrite(write func() error) bool {
	for {
		err := write()
		if err == nil {
			r.failure.Store(nil)
			return true
		}
		r.failure.Store(&err)
		r.logger.Error("audit write failed; retaining batch: ", err)
		select {
		case <-r.stopping:
			return false
		case <-time.After(time.Second):
		}
	}
}

func (r *Recorder) writeLoop() {
	defer close(r.writerDone)
	defer r.encoder.Close()
	defer func() {
		for _, v := range r.volumes {
			if v.file != nil {
				v.file.Close()
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	batches := map[string]*bytes.Buffer{"conn": {}, "dns": {}}
	var hour, oldest time.Time
	flush := func() bool {
		for kind, b := range batches {
			if b.Len() > 0 {
				frame := r.encoder.EncodeAll(b.Bytes(), nil)
				if !r.retryWrite(func() error { return r.appendFrame(kind, hour, frame) }) {
					return false
				}
				b.Reset()
			}
		}
		if !oldest.IsZero() {
			r.maxSyncLag.Store(max(r.maxSyncLag.Load(), time.Since(oldest).Nanoseconds()))
			oldest = time.Time{}
		}
		return true
	}
	for {
		select {
		case item, ok := <-r.queue:
			if !ok {
				if !flush() {
					return
				}
				var err error
				for kind := range r.volumes {
					err = errors.Join(err, r.seal(kind))
				}
				if err != nil {
					r.failure.Store(&err)
				}
				return
			}
			h := item.at.UTC().Truncate(time.Hour)
			if !h.Equal(hour) {
				if !flush() {
					return
				}
				hour = h
			}
			if oldest.IsZero() {
				oldest = item.at
			}
			b := batches[item.kind]
			if err := json.NewEncoder(b).Encode(item.data); err != nil {
				err = fmt.Errorf("encode audit event: %w", err)
				r.failure.Store(&err)
				r.logger.Error(err)
				return
			}
			if b.Len() >= 256<<10 && !flush() {
				return
			}
		case now := <-tick.C:
			r.checkSpace()
			if !flush() {
				return
			}
			for kind, v := range r.volumes {
				if v.hour.Before(now.UTC().Truncate(time.Hour)) {
					if !r.retryWrite(func() error { return r.seal(kind) }) {
						return
					}
				}
			}
		}
	}
}
