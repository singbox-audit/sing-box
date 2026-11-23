package audit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/klauspost/compress/zstd"
)

// Recorder writes one independent compressed frame per event. Only sealed volumes
// have the .jsonl.zst suffix, so a reader can safely copy them during operation.
type Recorder struct {
	directory string
	logger    log.ContextLogger
	mu        sync.Mutex
	encoder   *zstd.Encoder
	file      *os.File
	hour      time.Time
	writeErr  error
	active    map[*session]struct{}
}

func NewRecorder(directory string, logger log.ContextLogger) *Recorder {
	return &Recorder{directory: directory, logger: logger, active: make(map[*session]struct{})}
}

func (r *Recorder) Name() string { return "connection-audit" }

func (r *Recorder) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if err := os.MkdirAll(r.directory, 0o700); err != nil {
		return err
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return err
	}
	r.encoder = encoder
	scope.Add(r.close)
	return r.open(time.Now())
}

func (r *Recorder) open(now time.Time) error {
	r.hour = now.UTC().Truncate(time.Hour)
	file, err := os.CreateTemp(r.directory, "conn_"+r.hour.Format("20060102T15Z")+"_*.jsonl.zst.partial")
	r.file = file
	return err
}

func (r *Recorder) seal() error {
	if r.file == nil {
		return r.writeErr
	}
	file := r.file
	r.file = nil
	if err := errors.Join(r.writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), strings.TrimSuffix(file.Name(), ".partial")); err != nil {
		return err
	}
	dir, err := os.Open(r.directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (r *Recorder) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	for s := range r.active {
		if recordErr := r.writeEvent(s.finalEvent("interrupted")); recordErr != nil {
			err = recordErr
			break
		}
	}
	clear(r.active)
	return errors.Join(err, r.seal(), r.encoder.Close())
}

// writeEvent is called with mu held.
func (r *Recorder) writeEvent(event connectionEvent) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	if r.file == nil {
		return os.ErrClosed
	}
	now := time.Now()
	if !r.hour.Equal(now.UTC().Truncate(time.Hour)) {
		r.writeErr = r.seal()
		if r.writeErr != nil {
			return r.writeErr
		}
		r.writeErr = r.open(now)
		if r.writeErr != nil {
			return r.writeErr
		}
	}
	event.Time = now.UnixMilli()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	frame := r.encoder.EncodeAll(append(data, '\n'), nil)
	_, r.writeErr = r.file.Write(frame)
	return r.writeErr
}
