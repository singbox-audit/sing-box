package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/klauspost/compress/zstd"
)

func startRecorder(t *testing.T, dir string) (*Recorder, *adapter.Scope) {
	t.Helper()
	logger := log.NewNOPFactory().NewLogger("audit")
	scope := adapter.NewScope(t.Context(), logger)
	t.Cleanup(func() { scope.Close() })
	r := NewRecorder(dir, logger)
	if err := r.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	return r, scope
}

func events(t *testing.T, dir string) []connectionEvent {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "conn_*.jsonl.zst"))
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	var result []connectionEvent
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := decoder.DecodeAll(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		for {
			var e connectionEvent
			err = d.Decode(&e)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.Type != "run_closed" {
				result = append(result, e)
			}
		}
	}
	return result
}

func TestLifecycle(t *testing.T) {
	dir := t.TempDir()
	r, scope := startRecorder(t, dir)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	m := adapter.InboundContext{Network: "tcp", Inbound: "hy-in", User: "alice", RouteOutbound: "direct"}
	ctx, conn, end, err := r.TrackTCP(t.Context(), left, m, M.ParseSocksaddr("example.com:443"), nil)
	if err != nil {
		t.Fatal(err)
	}
	StartCopies(ctx)
	go func() { right.Write([]byte("upload")); io.CopyN(io.Discard, right, 2) }()
	if _, err = io.CopyN(io.Discard, conn, 6); err != nil {
		t.Fatal(err)
	}
	end(nil)
	CopyFinished(ctx)
	if _, err = conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	CopyFinished(ctx)
	end(nil)
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	es := events(t, dir)
	if len(es) != 2 || es[0].ID != es[1].ID || es[1].Seq != 1 || es[1].Upload != 6 || es[1].Download != 2 || es[1].RequestedHost != "example.com" {
		t.Fatalf("unexpected lifecycle: %+v", es)
	}
}

func TestRecoveryAtTruncatedFrame(t *testing.T) {
	dir := t.TempDir()
	r, scope := startRecorder(t, dir)
	m := adapter.InboundContext{User: "alice"}
	s, err := r.begin(m, m.Destination)
	if err != nil {
		t.Fatal(err)
	}
	s.upload.Store(19)
	r.mu.Lock()
	err = r.writeEvent(s.finalEvent("snapshot"))
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	es := events(t, dir)
	if len(es) != 3 || es[2].Seq != 2 || es[2].Type != "interrupted" || es[2].Upload != 19 {
		t.Fatal(es)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.zst"))
	path := files[0]
	partial := path + ".partial"
	if err = os.Rename(path, partial); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(partial, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte{0x28, 0xb5, 0x2f}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, other := startRecorder(t, dir)
	if err = other.Close(); err != nil {
		t.Fatal(err)
	}
	if len(events(t, dir)) != 3 {
		t.Fatal("lost recovered events")
	}
	tail, err := os.ReadFile(partial + ".damaged")
	if err != nil || len(tail) != 3 {
		t.Fatalf("tail %x: %v", tail, err)
	}
}

func TestRotationAndRetry(t *testing.T) {
	dir := t.TempDir()
	r, scope := startRecorder(t, dir)
	// A regular file in place of the spool directory forces a repeatable write
	// error without requiring root, a full filesystem, or timing a short write.
	renamed := dir + "-holding"
	if err := os.Rename(dir, renamed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(renamed) })
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, when := range []time.Time{now.Add(-time.Hour), now} {
		r.mu.Lock()
		err := r.enqueue(entry{"conn", when, connectionEvent{Type: "decision"}})
		r.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); r.failure.Load() == nil; {
		if time.Now().After(deadline) {
			t.Fatal("no write failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := r.begin(adapter.InboundContext{}, M.Socksaddr{}); err == nil {
		t.Fatal("admitted new session during failure")
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(renamed, dir); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); r.failure.Load() != nil; {
		if time.Now().After(deadline) {
			t.Fatal("did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.zst"))
	if len(files) != 2 || len(events(t, dir)) != 2 {
		t.Fatal("failed retry or rotation", files)
	}
}
