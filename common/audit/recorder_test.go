package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/klauspost/compress/zstd"
)

func TestConnectionAcrossVolumeBoundary(t *testing.T) {
	dir := t.TempDir()
	logger := log.NewNOPFactory().NewLogger("audit")
	scope := adapter.NewScope(t.Context(), logger)
	r := NewRecorder(dir, logger)
	if err := r.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	left, right := net.Pipe()
	defer right.Close()
	m := adapter.InboundContext{Inbound: "hy-in", InboundType: "hysteria2", User: "alice", RouteOutbound: "direct"}
	conn := r.RoutedConnection(t.Context(), left, m, nil, nil)
	go func() {
		right.Write([]byte("upload"))
		io.CopyN(io.Discard, right, 2)
	}()
	if _, err := io.CopyN(io.Discard, conn, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	r.hour = r.hour.Add(-time.Hour)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("expected two sealed volumes, got %v (%v)", files, err)
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	events := make(map[string]connectionEvent)
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".zst" {
			t.Fatalf("unsealed volume: %s", file.Name())
		}
		compressed, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		data, err := decoder.DecodeAll(compressed, nil)
		if err != nil {
			t.Fatal(err)
		}
		var e connectionEvent
		if err := json.Unmarshal(bytes.TrimSpace(data), &e); err != nil {
			t.Fatal(err)
		}
		events[e.Type] = e
	}
	start, end := events["start"], events["end"]
	if start.ID == "" || end.ID != start.ID || end.User != "alice" || end.Outbound != "direct" || end.Seq != 1 || end.Upload != 6 || end.Download != 2 {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestWriteFailureLeavesPartialVolume(t *testing.T) {
	dir := t.TempDir()
	logger := log.NewNOPFactory().NewLogger("audit")
	scope := adapter.NewScope(t.Context(), logger)
	r := NewRecorder(dir, logger)
	if err := r.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	name := r.file.Name()
	if err := r.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.begin(adapter.InboundContext{}, "tcp"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("expected closed file error, got %v", err)
	}
	scope.Close()
	if _, err := os.Stat(name); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownSettlesActiveSessionOnce(t *testing.T) {
	dir := t.TempDir()
	logger := log.NewNOPFactory().NewLogger("audit")
	scope := adapter.NewScope(t.Context(), logger)
	r := NewRecorder(dir, logger)
	if err := r.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	s, err := r.begin(adapter.InboundContext{Inbound: "vless-in", User: "alice"}, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s.upload.Add(19)
	name := strings.TrimSuffix(r.file.Name(), ".partial")
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.end(); err != nil {
		t.Fatal(err)
	}
	compressed, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	data, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("expected two events: %s", data)
	}
	var event connectionEvent
	if err := json.Unmarshal(lines[1], &event); err != nil {
		t.Fatal(err)
	}
	if event.ID != s.event.ID || event.Type != "interrupted" || event.Upload != 19 {
		t.Fatalf("unexpected interrupted session: %+v", event)
	}
}
