package dns

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/audit"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/klauspost/compress/zstd"
	mdns "github.com/miekg/dns"
)

type retryRouter struct{ adapter.DNSRouter }

func (retryRouter) ExchangeAsync(ctx context.Context, msg *mdns.Msg, _ adapter.DNSQueryOptions, done func(*mdns.Msg, error)) {
	audit.DNSAttempt(ctx, "first", false)
	audit.DNSAttempt(ctx, "second", false)
	done(new(mdns.Msg).SetReply(msg), nil)
}

type failingWriter struct{}

func (failingWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	b.Release()
	return errors.New("peer disconnected")
}

func TestClientQueryRetriesAndWriteFailure(t *testing.T) {
	dir := t.TempDir()
	ctx := service.ContextWithDefaultRegistry(t.Context())
	logger := log.NewNOPFactory().NewLogger("audit")
	scope := adapter.NewScope(ctx, logger)
	r := audit.NewRecorder(dir, logger)
	service.MustRegisterPtr(ctx, r)
	if err := r.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	msg := new(mdns.Msg).SetQuestion("test.example.", mdns.TypeAAAA)
	var writeErr error
	err := ExchangePacket(ctx, retryRouter{}, adapter.InboundContext{User: "alice"}, msg, msg.Len(), failingWriter{}, M.Socksaddr{}, 0, 0, func(e error) { writeErr = e })
	if err != nil || writeErr == nil {
		t.Fatalf("unexpected errors: %v, %v", err, writeErr)
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "dns_*.jsonl.zst"))
	if len(paths) != 1 {
		t.Fatal(paths)
	}
	f, err := os.Open(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	d := json.NewDecoder(z)
	var start, end struct {
		ID       string   `json:"request_id"`
		Type     string   `json:"event_type"`
		Attempts []string `json:"upstreams"`
		Error    string   `json:"write_error"`
		Download int      `json:"download_bytes"`
		Rcode    *int     `json:"rcode"`
	}
	if err = d.Decode(&start); err != nil {
		t.Fatal(err)
	}
	if err = d.Decode(&end); err != nil {
		t.Fatal(err)
	}
	if start.Type != "start" || end.Type != "end" || start.ID != end.ID || len(end.Attempts) != 2 || end.Error != "peer disconnected" || end.Download != 0 || end.Rcode == nil || *end.Rcode != 0 || d.More() {
		t.Fatalf("invalid DNS audit: %+v %+v", start, end)
	}
}
