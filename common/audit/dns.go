package audit

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
	"github.com/miekg/dns"
)

type dnsEvent struct {
	RunID        string         `json:"run_id"`
	ID           string         `json:"request_id"`
	Type         string         `json:"event_type"`
	Time         int64          `json:"event_time"`
	Inbound      string         `json:"inbound_tag"`
	Protocol     string         `json:"inbound_type"`
	User         string         `json:"auth_user"`
	Network      string         `json:"network"`
	Questions    []dns.Question `json:"questions"`
	Resolver     string         `json:"resolver,omitempty"`
	CacheHit     *bool          `json:"cache_hit,omitempty"`
	Upstreams    []string       `json:"upstreams,omitempty"`
	Rcode        *int           `json:"rcode,omitempty"`
	Answers      []string       `json:"answers,omitempty"`
	Truncated    bool           `json:"truncated"`
	ResolveError string         `json:"resolve_error,omitempty"`
	WriteError   string         `json:"write_error,omitempty"`
	Upload       int            `json:"upload_bytes"`
	Download     int            `json:"download_bytes"`
}

type queryKey struct{}

type DNSQuery struct {
	r         *Recorder
	initial   dnsEvent
	mu        sync.Mutex
	resolver  string
	hits      map[string]bool
	upstreams []string
}

func BeginDNS(ctx context.Context, m adapter.InboundContext, net string, msg *dns.Msg, n int) (context.Context, *DNSQuery, error) {
	r := service.PtrFromContext[Recorder](ctx)
	if r == nil {
		return ctx, nil, nil
	}
	id, err := uuid.NewV4()
	if err != nil {
		return ctx, nil, err
	}
	q := &DNSQuery{
		r: r, hits: make(map[string]bool),
		initial: dnsEvent{
			ID: id.String(), Inbound: m.Inbound, Protocol: m.InboundType,
			User: m.User, Network: net, Upload: n,
			Questions: append([]dns.Question(nil), msg.Question...),
		},
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.admissionError(); err != nil {
		return ctx, nil, err
	}
	if err = r.writeDNS(q.initial, "start"); err != nil {
		return ctx, nil, err
	}
	r.queries[q] = struct{}{}
	return context.WithValue(ctx, queryKey{}, q), q, nil
}

func (r *Recorder) writeDNS(e dnsEvent, kind string) error {
	now := time.Now()
	e.Type = kind
	e.Time = now.UnixMilli()
	e.RunID = r.runID
	return r.enqueue(entry{"dns", now, e})
}

func DNSAttempt(ctx context.Context, tag string, hit bool) {
	q, _ := ctx.Value(queryKey{}).(*DNSQuery)
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.hits[tag] = hit
	if !hit {
		q.upstreams = append(q.upstreams, tag)
	}
}

func DNSSelected(ctx context.Context, t adapter.DNSTransport) {
	q, _ := ctx.Value(queryKey{}).(*DNSQuery)
	if q == nil || t == nil {
		return
	}
	q.mu.Lock()
	q.resolver = t.Tag()
	q.mu.Unlock()
}

// Response snapshots the wire representation before a packet writer takes
// ownership of its buffer. The returned closure accepts the actual write result.
func (q *DNSQuery) Response(msg *dns.Msg) func(int, error) {
	if q == nil {
		return nil
	}
	e := q.initial
	if msg != nil {
		rc := msg.Rcode
		e.Rcode = &rc
		e.Truncated = msg.Truncated
		for _, rr := range msg.Answer {
			e.Answers = append(e.Answers, rr.String())
		}
	}
	return func(n int, err error) {
		e.Download = n
		if err != nil {
			e.WriteError = err.Error()
		}
		q.finish(e)
	}
}

func (q *DNSQuery) Failed(err error) {
	if q == nil {
		return
	}
	e := q.initial
	e.ResolveError = err.Error()
	q.finish(e)
}

func (q *DNSQuery) finish(e dnsEvent) {
	q.mu.Lock()
	e.Resolver = q.resolver
	if hit, ok := q.hits[q.resolver]; ok {
		e.CacheHit = &hit
	}
	e.Upstreams = append([]string(nil), q.upstreams...)
	q.mu.Unlock()
	r := q.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.queries[q]; !ok {
		return
	}
	delete(r.queries, q)
	if err := r.writeDNS(e, "end"); err != nil {
		r.logger.Error("record DNS completion: ", err)
	}
}
