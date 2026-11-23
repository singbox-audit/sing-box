package audit

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type connectionEvent struct {
	RunID             string   `json:"run_id"`
	ID                string   `json:"conn_id"`
	Type              string   `json:"event_type"`
	Time              int64    `json:"event_time"`
	Seq               uint64   `json:"seq"`
	Inbound           string   `json:"inbound_tag"`
	Protocol          string   `json:"inbound_type"`
	User              string   `json:"auth_user"`
	Network           string   `json:"network"`
	RequestedHost     string   `json:"requested_host"`
	RequestedPort     uint16   `json:"requested_port"`
	Result            string   `json:"result"`
	Detail            string   `json:"error,omitempty"`
	TargetIP          string   `json:"target_ip,omitempty"`
	RoutedDestination string   `json:"routed_destination"`
	SniffedDomain     string   `json:"sniffed_domain,omitempty"`
	Rule              string   `json:"route_rule,omitempty"`
	Outbound          string   `json:"route_outbound"`
	Chain             []string `json:"outbound_chain"`
	Upload            int64    `json:"upload_bytes"`
	Download          int64    `json:"download_bytes"`
}

type session struct {
	recorder         *Recorder
	event            connectionEvent
	upload, download atomic.Int64
	copies           atomic.Int32
}

func makeConnectionEvent(id string, m adapter.InboundContext, original M.Socksaddr) connectionEvent {
	event := connectionEvent{
		ID:                id,
		Type:              "start",
		Inbound:           m.Inbound,
		Protocol:          m.InboundType,
		User:              m.User,
		Network:           m.Network,
		RequestedHost:     original.AddrString(),
		RequestedPort:     original.Port,
		Result:            "routed",
		RoutedDestination: m.Destination.String(),
		SniffedDomain:     m.Domain,
		Rule:              m.RouteRule,
		Outbound:          m.RouteOutbound,
	}
	for _, member := range m.OutboundChain {
		event.Chain = append(event.Chain, member.Tag())
	}
	return event
}

func (r *Recorder) Decision(m adapter.InboundContext, original M.Socksaddr, rule adapter.Rule, outbound, result string, cause error) error {
	if r == nil {
		return nil
	}
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	e := makeConnectionEvent(id.String(), m, original)
	e.Type = "decision"
	e.Result = result
	e.Outbound = outbound
	if rule != nil {
		e.Rule = rule.String()
	}
	if cause != nil {
		e.Detail = cause.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeEvent(e)
}

func (r *Recorder) SelectionError(m adapter.InboundContext, original M.Socksaddr, rule adapter.Rule, outbound string, cause error) error {
	if err := r.Decision(m, original, rule, outbound, "selection_error", cause); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (r *Recorder) begin(m adapter.InboundContext, original M.Socksaddr) (*session, error) {
	if err := r.admissionError(); err != nil {
		return nil, err
	}
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	event := makeConnectionEvent(id.String(), m, original)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.writeEvent(event); err != nil {
		return nil, err
	}
	s := &session{recorder: r, event: event}
	r.active[s] = struct{}{}
	return s, nil
}

func (s *session) finalEvent(kind string) connectionEvent {
	s.event.Seq++
	event := s.event
	event.Type = kind
	event.Upload = s.upload.Load()
	event.Download = s.download.Load()
	return event
}

func (s *session) end() error {
	r := s.recorder
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.active[s]; !ok {
		return nil
	}
	delete(r.active, s)
	err := r.writeEvent(s.finalEvent("end"))
	if err != nil {
		s.recorder.logger.Error("record connection end: ", err)
	}
	return err
}

// Track after the router has selected its outbound, before the dial starts.
func (r *Recorder) TrackTCP(ctx context.Context, c net.Conn, m adapter.InboundContext, original M.Socksaddr, onClose N.CloseHandlerFunc) (context.Context, net.Conn, N.CloseHandlerFunc, error) {
	s, err := r.begin(m, original)
	if err != nil {
		return ctx, c, onClose, err
	}
	return context.WithValue(ctx, sessionKey{}, s), bufio.NewInt64CounterConn(c, []*atomic.Int64{&s.upload}, []*atomic.Int64{&s.download}), s.onClose(onClose), nil
}

func (r *Recorder) TrackUDP(ctx context.Context, c N.PacketConn, m adapter.InboundContext, original M.Socksaddr, onClose N.CloseHandlerFunc) (context.Context, N.PacketConn, N.CloseHandlerFunc, error) {
	s, err := r.begin(m, original)
	if err != nil {
		return ctx, c, onClose, err
	}
	return context.WithValue(ctx, sessionKey{}, s), bufio.NewInt64CounterPacketConn(c, []*atomic.Int64{&s.upload}, nil, []*atomic.Int64{&s.download}, nil), s.onClose(onClose), nil
}

type sessionKey struct{}

func (s *session) onClose(next N.CloseHandlerFunc) N.CloseHandlerFunc {
	return N.AppendClose(next, func(error) {
		if s.copies.Load() == 0 {
			s.end()
		}
	})
}

// The UDP manager reports closure on the first returning copy. Publish final
// counters only after both copy loops have finished updating them.
func StartCopies(ctx context.Context) {
	if s, _ := ctx.Value(sessionKey{}).(*session); s != nil {
		s.copies.Store(2)
	}
}

func CopyFinished(ctx context.Context) {
	if s, _ := ctx.Value(sessionKey{}).(*session); s != nil && s.copies.Add(-1) == 0 {
		s.end()
	}
}

func DialResult(ctx context.Context, result string, ip netip.Addr, err error) {
	s, _ := ctx.Value(sessionKey{}).(*session)
	if s == nil {
		return
	}
	s.recorder.mu.Lock()
	defer s.recorder.mu.Unlock()
	s.event.Result = result
	if ip.IsValid() {
		s.event.TargetIP = ip.String()
	}
	if err != nil {
		s.event.Detail = err.Error()
	}
}
