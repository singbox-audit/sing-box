package audit

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

var _ adapter.ConnectionTracker = (*Recorder)(nil)

type connectionEvent struct {
	ID                string   `json:"conn_id"`
	Type              string   `json:"event_type"`
	Time              int64    `json:"event_time"`
	Seq               uint64   `json:"seq"`
	Inbound           string   `json:"inbound_tag"`
	Protocol          string   `json:"inbound_type"`
	User              string   `json:"auth_user"`
	Network           string   `json:"network"`
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
}

func (r *Recorder) begin(m adapter.InboundContext, network string) (*session, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	event := connectionEvent{
		ID:                id.String(),
		Type:              "start",
		Inbound:           m.Inbound,
		Protocol:          m.InboundType,
		User:              m.User,
		Network:           network,
		RoutedDestination: m.Destination.String(),
		SniffedDomain:     m.Domain,
		Rule:              m.RouteRule,
		Outbound:          m.RouteOutbound,
	}
	for _, member := range m.OutboundChain {
		event.Chain = append(event.Chain, member.Tag())
	}
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
	event := s.event
	event.Type = kind
	event.Seq++
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

func (r *Recorder) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	s, err := r.begin(m, "tcp")
	if err != nil {
		r.logger.Error("record TCP connection start: ", err)
		conn.Close()
		return conn
	}
	counted := bufio.NewInt64CounterConn(conn, []*atomic.Int64{&s.upload}, []*atomic.Int64{&s.download})
	return &stream{ExtendedConn: counted, close: sync.OnceValue(func() error { return errors.Join(counted.Close(), s.end()) })}
}

func (r *Recorder) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	s, err := r.begin(m, "udp")
	if err != nil {
		r.logger.Error("record UDP connection start: ", err)
		conn.Close()
		return conn
	}
	counted := bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&s.upload}, nil, []*atomic.Int64{&s.download}, nil)
	return &packet{PacketConn: counted, close: sync.OnceValue(func() error { return errors.Join(counted.Close(), s.end()) })}
}

func (*Recorder) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type stream struct {
	N.ExtendedConn
	close func() error
}

func (s *stream) Close() error            { return s.close() }
func (s *stream) Upstream() any           { return s.ExtendedConn }
func (s *stream) ReaderReplaceable() bool { return true }
func (s *stream) WriterReplaceable() bool { return true }

type packet struct {
	N.PacketConn
	close func() error
}

func (p *packet) Close() error            { return p.close() }
func (p *packet) Upstream() any           { return p.PacketConn }
func (p *packet) ReaderReplaceable() bool { return true }
func (p *packet) WriterReplaceable() bool { return true }
