package route

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	dnsOutbound "github.com/sagernet/sing-box/protocol/dns"
	R "github.com/sagernet/sing-box/route/rule"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func (r *Router) hijackDNSStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.searchProcessInfo(ctx, &metadata)
	metadata.Destination = M.Socksaddr{}
	err := N.ReportConnHandshakeSuccess(conn, conn)
	if err != nil {
		return E.Cause(err, "report handshake success")
	}
	for {
		conn.SetReadDeadline(time.Now().Add(C.DNSTimeout))
		err = dnsOutbound.HandleStreamDNSRequest(ctx, r.dns, conn, metadata)
		if err != nil {
			if !E.IsClosedOrCanceled(err) {
				return err
			} else {
				return nil
			}
		}
	}
}

func (r *Router) hijackDNSPacket(ctx context.Context, conn N.PacketConn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	r.searchProcessInfo(ctx, &metadata)
	err := N.ReportPacketConnHandshakeSuccess(conn, nil)
	if err != nil {
		N.ReleaseMultiPacketBuffer(packetBuffers)
		err = E.Cause(err, "report handshake success")
	} else {
		err = dnsOutbound.NewDNSPacketConnection(ctx, r.dns, conn, packetBuffers, metadata)
	}
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil && !E.IsClosedOrCanceled(err) {
		return E.Cause(err, "process DNS packet")
	}
	return nil
}

func (r *Router) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
	var message mDNS.Msg
	err := message.Unpack(payload)
	if err != nil {
		r.logger.ErrorContext(ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	r.searchProcessInfo(ctx, &metadata)
	destination := metadata.Destination
	metadata.Destination = M.Socksaddr{}
	report := func(exchangeErr error) {
		if exchangeErr != nil && !R.IsRejected(exchangeErr) && !E.IsClosedOrCanceled(exchangeErr) {
			r.logger.ErrorContext(ctx, E.Cause(exchangeErr, "process DNS packet"))
		}
	}
	report(dnsOutbound.ExchangePacket(ctx, r.dns, metadata, &message, len(payload), writer, destination, N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer), report))
}
