package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/audit"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

func HandleStreamDNSRequest(ctx context.Context, router adapter.DNSRouter, conn net.Conn, metadata adapter.InboundContext) error {
	var queryLength uint16
	err := binary.Read(conn, binary.BigEndian, &queryLength)
	if err != nil {
		return err
	}
	if queryLength == 0 {
		return dns.RcodeFormatError
	}
	buffer := buf.NewSize(int(queryLength))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(conn, int(queryLength))
	if err != nil {
		return err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	if err != nil {
		return err
	}
	ctx, q, err := audit.BeginDNS(ctx, metadata, "tcp", &message, int(queryLength)+2)
	if err != nil {
		return err
	}
	metadataInQuery := metadata
	router.ExchangeAsync(adapter.WithContext(ctx, &metadataInQuery), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
		if err != nil {
			q.Failed(err)
			conn.Close()
			return
		}
		go writeStreamResponse(conn, response, q)
	})
	return nil
}

func writeStreamResponse(conn net.Conn, response *mDNS.Msg, q *audit.DNSQuery) {
	responseLength := response.Len()
	responseBuffer := buf.NewSize(3 + responseLength)
	defer responseBuffer.Release()
	responseBuffer.Resize(2, 0)
	compressedResponse := *response
	compressedResponse.Compress = true
	n, err := compressedResponse.PackBuffer(responseBuffer.FreeBytes())
	result := q.Response(response)
	if err != nil {
		if result != nil {
			result(0, err)
		}
		return
	}
	responseBuffer.Truncate(len(n))
	binary.BigEndian.PutUint16(responseBuffer.ExtendHeader(2), uint16(len(n)))
	written, err := conn.Write(responseBuffer.Bytes())
	if written != responseBuffer.Len() && err == nil {
		err = io.ErrShortWrite
	}
	if result != nil {
		result(written, err)
	}
}

func NewDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, cachedPackets []*N.PacketBuffer, metadata adapter.InboundContext) error {
	metadata.Destination = M.Socksaddr{}
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)
	var reader N.PacketReader = conn
	var counters []N.CountFunc
	cachedPackets = common.Reverse(cachedPackets)
	for {
		reader, counters = N.UnwrapCountPacketReader(reader, counters)
		if cachedReader, isCached := reader.(N.CachedPacketReader); isCached {
			packet := cachedReader.ReadCachedPacket()
			if packet != nil {
				cachedPackets = append(cachedPackets, packet)
				continue
			}
		}
		if readWaiter, created := bufio.CreatePacketReadWaiter(reader); created {
			readWaiter.InitializeReadWaiter(N.ReadWaitOptions{})
			return newDNSPacketConnection(ctx, router, conn, readWaiter, counters, cachedPackets, metadata)
		}
		break
	}
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var message mDNS.Msg
			var size int
			var destination M.Socksaddr
			var err error
			if len(cachedPackets) > 0 {
				packet := cachedPackets[0]
				cachedPackets = cachedPackets[1:]
				for _, counter := range counters {
					counter(int64(packet.Buffer.Len()))
				}
				size = packet.Buffer.Len()
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				destination = packet.Destination
			} else {
				buffer := buf.NewPacket()
				destination, err = conn.ReadPacket(buffer)
				if err != nil {
					buffer.Release()
					cancel(err)
					return err
				}
				for _, counter := range counters {
					counter(int64(buffer.Len()))
				}
				size = buffer.Len()
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			err = ExchangePacket(ctx, router, metadata, &message, size, conn, destination, frontHeadroom, rearHeadroom, func(e error) {
				if e != nil {
					cancel(e)
				} else {
					timeout.Update()
				}
			})
			if err != nil {
				return err
			}
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}

func newDNSPacketConnection(ctx context.Context, router adapter.DNSRouter, conn N.PacketConn, readWaiter N.PacketReadWaiter, readCounters []N.CountFunc, cached []*N.PacketBuffer, metadata adapter.InboundContext) error {
	frontHeadroom := N.CalculateFrontHeadroom(conn)
	rearHeadroom := N.CalculateRearHeadroom(conn)
	fastClose, cancel := context.WithCancelCause(ctx)
	timeout := canceler.New(fastClose, cancel, C.DNSTimeout)
	var group task.Group
	group.Append0(func(_ context.Context) error {
		for {
			var (
				size        int
				message     mDNS.Msg
				destination M.Socksaddr
				err         error
				buffer      *buf.Buffer
			)
			if len(cached) > 0 {
				packet := cached[0]
				cached = cached[1:]
				for _, counter := range readCounters {
					counter(int64(packet.Buffer.Len()))
				}
				size = packet.Buffer.Len()
				err = message.Unpack(packet.Buffer.Bytes())
				packet.Buffer.Release()
				destination = packet.Destination
				N.PutPacketBuffer(packet)
				if err != nil {
					cancel(err)
					return err
				}
			} else {
				buffer, destination, err = readWaiter.WaitReadPacket()
				if err != nil {
					cancel(err)
					return err
				}
				for _, counter := range readCounters {
					counter(int64(buffer.Len()))
				}
				size = buffer.Len()
				err = message.Unpack(buffer.Bytes())
				buffer.Release()
				if err != nil {
					cancel(err)
					return err
				}
				timeout.Update()
			}
			err = ExchangePacket(ctx, router, metadata, &message, size, conn, destination, frontHeadroom, rearHeadroom, func(e error) {
				if e != nil {
					cancel(e)
				} else {
					timeout.Update()
				}
			})
			if err != nil {
				return err
			}
		}
	})
	group.Cleanup(func() {
		conn.Close()
	})
	return group.Run(fastClose)
}

// ExchangePacket handles one decoded client datagram, including its final wire response.
func ExchangePacket(ctx context.Context, router adapter.DNSRouter, metadata adapter.InboundContext, msg *mDNS.Msg, size int, writer N.PacketWriter, destination M.Socksaddr, front, rear int, done func(error)) error {
	ctx, q, err := audit.BeginDNS(ctx, metadata, "udp", msg, size)
	if err != nil {
		return err
	}
	router.ExchangeAsync(adapter.WithContext(ctx, &metadata), msg, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, err error) {
		if err != nil {
			q.Failed(err)
			done(err)
			return
		}
		buffer, err := dns.TruncateDNSMessage(msg, response, front, rear)
		if err != nil {
			if result := q.Response(response); result != nil {
				result(0, err)
			}
			done(err)
			return
		}
		n := buffer.Len()
		var result func(int, error)
		if q != nil {
			var wire mDNS.Msg
			if err = wire.Unpack(buffer.Bytes()); err != nil {
				buffer.Release()
				q.Failed(err)
				done(err)
				return
			}
			result = q.Response(&wire)
		}
		err = writer.WritePacket(buffer, destination)
		if result != nil {
			if err != nil {
				n = 0
			}
			result(n, err)
		}
		done(err)
	})
	return nil
}
