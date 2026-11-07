package musess

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/musess/fec"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// FEC wiring between the musess data plane and the transport-
// agnostic fec package (DESIGN.md 5.2). Negotiation model: the
// client asks for FEC in its v2 request header (both direction
// bits set — FEC runs as a symmetric duplex because fec.Conn
// frames both directions of one connection). The server answers
// with one status byte after the header: 0x01 = FEC duplex active,
// 0x00 = plain milestone-1 framing. A v1 client never triggers FEC
// and never reads a status byte.

// fecMode is the parsed fec option.
type fecMode int

const (
	fecModeOff fecMode = iota
	fecModeAuto
	fecModeOn
)

func parseFECMode(value string) (fecMode, error) {
	switch value {
	case "", "off":
		return fecModeOff, nil
	case "auto":
		return fecModeAuto, nil
	case "on":
		return fecModeOn, nil
	default:
		return fecModeOff, E.New("musess: invalid fec mode ", value, " (want off, auto or on)")
	}
}

func (m fecMode) enabled() bool { return m != fecModeOff }

func (m fecMode) optionString() string {
	switch m {
	case fecModeAuto:
		return "auto"
	case fecModeOn:
		return "on"
	default:
		return "off"
	}
}

// Production FEC construction. Codec and controller strategy are
// the winners of the milestone-2 head-to-head comparison recorded
// in impl/README.md (Reed-Solomon + estimator): RS won on delivery
// under burst loss and on encode CPU; the estimator won on
// goodput across the loss matrix. Both losers remain in the fec
// package and in its benchmark harness.
func newFECController(mode fecMode) fec.Controller {
	return fec.NewController("estimator", fec.FloorForMode(mode.optionString()))
}

// applyFECEscapeHatches applies the MUSESS_FEC_EXP environment
// variable (comma list), which since the 2026-11-05 landing only
// *disables* adopted fec behaviours — an escape hatch for
// measurement baselines and emergency rollback, never part of
// normal configuration:
//
//	"ordered"  packet plane delivers in group order (milestone 2)
//	"noeager"  gap accounting waits for arrival pauses (milestone 2)
//	"nospend"  small-group spend policy off (milestone 2 pricing)
//
// The legacy tokens "uo" and "eager" are accepted and ignored:
// they name what is now the production default. With the
// variable unset the options are exactly the production ones.
func applyFECEscapeHatches(options *fec.Options) {
	for _, flag := range strings.Split(os.Getenv("MUSESS_FEC_EXP"), ",") {
		switch strings.TrimSpace(flag) {
		case "ordered":
			options.PacketOrdered = true
		case "noeager":
			options.NoEagerGapSynthesis = true
		case "nospend":
			options.SpendPolicyOff = true
		}
	}
}

func newFECConn(conn net.Conn, mode fecMode, packet bool, logger logger.ContextLogger) *fec.Conn {
	options := fec.Options{Mode: fec.ModeStream}
	if packet {
		options.Mode = fec.ModePacket
	}
	applyFECEscapeHatches(&options)
	options.OnClose = func(stats fec.Stats) {
		if logger != nil {
			// sing's log formatter panics on float64 arguments
			// ("unknown value"), so format to a single string.
			logger.Debug(fmt.Sprintf("musess fec stats: app_out=%d wire_out=%d overhead=%.4f recovered=%d lost=%d",
				stats.AppBytesOut, stats.WireBytesOut, stats.OverheadRatio(), stats.ShardsRecovered, stats.ShardsLost))
		}
	}
	return fec.NewConn(conn, fec.NewRSCodec(16), newFECController(mode), options)
}

// fecPacketConn adapts a packet-mode fec.Conn to sing's PacketConn:
// each message carries the milestone-1 per-packet framing
// ([address][uint16 length][payload]) as its payload, so the UDP
// plane's semantics are unchanged — the FEC layer only decides
// which of those framed packets also get parity protection.
type fecPacketConn struct {
	ep         *fec.Conn
	writeMutex sync.Mutex
}

func newFECPacketConn(ep *fec.Conn) *fecPacketConn {
	return &fecPacketConn{ep: ep}
}

func (c *fecPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	message, err := c.ep.ReadMessage()
	if err != nil {
		return M.Socksaddr{}, err
	}
	reader := &sliceReader{data: message}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return M.Socksaddr{}, err
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(reader, lengthBytes[:]); err != nil {
		return M.Socksaddr{}, err
	}
	length := int(lengthBytes[0])<<8 | int(lengthBytes[1])
	// Same headroom contract as streamPacketConn.ReadPacket: do NOT
	// Reset() the buffer, it would destroy the front headroom reserved
	// for the destination's WritePacket. Truncate(0) preserves start.
	buffer.Truncate(0)
	if _, err = io.CopyN(buffer, reader, int64(length)); err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *fecPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	frame := buf.NewSize(M.MaxSocksaddrLength + 2 + buffer.Len())
	err := M.SocksaddrSerializer.WriteAddrPort(frame, destination)
	if err != nil {
		frame.Release()
		return err
	}
	var lengthBytes [2]byte
	lengthBytes[0] = byte(uint16(buffer.Len()) >> 8)
	lengthBytes[1] = byte(uint16(buffer.Len()))
	frame.Write(lengthBytes[:])
	frame.Write(buffer.Bytes())
	err = c.ep.WriteMessage(frame.Bytes())
	frame.Release()
	return err
}

func (c *fecPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := buf.NewSize(len(p))
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, buffer.Bytes())
	buffer.Release()
	return n, destination.UDPAddr(), nil
}

func (c *fecPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	buffer := buf.NewSize(len(p))
	buffer.Write(p)
	err := c.WritePacket(buffer, destination)
	buffer.Release()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *fecPacketConn) Close() error                       { return c.ep.Close() }
func (c *fecPacketConn) LocalAddr() net.Addr                { return c.ep.LocalAddr() }
func (c *fecPacketConn) RemoteAddr() net.Addr               { return c.ep.RemoteAddr() }
func (c *fecPacketConn) SetDeadline(t time.Time) error      { return c.ep.SetDeadline(t) }
func (c *fecPacketConn) SetReadDeadline(t time.Time) error  { return c.ep.SetReadDeadline(t) }
func (c *fecPacketConn) SetWriteDeadline(t time.Time) error { return c.ep.SetWriteDeadline(t) }

// sliceReader is a minimal io.Reader over a byte slice.
type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}
