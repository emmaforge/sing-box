package musess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Data-plane framing inside the authenticated TLS stream. Deliberately
// minimal (Emma's priority order: throughput first): a one-byte version,
// a one-byte command, a SOCKS-style address, then either the raw stream
// (TCP) or length-prefixed addressed packets (UDP). No padding, no
// extra layers.

const (
	framingVersion = 0x01
	// framingVersion2 adds a flags byte to the request header for
	// FEC negotiation. Peers that only speak v1 keep the exact
	// milestone-1 wire behaviour.
	framingVersion2   = 0x02
	commandTCP        = 0x01
	commandUDP        = 0x02
	serverProofLength = 32
)

// Request-header flags (v2 only).
const (
	// fecFlagForward: the sender protects its sending direction
	// with FEC records and asks the peer to do the same in reverse
	// (FEC is negotiated as a symmetric duplex; see fecwire.go).
	fecFlagForward = 0x01
	// fecFlagReverse: the sender accepts FEC records in the
	// reverse direction.
	fecFlagReverse = 0x02
	// deshellFlag: the sender offers the Direction 4 deshell
	// (XTLS-Vision-style post-handshake raw splice; see deshell.go).
	// TCP only, and only when FEC is off. The server answers in
	// the v2 status byte (deshellStatusFlag).
	deshellFlag = 0x04
	// deshellAckFlag: the sender supports the deshell post-switch
	// ack (deshell ack v1; see deshell.go). Set in the v2 request
	// header alongside deshellFlag. The server answers in the v2
	// status byte (deshellAckStatusFlag) when it wants the ack.
	deshellAckFlag = 0x08
)

// Status-byte flags (v2 only, server -> client).
const (
	// fecStatusFlag: FEC duplex is active for this connection.
	fecStatusFlag = 0x01
	// deshellStatusFlag: the server agrees to deshell. It will
	// switch to the raw TCP stream if the first inner record is a
	// TLS 1.3 ClientHello, and will then send the deshell go-signal
	// (deshell.go) so the client switches too. No signal is sent
	// when the inner traffic is not TLS 1.3; the client then keeps
	// reading through TLS and nothing changes.
	deshellStatusFlag = 0x02
	// deshellAckStatusFlag: the server requires the client to send
	// the one-byte post-switch ack (deshell ack v1; see deshell.go).
	// Set only when the client advertised deshellAckFlag, so old
	// clients are never asked for an ack they cannot send (they
	// keep the pre-ack behaviour, including the ~2% read-ahead
	// race) and new clients always get the protection.
	deshellAckStatusFlag = 0x04
)

func writeRequest(w io.Writer, command byte, destination M.Socksaddr) error {
	header := buf.NewSize(2 + M.MaxSocksaddrLength)
	header.WriteByte(framingVersion)
	header.WriteByte(command)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	_, err = w.Write(header.Bytes())
	return err
}

func writeRequestV2(w io.Writer, command byte, destination M.Socksaddr, flags byte) error {
	header := buf.NewSize(3 + M.MaxSocksaddrLength)
	header.WriteByte(framingVersion2)
	header.WriteByte(command)
	header.WriteByte(flags)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	_, err = w.Write(header.Bytes())
	return err
}

// buildRequestHeader renders a request header into memory: v2 with
// flags when useV2, v1 otherwise (mirrors the on-wire writers).
// A v2 header is needed whenever FEC is enabled or deshell is
// requested, because the server answers both negotiations in the
// v2 status byte.
func buildRequestHeader(useV2 bool, command byte, destination M.Socksaddr, flags byte) ([]byte, error) {
	var buffer bytes.Buffer
	var err error
	if useV2 {
		err = writeRequestV2(&buffer, command, destination, flags)
	} else {
		err = writeRequest(&buffer, command, destination)
	}
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// readRequestAuto reads a request header that may be plain (first
// byte is a framing version) or sealed (first byte is
// sealedRequestMarker; see auth.go). It lets an early_request server
// keep accepting plain clients.
//
// It also accepts at most one leading safe 0-RTT frame (first byte
// zeroRTTMarker; see speculative.go) before the request. The frame is
// decrypted against the TLS exporter and its one-time nonce checked:
// a fresh nonce applies the (non-authenticated) transport state, a
// replayed or corrupt frame is silently discarded, and in every case
// the session still needs its normal authenticated request header
// afterwards. The frame can never authenticate, route, or serve
// anything, so a client sending one to a server that does not apply
// 0-RTT state (zrt == nil or zrt.apply == false) still gets a normal
// working session.
func readRequestAuto(r io.Reader, proofKey []byte, zrt *zeroRTTServer, exporter []byte) (version byte, command byte, flags byte, destination M.Socksaddr, err error) {
	var first [1]byte
	if _, err = io.ReadFull(r, first[:]); err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	if first[0] == zeroRTTMarker {
		var lengthBytes [2]byte
		if _, err = io.ReadFull(r, lengthBytes[:]); err != nil {
			return 0, 0, 0, M.Socksaddr{}, err
		}
		bodyLen := int(binary.BigEndian.Uint16(lengthBytes[:]))
		if bodyLen > zeroRTTMaxBody {
			return 0, 0, 0, M.Socksaddr{}, errors.New("musess: 0-RTT frame too large")
		}
		body := make([]byte, bodyLen)
		if _, err = io.ReadFull(r, body); err != nil {
			return 0, 0, 0, M.Socksaddr{}, err
		}
		if zrt != nil {
			// Fresh, replayed, or corrupt: all three are safe
			// outcomes here. Only a fresh frame changes anything
			// (transport state), and it never changes routing.
			_, _, _ = zrt.AcceptFrame(exporter, body)
		}
		if _, err = io.ReadFull(r, first[:]); err != nil {
			return 0, 0, 0, M.Socksaddr{}, err
		}
	}
	if first[0] != sealedRequestMarker {
		return readRequest(io.MultiReader(bytes.NewReader(first[:]), r))
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(r, lengthBytes[:]); err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	body := make([]byte, int(binary.BigEndian.Uint16(lengthBytes[:])))
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	header, err := openSealedRequest(proofKey, body)
	if err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	return readRequest(bytes.NewReader(header))
}

// readRequest parses a v1 or v2 request header. It returns the
// header version and flags (zero for v1) alongside command and
// destination.
func readRequest(r io.Reader) (version byte, command byte, flags byte, destination M.Socksaddr, err error) {
	var preamble [2]byte
	if _, err = io.ReadFull(r, preamble[:]); err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	version = preamble[0]
	switch version {
	case framingVersion:
	case framingVersion2:
		var flagByte [1]byte
		if _, err = io.ReadFull(r, flagByte[:]); err != nil {
			return 0, 0, 0, M.Socksaddr{}, err
		}
		flags = flagByte[0]
	default:
		return 0, 0, 0, M.Socksaddr{}, errors.New("musess: unsupported framing version")
	}
	destination, err = M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return 0, 0, 0, M.Socksaddr{}, err
	}
	return version, preamble[1], flags, destination, nil
}

// streamPacketConn adapts the framed TLS stream to sing's PacketConn:
// each packet is [address][2-byte length][payload].
type streamPacketConn struct {
	net.Conn
	writeMutex sync.Mutex
}

func newStreamPacketConn(conn net.Conn) *streamPacketConn {
	return &streamPacketConn{Conn: conn}
}

func (c *streamPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := M.SocksaddrSerializer.ReadAddrPort(c.Conn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return M.Socksaddr{}, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	// Do NOT Reset() here: the caller (bufio.CopyPacketWithPool) may have
	// reserved front headroom in this buffer for the destination's
	// WritePacket (e.g. SOCKS UDP header via ExtendHeader). Reset() zeroes
	// start and destroys that headroom, crashing the destination with
	// "buffer overflow" on ExtendHeader. Truncate(0) clears the length
	// while preserving start.
	buffer.Truncate(0)
	if _, err = io.CopyN(buffer, c.Conn, int64(length)); err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *streamPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	header := buf.NewSize(M.MaxSocksaddrLength + 2)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(buffer.Len()))
	header.Write(lengthBytes[:])
	_, err = c.Conn.Write(header.Bytes())
	header.Release()
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(buffer.Bytes())
	return err
}

// ReadFrom implements net.PacketConn on top of the framed stream.
func (c *streamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := buf.NewSize(len(p))
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, buffer.Bytes())
	buffer.Release()
	return n, destination.UDPAddr(), nil
}

// WriteTo implements net.PacketConn on top of the framed stream.
func (c *streamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
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

// framedPacketConn is the packet-framing interface shared by the
// plain stream packet conn and the FEC packet conn.
type framedPacketConn interface {
	ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error)
	WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// packetStreamConn adapts a packet connection bound to one fixed
// destination to a net.Conn (used for outbound DialContext with UDP).
type packetStreamConn struct {
	packetConn  framedPacketConn
	destination M.Socksaddr
	leftover    []byte
}

func newPacketStreamConn(packetConn framedPacketConn, destination M.Socksaddr) *packetStreamConn {
	return &packetStreamConn{packetConn: packetConn, destination: destination}
}

func (c *packetStreamConn) Read(p []byte) (int, error) {
	if len(c.leftover) == 0 {
		buffer := buf.NewSize(64 * 1024)
		_, err := c.packetConn.ReadPacket(buffer)
		if err != nil {
			return 0, err
		}
		c.leftover = append(c.leftover[:0], buffer.Bytes()...)
		buffer.Release()
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *packetStreamConn) Write(p []byte) (int, error) {
	buffer := buf.NewSize(len(p))
	buffer.Write(p)
	err := c.packetConn.WritePacket(buffer, c.destination)
	buffer.Release()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetStreamConn) Close() error         { return c.packetConn.Close() }
func (c *packetStreamConn) LocalAddr() net.Addr  { return c.packetConn.LocalAddr() }
func (c *packetStreamConn) RemoteAddr() net.Addr { return c.packetConn.RemoteAddr() }
func (c *packetStreamConn) SetDeadline(t time.Time) error {
	return c.packetConn.SetDeadline(t)
}
func (c *packetStreamConn) SetReadDeadline(t time.Time) error {
	return c.packetConn.SetReadDeadline(t)
}
func (c *packetStreamConn) SetWriteDeadline(t time.Time) error {
	return c.packetConn.SetWriteDeadline(t)
}
