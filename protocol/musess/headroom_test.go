package musess

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Regression test for the 2026-11-06 e2e UDP panic.
//
// sing's packet-copy path (bufio.CopyPacketWithPool) allocates the read
// buffer with front headroom reserved for the destination's WritePacket
// (a SOCKS UDP destination needs 3 + AddrPortLen bytes, 10 for an IPv4
// destination, via ExtendHeader). The musess packet conns used to call
// buffer.Reset() in ReadPacket, which zeroes start and destroys that
// headroom, so the destination's ExtendHeader panicked with
// "buffer overflow: capacity 16384, start 0, need 10" and crashed the
// client. The fix is Truncate(0), which clears the length while
// preserving start.
//
// Both tests below read into a buffer with 10 bytes of front headroom
// reserved (the same shape CopyPacketWithPool produces) and then perform
// the destination's ExtendHeader call. With the old Reset() code the
// headroom assertion fails and ExtendHeader panics; with the fix both
// pass and the payload is intact.

func TestStreamPacketConnPreservesFrontHeadroom(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverSide := make(chan *streamPacketConn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serverSide <- newStreamPacketConn(conn)
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	client := newStreamPacketConn(clientConn)
	server := <-serverSide

	destination := M.ParseSocksaddr("127.0.0.1:15353")
	payload := []byte("musess-udp-probe-0123456789")

	outBuffer := buf.NewSize(len(payload))
	outBuffer.Write(payload)
	if err = server.WritePacket(outBuffer, destination); err != nil {
		t.Fatal("WritePacket:", err)
	}
	outBuffer.Release()

	// Buffer as CopyPacketWithPool hands it to ReadPacket: 10 bytes of
	// front headroom reserved for the downstream WritePacket.
	inBuffer := buf.NewSize(4096)
	inBuffer.Resize(10, 0)
	if _, err = client.ReadPacket(inBuffer); err != nil {
		t.Fatal("ReadPacket:", err)
	}
	if inBuffer.Start() < 10 {
		t.Fatalf("front headroom destroyed by ReadPacket: start=%d, want >= 10", inBuffer.Start())
	}
	if string(inBuffer.Bytes()) != string(payload) {
		t.Fatalf("payload mismatch: got %q", string(inBuffer.Bytes()))
	}
	// The exact call a SOCKS UDP destination makes in WritePacket.
	header := inBuffer.ExtendHeader(10)
	if len(header) != 10 {
		t.Fatalf("ExtendHeader returned %d bytes, want 10", len(header))
	}
	inBuffer.Release()
}

func TestFECPacketConnPreservesFrontHeadroom(t *testing.T) {
	a, b := net.Pipe()
	senderEP := newFECConn(a, fecModeAuto, true, nil)
	receiverEP := newFECConn(b, fecModeAuto, true, nil)
	defer senderEP.Close()
	defer receiverEP.Close()
	sender := newFECPacketConn(senderEP)
	receiver := newFECPacketConn(receiverEP)

	destination := M.ParseSocksaddr("127.0.0.1:15353")
	payload := []byte("musess-udp-probe-0123456789")

	outBuffer := buf.NewSize(len(payload))
	outBuffer.Write(payload)
	if err := sender.WritePacket(outBuffer, destination); err != nil {
		t.Fatal("WritePacket:", err)
	}
	outBuffer.Release()

	inBuffer := buf.NewSize(4096)
	inBuffer.Resize(10, 0)
	if _, err := receiver.ReadPacket(inBuffer); err != nil {
		t.Fatal("ReadPacket:", err)
	}
	if inBuffer.Start() < 10 {
		t.Fatalf("front headroom destroyed by ReadPacket: start=%d, want >= 10", inBuffer.Start())
	}
	if string(inBuffer.Bytes()) != string(payload) {
		t.Fatalf("payload mismatch: got %q", string(inBuffer.Bytes()))
	}
	header := inBuffer.ExtendHeader(10)
	if len(header) != 10 {
		t.Fatalf("ExtendHeader returned %d bytes, want 10", len(header))
	}
	inBuffer.Release()
}
