package musess

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	sbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recordingPacketWriter struct {
	packets chan []byte
}

func (w *recordingPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := make([]byte, buffer.Len())
	copy(payload, buffer.Bytes())
	w.packets <- payload
	return nil
}

// Replicates the sing-box route stack for inbound packet connections:
// the router sniffs (reads) the first packet, wraps the connection in a
// CachedPacketConn, then ConnectionManager copies with bufio.CopyPacket.
func TestRouteCopyStack(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			serverConnCh <- conn
		}
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverRaw := <-serverConnCh

	client := newStreamPacketConn(clientRaw)
	server := newStreamPacketConn(serverRaw)
	destination := M.ParseSocksaddr("127.0.0.1:15353")
	payload := []byte("musess-udp-probe-0123456789")

	// Client sends one packet before the "router" starts: this is the
	// packet the sniffer will peek.
	outBuffer := buf.NewSize(len(payload))
	outBuffer.Write(payload)
	if err = client.WritePacket(outBuffer, destination); err != nil {
		t.Fatal(err)
	}
	outBuffer.Release()

	// Sniff peek: read one packet from the raw inbound conn.
	peekBuffer := buf.NewSize(4096)
	peekDest, err := server.ReadPacket(peekBuffer)
	if err != nil {
		t.Fatal("sniff peek:", err)
	}
	cached := sbufio.NewCachedPacketConn(server, peekBuffer, peekDest)

	writer := &recordingPacketWriter{packets: make(chan []byte, 4)}
	copyDone := make(chan error, 1)
	go func() {
		_, err := sbufio.CopyPacket(writer, cached)
		copyDone <- err
	}()

	select {
	case got := <-writer.packets:
		if string(got) != string(payload) {
			t.Fatalf("forwarded payload mismatch: %q", got)
		}
		t.Log("first packet forwarded by copy loop")
	case <-time.After(3 * time.Second):
		t.Fatal("copy loop did not forward the cached packet")
	}

	// The copy loop must still be alive, waiting for the next packet.
	select {
	case err := <-copyDone:
		t.Fatalf("copy loop exited after first packet: err=%v", err)
	case <-time.After(500 * time.Millisecond):
		t.Log("copy loop still running after first packet (expected)")
	}

	// A second packet must also be forwarded.
	outBuffer2 := buf.NewSize(len(payload))
	outBuffer2.Write(payload)
	if err = client.WritePacket(outBuffer2, destination); err != nil {
		t.Fatal(err)
	}
	outBuffer2.Release()
	select {
	case got := <-writer.packets:
		if string(got) != string(payload) {
			t.Fatalf("second payload mismatch: %q", got)
		}
		t.Log("second packet forwarded")
	case <-time.After(3 * time.Second):
		t.Fatal("copy loop did not forward the second packet")
	}
	_ = N.NetworkTCP
}
