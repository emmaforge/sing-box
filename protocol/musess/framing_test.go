package musess

import (
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestStreamPacketConnRoundTrip(t *testing.T) {
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
	client := newStreamPacketConn(clientConn)
	server := <-serverSide

	destination := M.ParseSocksaddr("127.0.0.1:15353")
	payload := []byte("musess-udp-probe-0123456789")

	// client -> server
	outBuffer := buf.NewSize(len(payload))
	outBuffer.Write(payload)
	if err = client.WritePacket(outBuffer, destination); err != nil {
		t.Fatal("WritePacket:", err)
	}
	outBuffer.Release()

	inBuffer := buf.NewSize(4096)
	gotDestination, err := server.ReadPacket(inBuffer)
	if err != nil {
		t.Fatal("ReadPacket:", err)
	}
	if gotDestination != destination {
		t.Fatalf("destination mismatch: got %v, want %v", gotDestination, destination)
	}
	if string(inBuffer.Bytes()) != string(payload) {
		t.Fatalf("payload mismatch: got %q", string(inBuffer.Bytes()))
	}
	inBuffer.Release()

	// server -> client (echo direction)
	echoBuffer := buf.NewSize(len(payload))
	echoBuffer.Write(payload)
	if err = server.WritePacket(echoBuffer, destination); err != nil {
		t.Fatal("WritePacket (echo):", err)
	}
	echoBuffer.Release()
	backBuffer := buf.NewSize(4096)
	if _, err = client.ReadPacket(backBuffer); err != nil {
		t.Fatal("ReadPacket (echo):", err)
	}
	if string(backBuffer.Bytes()) != string(payload) {
		t.Fatalf("echo payload mismatch: got %q", string(backBuffer.Bytes()))
	}
	backBuffer.Release()
}

func TestRequestHeaderRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	destination := M.ParseSocksaddr("dest.test:8443")
	go func() {
		_ = writeRequest(clientConn, commandUDP, destination)
	}()
	version, command, flags, got, err := readRequest(serverConn)
	if err != nil {
		t.Fatal("readRequest:", err)
	}
	if version != framingVersion || flags != 0 {
		t.Fatalf("v1 header: version %d flags %d", version, flags)
	}
	if command != commandUDP {
		t.Fatalf("command mismatch: %d", command)
	}
	if got != destination {
		t.Fatalf("destination mismatch: got %v, want %v", got, destination)
	}
	_ = io.Discard
}

func TestRequestHeaderV2RoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	destination := M.ParseSocksaddr("dest.test:8443")
	go func() {
		_ = writeRequestV2(clientConn, commandTCP, destination, fecFlagForward|fecFlagReverse)
	}()
	version, command, flags, got, err := readRequest(serverConn)
	if err != nil {
		t.Fatal("readRequest:", err)
	}
	if version != framingVersion2 {
		t.Fatalf("version: got %d want %d", version, framingVersion2)
	}
	if flags != fecFlagForward|fecFlagReverse {
		t.Fatalf("flags: got %d", flags)
	}
	if command != commandTCP {
		t.Fatalf("command mismatch: %d", command)
	}
	if got != destination {
		t.Fatalf("destination mismatch: got %v, want %v", got, destination)
	}
}
