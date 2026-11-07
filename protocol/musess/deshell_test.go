package musess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// buildTLS13ClientHelloRecord returns one complete TLS record carrying
// a real TLS 1.3 ClientHello, built from the tree's uTLS Chrome 120
// parrot (the same hello the musess outbound sends).
func buildTLS13ClientHelloRecord(t *testing.T) []byte {
	t.Helper()
	raw := buildHello(t, filterParrot)
	if len(raw) == 0 || raw[0] != 0x01 {
		t.Fatalf("parrot hello is not a ClientHello handshake message (first byte %x)", raw[0])
	}
	record := make([]byte, 5+len(raw))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(raw) >> 8)
	record[4] = byte(len(raw))
	copy(record[5:], raw)
	return record
}

// buildMinimalClientHelloRecord builds a small but well-formed TLS 1.3
// ClientHello record by hand, advertising exactly the versions in
// versions (each 0x0303 / 0x0304 ...). Used for the negative cases.
func buildMinimalClientHelloRecord(t *testing.T, versions []uint16) []byte {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0x00)           // session id length 0
	body.Write([]byte{0x00, 0x02, 0x13, 0x01}) // cipher suites: TLS_AES_128_GCM_SHA256
	body.Write([]byte{0x01, 0x00})             // compression methods: null
	// extensions: supported_versions only.
	var extData bytes.Buffer
	extData.WriteByte(byte(len(versions) * 2))
	for _, v := range versions {
		extData.WriteByte(byte(v >> 8))
		extData.WriteByte(byte(v))
	}
	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x2b}) // supported_versions
	exts.Write([]byte{byte(extData.Len() >> 8), byte(extData.Len())})
	exts.Write(extData.Bytes())
	body.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	body.Write(exts.Bytes())
	hs := make([]byte, 4+body.Len())
	hs[0] = 0x01
	hs[1] = byte(body.Len() >> 16)
	hs[2] = byte(body.Len() >> 8)
	hs[3] = byte(body.Len())
	copy(hs[4:], body.Bytes())
	record := make([]byte, 5+len(hs))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(hs) >> 8)
	record[4] = byte(len(hs))
	copy(record[5:], hs)
	return record
}

func TestIsTLS13ClientHello(t *testing.T) {
	real := buildTLS13ClientHelloRecord(t)
	if !isTLS13ClientHello(real) {
		t.Fatalf("real Chrome 120 TLS 1.3 ClientHello not recognised (len=%d)", len(real))
	}
	minimal := buildMinimalClientHelloRecord(t, []uint16{0x0304})
	if !isTLS13ClientHello(minimal) {
		t.Fatalf("minimal TLS 1.3 ClientHello not recognised")
	}
	cases := []struct {
		name   string
		record []byte
	}{
		{"tls12-only", buildMinimalClientHelloRecord(t, []uint16{0x0303})},
		{"no-supported-versions", func() []byte {
			r := buildMinimalClientHelloRecord(t, []uint16{0x0304})
			// Truncate the extensions away by shrinking the body: rebuild
			// without extensions is complex; instead corrupt the extension
			// type to something else.
			// The supported_versions extension sits at the end; find it
			// by scanning for 0x002b.
			for i := 0; i+1 < len(r); i++ {
				if r[i] == 0x00 && r[i+1] == 0x2b {
					r[i+1] = 0x2c
					break
				}
			}
			return r
		}()},
		{"server-hello", func() []byte {
			r := append([]byte(nil), real...)
			r[5] = 0x02 // handshake type ServerHello
			return r
		}()},
		{"application-data-record", func() []byte {
			r := append([]byte(nil), real...)
			r[0] = 0x17
			return r
		}()},
		{"plain-http", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"garbage", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
		{"truncated-record", real[:len(real)/2]},
		{"wrong-record-length", func() []byte {
			r := append([]byte(nil), real...)
			r[3] = 0x00
			r[4] = 0x10
			return r
		}()},
		{"empty", nil},
		{"short", []byte{0x16, 0x03, 0x01}},
	}
	for _, tc := range cases {
		if isTLS13ClientHello(tc.record) {
			t.Errorf("%s: unexpectedly recognised as a TLS 1.3 ClientHello", tc.name)
		}
	}
}

// testSelfSignedCert generates a self-signed ECDSA certificate for the
// outer TLS layer in the wrapper tests.
func testSelfSignedCert(t *testing.T) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "deshell-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := stdtls.X509KeyPair(pemEncodeCert(der), pemEncodeKey(key))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// testOuterTLS returns a connected outer-TLS pair (server, client) over
// a real TCP loopback socket, plus the underlying raw conns.
func testOuterTLS(t *testing.T) (serverTLS, clientTLS *stdtls.Conn, serverRaw, clientRaw net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	acceptCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			acceptCh <- conn
		}
	}()
	clientRaw, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientRaw.Close() })
	select {
	case serverRaw = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	t.Cleanup(func() { serverRaw.Close() })
	cert := testSelfSignedCert(t)
	serverTLS = stdtls.Server(serverRaw, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
	clientTLS = stdtls.Client(clientRaw, &stdtls.Config{InsecureSkipVerify: true, ServerName: "test"})
	errCh := make(chan error, 2)
	go func() { errCh <- serverTLS.Handshake() }()
	go func() { errCh <- clientTLS.Handshake() }()
	deadline := time.After(10 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("outer TLS handshake: %v", err)
			}
		case <-deadline:
			t.Fatal("outer TLS handshake timed out")
		}
	}
	t.Cleanup(func() { serverTLS.Close() })
	t.Cleanup(func() { clientTLS.Close() })
	return serverTLS, clientTLS, serverRaw, clientRaw
}

func testLogger() log.ContextLogger {
	return log.NewNOPFactory().NewLogger("deshell-test")
}

// TestDeshellConnSwitchEndToEnd runs the full Vision-style switch over
// a real TCP + outer-TLS pair: the client writes an inner TLS 1.3
// ClientHello, the server switches and sends the go-signal, the client
// switches, and bulk data then flows raw in both directions.
func TestDeshellConnSwitchEndToEnd(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, true, testLogger())
	if _, err := serverW.SyscallConn(); err == nil {
		t.Fatal("server SyscallConn must fail before the switch")
	}
	if _, err := clientW.SyscallConn(); err == nil {
		t.Fatal("client SyscallConn must fail before the switch")
	}
	if !serverW.NeedHandshakeForRead() || !serverW.NeedHandshakeForWrite() {
		t.Fatal("server handshake must be pending before the switch")
	}
	if !clientW.NeedHandshakeForRead() || !clientW.NeedHandshakeForWrite() {
		t.Fatal("client handshake must be pending before the switch")
	}
	if !serverW.CanDeshell() || !clientW.CanDeshell() {
		t.Fatal("loopback TCP sockets must expose a RawConn")
	}

	hello := buildTLS13ClientHelloRecord(t)
	if _, err := clientW.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	// The server reads the ClientHello (decrypted) and switches.
	got := make([]byte, len(hello)+1024)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Fatalf("server read ClientHello: %v", err)
	}
	if n != len(hello) || !bytes.Equal(got[:n], hello) {
		t.Fatalf("server read %d bytes, want the %d-byte ClientHello", n, len(hello))
	}
	if !serverW.Deshelled() {
		t.Fatal("server did not switch after a TLS 1.3 ClientHello")
	}
	if _, err := serverW.SyscallConn(); err != nil {
		t.Fatalf("server SyscallConn must succeed after the switch: %v", err)
	}
	// With the ack negotiated the handshake stays open past the
	// switch: the ack is still outstanding, and the copy loop must
	// not splice until it is consumed (see TestDeshellAckHoldsHandshakeOpen).
	if !serverW.NeedHandshakeForRead() || !serverW.NeedHandshakeForWrite() {
		t.Fatal("server handshake must stay open after the switch while the ack is outstanding")
	}

	// The server answers with a simulated ServerHello (raw now).
	// Start the client Read first (it blocks on the go-signal),
	// then let a dest-RTT pass before the ServerHello arrives: in
	// the real flow the ServerHello is causally a dest RTT behind
	// the go-signal, so the client consumes the signal before any
	// raw byte can reach it. Writing the ServerHello immediately
	// would let the client's TLS layer read-ahead the raw bytes
	// into its internal buffer (crypto/tls reads up to 512 bytes
	// past the current record), stranding them from the raw read.
	//
	// The server's bulk read also starts now (like the router's
	// upload copy loop, which reads concurrently): it is the reader
	// that consumes the client ack, so the server's Write below is
	// released by the ack itself, not by the ack timeout.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	serverReceived := make([]byte, len(payload))
	serverBulkDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(serverW, serverReceived)
		serverBulkDone <- err
	}()
	clientGot := make([]byte, 4096)
	clientDone := make(chan struct{})
	var clientN int
	var clientErr error
	go func() {
		clientN, clientErr = clientW.Read(clientGot)
		close(clientDone)
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := serverW.Write([]byte("inner-server-hello")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	// The client consumes the go-signal, switches, and reads the answer.
	select {
	case <-clientDone:
	case <-time.After(10 * time.Second):
		t.Fatal("client read timed out")
	}
	if clientErr != nil {
		t.Fatalf("client read: %v", clientErr)
	}
	if string(clientGot[:clientN]) != "inner-server-hello" {
		t.Fatalf("client read %q, want inner-server-hello", clientGot[:clientN])
	}
	if !clientW.Deshelled() {
		t.Fatal("client did not switch after the go-signal")
	}
	if _, err := clientW.SyscallConn(); err != nil {
		t.Fatalf("client SyscallConn must succeed after the switch: %v", err)
	}
	if clientW.NeedHandshakeForRead() || clientW.NeedHandshakeForWrite() {
		t.Fatal("client handshake must be settled after the switch")
	}

	// Bulk data flows raw in both directions after the switch.
	done := make(chan error, 2)
	go func() {
		_, err := clientW.Write(payload)
		done <- err
	}()
	select {
	case err := <-serverBulkDone:
		if err != nil {
			t.Fatalf("server bulk read: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server bulk read timed out")
	}
	if !bytes.Equal(serverReceived, payload) {
		t.Fatal("server bulk payload corrupted")
	}
	if err := <-done; err != nil {
		t.Fatalf("client bulk write: %v", err)
	}
	// The ack was consumed by the server's concurrent bulk read,
	// so the handshake must now be settled and the copy loop free
	// to splice.
	if !serverW.deshellAckGot() {
		t.Fatal("server did not consume the client ack")
	}
	if serverW.NeedHandshakeForRead() || serverW.NeedHandshakeForWrite() {
		t.Fatal("server handshake must be settled after the ack is consumed")
	}
	go func() {
		_, err := serverW.Write(payload)
		done <- err
	}()
	received2 := make([]byte, len(payload))
	if _, err := io.ReadFull(clientW, received2); err != nil {
		t.Fatalf("client bulk read: %v", err)
	}
	if !bytes.Equal(received2, payload) {
		t.Fatal("client bulk payload corrupted")
	}
	if err := <-done; err != nil {
		t.Fatalf("server bulk write: %v", err)
	}
}

// TestDeshellRaceImmediateServerHello reproduces the client TLS
// read-ahead race (DESHELL-MERGE-REPORT.md §6): when the ServerHello
// arrives with zero delay after the go-signal, the client's crypto/tls
// read pulls the raw ServerHello bytes into its internal rawInput
// buffer together with the go-signal record; after the switch to raw
// those bytes are stranded and the inner handshake hangs forever.
//
// Each attempt is one fresh outer-TLS pair + switch, with the
// ServerHello written immediately after the client Read starts (no
// 50 ms grace like TestDeshellConnSwitchEndToEnd). Pre-fix this test
// FAILS on a substantial fraction of attempts; post-fix (client ack)
// it must pass 20/20.
func TestDeshellRaceImmediateServerHello(t *testing.T) {
	const attempts = 20
	failures := 0
	for i := 0; i < attempts; i++ {
		if !deshellRaceImmediateAttempt(t, i) {
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("immediate-ServerHello race: %d/%d attempts failed (client read timed out or got wrong data)", failures, attempts)
	}
}

func deshellRaceImmediateAttempt(t *testing.T, i int) bool {
	t.Helper()
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, true, testLogger())

	hello := buildTLS13ClientHelloRecord(t)
	if _, err := clientW.Write(hello); err != nil {
		t.Logf("attempt %d: client write ClientHello: %v", i, err)
		return false
	}
	got := make([]byte, len(hello)+1024)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Logf("attempt %d: server read ClientHello: %v", i, err)
		return false
	}
	if n != len(hello) || !bytes.Equal(got[:n], hello) {
		t.Logf("attempt %d: server read %d bytes, want the %d-byte ClientHello", i, n, len(hello))
		return false
	}
	if !serverW.Deshelled() {
		t.Logf("attempt %d: server did not switch", i)
		return false
	}

	// The client Read starts first (it blocks on the go-signal),
	// then the ServerHello is written IMMEDIATELY -- no dest-RTT
	// grace. This is the loopback shape (dest RTT ~= 0) that
	// strands the ServerHello in the client's TLS read-ahead buffer.
	//
	// The server's bulk read runs concurrently (like the router's
	// upload copy loop, which reads while the download copy writes):
	// it is the reader that consumes the client ack, so the
	// server's Write is released by the ack itself, not by the
	// ack timeout. Without this concurrent reader the Write would
	// wait out the whole timeout on every attempt.
	payload := bytes.Repeat([]byte("a"), 1024)
	serverGot := make([]byte, len(payload))
	serverReadDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(serverW, serverGot)
		serverReadDone <- err
	}()
	clientGot := make([]byte, 4096)
	clientDone := make(chan struct{})
	var clientN int
	var clientErr error
	go func() {
		clientN, clientErr = clientW.Read(clientGot)
		close(clientDone)
	}()
	writeStart := time.Now()
	if _, err := serverW.Write([]byte("inner-server-hello")); err != nil {
		t.Logf("attempt %d: server write: %v", i, err)
		return false
	}
	writeDur := time.Since(writeStart)
	// The Write must have been released by the ack (fast), not by
	// the ack timeout (2s). A timeout release here would mean the
	// concurrent reader never consumed the ack.
	if writeDur > time.Second {
		t.Logf("attempt %d: server write took %v, want the ack release (~1 RTT), not the %v timeout", i, writeDur, deshellAckTimeout)
		return false
	}
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Logf("attempt %d: client read timed out (ServerHello stranded in TLS read-ahead)", i)
		return false
	}
	if clientErr != nil {
		t.Logf("attempt %d: client read: %v", i, clientErr)
		return false
	}
	if string(clientGot[:clientN]) != "inner-server-hello" {
		t.Logf("attempt %d: client read %q, want inner-server-hello", i, clientGot[:clientN])
		return false
	}
	if !clientW.Deshelled() {
		t.Logf("attempt %d: client did not switch", i)
		return false
	}
	// The client sends 1 KiB; the server's concurrent first
	// post-switch read must have consumed the ack byte first and
	// then deliver the payload intact. This also proves the ack
	// was actually exchanged (the server cannot have released the
	// ServerHello otherwise).
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientW.Write(payload)
		writeDone <- err
	}()
	select {
	case err := <-serverReadDone:
		if err != nil {
			t.Logf("attempt %d: server bulk read: %v", i, err)
			return false
		}
	case <-time.After(3 * time.Second):
		t.Logf("attempt %d: server bulk read timed out", i)
		return false
	}
	if !bytes.Equal(serverGot, payload) {
		t.Logf("attempt %d: server bulk payload corrupted", i)
		return false
	}
	if err := <-writeDone; err != nil {
		t.Logf("attempt %d: client bulk write: %v", i, err)
		return false
	}
	if !serverW.deshellAckGot() {
		t.Logf("attempt %d: server did not consume the client ack", i)
		return false
	}
	return true
}

// TestDeshellAckHoldsHandshakeOpen: the splice guard. While the
// client ack is outstanding, the server's NeedHandshakeForRead and
// NeedHandshakeForWrite must stay true, so sing-box's copy loop
// keeps calling the wrapper's Read/Write (where the ack is
// classified and waited on) instead of upgrading to a kernel splice
// of the raw socket, which would bypass both. Once the ack is
// consumed, both must close so the copy can splice.
func TestDeshellAckHoldsHandshakeOpen(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, true, testLogger())
	defer serverW.Close()
	defer clientW.Close()

	if !serverW.NeedHandshakeForRead() || !serverW.NeedHandshakeForWrite() {
		t.Fatal("handshake must be open before the switch")
	}
	hello := buildTLS13ClientHelloRecord(t)
	if _, err := clientW.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	got := make([]byte, len(hello)+1024)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := serverW.Read(got); err != nil {
		t.Fatalf("server read ClientHello: %v", err)
	}
	if !serverW.Deshelled() {
		t.Fatal("server did not switch")
	}
	// After the switch the handshake must STAY open: the ack is
	// still outstanding, and the copy loop must not splice yet.
	if !serverW.NeedHandshakeForRead() {
		t.Error("NeedHandshakeForRead must stay true while the ack is outstanding (else the copy splices before the ack is consumed)")
	}
	if !serverW.NeedHandshakeForWrite() {
		t.Error("NeedHandshakeForWrite must stay true while the ack is outstanding (else the download splices past the ack wait)")
	}
	// The client reads the go-signal (switches, sends the ack) and
	// the server reads concurrently to consume it.
	go func() {
		buf := make([]byte, 4096)
		_, _ = clientW.Read(buf)
	}()
	go func() {
		buf := make([]byte, 4096)
		_, _ = serverW.Read(buf)
	}()
	// The server writes the ServerHello; it must be released by the
	// ack (fast), proving the concurrent read consumed it.
	writeStart := time.Now()
	if _, err := serverW.Write([]byte("inner-server-hello")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if d := time.Since(writeStart); d > time.Second {
		t.Errorf("server write took %v, want the ack release, not the %v timeout", d, deshellAckTimeout)
	}
	// Wait until the ack is consumed, then the handshake must close.
	deadline := time.Now().Add(3 * time.Second)
	for !serverW.deshellAckGot() {
		if time.Now().After(deadline) {
			t.Fatal("server never consumed the client ack")
		}
		time.Sleep(time.Millisecond)
	}
	if serverW.NeedHandshakeForRead() {
		t.Error("NeedHandshakeForRead must be false after the ack is consumed")
	}
	if serverW.NeedHandshakeForWrite() {
		t.Error("NeedHandshakeForWrite must be false after the ack is consumed")
	}
}

// TestDeshellAckOldClientTimeout: the server negotiated the ack (it
// asked for one) but the client is old and never sends it. The server
// must release its held first downstream bytes after
// deshellAckTimeout, and the client's first data byte must NOT be
// eaten as a fake ack: the stream stays intact.
func TestDeshellAckOldClientTimeout(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, false, testLogger())

	hello := buildTLS13ClientHelloRecord(t)
	if _, err := clientW.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	got := make([]byte, len(hello)+1024)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Fatalf("server read ClientHello: %v", err)
	}
	if n != len(hello) || !bytes.Equal(got[:n], hello) {
		t.Fatalf("server read %d bytes, want the %d-byte ClientHello", n, len(hello))
	}
	if !serverW.Deshelled() {
		t.Fatal("server did not switch after a TLS 1.3 ClientHello")
	}

	// The client Read starts first, then the server writes the
	// ServerHello immediately. Nobody acks, so the server's Write
	// must block for the ack timeout and then succeed.
	clientGot := make([]byte, 4096)
	clientDone := make(chan struct{})
	var clientN int
	var clientErr error
	go func() {
		clientN, clientErr = clientW.Read(clientGot)
		close(clientDone)
	}()
	writeStart := time.Now()
	if _, err := serverW.Write([]byte("inner-server-hello")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	writeDur := time.Since(writeStart)
	select {
	case <-clientDone:
	case <-time.After(10 * time.Second):
		t.Fatal("client read timed out")
	}
	if clientErr != nil {
		t.Fatalf("client read: %v", clientErr)
	}
	if string(clientGot[:clientN]) != "inner-server-hello" {
		t.Fatalf("client read %q, want inner-server-hello", clientGot[:clientN])
	}
	if !clientW.Deshelled() {
		t.Fatal("client did not switch after the go-signal")
	}
	// The Write must have waited for the timeout (not returned
	// instantly, and not hung forever).
	if writeDur < 1500*time.Millisecond {
		t.Errorf("server write returned after %v, want ~= %v ack timeout", writeDur, deshellAckTimeout)
	}
	if writeDur > 4*time.Second {
		t.Errorf("server write took %v, want ~= %v ack timeout", writeDur, deshellAckTimeout)
	}
	if serverW.deshellAckGot() {
		t.Error("server consumed an ack that was never sent")
	}
	if !serverW.deshellAckResolved() {
		t.Error("server ack not resolved after the timeout")
	}

	// Bulk data flows intact in both directions afterwards: the
	// server's ack classifier must not have eaten the client's
	// first data byte (0x61 'a', not the 0x01 ack byte).
	payload := bytes.Repeat([]byte("a"), 64*1024)
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientW.Write(payload)
		writeDone <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(serverW, received); err != nil {
		t.Fatalf("server bulk read: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("server bulk payload corrupted (first byte eaten as a fake ack?)")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client bulk write: %v", err)
	}
	go func() {
		_, err := serverW.Write(payload)
		writeDone <- err
	}()
	received2 := make([]byte, len(payload))
	if _, err := io.ReadFull(clientW, received2); err != nil {
		t.Fatalf("client bulk read: %v", err)
	}
	if !bytes.Equal(received2, payload) {
		t.Fatal("client bulk payload corrupted")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("server bulk write: %v", err)
	}
}

// TestDeshellDeclineSettlesHandshake: the decline-bug fix (idle-box
// full bench 2026-11-07). When deshell negotiates but does NOT
// engage (non-TLS inner traffic), the handshake must still settle
// on both peers so the copy loop leaves its handshake-pending mode
// and the connection runs at plain-TLS speed. Before the fix the
// server's ack was never resolved (the ack timer only starts on the
// switch branch) and the client never marked the decision final, so
// NeedHandshakeForRead/Write stayed true forever and declined
// connections paid ~40% goodput and ~2x CPU.
func TestDeshellDeclineSettlesHandshake(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	// Ack negotiated (true) on both sides: this is the exact shape
	// that kept the handshake open before the fix.
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, true, testLogger())
	defer serverW.Close()
	defer clientW.Close()

	if !serverW.NeedHandshakeForRead() || !serverW.NeedHandshakeForWrite() {
		t.Fatal("server handshake must be open before the decision")
	}
	if !clientW.NeedHandshakeForRead() || !clientW.NeedHandshakeForWrite() {
		t.Fatal("client handshake must be open before the decision")
	}

	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := clientW.Write(httpReq); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 4096)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got[:n], httpReq) {
		t.Fatalf("server read %q, want the HTTP request", got[:n])
	}
	if serverW.Deshelled() {
		t.Fatal("server switched on non-TLS inner traffic")
	}
	// The decline must settle the server handshake: the ack is
	// resolved (it can never arrive) so the copy loop may leave
	// handshake-pending mode.
	if !serverW.deshellAckResolved() {
		t.Error("server ack must be resolved on decline (no ack can ever arrive)")
	}
	if serverW.NeedHandshakeForRead() {
		t.Error("server NeedHandshakeForRead must be false after decline")
	}
	if serverW.NeedHandshakeForWrite() {
		t.Error("server NeedHandshakeForWrite must be false after decline")
	}
	// ... but the raw socket stays hidden: a declined connection
	// is still outer-TLS encrypted and must never be spliced raw.
	if _, err := serverW.SyscallConn(); err == nil {
		t.Error("server SyscallConn must still fail after decline (connection is still encrypted)")
	}

	// The server answers through TLS; the client must read it as
	// data (no go-signal was sent), settle its own handshake, and
	// stay unswitched.
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := serverW.Write(resp); err != nil {
		t.Fatalf("server write: %v", err)
	}
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = clientW.Read(got)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got[:n], resp) {
		t.Fatalf("client read %q, want the HTTP response", got[:n])
	}
	if clientW.Deshelled() {
		t.Fatal("client switched without a go-signal")
	}
	if clientW.NeedHandshakeForRead() {
		t.Error("client NeedHandshakeForRead must be false after receiving non-magic data")
	}
	if clientW.NeedHandshakeForWrite() {
		t.Error("client NeedHandshakeForWrite must be false after receiving non-magic data")
	}
	if _, err := clientW.SyscallConn(); err == nil {
		t.Error("client SyscallConn must still fail after decline (connection is still encrypted)")
	}

	// Bulk data flows intact in both directions on the declined
	// connection (nothing eaten, nothing duplicated).
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	done := make(chan error, 2)
	go func() {
		_, err := clientW.Write(payload)
		done <- err
	}()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(serverW, received); err != nil {
		t.Fatalf("server bulk read: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("server bulk payload corrupted")
	}
	if err := <-done; err != nil {
		t.Fatalf("client bulk write: %v", err)
	}
	go func() {
		_, err := serverW.Write(payload)
		done <- err
	}()
	received2 := make([]byte, len(payload))
	if _, err := io.ReadFull(clientW, received2); err != nil {
		t.Fatalf("client bulk read: %v", err)
	}
	if !bytes.Equal(received2, payload) {
		t.Fatal("client bulk payload corrupted")
	}
	if err := <-done; err != nil {
		t.Fatalf("server bulk write: %v", err)
	}
}

// TestDeshellDeclinedClientReadBypassesSignalCheck pins the second half
// of the decline fix: once the client has decided (non-magic data seen),
// later Reads must go straight to the TLS connection instead of through
// readClientSignal on every call. The signal check is only needed while
// the decision is pending; after it, each Read through readClientSignal
// pays a fresh 16 KiB buffer plus two extra copies (tmp -> chunk ->
// pending -> p) per chunk. On a declined bulk transfer that is the
// dominant cost (~4x CPU per byte, 0.42x goodput on loopback in the
// 2026-11-07 bench), and merely settling `decided` does not remove it.
// This test measures allocations per post-decision Read: the direct
// path allocates ~0, the signal-check path allocates >= 2 (tmp + chunk).
func TestDeshellDeclinedClientReadBypassesSignalCheck(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), true)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, true, testLogger())
	defer serverW.Close()
	defer clientW.Close()

	// Drive the client to a decided state with non-TLS traffic.
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := clientW.Write(httpReq); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 4096)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := serverW.Read(got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := serverW.Write(resp); err != nil {
		t.Fatalf("server write: %v", err)
	}
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := clientW.Read(got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if clientW.NeedHandshakeForRead() {
		t.Fatal("client handshake must be settled before measuring post-decision Reads")
	}

	// Pre-queue 64 chunks of 16 KiB from the server, then measure
	// Reads with no writer running concurrently: AllocsPerRun counts
	// every allocation in the process during the measured calls, so a
	// concurrent writer's own allocations would pollute the number.
	// 1 MiB fits in the socket buffers, so the writer finishes before
	// the measurement starts and each measured Read consumes one
	// buffered chunk.
	chunk := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KiB
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for i := 0; i < 64; i++ {
			if _, err := serverW.Write(chunk); err != nil {
				return
			}
		}
	}()
	select {
	case <-writeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server pre-write timed out")
	}
	buf := make([]byte, 65536)
	// Warm up once so the TLS layer's steady state is measured, not
	// first-Read setup.
	if _, err := clientW.Read(buf); err != nil {
		t.Fatalf("warmup read: %v", err)
	}
	allocs := testing.AllocsPerRun(20, func() {
		if _, err := clientW.Read(buf); err != nil {
			t.Errorf("measured read: %v", err)
		}
	})
	t.Logf("allocs per post-decision client Read: %.1f", allocs)
	if allocs >= 2 {
		t.Errorf("post-decision client Read allocates %.1f times per call, want < 2: the Read is still going through the per-call signal check (fresh 16 KiB tmp + chunk copy) instead of reading straight from TLS", allocs)
	}
}

// TestDeshellConnNonTLSDeclines verifies that non-TLS inner traffic
// never switches either peer and flows through correctly, fully
// encrypted.
func TestDeshellConnNonTLSDeclines(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, nil, testLogger(), false)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, false, testLogger())
	httpReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := clientW.Write(httpReq); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 4096)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got[:n], httpReq) {
		t.Fatalf("server read %q, want the HTTP request", got[:n])
	}
	if serverW.Deshelled() {
		t.Fatal("server switched on non-TLS inner traffic")
	}
	if _, err := serverW.SyscallConn(); err == nil {
		t.Fatal("server SyscallConn must fail when not switched")
	}
	// The server answers through TLS; the client must read it as data
	// (no go-signal was sent) and stay unswitched.
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := serverW.Write(resp); err != nil {
		t.Fatalf("server write: %v", err)
	}
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = clientW.Read(got)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got[:n], resp) {
		t.Fatalf("client read %q, want the HTTP response", got[:n])
	}
	if clientW.Deshelled() {
		t.Fatal("client switched without a go-signal")
	}
}

// TestDeshellConnClientNotAgreed verifies that a client whose server
// did not agree never consumes the go-signal: the magic bytes are
// delivered to the application as ordinary data.
func TestDeshellConnClientNotAgreed(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, _, clientRaw := testOuterTLS(t)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, false, false, testLogger())
	if _, err := serverTLS.Write(deshellMagic); err != nil {
		t.Fatalf("server write magic: %v", err)
	}
	got := make([]byte, 64)
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := clientW.Read(got)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got[:n], deshellMagic) {
		t.Fatalf("client read %q, want the magic bytes delivered as data", got[:n])
	}
	if clientW.Deshelled() {
		t.Fatal("client switched although the server did not agree")
	}
}

// TestDeshellConnStrandedReaderDeclines verifies that a server whose
// peek reader still holds buffered bytes declines the switch (those
// bytes would be stranded by going raw) while still delivering the
// ClientHello correctly through TLS.
func TestDeshellConnStrandedReaderDeclines(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS, serverRaw, clientRaw := testOuterTLS(t)
	// A peek reader holding stranded bytes. A bufio.Reader only
	// fills its buffer on the first Read, so consume one byte to
	// leave the rest buffered.
	stranded := bufio.NewReader(bytes.NewReader([]byte("stranded-bytes")))
	if _, err := stranded.ReadByte(); err != nil {
		t.Fatal(err)
	}
	if stranded.Buffered() == 0 {
		t.Fatal("test setup: peek reader holds no buffered bytes")
	}
	serverW := newServerDeshellConn(ctx, serverTLS, serverRaw, stranded, testLogger(), false)
	clientW := newClientDeshellConn(ctx, clientTLS, clientRaw, true, false, testLogger())
	hello := buildTLS13ClientHelloRecord(t)
	if _, err := clientW.Write(hello); err != nil {
		t.Fatalf("client write ClientHello: %v", err)
	}
	got := make([]byte, len(hello)+1024)
	serverTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := serverW.Read(got)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got[:n], hello) {
		t.Fatalf("server read %d bytes, want the ClientHello", n)
	}
	if serverW.Deshelled() {
		t.Fatal("server switched although the peek reader holds stranded bytes")
	}
	if _, err := serverW.SyscallConn(); err == nil {
		t.Fatal("server SyscallConn must fail when not switched")
	}
}
