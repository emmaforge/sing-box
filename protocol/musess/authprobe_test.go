// Auth-path differential prober (certshape-probe ONLY — never merge).
//
// Measures the DESIGN.md Ch.10 #2 single-stack items on the
// AUTHENTICATED path (Go stdlib TLS termination with the local cert)
// against the same items on a direct connection to the dest
// stand-in (Go stdlib TLS with the dest cert):
//   - ServerHello bytes / JA4S (raw record dumped for ja4.py)
//   - presented certificate (leaf fingerprint, issuer, SANs)
//   - NewSessionTicket count / length / arrival timing
//   - Q2: random app-data record after handshake -> alert bytes + close
//   - Q3: valid app-data record with corrupted MAC -> alert + close
//   - non-advancing (empty app-data) record tolerance count
//   - close_notify behaviour on clean close
//
// Run (env-gated, skipped by default):
//   MUSESS_AUTH_PROBE=1 PROBE_ADDR=127.0.0.1:18443 PROBE_DEST_ADDR=127.0.0.1:22443 \
//     PROBE_PUBKEY=<base64> PROBE_UUID=<uuid> PROBE_SECRET=<secret> PROBE_SNI=dest.test \
//     PROBE_MODE=auth|direct PROBE_OUT=/tmp/probe.json \
//     go test -run TestAuthPathProbe -v -count=1 ./protocol/musess/
//
// The probe builds the ClientHello exactly like the musess outbound
// (uTLS Chrome 120 parrot, ML-KEM share stripped, auth token in
// legacy_session_id when PROBE_MODE=auth, random session ID when
// direct). A tap conn records every server->client byte with a
// timestamp so NSTs and alerts are visible even though TLS 1.3
// encrypts them.
package musess

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	utls "github.com/metacubex/utls"
)

type tapEvent struct {
	At     time.Time `json:"at"`
	Dir    string    `json:"dir"` // "r" = server->client bytes read, "w" = client->server bytes written
	Record []byte    `json:"-"`   // raw bytes (not serialized)
	Note   string    `json:"note,omitempty"`
}

type tapConn struct {
	net.Conn
	mu     sync.Mutex
	events []tapEvent
	t0     time.Time
}

func newTapConn(c net.Conn) *tapConn { return &tapConn{Conn: c, t0: time.Now()} }

func (t *tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		cp := make([]byte, n)
		copy(cp, p[:n])
		t.mu.Lock()
		t.events = append(t.events, tapEvent{At: time.Now(), Dir: "r", Record: cp})
		t.mu.Unlock()
	}
	return n, err
}

func (t *tapConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		cp := make([]byte, n)
		copy(cp, p[:n])
		t.mu.Lock()
		t.events = append(t.events, tapEvent{At: time.Now(), Dir: "w", Record: cp})
		t.mu.Unlock()
	}
	return n, err
}

// splitRecords parses a byte stream into (type, len) TLS records.
func splitRecords(b []byte) [][2]int {
	var out [][2]int
	off := 0
	for off+5 <= len(b) {
		ln := int(b[off+3])<<8 | int(b[off+4])
		out = append(out, [2]int{int(b[off]), ln})
		off += 5 + ln
		if ln < 0 || off > len(b) {
			break
		}
	}
	return out
}

type probeResult struct {
	Mode         string      `json:"mode"`
	ServerHello  string      `json:"server_hello_hex,omitempty"` // raw first handshake record
	CipherSuite  uint16      `json:"cipher_suite"`
	Extensions   []uint16    `json:"server_hello_extensions"`
	CertSHA256   string      `json:"cert_sha256,omitempty"`
	CertSubject  string      `json:"cert_subject,omitempty"`
	CertIssuer   string      `json:"cert_issuer,omitempty"`
	CertDNSNames []string    `json:"cert_dns_names,omitempty"`
	PostHS       [][2]int    `json:"post_handshake_records"` // (type,len) of records after the handshake flight
	NSTCount     int         `json:"nst_count"`
	NSTLens      []int       `json:"nst_lengths"`
	FirstByteMs  float64     `json:"first_byte_ms"`
	ProofLen     int         `json:"proof_len"`
	Q2Alert      string      `json:"q2_alert"` // hex of alert record, "" if none
	Q2Closed     bool        `json:"q2_closed"`
	Q3Alert      string      `json:"q3_alert"`
	Q3Closed     bool        `json:"q3_closed"`
	NonAdvCount  int         `json:"nonadv_tolerated"` // empty records tolerated before alert/close (-1 = never)
	NonAdvFirst  string      `json:"nonadv_first_response,omitempty"` // hex of what arrived on the first empty record, if anything
	CloseNotify  bool        `json:"close_notify_on_clean_close"`
	Notes        []string    `json:"notes,omitempty"`
}

func probeBuildHello(t *testing.T, rawConn net.Conn, serverName, pubkeyB64, uuid, secret, mode string) (*utls.UConn, *tapConn) {
	tap := newTapConn(rawConn)
	uConfig := &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
	}
	uConn := utls.UClient(tap, uConfig, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	for i, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.KeyShareExtension:
			ext.KeyShares = common.Filter(ext.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		case *utls.SupportedCurvesExtension:
			ext.Curves = common.Filter(ext.Curves, func(curve utls.CurveID) bool {
				return curve != utls.X25519MLKEM768
			})
		case *utls.RenegotiationInfoExtension:
			spec.Extensions[i] = &utls.GenericExtension{Id: 65281, Data: []byte{0x00}}
		}
	}
	if err = uConn.ApplyPreset(&spec); err != nil {
		t.Fatalf("preset: %v", err)
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		t.Fatalf("build state: %v", err)
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) < 39+sessionIDLength {
		t.Fatalf("hello too short")
	}
	hello.SessionId = make([]byte, sessionIDLength)
	copy(hello.Raw[39:], hello.SessionId)
	fields, err := ParseClientHello(hello.Raw)
	if err != nil {
		t.Fatalf("parse own hello: %v", err)
	}
	if mode == "auth" {
		pub, err := ParsePublicKey(pubkeyB64)
		if err != nil {
			t.Fatalf("pubkey: %v", err)
		}
		ks := uConn.HandshakeState.State13.KeyShareKeys
		if ks == nil || ks.Ecdhe == nil {
			t.Fatalf("no ecdhe share")
		}
		sa, err := NewClientSessionAuth(pub, ks.Ecdhe, uuid, secret)
		if err != nil {
			t.Fatalf("session auth: %v", err)
		}
		sid := sa.SessionID(fields, time.Now())
		hello.SessionId = sid
		copy(hello.Raw[39:], sid)
	} else {
		// direct: random session id, no auth
		sid := make([]byte, sessionIDLength)
		if _, err := rand.Read(sid); err != nil {
			t.Fatalf("rand: %v", err)
		}
		hello.SessionId = sid
		copy(hello.Raw[39:], sid)
	}
	return uConn, tap
}

func TestAuthPathProbe(t *testing.T) {
	if os.Getenv("MUSESS_AUTH_PROBE") == "" {
		t.Skip("set MUSESS_AUTH_PROBE=1 to run")
	}
	mode := os.Getenv("PROBE_MODE") // auth | direct
	addr := os.Getenv("PROBE_ADDR")
	serverName := os.Getenv("PROBE_SNI")
	outPath := os.Getenv("PROBE_OUT")
	if addr == "" || serverName == "" {
		t.Fatalf("PROBE_ADDR and PROBE_SNI required")
	}
	res := &probeResult{Mode: mode}

	// ---- phase 1: handshake, record flight -------------------------
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	uConn, tap := probeBuildHello(t, rawConn, serverName,
		os.Getenv("PROBE_PUBKEY"), os.Getenv("PROBE_UUID"), os.Getenv("PROBE_SECRET"), mode)
	t0 := time.Now()
	if err := uConn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	hsDone := time.Since(t0)
	_ = hsDone
	cs := uConn.ConnectionState()
	res.CipherSuite = cs.CipherSuite
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		res.CertSHA256 = hex.EncodeToString(sum[:])
		res.CertSubject = leaf.Subject.String()
		res.CertIssuer = leaf.Issuer.String()
		res.CertDNSNames = leaf.DNSNames
	}
	// ServerHello = first server->client handshake record.
	tap.mu.Lock()
	var s2c []byte
	for _, ev := range tap.events {
		if ev.Dir == "r" {
			s2c = append(s2c, ev.Record...)
		}
	}
	tap.mu.Unlock()
	if len(s2c) >= 5 && s2c[0] == 0x16 {
		ln := int(s2c[3])<<8 | int(s2c[4])
		if 5+ln <= len(s2c) {
			res.ServerHello = hex.EncodeToString(s2c[:5+ln])
			// parse extensions: record[5]=handshake type 2, len 3, then
			// legacy_version(2) random(32) session_id len(1)+id
			// cipher(2) compression(1) extensions len(2) extensions...
			body := s2c[5 : 5+ln]
			if len(body) > 4 && body[0] == 2 {
				exts, err := parseServerHelloExtensions(body)
				if err == nil {
					res.Extensions = exts
				} else {
					res.Notes = append(res.Notes, "sh ext parse: "+err.Error())
				}
			}
		}
	}
	// (The post-handshake record split is recomputed after the
	// 2s drain in phase 2, where the flight/NST boundary is known.)
	_ = tap
	_ = s2c

	// ---- phase 2: drain post-handshake server records for 2s -------
	// Read via the TLS conn: the musess server sends a 32-byte proof
	// (auth mode) right after the handshake; the dest sends nothing
	// until it gets an HTTP request. Use a short deadline and count
	// what arrives at the tap level.
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if mode == "auth" {
		buf := make([]byte, 32)
		if _, err := io.ReadFull(uConn, buf); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("proof read: %v", err))
		} else {
			res.ProofLen = 32
		}
	} else {
		buf := make([]byte, 1)
		_, _ = uConn.Read(buf) // expect timeout; dest sends nothing yet
	}
	rawConn.SetReadDeadline(time.Time{})

	// Re-collect the tap stream and recount post-handshake records
	// with timing. In TLS 1.3 the handshake flight after ServerHello
	// is encrypted: EncryptedExtensions, Certificate, CertificateVerify
	// and Finished arrive as four type-23 records, then the NST(s),
	// then (auth mode) the 32-byte musess proof as a 49-byte record.
	// NST = type-23 records after those first four, excluding the proof.
	tap.mu.Lock()
	var timed []tapEvent
	for _, ev := range tap.events {
		if ev.Dir == "r" {
			timed = append(timed, ev)
		}
	}
	tap.mu.Unlock()
	var full []byte
	for _, ev := range timed {
		full = append(full, ev.Record...)
	}
	allRecs := splitRecords(full)
	// Flight = records up to and including the 4th type-23 record
	// (EE, Cert, CV, Finished). Everything after is NST / proof.
	seen23 := 0
	fe := len(allRecs)
	for i, r := range allRecs {
		if r[0] == 23 {
			seen23++
			if seen23 == 4 {
				fe = i + 1
				break
			}
		}
	}
	var nstLens []int
	for _, r := range allRecs[fe:] {
		if r[0] == 23 && r[1] != 49 { // 49 = musess proof record
			nstLens = append(nstLens, r[1])
		}
	}
	res.NSTCount = len(nstLens)
	res.NSTLens = nstLens
	res.PostHS = allRecs[fe:]

	// ---- phase 3: Q2/Q3/non-advancing on FRESH connections ---------
	// (fresh conns so each probe starts from a clean handshake)
	res.Q2Alert, res.Q2Closed = probeGarbage(t, addr, serverName, mode, false)
	res.Q3Alert, res.Q3Closed = probeGarbage(t, addr, serverName, mode, true)
	res.NonAdvCount, res.NonAdvFirst = probeNonAdv(t, addr, serverName, mode)
	res.CloseNotify = probeCleanClose(t, addr, serverName, mode)

	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if outPath != "" {
		_ = os.WriteFile(outPath, out, 0o644)
	}
}

func parseServerHelloExtensions(body []byte) ([]uint16, error) {
	// body: handshake msg: type(1) len(3) legacy_version(2) random(32)
	// session_id_len(1) session_id cipher(2) compression(1) ext_len(2) exts
	if len(body) < 39 {
		return nil, fmt.Errorf("short hello %d", len(body))
	}
	p := 4 + 2 + 32
	if p >= len(body) {
		return nil, fmt.Errorf("no sid len")
	}
	sidLen := int(body[p])
	p += 1 + sidLen + 2 + 1
	if p+2 > len(body) {
		return nil, fmt.Errorf("no ext len")
	}
	extLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	end := p + extLen
	if end > len(body) {
		return nil, fmt.Errorf("ext overrun")
	}
	var exts []uint16
	for p+4 <= end {
		exts = append(exts, uint16(body[p])<<8|uint16(body[p+1]))
		ln := int(body[p+2])<<8 | int(body[p+3])
		p += 4 + ln
	}
	return exts, nil
}

// probeGarbage dials fresh, handshakes, reads the proof if auth mode,
// then writes one garbage app-data record (random bytes) or, when
// badMAC, a copy of a valid app-data record with one MAC byte flipped.
// Returns the alert record hex (if any) and whether the server closed.
func probeGarbage(t *testing.T, addr, serverName, mode string, badMAC bool) (string, bool) {
	t.Helper()
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "dial-fail:" + err.Error(), false
	}
	defer rawConn.Close()
	uConn, _ := probeBuildHello(t, rawConn, serverName,
		os.Getenv("PROBE_PUBKEY"), os.Getenv("PROBE_UUID"), os.Getenv("PROBE_SECRET"), mode)
	if err := uConn.HandshakeContext(t.Context()); err != nil {
		return "hs-fail:" + err.Error(), false
	}
	// Drain the proof (auth) so the server is waiting for the request.
	if mode == "auth" {
		rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 32)
		_, _ = io.ReadFull(uConn, buf)
		rawConn.SetReadDeadline(time.Time{})
	}
	if badMAC {
		// Q3 as in probe-chasing-nst.py: a well-formed 48-byte
		// app-data record of random bytes. The server cannot
		// decrypt it (AEAD failure, same class as a flipped-MAC
		// record — a true flipped-MAC copy is unobtainable without
		// a valid record to copy, and the TLS layer cannot tell
		// the two apart).
		rec := make([]byte, 5+48)
		rec[0] = 23
		rec[3] = 0
		rec[4] = 48
		if _, err := rand.Read(rec[5:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		_, _ = rawConn.Write(rec)
	} else {
		rec := make([]byte, 5+64)
		rec[0] = 23
		rec[3] = 0
		rec[4] = 64
		if _, err := rand.Read(rec[5:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		_, _ = rawConn.Write(rec)
	}
	// Read the response: expect alert(21) + close, within 3s.
	rawConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 4096)
	n, _ := rawConn.Read(resp)
	closed := false
	rawConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = rawConn.Read(make([]byte, 1))
	if err != nil {
		closed = true
	}
	if n <= 0 {
		return "", closed
	}
	return hex.EncodeToString(resp[:n]), closed
}

// probeNonAdv sends empty app-data records one at a time and counts
// how many the server tolerates before alerting/closing. It first
// drains for 500ms so a late NST cannot be mistaken for a reaction
// to the empty record; returns the count and the hex of the first
// response bytes, if any.
func probeNonAdv(t *testing.T, addr, serverName, mode string) (int, string) {
	t.Helper()
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return -2, ""
	}
	defer rawConn.Close()
	uConn, _ := probeBuildHello(t, rawConn, serverName,
		os.Getenv("PROBE_PUBKEY"), os.Getenv("PROBE_UUID"), os.Getenv("PROBE_SECRET"), mode)
	if err := uConn.HandshakeContext(t.Context()); err != nil {
		return -2, ""
	}
	// Drain: auth mode reads the proof (NST is consumed internally
	// first); direct mode waits out the NST window.
	rawConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if mode == "auth" {
		buf := make([]byte, 32)
		_, _ = io.ReadFull(uConn, buf)
	} else {
		buf := make([]byte, 1)
		_, _ = uConn.Read(buf) // expect timeout; dest sends only the NST
	}
	// Any bytes the TLS stack already buffered internally are gone;
	// now read the raw socket once more to catch a straggler NST.
	rawConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	straggler := make([]byte, 4096)
	n, _ := rawConn.Read(straggler)
	_ = n
	rawConn.SetReadDeadline(time.Time{})
	tolerated := 0
	empty := []byte{23, 0x03, 0x03, 0, 0}
	for i := 0; i < 40; i++ {
		if _, err := rawConn.Write(empty); err != nil {
			return tolerated, ""
		}
		// Give the server a moment to react, then check for a reply.
		rawConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		resp := make([]byte, 256)
		n, _ := rawConn.Read(resp)
		if n > 0 {
			// alert or anything else: stop, this record was not tolerated
			return tolerated, hex.EncodeToString(resp[:n])
		}
		tolerated++
	}
	rawConn.SetReadDeadline(time.Time{})
	return tolerated, ""
}

// probeCleanClose: handshake, read proof if auth, then send
// close_notify and see whether the server answers with close_notify.
func probeCleanClose(t *testing.T, addr, serverName, mode string) bool {
	t.Helper()
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return false
	}
	defer rawConn.Close()
	uConn, _ := probeBuildHello(t, rawConn, serverName,
		os.Getenv("PROBE_PUBKEY"), os.Getenv("PROBE_UUID"), os.Getenv("PROBE_SECRET"), mode)
	if err := uConn.HandshakeContext(t.Context()); err != nil {
		return false
	}
	if mode == "auth" {
		rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 32)
		_, _ = io.ReadFull(uConn, buf)
		rawConn.SetReadDeadline(time.Time{})
	}
	// Clean close via the TLS conn: sends close_notify.
	_ = uConn.Close()
	// Read raw: server should reply close_notify (alert 21, len 2,
	// payload 01 00) before TCP FIN, if it mirrors Go behaviour.
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 256)
	n, _ := rawConn.Read(resp)
	if n >= 7 && resp[0] == 21 && resp[5] == 1 && resp[6] == 0 {
		return true
	}
	return false
}
