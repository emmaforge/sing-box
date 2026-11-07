package musess

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// Speculative direction-5 tests: safe 0-RTT (nonce replay), warm pool
// lifecycle, race byte counting, and option parsing. Nothing here
// touches the network: the live behaviour is covered by
// impl/test/test-speculative.sh.

var specTestExporter = bytes.Repeat([]byte{0x5a}, 32)

func TestZeroRTTFrameRoundTrip(t *testing.T) {
	frame, nonce, err := sealZeroRTTFrame(specTestExporter, zeroRTTPayload{FECModeHint: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != zeroRTTNonceLength {
		t.Fatalf("nonce length %d, want %d", len(nonce), zeroRTTNonceLength)
	}
	if frame[0] != zeroRTTMarker {
		t.Fatalf("frame marker %#x, want %#x", frame[0], zeroRTTMarker)
	}
	// A different exporter (a different TLS session) must not open it.
	if _, _, err := openZeroRTTFrame(bytes.Repeat([]byte{0x6b}, 32), frame[3:]); err == nil {
		t.Fatal("frame opened under a different exporter, want failure")
	}
	gotNonce, payload, err := openZeroRTTFrame(specTestExporter, frame[3:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Fatal("nonce mismatch after round trip")
	}
	if payload.FECModeHint != 1 {
		t.Fatalf("payload hint %d, want 1", payload.FECModeHint)
	}
	// Tamper with one ciphertext byte: open must fail.
	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := openZeroRTTFrame(specTestExporter, tampered[3:]); err == nil {
		t.Fatal("tampered frame opened, want failure")
	}
}

func TestZeroRTTNonceReplay(t *testing.T) {
	registry := newZeroRTTRegistry()
	nonce := bytes.Repeat([]byte{0x11}, zeroRTTNonceLength)
	now := time.Now()
	if !registry.checkAndInsert(nonce, now) {
		t.Fatal("fresh nonce rejected")
	}
	if registry.checkAndInsert(nonce, now) {
		t.Fatal("replayed nonce accepted, want rejection")
	}
	other := bytes.Repeat([]byte{0x22}, zeroRTTNonceLength)
	if !registry.checkAndInsert(other, now) {
		t.Fatal("different nonce rejected, want acceptance")
	}
	// A nonce whose window has expired may be used again.
	if !registry.checkAndInsert(nonce, now.Add(zeroRTTWindow+time.Second)) {
		t.Fatal("expired nonce rejected, want acceptance after window")
	}
}

func TestZeroRTTServerAcceptAndReplay(t *testing.T) {
	server := newZeroRTTServer(true)
	frame, _, err := sealZeroRTTFrame(specTestExporter, zeroRTTPayload{FECModeHint: 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, fresh, applied := server.AcceptFrame(specTestExporter, frame[3:])
	if !fresh || !applied {
		t.Fatalf("fresh frame: fresh=%v applied=%v, want true/true", fresh, applied)
	}
	if payload.FECModeHint != 2 {
		t.Fatalf("payload hint %d, want 2", payload.FECModeHint)
	}
	// Byte-identical replay of the same frame: the nonce is spent,
	// so the server reports nothing usable — and the session must
	// continue as an ordinary session (fresh=false).
	if _, fresh, _ := server.AcceptFrame(specTestExporter, frame[3:]); fresh {
		t.Fatal("replayed frame reported fresh, want stale")
	}
	if server.replayed.Load() != 1 {
		t.Fatalf("replayed counter %d, want 1", server.replayed.Load())
	}
	// Corrupt body: invalid, never fresh.
	if _, fresh, _ := server.AcceptFrame(specTestExporter, []byte{0x00, 0x01}); fresh {
		t.Fatal("corrupt frame reported fresh, want stale")
	}
	// Server with apply=false still consumes the nonce and reports
	// fresh, but does not apply the transport state.
	off := newZeroRTTServer(false)
	frame2, _, err := sealZeroRTTFrame(specTestExporter, zeroRTTPayload{FECModeHint: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, fresh, applied := off.AcceptFrame(specTestExporter, frame2[3:]); !fresh || applied {
		t.Fatalf("apply=false frame: fresh=%v applied=%v, want true/false", fresh, applied)
	}
}

func TestReadRequestAutoWithZeroRTTFrame(t *testing.T) {
	server := newZeroRTTServer(true)
	header, err := buildRequestHeader(false, commandTCP, earlyTestDest, 0)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealRequest(earlyTestProofKey, header)
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := sealZeroRTTFrame(specTestExporter, zeroRTTPayload{FECModeHint: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Frame first, then the sealed request: the request must still
	// parse and the frame must count as accepted.
	wire := append(append([]byte(nil), frame...), sealed...)
	_, command, _, dest, err := readRequestAuto(bytes.NewReader(wire), earlyTestProofKey, server, specTestExporter)
	if err != nil {
		t.Fatal(err)
	}
	if command != commandTCP || dest != earlyTestDest {
		t.Fatalf("got command %d dest %v", command, dest)
	}
	if server.accepted.Load() != 1 {
		t.Fatalf("accepted counter %d, want 1", server.accepted.Load())
	}
	// Same frame bytes replayed in a new session: the frame is
	// ignored as a replay, but the request behind it is still
	// served normally — the replay buys nothing and breaks nothing.
	wire2 := append(append([]byte(nil), frame...), sealed...)
	_, command, _, dest, err = readRequestAuto(bytes.NewReader(wire2), earlyTestProofKey, server, specTestExporter)
	if err != nil {
		t.Fatal(err)
	}
	if command != commandTCP || dest != earlyTestDest {
		t.Fatalf("replay leg: got command %d dest %v", command, dest)
	}
	if server.replayed.Load() != 1 {
		t.Fatalf("replayed counter %d, want 1", server.replayed.Load())
	}
	// No 0-RTT server configured (nil): the frame is parsed and
	// discarded, the request still parses.
	wire3 := append(append([]byte(nil), frame...), sealed...)
	if _, _, _, _, err := readRequestAuto(bytes.NewReader(wire3), earlyTestProofKey, nil, nil); err != nil {
		t.Fatalf("nil 0-RTT server rejected a framed request: %v", err)
	}
}

func TestWarmPoolLifecycle(t *testing.T) {
	newPipeSession := func() *warmSession {
		client, server := net.Pipe()
		_ = server // the test holds one end; the pool owns the other
		return &warmSession{conn: client, proofKey: []byte{0x01}, exporter: specTestExporter, createdAt: time.Now()}
	}
	pool := newWarmPool(2, 50*time.Millisecond, nil, nil)
	if got := pool.get(); got != nil {
		t.Fatal("empty pool returned a session")
	}
	if pool.Stats().Misses != 1 {
		t.Fatalf("misses %d, want 1", pool.Stats().Misses)
	}
	s1 := newPipeSession()
	s2 := newPipeSession()
	s3 := newPipeSession()
	pool.put(s1)
	pool.put(s2)
	pool.put(s3) // pool is full (max 2): s3 must be closed, not stored
	if pool.Stats().Closed != 1 {
		t.Fatalf("closed %d, want 1", pool.Stats().Closed)
	}
	if got := pool.get(); got != s2 {
		t.Fatal("pool did not return the most recent session (LIFO)")
	}
	if got := pool.get(); got != s1 {
		t.Fatal("pool did not return the remaining session")
	}
	if got := pool.get(); got != nil {
		t.Fatal("drained pool returned a session")
	}
	// Expiry: a session older than the TTL is closed, not returned.
	stale := &warmSession{conn: newPipeSession().conn, createdAt: time.Now().Add(-time.Second)}
	pool.put(stale)
	if pool.Stats().Closed != 2 {
		t.Fatalf("closed %d after stale put, want 2", pool.Stats().Closed)
	}
	fresh := newPipeSession()
	pool.put(fresh)
	time.Sleep(80 * time.Millisecond)
	if got := pool.get(); got != nil {
		t.Fatal("expired session returned from pool")
	}
	if pool.Stats().Expired != 1 {
		t.Fatalf("expired %d, want 1", pool.Stats().Expired)
	}
}

func TestCountingConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	counter := &countingConn{Conn: client}
	go func() {
		buffer := make([]byte, 4)
		_, _ = server.Read(buffer)
		_, _ = server.Write([]byte("pong"))
	}()
	if _, err := counter.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := counter.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if counter.WastedBytes() != 8 {
		t.Fatalf("wasted bytes %d, want 8 (4 written + 4 read)", counter.WastedBytes())
	}
}

func TestSpeculativeOptionsParsing(t *testing.T) {
	parsed, err := singjson.UnmarshalExtended[option.MusessOutboundOptions]([]byte(`{
		"warm_pool": 3,
		"warm_pool_idle_seconds": 20,
		"zero_rtt": true,
		"race_servers": ["127.0.0.1:15753"]
	}`))
	if err != nil {
		t.Fatalf("unmarshal outbound: %v", err)
	}
	if parsed.WarmPool == nil || *parsed.WarmPool != 3 || parsed.WarmPoolIdleSeconds != 20 || !parsed.ZeroRTT {
		t.Fatalf("parsed outbound %+v", parsed)
	}
	if len(parsed.RaceServers) != 1 || parsed.RaceServers[0] != "127.0.0.1:15753" {
		t.Fatalf("race servers %v", parsed.RaceServers)
	}
	// Defaults: warm pool on at size 2; zero_rtt and race off.
	def, err := singjson.UnmarshalExtended[option.MusessOutboundOptions]([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if def.WarmPool != nil || def.WarmPoolSize() != 2 || def.ZeroRTT || len(def.RaceServers) != 0 {
		t.Fatalf("default outbound mismatch: %+v", def)
	}
	in, err := singjson.UnmarshalExtended[option.MusessInboundOptions]([]byte(`{"zero_rtt": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !in.ZeroRTT {
		t.Fatal("inbound zero_rtt did not parse")
	}
}

func TestWarmPoolSizeDefault(t *testing.T) {
	// Unset (nil) means the default pool size 2; explicit 0 disables
	// the pool; any other value is the pool size.
	var def option.MusessOutboundOptions
	if def.WarmPoolSize() != 2 {
		t.Fatalf("unset warm pool size %d, want 2", def.WarmPoolSize())
	}
	off := 0
	def.WarmPool = &off
	if def.WarmPoolSize() != 0 {
		t.Fatalf("explicit 0 warm pool size %d, want 0", def.WarmPoolSize())
	}
	five := 5
	def.WarmPool = &five
	if def.WarmPoolSize() != 5 {
		t.Fatalf("explicit 5 warm pool size %d, want 5", def.WarmPoolSize())
	}
}

func TestWarmPoolParallelRefill(t *testing.T) {
	// Merge-time fix for the prototype's serial refill (one session
	// per 200 ms tick): one topUp must fill every missing slot in
	// parallel. With a 50 ms establish, three slots fill in ~50 ms;
	// the serial version would fill one per call and need three
	// ticks to reach the same level — at low RTT the consumption
	// rate (~120 ms/request at delay25) outran the refill rate and
	// the p95 tail never improved.
	establish := func(ctx context.Context) (*warmSession, error) {
		time.Sleep(50 * time.Millisecond)
		client, server := net.Pipe()
		_ = server // the test holds one end; the pool owns the other
		return &warmSession{conn: client, proofKey: []byte{0x01}, exporter: specTestExporter, createdAt: time.Now()}, nil
	}
	pool := newWarmPool(3, 10*time.Second, establish, nil)
	pool.topUp(context.Background())
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pool.Stats().Establish >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pool.Stats().Establish != 3 {
		t.Fatalf("established %d, want 3 after one parallel topUp", pool.Stats().Establish)
	}
	for i := 0; i < 3; i++ {
		if got := pool.get(); got == nil {
			t.Fatalf("pool returned nil on checkout %d, want a session", i)
		}
	}
	if got := pool.get(); got != nil {
		t.Fatal("pool returned a session after draining 3, want nil")
	}
}
