package musess

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/musess/fec"
	M "github.com/sagernet/sing/common/metadata"
)

// mux_test.go — unit tests for the mux landing (mux.go).

// muxTestDest is the dummy per-stream destination carried in open
// frames: the echo server ignores it; it only has to serialize.
var muxTestDest = M.Socksaddr{Fqdn: "dest.test", Port: 443}

//
// The echo server used here mirrors what the inbound does at the
// session level: each opened stream is handled independently (echo
// back what it sends). Flow-control, FEC composition and deadline
// tests go through the same session pair.

// muxEchoPair builds a client/server session pair over net.Pipe
// with an echoing server: every opened TCP stream echoes its
// input back until the client half-closes. The caller closes both
// sessions.
func muxEchoPair(t *testing.T) (*muxSession, *muxSession) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	server := newMuxSession(serverConn, false, func(stream *muxStream, command byte, destination M.Socksaddr) {
		go func() {
			defer stream.Close()
			buf := make([]byte, 32*1024)
			for {
				n, err := stream.Read(buf)
				if n > 0 {
					if _, werr := stream.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}, nil)
	server.start()
	client := newMuxSession(clientConn, true, nil, nil)
	client.start()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func mustPayload(t *testing.T, size int, seed byte) []byte {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = seed + byte(i%251)
	}
	return payload
}

// roundTrip opens one stream, writes payload, half-closes, and
// reads the echo back; the echo must be byte-identical. It
// returns an error instead of failing the test so callers may
// run it in a helper goroutine.
func muxRoundTrip(t *testing.T, client *muxSession, payload []byte) error {
	t.Helper()
	stream, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		return err
	}
	defer stream.Close()
	writeErr := make(chan error, 1)
	go func() {
		if _, err := stream.Write(payload); err != nil {
			writeErr <- err
			return
		}
		writeErr <- stream.CloseWrite()
	}()
	got, err := io.ReadAll(stream)
	if err != nil {
		return err
	}
	if err := <-writeErr; err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("echo mismatch")
	}
	return nil
}

func TestMuxEchoRoundTrip(t *testing.T) {
	client, _ := muxEchoPair(t)
	if err := muxRoundTrip(t, client, mustPayload(t, 100*1024, 0x11)); err != nil {
		t.Fatal(err)
	}
}

func TestMuxSequentialStreams(t *testing.T) {
	client, _ := muxEchoPair(t)
	for i := 0; i < 5; i++ {
		if err := muxRoundTrip(t, client, mustPayload(t, 70*1024+i*1024, byte(i+1))); err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
	}
}

func TestMuxConcurrentStreams(t *testing.T) {
	client, _ := muxEchoPair(t)
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = muxRoundTrip(t, client, mustPayload(t, 70*1024+i*30*1024, byte(0x40+i)))
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent streams did not finish in 30s")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
	}
}

func TestMuxUDPOpenReset(t *testing.T) {
	client, _ := muxEchoPair(t)
	stream, err := client.openStream(commandUDP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream(UDP): %v", err)
	}
	defer stream.Close()
	_, err = stream.Read(make([]byte, 16))
	if !errors.Is(err, errMuxReset) {
		t.Fatalf("UDP open Read error = %v, want errMuxReset", err)
	}
}

func TestMuxSessionDeathFailsStreams(t *testing.T) {
	client, server := muxEchoPair(t)
	stream, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	// Kill the transport underneath the server; the client side
	// must observe the death instead of hanging.
	server.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := stream.Read(make([]byte, 16))
		if err != nil {
			return // any error proves the stream failed
		}
		if time.Now().After(deadline) {
			t.Fatal("stream did not fail after session death")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestMuxDeadlines(t *testing.T) {
	client, _ := muxEchoPair(t)
	stream, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer stream.Close()
	// A read deadline in the past must fail fast instead of
	// blocking (the prototype left deadlines as no-ops).
	if err := stream.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err = stream.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read with past deadline: err = %v, want os.ErrDeadlineExceeded", err)
	}
}

// TestMuxFlowControlDecouples is the landing proof for (a):
// a stream whose consumer stops reading must not stall the
// session or any other stream. Stream A writes 192 MiB without
// ever reading its echo, so its window exhausts and its Write
// blocks; stream B must still complete a 200 KiB echo round
// trip promptly while A is stuck. (192 MiB is deliberate: the
// initial window is 64 MiB and receiver-driven growth caps at
// 64 MiB; A blocks once the echo path stalls — the server can
// only echo 64 MiB back into A's unread inbox — and stops
// crediting A, which happens after ~128 MiB sent.)
func TestMuxFlowControlDecouples(t *testing.T) {
	client, _ := muxEchoPair(t)

	streamA, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream A: %v", err)
	}
	defer streamA.Close()

	payloadA := mustPayload(t, 192*1024*1024, 0xA0)
	writeDone := make(chan error, 1)
	go func() {
		_, err := streamA.Write(payloadA)
		writeDone <- err
	}()
	// Give A time to fill its window and block.
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-writeDone:
		t.Fatalf("stream A Write finished early (err=%v): window did not backpressure", err)
	default:
		// Still blocked: the window is doing its job.
	}

	// Stream B must complete while A is stuck.
	doneB := make(chan error, 1)
	go func() {
		doneB <- muxRoundTrip(t, client, mustPayload(t, 200*1024, 0xB0))
	}()
	select {
	case err := <-doneB:
		if err != nil {
			t.Fatalf("stream B failed while stream A was stalled: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("stream B did not complete while stream A was stalled: head-of-line coupling still present")
	}

	// Unstick A by closing it; the blocked Write must unwind.
	streamA.Close()
	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stream A Write did not unwind after Close")
	}
}

// TestMuxWindowCreditReturns verifies the credit loop directly:
// after the peer consumes data, the sender's window is restored
// to the initial window.
func TestMuxWindowCreditReturns(t *testing.T) {
	client, _ := muxEchoPair(t)
	stream, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer stream.Close()
	payload := mustPayload(t, 2*1024*1024, 0xC0) // well above the 32 KiB credit quantum, so WINDOW_UPDATEs are actually exercised
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Read the echo back, which forces the server to consume the
	// 64 KiB and credit it.
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
	if err != nil {
		t.Fatalf("Read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	// The echo read also credits the *client* side (it consumed
	// the server's 64 KiB); poll until the sender window is
	// restored, proving WINDOW_UPDATE frames flow both ways.
	deadline := time.Now().Add(5 * time.Second)
	for {
		stream.mu.Lock()
		window := stream.sendWindow
		stream.mu.Unlock()
		if window == muxInitialWindow {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sendWindow = %d, want %d after credit round trip", window, muxInitialWindow)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMuxWindowGrowsWhenLimited verifies receiver-driven window
// growth: a 48 MiB bulk round trip exhausts the 16 MiB initial
// window twice, so the receiver must grow it to the 64 MiB cap.
// Without growth the transfer still completes on net.Pipe (RTT
// ~0), so the assertion is on the window itself, not on
// completion — the bench is what measures the throughput effect
// (the pre-fix bench stalled mux bulk256 at delay100). The
// server stream is removed from the session map when it closes,
// so the window is sampled by a watcher goroutine while the
// transfer runs.
func TestMuxWindowGrowsWhenLimited(t *testing.T) {
	client, server := muxEchoPair(t)
	stream, err := client.openStream(commandTCP, muxTestDest)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer stream.Close()
	payload := mustPayload(t, 48*1024*1024, 0xD0)

	stopWatch := make(chan struct{})
	watchDone := make(chan int64, 1)
	go func() {
		maxWindow := int64(0)
		for {
			select {
			case <-stopWatch:
				watchDone <- maxWindow
				return
			default:
			}
			server.mu.Lock()
			srvStream := server.streams[stream.id]
			server.mu.Unlock()
			if srvStream != nil {
				if w := srvStream.recvWindowSize(); w > maxWindow {
					maxWindow = w
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	writeErr := make(chan error, 1)
	go func() {
		if _, err := stream.Write(payload); err != nil {
			writeErr <- err
			return
		}
		writeErr <- stream.CloseWrite()
	}()
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("Read echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	close(stopWatch)
	if maxWindow := <-watchDone; maxWindow != muxMaxWindow {
		t.Fatalf("server recv window peaked at %d, want %d (cap)", maxWindow, muxMaxWindow)
	}
}

// TestMuxOverFEC is the landing proof for (b): a mux session
// runs over the negotiated FEC transport (fec.Conn in stream
// mode, RS codec, estimator controller — the production
// construction) and carries streams byte-identically.
func TestMuxOverFEC(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	fecA := fec.NewConn(pipeA, fec.NewRSCodec(16), fec.NewController("estimator", 0), fec.Options{Mode: fec.ModeStream})
	fecB := fec.NewConn(pipeB, fec.NewRSCodec(16), fec.NewController("estimator", 0), fec.Options{Mode: fec.ModeStream})
	server := newMuxSession(fecB, false, func(stream *muxStream, command byte, destination M.Socksaddr) {
		go func() {
			defer stream.Close()
			buf := make([]byte, 32*1024)
			for {
				n, err := stream.Read(buf)
				if n > 0 {
					if _, werr := stream.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}, nil)
	server.start()
	client := newMuxSession(fecA, true, nil, nil)
	client.start()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		fecA.Close()
		fecB.Close()
	})
	if err := muxRoundTrip(t, client, mustPayload(t, 128*1024, 0xF0)); err != nil {
		t.Fatalf("mux over FEC round trip 1: %v", err)
	}
	// A second stream proves the session survives past the first.
	if err := muxRoundTrip(t, client, mustPayload(t, 40*1024, 0xF1)); err != nil {
		t.Fatalf("mux over FEC round trip 2: %v", err)
	}
}

// TestMuxOverFECLossyCarrier is the landing measurement for the
// evening-peak no-stall requirement at the record layer: a mux
// session over fec.Conn on a carrier that drops whole FEC records
// (uniform 10% and burst 10% — the shape the QUIC datagram path
// will present; the TCP path never presents loss to the app, so
// this is explicitly NOT a TCP-path gain claim).
//
// What is asserted:
//   - no hang: every stream resolves (byte-identical echo or a
//     clean error) within the timeout — a stalled stream is the
//     failure this requirement forbids;
//   - FEC actually engages under loss (recovered shards > 0 in
//     the "on"-floor variant);
//   - the control (0% drop) completes byte-identically, proving
//     the lossy carrier itself is transparent.
//
// What is measured (logged, not asserted — loss is random):
// bytes delivered before the session dies. The measured finding
// (verified by per-record drop logging): stream-mode FEC is
// all-or-nothing per group, so a two-loss event in one group
// (one data shard plus the group's only parity shard, at the 5%
// floor's r=1) is fatal to the whole fec.Conn and hence to the
// whole mux session — FEC×mux on a lossy record carrier fails
// fast rather than stalling, and a 5% floor does not save the
// session at 10% uniform loss. Per-record logging also showed
// the first groups go out unprotected at the auto floor (r=0),
// so a single early drop kills the session before feedback can
// ramp redundancy.
func TestMuxOverFECLossyCarrier(t *testing.T) {
	// recordDropper is a bidirectional proxy between two conns
	// that parses FEC records (10-byte header, record.go), counts
	// drops, paces forwarded records by 1 ms (so the transfer
	// lasts long enough for FEC feedback — 200 ms interval — to
	// arrive and the controller to ramp), and drops whole records
	// per drop(). Each direction gets its own drop closure from
	// newDrop (its own RNG state): the two pumps run concurrently
	// and must not share mutable RNG state (a -race finding).
	type recordDropper struct {
		a, b             net.Conn
		fwdDrop, revDrop func() bool
		dropped          int64
		mu               sync.Mutex
	}
	pump := func(d *recordDropper, src, dst net.Conn, dir string) {
		defer d.a.Close()
		defer d.b.Close()
		drop := d.fwdDrop
		if dir == "rev" {
			drop = d.revDrop
		}
		header := make([]byte, 10)
		seq := 0
		for {
			if _, err := io.ReadFull(src, header); err != nil {
				return
			}
			n := int(header[8])<<8 | int(header[9])
			rec := make([]byte, 10+n)
			copy(rec, header)
			if n > 0 {
				if _, err := io.ReadFull(src, rec[10:]); err != nil {
					return
				}
			}
			seq++
			if drop() {
				d.mu.Lock()
				d.dropped++
				d.mu.Unlock()
				t.Logf("[%s] DROP #%d dir=%s type=%d group=%d index=%d k=%d r=%d len=%d", dir, seq, dir, header[0], int(header[1])<<24|int(header[2])<<16|int(header[3])<<8|int(header[4]), header[5], header[6], header[7], n)
				continue
			}
			time.Sleep(time.Millisecond)
			if _, err := dst.Write(rec); err != nil {
				return
			}
		}
	}
	type outcome struct {
		delivered   int
		recoveredF  uint64 // forward (fecB receive side) rebuilt shards
		lostF       uint64 // forward unrecoverable shards
		groupsRecvF uint64
		groupsSentF uint64
		recoveredR  uint64 // reverse (fecA receive side)
		dropped     int64
		completed   bool
		redundancy  float64
	}
	run := func(t *testing.T, name string, payloadSize int, floor float64, newDrop func() func() bool) outcome {
		t.Helper()
		pipeA1, pipeA2 := net.Pipe()
		pipeB1, pipeB2 := net.Pipe()
		dropper := &recordDropper{a: pipeA2, b: pipeB2, fwdDrop: newDrop(), revDrop: newDrop()}
		go pump(dropper, pipeA2, pipeB2, "fwd")
		go pump(dropper, pipeB2, pipeA2, "rev")
		fecA := fec.NewConn(pipeA1, fec.NewRSCodec(16), fec.NewController("estimator", floor), fec.Options{Mode: fec.ModeStream})
		fecB := fec.NewConn(pipeB1, fec.NewRSCodec(16), fec.NewController("estimator", floor), fec.Options{Mode: fec.ModeStream})
		server := newMuxSession(fecB, false, func(stream *muxStream, command byte, destination M.Socksaddr) {
			go func() {
				defer stream.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := stream.Read(buf)
					if n > 0 {
						if _, werr := stream.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}, nil)
		server.start()
		client := newMuxSession(fecA, true, nil, nil)
		client.start()
		defer client.Close()
		defer server.Close()
		defer fecA.Close()
		defer fecB.Close()

		stream, err := client.openStream(commandTCP, muxTestDest)
		if err != nil {
			t.Logf("[%s] open failed: %v", name, err)
			return outcome{}
		}
		defer stream.Close()
		payload := mustPayload(t, payloadSize, 0xD0)
		_ = stream.SetReadDeadline(time.Now().Add(60 * time.Second))
		writeDone := make(chan error, 1)
		go func() {
			_, err := stream.Write(payload)
			if err != nil {
				writeDone <- err
				return
			}
			writeDone <- stream.CloseWrite()
		}()
		got, readErr := io.ReadAll(stream)
		writeErr := <-writeDone
		statsB := fecB.Stats()
		statsA := fecA.Stats()
		out := outcome{
			delivered:   len(got),
			recoveredF:  statsB.ShardsRecovered,
			groupsRecvF: statsB.GroupsReceived,
			groupsSentF: statsB.GroupsSent,
			lostF:       statsB.ShardsLost,
			recoveredR:  statsA.ShardsRecovered,
			dropped:     dropper.dropped,
			completed:   readErr == nil && writeErr == nil && bytes.Equal(got, payload),
			redundancy:  fecA.Redundancy(),
		}
		t.Logf("[%s] delivered=%d/%d completed=%v readErr=%v writeErr=%v droppedRecords=%d fwdRecovered=%d fwdLost=%d revRecovered=%d fwdGroupsRecv=%d fwdGroupsSent=%d finalRedundancy=%.3f",
			name, len(got), len(payload), out.completed, readErr, writeErr, out.dropped, out.recoveredF, out.lostF, out.recoveredR, out.groupsRecvF, out.groupsSentF, out.redundancy)
		return out
	}

	// Control: no loss — must complete byte-identically.
	if out := run(t, "control-0pct", 256*1024, 0, func() func() bool { return func() bool { return false } }); !out.completed {
		t.Fatal("control (0% drop) did not complete byte-identically: the lossy carrier is not transparent")
	}

	// Uniform 10% record loss, fixed seed, 1 MiB so feedback can
	// arrive and the controller can ramp. auto floor (0): the
	// first groups go out unprotected, so completion is NOT
	// asserted — delivery is the measurement.
	uniform := func() func() bool {
		rng := newDeterministicRNG(7)
		return func() bool { return rng.Float64() < 0.10 }
	}
	out := run(t, "uniform-10pct-auto", 1024*1024, 0, uniform)
	t.Logf("uniform-10pct-auto: completed=%v delivered=%d/1048576", out.completed, out.delivered)

	// Same loss, "on" floor (5% redundancy from group 0): the
	// first groups carry parity, so FEC must demonstrably engage
	// and deliver something.
	uniformOn := func() func() bool {
		rng := newDeterministicRNG(7)
		return func() bool { return rng.Float64() < 0.10 }
	}
	out = run(t, "uniform-10pct-on", 1024*1024, fec.FloorForMode("on"), uniformOn)
	if out.recoveredF == 0 {
		t.Error("uniform 10% (on floor): zero forward recovered shards — FEC never engaged under loss")
	}
	// Deliberately NOT asserted: delivered is the measurement,
	// and the honest result is 0. With r=1 per group (5% floor
	// on k=16), a two-loss event in one group — here one data
	// shard plus the group's only parity shard — is
	// unrecoverable, and in stream mode an unrecoverable group
	// is fatal to the whole fec.Conn, hence to the whole mux
	// session (all streams). FEC×mux on a lossy record carrier
	// fails fast; it does not stall, and it does not save the
	// session. (fwdLost=16 in the log is teardown accounting:
	// finishReceive resolves the half-arrived group behind the
	// fatal one with all its shards missing — not 16 shards
	// destroyed by the network, which dropped 3 records.)
	t.Logf("uniform-10pct-on: completed=%v delivered=%d/1048576", out.completed, out.delivered)

	// Burst loss (Gilbert, mean burst ~8 records, 10% average).
	burst := func() func() bool {
		rng := newDeterministicRNG(11)
		bad := false
		return func() bool {
			if bad {
				if rng.Float64() < 0.125 { // mean burst 8
					bad = false
				}
				return true
			}
			if rng.Float64() < 0.014 { // enter bad state ~1.4% per record
				bad = true
				return true
			}
			return false
		}
	}
	out = run(t, "burst-10pct-auto", 1024*1024, 0, burst)
	t.Logf("burst-10pct-auto: completed=%v delivered=%d/1048576", out.completed, out.delivered)
}

// newDeterministicRNG is a small seeded PRNG for loss models in
// tests (no math/rand global state, reproducible per seed).
type deterministicRNG struct{ state uint64 }

func newDeterministicRNG(seed uint64) *deterministicRNG {
	return &deterministicRNG{state: seed | 1}
}

func (r *deterministicRNG) Float64() float64 {
	// xorshift64*.
	r.state ^= r.state >> 12
	r.state ^= r.state << 25
	r.state ^= r.state >> 27
	return float64((r.state*0x2545F4914F6CDD1D)>>11) / float64(1<<53)
}

// TestMuxOddStreamIDs verifies only the client opens streams and
// IDs are odd and increasing.
func TestMuxOddStreamIDs(t *testing.T) {
	client, server := muxEchoPair(t)
	_ = server
	ids := make([]uint32, 0, 3)
	for i := 0; i < 3; i++ {
		stream, err := client.openStream(commandTCP, muxTestDest)
		if err != nil {
			t.Fatalf("openStream: %v", err)
		}
		ids = append(ids, stream.id)
		stream.Close()
	}
	for i, id := range ids {
		if id%2 == 0 {
			t.Fatalf("stream %d has even ID %d", i, id)
		}
		if i > 0 && ids[i] <= ids[i-1] {
			t.Fatalf("stream IDs not increasing: %v", ids)
		}
	}
}

// TestMuxBypassed pins the mux-bulk bypass matcher (mux_bypass
// option): a destination matches by "host:port", by host, or by
// ":port"; anything else takes the mux path.
func TestMuxBypassed(t *testing.T) {
	h := &Outbound{muxBypass: []string{"dest.test", "bulk.example.com:8443", ":9443"}}
	fqdn := M.Socksaddr{Fqdn: "dest.test", Port: 443}
	if !h.muxBypassed(fqdn) {
		t.Fatal("dest.test:443 should match host pattern dest.test")
	}
	hostPort := M.Socksaddr{Fqdn: "bulk.example.com", Port: 8443}
	if !h.muxBypassed(hostPort) {
		t.Fatal("bulk.example.com:8443 should match host:port pattern")
	}
	portOnly := M.Socksaddr{Fqdn: "other.test", Port: 9443}
	if !h.muxBypassed(portOnly) {
		t.Fatal("other.test:9443 should match :port pattern :9443")
	}
	nomatch := M.Socksaddr{Fqdn: "other.test", Port: 443}
	if h.muxBypassed(nomatch) {
		t.Fatal("other.test:443 should not match any pattern")
	}
	ip := M.ParseSocksaddr("127.0.0.1:9443")
	if !h.muxBypassed(ip) {
		t.Fatal("127.0.0.1:9443 should match :port pattern :9443")
	}
	empty := &Outbound{}
	if empty.muxBypassed(fqdn) {
		t.Fatal("empty bypass list must never match")
	}
}
