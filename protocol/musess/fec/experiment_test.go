package fec

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// Unit tests for the flagged-observation experiment treatments
// (experiment.go, and the Options experiment fields in
// endpoint.go). The production-behaviour gates live in fec_test.go
// and endpoint_test.go; these pin the *treatments'* mechanics.

// TestExpYieldFidelity: the experimental wrapper with a zero
// YieldPolicy must reproduce the production yieldWrapper exactly,
// step for step, for both strategies — the clone-fidelity gate
// the cap experiment established as house style.
func TestExpYieldFidelity(t *testing.T) {
	type step struct {
		feedback   Feedback
		backlogged bool
	}
	script := []step{
		{feedbackWindow(200, 0), false},
		{feedbackWindow(200, 20), false}, // 10% loss
		{feedbackWindow(200, 20), true},  // backlog starts
		{feedbackWindow(200, 24), true},
		{feedbackWindow(200, 16), true},
		{feedbackWindow(200, 20), true},
		{feedbackWindow(200, 20), true},
		{feedbackWindow(200, 20), false}, // backlog clears
		{feedbackWindow(200, 20), false},
		{feedbackWindow(200, 20), false},
		{feedbackWindow(200, 20), false},
		{feedbackWindow(200, 0), false},
		{feedbackWindow(200, 0), false},
		{feedbackWindow(200, 30), true},
		{feedbackWindow(200, 30), true},
	}
	for _, strategy := range []string{"estimator", "fixed-step"} {
		prod := NewController(strategy, 0)
		exp := NewControllerWithYieldPolicy(strategy, 0, YieldPolicy{})
		for i, s := range script {
			prod.SetBacklogged(s.backlogged)
			exp.SetBacklogged(s.backlogged)
			prod.OnFeedback(s.feedback)
			exp.OnFeedback(s.feedback)
			if prod.Redundancy() != exp.Redundancy() {
				t.Fatalf("%s step %d: production %v != experiment clone %v",
					strategy, i, prod.Redundancy(), exp.Redundancy())
			}
		}
	}
}

// TestExpYieldLossAwareFloor: under sustained backlog the
// loss-aware floor keeps applied redundancy at the measured-loss
// cover instead of collapsing to inner x 0.2, while never
// exceeding what the inner controller asks for.
func TestExpYieldLossAwareFloor(t *testing.T) {
	drive := func(c Controller, windows int, lost int, backlog bool) {
		c.SetBacklogged(backlog)
		for i := 0; i < windows; i++ {
			c.OnFeedback(feedbackWindow(200, lost))
		}
	}
	// 10% loss, then backlog: production collapses to ~0.026.
	blind := NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{})
	drive(blind, 8, 20, false)
	drive(blind, 6, 20, true)
	if got := blind.Redundancy(); got > 0.032 {
		t.Fatalf("blind yield under backlog: %v, want ~0.026 (inner x 0.2)", got)
	}
	// Loss-aware: cover at p=0.10 is 0.10/1.10 = 0.0909.
	aware := NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{LossAwareFloor: true})
	drive(aware, 8, 20, false)
	drive(aware, 6, 20, true)
	if got := aware.Redundancy(); got < 0.085 || got > 0.1295 {
		t.Fatalf("loss-aware yield under backlog: %v, want within [0.085, 0.129]", got)
	}
	// 20% loss: cover (0.1667) exceeds the capped inner (0.15),
	// so the yield is fully overridden — applied stays at cap.
	aware20 := NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{LossAwareFloor: true})
	drive(aware20, 8, 40, false)
	drive(aware20, 6, 40, true)
	if got := aware20.Redundancy(); got != MaxRedundancy {
		t.Fatalf("loss-aware at 20%% loss under backlog: %v, want cap %v", got, MaxRedundancy)
	}
	// 1% loss: the cover is small and must not inflate the
	// applied redundancy beyond the inner request.
	awareLow := NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{LossAwareFloor: true})
	drive(awareLow, 8, 2, false)
	drive(awareLow, 6, 2, true)
	if got := awareLow.Redundancy(); got > 0.012 {
		t.Fatalf("loss-aware at 1%% loss under backlog: %v, want <= 0.012", got)
	}
}

// TestExpYieldBlindFloorArm: the shallower static floor (0.4)
// behaves as a pure rescale of the production collapse.
func TestExpYieldBlindFloorArm(t *testing.T) {
	c := NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{FactorFloor: 0.4})
	c.SetBacklogged(false)
	for i := 0; i < 8; i++ {
		c.OnFeedback(feedbackWindow(200, 20))
	}
	c.SetBacklogged(true)
	for i := 0; i < 6; i++ {
		c.OnFeedback(feedbackWindow(200, 20))
	}
	// inner ~0.129 x 0.4 = 0.0516.
	if got := c.Redundancy(); got < 0.045 || got > 0.058 {
		t.Fatalf("floor-0.4 arm under backlog: %v, want ~0.0516", got)
	}
}

// groupDropConn drops every record (except feedback) whose group
// ID is in the drop set — whole-group loss, deterministic.
type groupDropConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	drop map[uint32]bool
}

func (c *groupDropConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for len(c.buf) >= recordHeaderLen {
		payloadLen := int(binary.BigEndian.Uint16(c.buf[8:10]))
		total := recordHeaderLen + payloadLen
		if len(c.buf) < total {
			break
		}
		rec := c.buf[:total]
		c.buf = c.buf[total:]
		group := binary.BigEndian.Uint32(rec[1:5])
		if rec[0] != recordFeedback && c.drop[group] {
			continue
		}
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// trickleRun drives a paced packet-mode stream (one message per
// pacing interval, so groups form at k=1 — the trickle regime of
// flagged observations 2 and 3) over a group-dropping carrier and
// returns a snapshot of what the receiver delivered by the time
// sending finished (plus a short grace), and the sender.
func trickleRun(t *testing.T, drop map[uint32]bool, mod func(*Options), ctrl Controller, count int, pace time.Duration) (seqs []int, sender *Conn) {
	t.Helper()
	a, b := pipePair()
	dropping := &groupDropConn{Conn: a, drop: drop}
	if ctrl == nil {
		ctrl = staticController{r: 0}
	}
	opts := testOptions(ModePacket)
	opts.FlushInterval = time.Millisecond
	if mod != nil {
		mod(&opts)
	}
	sender = NewConn(dropping, NewRSCodec(16), ctrl, opts)
	receiver := NewConn(b, NewRSCodec(16), staticController{}, opts)
	t.Cleanup(func() { sender.Close(); receiver.Close() })

	var mu sync.Mutex
	go func() {
		for {
			msg, err := receiver.ReadMessage()
			if err != nil {
				return
			}
			mu.Lock()
			seqs = append(seqs, int(binary.BigEndian.Uint32(msg[0:4])))
			mu.Unlock()
		}
	}()
	for i := 0; i < count; i++ {
		msg := make([]byte, 200)
		binary.BigEndian.PutUint32(msg[0:4], uint32(i))
		if err := sender.WriteMessage(msg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(pace)
	}
	time.Sleep(60 * time.Millisecond) // grace for in-flight records
	mu.Lock()
	defer mu.Unlock()
	return append([]int(nil), seqs...), sender
}

// TestEndpointPacketOutOfOrder: with two early groups dropped
// whole and arrivals continuous (never pausing past the group
// timeout), the ordered pump (PacketOrdered escape hatch — the
// milestone-2 behaviour) stalls behind the gap for the rest of
// the stream, while the unordered pump (the landed production
// default) delivers everything that arrived.
func TestEndpointPacketOutOfOrder(t *testing.T) {
	const count = 150
	drop := map[uint32]bool{2: true, 3: true}

	ordered, _ := trickleRun(t, drop, nil, nil, count, 12*time.Millisecond)
	if len(ordered) > 6 {
		t.Fatalf("ordered pump delivered %d messages mid-stream, want <= 6 (stalled at gap)", len(ordered))
	}
	for i, s := range ordered {
		if s != i {
			t.Fatalf("ordered delivery out of order at %d: seq %d", i, s)
		}
	}

	uo, _ := trickleRun(t, drop, func(o *Options) { o.PacketOrdered = false }, nil, count, 12*time.Millisecond)
	if len(uo) < count-12 {
		t.Fatalf("unordered pump delivered %d/%d, want >= %d", len(uo), count, count-12)
	}
	maxSeq := 0
	for _, s := range uo {
		if s > maxSeq {
			maxSeq = s
		}
	}
	if maxSeq < count-10 {
		t.Fatalf("unordered pump max seq %d, want near %d (tail delivered despite gap)", maxSeq, count-1)
	}
}

// TestEndpointEagerGapFeedback: with whole-group drops only
// (groups = k=1 at trickle pacing, ~5% of groups), pause-based
// gap accounting (NoEagerGapSynthesis escape hatch — the
// milestone-2 behaviour) shows feedback windows of exactly
// 0.000 for the whole stream — the sender's estimator never
// engages until the stream ends and arrivals pause. Eager gap
// synthesis (the landed production default) makes the same
// losses visible mid-stream. Post-stream, pause-based engages
// too: the difference is timing, not capability.
func TestEndpointEagerGapFeedback(t *testing.T) {
	const count = 240
	drop := map[uint32]bool{}
	for id := uint32(3); id < 400; id += 20 {
		drop[id] = true
	}
	// The sampling needs to run concurrently with the transfer,
	// so drive the scenario inline here rather than via
	// trickleRun's snapshot.
	run := func(mod func(*Options)) (midMax, post float64) {
		a, b := pipePair()
		dropping := &groupDropConn{Conn: a, drop: drop}
		ctrl := NewController("estimator", 0)
		opts := testOptions(ModePacket)
		opts.FlushInterval = time.Millisecond
		if mod != nil {
			mod(&opts)
		}
		sender := NewConn(dropping, NewRSCodec(16), ctrl, opts)
		receiver := NewConn(b, NewRSCodec(16), staticController{}, opts)
		defer sender.Close()
		defer receiver.Close()
		go func() {
			for {
				if _, err := receiver.ReadMessage(); err != nil {
					return
				}
			}
		}()
		start := time.Now()
		stop := make(chan struct{})
		var mu sync.Mutex
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-time.After(50 * time.Millisecond):
					r := sender.Redundancy()
					mu.Lock()
					if time.Since(start) > 1200*time.Millisecond && r > midMax {
						midMax = r
					}
					mu.Unlock()
				}
			}
		}()
		for i := 0; i < count; i++ {
			msg := make([]byte, 200)
			binary.BigEndian.PutUint32(msg[0:4], uint32(i))
			if err := sender.WriteMessage(msg); err != nil {
				t.Fatal(err)
			}
			time.Sleep(12 * time.Millisecond)
		}
		close(stop)
		mu.Lock()
		m := midMax
		mu.Unlock()
		// Post-stream pause: production gap synthesis now fires
		// and the estimator gets its first nonzero windows.
		time.Sleep(900 * time.Millisecond)
		return m, sender.Redundancy()
	}

	prodMid, prodPost := run(nil)
	eagerMid, _ := run(func(o *Options) { o.NoEagerGapSynthesis = false })

	if prodMid != 0 {
		t.Fatalf("pause-based mid-stream redundancy = %v, want exactly 0 (feedback blindness)", prodMid)
	}
	if eagerMid < 0.05 {
		t.Fatalf("eager mid-stream redundancy = %v, want >= 0.05 (loss visible mid-stream)", eagerMid)
	}
	if prodPost < 0.03 {
		t.Fatalf("pause-based post-pause redundancy = %v, want >= 0.03 (engages only after the pause)", prodPost)
	}
	t.Logf("mid-stream redundancy: pause-based %v, eager %v; pause-based post-pause %v", prodMid, eagerMid, prodPost)
}
