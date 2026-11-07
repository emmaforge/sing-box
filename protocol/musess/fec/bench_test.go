package fec

// Head-to-head candidate comparison harness (Emma's method: test
// several approaches on the same rig, pick by measurement in the
// order goodput > camouflage/overhead > latency).
//
// Carrier: an ordered stream (net.Pipe) with a record-aware shim
// that drops/delays whole FEC records — the loss unit is one FEC
// record, matching the future one-record-per-datagram QUIC
// mapping. This is a user-space record shim, NOT kernel netem;
// numbers are labelled "measured in this environment".
//
// Accounting (fixed 2026-11-05 after the repetition re-run exposed
// the original scheme; see impl/README.md "Harness fix"):
//   - The shim is asynchronous: Write parses records, applies the
//     seeded loss model, and enqueues survivors; a forwarder
//     goroutine releases them in order on an absolute service
//     schedule (timer waits). The link's service rate is therefore
//     enforced by the model's clock, not by how fast the host
//     happens to execute the sender's writes — under the old
//     synchronous shim, host scheduling latency silently added to
//     the service time, the effective link fell below the offered
//     load, the FEC send queue sat backlogged, and the production
//     yield wrapper throttled the very redundancy being measured.
//   - A transfer ends at quiescence: the sender is done, both
//     shims have released everything they hold, and the
//     receiver's resolution accounting (groups received, shards
//     lost) has been frozen for a settle window several times
//     the group timeout. Delivery silence alone is not
//     quiescence — a fully-lost group stalls ordered delivery
//     behind it while later groups keep resolving, and the
//     receiver's gap synthesis only advances that blockage once
//     arrivals pause. Elapsed — the goodput denominator — is
//     the arrival time of the LAST delivered message, not the
//     loop's exit time. The previous scheme ran
//     every lossy cell to a 60 s drain timer and printed the
//     drain as "goodput"; that column was an artefact.
//   - Deliveries are collected by one persistent reader goroutine
//     (the old per-message goroutine spawn could swallow a message
//     at loop exit and perturbed timing).
//   - Shim drop/forward counters are printed per cell so the loss
//     model's realised drop count is auditable against the seeded
//     prediction (the no-FEC baseline is deterministic: seed 1234
//     over 4000 records drops exactly 45/121/204/412/596 shards at
//     1/3/5/10/15% loss).
//
// Run the comparison with:
//   MUSESS_FEC_BENCH=1 go test -run TestBenchComparison -v ./protocol/musess/fec/
// Repetitions (median/range, for ranking questions):
//   MUSESS_FEC_BENCH_REPS=10 go test -run TestBenchRepetitions -v ./protocol/musess/fec/
// 20% cap experiment (harness-side clones, production untouched):
//   MUSESS_FEC_BENCH_CAP20=1 go test -run TestBenchCap20 -v ./protocol/musess/fec/

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shimConn wraps the write side of a connection: it parses whole
// FEC records out of the byte stream, applies the loss model, and
// releases records in order at a fixed per-record service time.
// Write itself never sleeps: release timing lives in the
// forwarder goroutine, on an absolute schedule.
type shimConn struct {
	net.Conn
	mu        sync.Mutex // guards buf and the loss-model state
	buf       []byte
	rng       *rand.Rand
	loss      float64
	burst     bool // Gilbert-style: bad state drops at burstLoss
	inBad     bool
	burstLoss float64
	pBad      float64 // P(good -> bad) per record
	pGood     float64 // P(bad -> good) per record
	service   time.Duration

	queue     chan []byte
	done      chan struct{}
	closeOnce sync.Once
	dropped   atomic.Int64
	forwarded atomic.Int64
}

// shimQueueRecords bounds the shim's release queue. It models a
// finite link buffer: large enough that a non-saturated link
// never fills it (steady-state occupancy is a few records — the
// forwarder drains faster than the sender fills), small enough
// that a genuinely saturated link fills it, Write blocks, and
// backpressure propagates into the FEC send queue — which is
// what the production yield rule observes. With an effectively
// unbounded queue the saturation cells silently stopped
// saturating anything.
const shimQueueRecords = 512

func newShimConn(conn net.Conn, loss float64, seed int64, service time.Duration) *shimConn {
	c := &shimConn{
		Conn:    conn,
		rng:     rand.New(rand.NewSource(seed)),
		loss:    loss,
		service: service,
		queue:   make(chan []byte, shimQueueRecords),
		done:    make(chan struct{}),
	}
	go c.forwardLoop()
	return c
}

// forwardLoop releases queued records on an absolute schedule:
// each record's release time is the previous release time plus
// the service time, re-based to now if the schedule has fallen
// behind (no catch-up bursts), exactly the pacing the original
// synchronous shim intended — but implemented with timer waits,
// whose fidelity this environment measures at ~nominal, and in a
// dedicated goroutine, so sender-side write latency no longer
// leaks into the link model.
func (c *shimConn) forwardLoop() {
	var nextFree time.Time
	for {
		select {
		case <-c.done:
			return
		case rec := <-c.queue:
			if c.service > 0 {
				now := time.Now()
				if nextFree.Before(now) {
					nextFree = now
				}
				nextFree = nextFree.Add(c.service)
				if wait := time.Until(nextFree); wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-timer.C:
					case <-c.done:
						timer.Stop()
						return
					}
				}
			}
			if _, err := c.Conn.Write(rec); err != nil {
				return
			}
			c.forwarded.Add(1)
		}
	}
}

func (c *shimConn) drop() bool {
	if c.burst {
		if c.inBad {
			if c.rng.Float64() < c.pGood {
				c.inBad = false
			}
		} else if c.rng.Float64() < c.pBad {
			c.inBad = true
		}
		if c.inBad {
			return c.rng.Float64() < c.burstLoss
		}
		return false
	}
	return c.rng.Float64() < c.loss
}

func (c *shimConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for len(c.buf) >= recordHeaderLen {
		payloadLen := int(binary.BigEndian.Uint16(c.buf[8:10]))
		total := recordHeaderLen + payloadLen
		if len(c.buf) < total {
			break
		}
		rec := append([]byte(nil), c.buf[:total]...)
		c.buf = c.buf[total:]
		// Feedback records are control traffic: forwarded
		// undropped but still through the service schedule.
		isFeedback := rec[0] == recordFeedback
		if !isFeedback && c.drop() {
			c.dropped.Add(1)
			continue
		}
		select {
		case c.queue <- rec:
		case <-c.done:
			return 0, ErrClosed
		}
	}
	return len(p), nil
}

// Close releases the forwarder goroutine; the underlying
// connection is closed by the owner's usual path.
func (c *shimConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type benchResult struct {
	label       string
	sent        int
	delivered   int
	goodputMbps float64 // delivered bytes / time to last delivery
	wallSeconds float64 // total runTransfer wall time (transparency)
	delivery    float64
	overhead    float64
	recovered   uint64
	lost        uint64
	finalRedund float64
	dropped     int64 // shim-side realised drops (forward direction)
	forwarded   int64
	capped      bool // hit the hard deadline: treat numbers as suspect
	p50Ms       float64
	p95Ms       float64
}

// settleWindow is how long deliveries may be silent (after the
// sender finished) before the transfer is declared complete. It
// must comfortably exceed the receiver's group expiry path: a
// group resolves on the next group's arrival or GroupTimeout
// after its first record, and gap synthesis needs one more
// timeout — 2 s is >10x the 150 ms group timeout used here.
const settleWindow = 2 * time.Second

// hardDeadline bounds a single transfer no matter what; the old
// scheme's was 60 s and it fired on every lossy cell.
const hardDeadline = 30 * time.Second

func runTransfer(t *testing.T, codec Codec, ctrl Controller, loss float64, burst bool, offeredMbps float64, linkMbps float64, count int, size int, seed int64) benchResult {
	return runTransferMod(t, codec, ctrl, loss, burst, offeredMbps, linkMbps, count, size, seed, nil)
}

// runTransferMod is runTransfer with an optional Options modifier
// applied to both ends before the Conns are built. It exists for
// the flagged-observation experiments (exp_bench_test.go), which
// need the endpoint behaviour flags varied per arm. The fixed
// harness's accounting is unchanged: a nil modifier reproduces
// runTransfer exactly, and every established entry point calls
// runTransfer. The base Options pin the milestone-2 baseline via
// the escape hatches, so the established cells keep the meaning
// their README tables recorded; arms opt INTO treatments (and
// the landing spot cells in landing_bench_test.go opt into the
// adopted production defaults) by clearing/setting fields in
// the modifier.
func runTransferMod(t *testing.T, codec Codec, ctrl Controller, loss float64, burst bool, offeredMbps float64, linkMbps float64, count int, size int, seed int64, mod func(*Options)) benchResult {
	t.Helper()
	a, b := net.Pipe()
	// Service time per record emulates the link rate for records
	// of ~size bytes. Non-saturation runs set the link ~18% above
	// the offered load so queues stay short; saturation runs set
	// the link far below the offered load.
	service := time.Duration(float64(size+recordHeaderLen) * 8 / (linkMbps * 1e6) * float64(time.Second))
	shimAB := newShimConn(a, loss, seed, service)
	shimBA := newShimConn(b, 0, seed+1, service)
	if burst {
		// Gilbert model tuned for the target average loss with a
		// mean burst length of ~8 records: pGood = 1/8; average
		// loss = pi_bad * burstLoss; choose burstLoss = 0.5 and
		// pi_bad = loss/0.5 -> pBad from stationary distribution.
		shimAB.burst = true
		shimAB.burstLoss = 0.5
		shimAB.pGood = 1.0 / 8
		piBad := loss / 0.5
		if piBad >= 0.95 {
			piBad = 0.95
		}
		shimAB.pBad = piBad * shimAB.pGood / (1 - piBad)
	}
	opts := Options{
		Mode:             ModePacket,
		MaxShard:         1400,
		FlushInterval:    5 * time.Millisecond, // production default
		FeedbackInterval: 100 * time.Millisecond,
		GroupTimeout:     150 * time.Millisecond,
		// Milestone-2 baseline (see runTransferMod's comment).
		PacketOrdered:       true,
		NoEagerGapSynthesis: true,
		SpendPolicyOff:      true,
	}
	if mod != nil {
		mod(&opts)
	}
	sender := NewConn(shimAB, codec, ctrl, opts)
	receiver := NewConn(shimBA, codec, staticController{}, opts)
	defer sender.Close()
	defer receiver.Close()

	payload := make([]byte, size)
	rand.New(rand.NewSource(5)).Read(payload)
	interval := time.Duration(float64(size) * 8 / (offeredMbps * 1e6) * float64(time.Second))
	start := time.Now()
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < count; i++ {
			msg := make([]byte, size)
			copy(msg, payload)
			binary.BigEndian.PutUint32(msg[0:4], uint32(i))
			binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))
			if err := sender.WriteMessage(msg); err != nil {
				return
			}
			if interval > 0 {
				target := start.Add(time.Duration(i+1) * interval)
				if wait := time.Until(target); wait > 0 {
					time.Sleep(wait)
				}
			}
		}
	}()

	// One persistent reader goroutine collects deliveries with
	// their arrival times; the main loop never spawns per-message
	// goroutines.
	type arrival struct {
		seq uint32
		at  time.Duration
		lat float64
	}
	arrivals := make(chan arrival, count+16)
	readerStop := make(chan struct{})
	defer close(readerStop)
	go func() {
		for {
			msg, err := receiver.ReadMessage()
			if err != nil {
				return
			}
			sentNs := int64(binary.BigEndian.Uint64(msg[8:16]))
			select {
			case arrivals <- arrival{
				seq: binary.BigEndian.Uint32(msg[0:4]),
				at:  time.Since(start),
				lat: float64(time.Now().UnixNano()-sentNs) / 1e6,
			}:
			case <-readerStop:
				return
			}
		}
	}()

	delivered := 0
	var latencies []float64
	seen := make(map[uint32]bool)
	var lastArrival time.Duration
	// Quiescence tracking: the transfer is complete when the
	// sender is done, both shims have released everything they
	// hold, and the receiver's resolution accounting (delivered
	// messages, resolved groups, lost shards) has been frozen
	// for settleWindow. Silence of deliveries alone is NOT
	// sufficient: a fully-lost group blocks ordered delivery
	// behind it while later groups keep resolving, and the
	// receiver's gap synthesis only advances that blockage
	// after arrivals pause — the accounting keeps moving
	// (groups resolved as lost) while deliveries are silent.
	var lastChange time.Duration
	lastGroups, lastLost := uint64(0), uint64(0)
	sendFinished := false
	capped := false
	deadline := start.Add(hardDeadline)
	progress := os.Getenv("MUSESS_FEC_PROGRESS") != ""
	lastProgress := time.Duration(0)
	for {
		if progress && time.Since(start)-lastProgress >= 2*time.Second {
			lastProgress = time.Since(start)
			rs := receiver.Stats()
			fmt.Printf("    [progress %5.1fs] delivered=%d sendFin=%v qAB=%d qBA=%d groups=%d lost=%d lastChange=%.1fs\n",
				lastProgress.Seconds(), delivered, sendFinished, len(shimAB.queue), len(shimBA.queue),
				rs.GroupsReceived, rs.ShardsLost, lastChange.Seconds())
		}
		if delivered >= count {
			break
		}
		if sendFinished && len(shimAB.queue) == 0 && len(shimBA.queue) == 0 &&
			lastChange > 0 && time.Since(start)-lastChange >= settleWindow {
			break
		}
		if time.Now().After(deadline) {
			capped = true
			break
		}
		select {
		case a := <-arrivals:
			if !seen[a.seq] {
				seen[a.seq] = true
				delivered++
				lastArrival = a.at
				lastChange = a.at
				latencies = append(latencies, a.lat)
			}
		case <-sendDone:
			sendFinished = true
			sendDone = nil // a closed channel is always ready; nil it or the loop busy-spins
		case <-time.After(25 * time.Millisecond):
			rs := receiver.Stats()
			if rs.GroupsReceived != lastGroups || rs.ShardsLost != lastLost {
				lastGroups, lastLost = rs.GroupsReceived, rs.ShardsLost
				lastChange = time.Since(start)
			}
		}
	}
	elapsed := lastArrival.Seconds()
	if elapsed <= 0 {
		elapsed = time.Since(start).Seconds()
	}
	stats := sender.Stats()
	res := benchResult{
		sent:        count,
		delivered:   delivered,
		delivery:    float64(delivered) / float64(count),
		goodputMbps: float64(delivered*size) * 8 / elapsed / 1e6,
		wallSeconds: time.Since(start).Seconds(),
		overhead:    stats.OverheadRatio(),
		recovered:   receiver.Stats().ShardsRecovered,
		lost:        receiver.Stats().ShardsLost,
		finalRedund: sender.Redundancy(),
		dropped:     shimAB.dropped.Load(),
		forwarded:   shimAB.forwarded.Load(),
		capped:      capped,
	}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		res.p50Ms = latencies[len(latencies)/2]
		res.p95Ms = latencies[int(float64(len(latencies))*0.95)]
	}
	return res
}

func printCell(res benchResult, loss float64) {
	fmt.Printf("%-28s %6.0f %8.2f %8.2fM %8.2f %9d %9d %7.1f  drops=%d fwd=%d wall=%.1fs%s\n",
		res.label, loss*100, res.delivery*100, res.goodputMbps, res.overhead*100, res.recovered, res.lost, res.finalRedund*100,
		res.dropped, res.forwarded, res.wallSeconds, map[bool]string{true: " CAPPED", false: ""}[res.capped])
}

type benchConfig struct {
	label string
	codec func() Codec
	ctrl  func() Controller
}

func benchConfigs() []benchConfig {
	return []benchConfig{
		{"none (baseline)", func() Codec { return NewRSCodec(16) }, func() Controller { return staticController{r: 0} }},
		{"xor + fixed-step", func() Codec { return XORCodec{} }, func() Controller { return NewController("fixed-step", 0) }},
		{"xor + estimator", func() Codec { return XORCodec{} }, func() Controller { return NewController("estimator", 0) }},
		{"rs + fixed-step", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("fixed-step", 0) }},
		{"rs + estimator", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("estimator", 0) }},
	}
}

func (c benchConfig) run(t *testing.T, loss float64, burst bool, offeredMbps, linkMbps float64, count, size int, seed int64) benchResult {
	res := runTransfer(t, c.codec(), c.ctrl(), loss, burst, offeredMbps, linkMbps, count, size, seed)
	res.label = c.label
	return res
}

func TestBenchComparison(t *testing.T) {
	if os.Getenv("MUSESS_FEC_BENCH") == "" {
		t.Skip("set MUSESS_FEC_BENCH=1 to run the comparison harness")
	}
	const count = 4000
	const size = 1200
	const offered = 20.0 // Mbps
	configs := benchConfigs()

	fmt.Println("\n=== FEC candidate comparison (record shim, ordered stream carrier, 20 Mbps offered, 4000x1200B) ===")
	fmt.Printf("%-28s %6s %8s %9s %8s %9s %9s %7s\n", "config", "loss%", "deliv%", "goodput", "ovhd%", "recov", "lost", "finalR%")
	losses := []float64{0, 0.01, 0.03, 0.05, 0.10, 0.15}
	for _, cfg := range configs {
		for _, loss := range losses {
			printCell(cfg.run(t, loss, false, offered, offered/0.85, count, size, 1234), loss)
		}
	}

	fmt.Println("\n=== burst loss (Gilbert, mean burst ~8 records, burst drop 50%) ===")
	for _, cfg := range configs[1:] {
		for _, loss := range []float64{0.05, 0.10} {
			res := cfg.run(t, loss, true, offered, offered/0.85, count, size, 777)
			res.label = cfg.label + " (burst)"
			printCell(res, loss)
		}
	}

	fmt.Println("\n=== saturation: offered 100 Mbps into a 23 Mbps service-rate shim ===")
	for _, cfg := range configs[1:] {
		res := cfg.run(t, 0.05, false, 100.0, 23.0, count, size, 4242)
		res.label = cfg.label + " (sat)"
		printCell(res, 0.05)
	}
	// No-yield control: raw inner controllers without the wrapper.
	fmt.Println("--- saturation, yield wrapper disabled (control) ---")
	for _, inner := range []struct {
		label string
		codec Codec
		ctrl  Controller
	}{
		{"rs + estimator (noyield)", NewRSCodec(16), NewEstimatorController()},
		{"rs + fixed-step (noyield)", NewRSCodec(16), NewStepController()},
	} {
		res := runTransfer(t, inner.codec, inner.ctrl, 0.05, false, 100.0, 23.0, count, size, 4242)
		res.label = inner.label
		printCell(res, 0.05)
	}

	fmt.Println("\n=== latency: 100 msg/s trickle, 5% uniform loss (delivered messages only) ===")
	for _, cfg := range configs {
		res := cfg.run(t, 0.05, false, 0.96, 1.13, 300, size, 31337)
		fmt.Printf("%-28s deliv=%6.2f%% p50=%7.1fms p95=%7.1fms ovhd=%5.2f%%\n",
			cfg.label, res.delivery*100, res.p50Ms, res.p95Ms, res.overhead*100)
	}
}

// TestBenchRepetitions reruns the contested uniform-loss cells
// (the RS controller pair and the no-FEC baseline, plus the 20%
// band Emma's lines reach) N times with per-repetition seeds, and
// prints median (range) per cell. Ranking questions need
// repetitions: single runs of this harness carry grouping/drop
// alignment jitter of a few tenths of a point.
//
// The link here is offered/0.70 (43% headroom), not the main
// matrix's offered/0.85 (18%): at 18% headroom the wire itself
// saturates once redundancy approaches the 15% cap (max wire
// demand ≈ offered x 1.17), the send queue backlogs, the yield
// wrapper engages, and both controllers end up spending the
// wire ceiling (~18% overhead) — the cap never binds, so the
// cells measure queue/yield dynamics more than controller
// quality. At 43% headroom the wire itself never saturates and
// the production cap is the binding spending constraint; the
// yield wrapper can still engage transiently when this rig's
// receiver processing backlogs the sender (visible in the
// output: applied overhead vs each controller's final target).
// The main TestBenchComparison matrix keeps the historical 18%
// link and documents the tight-headroom regime.
func TestBenchRepetitions(t *testing.T) {
	reps := 0
	if v := os.Getenv("MUSESS_FEC_BENCH_REPS"); v != "" {
		fmt.Sscanf(v, "%d", &reps)
	}
	if reps <= 0 {
		t.Skip("set MUSESS_FEC_BENCH_REPS=N to run repetitions")
	}
	const count = 4000
	const size = 1200
	const offered = 20.0
	configs := []benchConfig{
		{"none (baseline)", func() Codec { return NewRSCodec(16) }, func() Controller { return staticController{r: 0} }},
		{"rs + fixed-step", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("fixed-step", 0) }},
		{"rs + estimator", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("estimator", 0) }},
	}
	losses := []float64{0.05, 0.10, 0.15, 0.20}
	type cellKey struct {
		label string
		loss  float64
	}
	results := map[cellKey][]benchResult{}
	for rep := 0; rep < reps; rep++ {
		seed := int64(1234 + rep*7919)
		for _, cfg := range configs {
			for _, loss := range losses {
				res := cfg.run(t, loss, false, offered, offered/0.70, count, size, seed)
				fmt.Printf("rep %d ", rep)
				printCell(res, loss)
				k := cellKey{cfg.label, loss}
				results[k] = append(results[k], res)
			}
		}
	}
	fmt.Printf("\n=== repetition summary: median (range) over %d reps ===\n", reps)
	fmt.Printf("%-28s %6s %22s %22s %14s\n", "config", "loss%", "delivery%", "goodput Mbps", "overhead%")
	for _, cfg := range configs {
		for _, loss := range losses {
			rs := results[cellKey{cfg.label, loss}]
			var d, g, o []float64
			for _, r := range rs {
				d = append(d, r.delivery*100)
				g = append(g, r.goodputMbps)
				o = append(o, r.overhead*100)
			}
			fmt.Printf("%-28s %6.0f %10.2f (%5.2f-%5.2f) %10.2f (%5.2f-%5.2f) %6.2f (%4.2f-%4.2f)\n",
				cfg.label, loss*100,
				median(d), minOf(d), maxOf(d),
				median(g), minOf(g), maxOf(g),
				median(o), minOf(o), maxOf(o))
		}
	}
}

// --- 20% cap experiment scaffolding (harness-only) ---
//
// estimatorClone and yieldClone replicate the production
// estimator + yield-wrapper formulas exactly, with the
// MaxRedundancy clamp replaced by a parameter, so the price of
// raising the cap can be measured without touching production
// code. Fidelity is checked inside TestBenchCap20 by running the
// clone at the production cap (0.15) next to the production
// controller itself.

type estimatorClone struct {
	mu       sync.Mutex
	estimate float64
	seen     bool
	cap      float64
}

func (c *estimatorClone) Name() string { return "estimator-clone" }

func (c *estimatorClone) OnFeedback(f Feedback) {
	if f.Expected == 0 {
		return
	}
	sample := f.LossRatio()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.seen {
		c.estimate = sample
		c.seen = true
		return
	}
	c.estimate += estimatorAlpha * (sample - c.estimate)
}

func (c *estimatorClone) Redundancy() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.seen || c.estimate < MinLossToEngage {
		return 0
	}
	r := estimatorMargin*c.estimate + estimatorBias
	if r > c.cap {
		r = c.cap
	}
	return r
}

// UncappedRequest exposes what the estimator formula would ask
// for without any clamp (for cap-pressure reporting).
func (c *estimatorClone) UncappedRequest() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.seen {
		return 0
	}
	return estimatorMargin*c.estimate + estimatorBias
}

func (c *estimatorClone) SetBacklogged(bool) {}

type yieldClone struct {
	inner Controller
	capV  float64

	mu          sync.Mutex
	factor      float64
	backlogged  bool
	seenBacklog bool
}

func (w *yieldClone) Name() string { return w.inner.Name() + "+yield-clone" }

func (w *yieldClone) OnFeedback(f Feedback) {
	w.inner.OnFeedback(f)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.backlogged {
		w.factor *= 0.5
		if w.factor < 0.2 {
			w.factor = 0.2
		}
		w.seenBacklog = true
	} else if w.seenBacklog {
		w.factor *= 1.5
		if w.factor >= 1 {
			w.factor = 1
			w.seenBacklog = false
		}
	}
}

func (w *yieldClone) SetBacklogged(b bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.backlogged = b
}

func (w *yieldClone) Redundancy() float64 {
	w.mu.Lock()
	factor := w.factor
	backlogged := w.backlogged
	w.mu.Unlock()
	r := w.inner.Redundancy() * factor
	if backlogged && r > w.inner.Redundancy()*factor {
		r = w.inner.Redundancy() * factor
	}
	if r > w.capV {
		r = w.capV
	}
	return r
}

// TestBenchCap20 prices the FEC redundancy cap at 20% loss
// (Emma's lossy-direction ceiling): production rs+estimator at
// its 15% cap vs a formula-identical clone capped at 30%, on
// uniform and Gilbert-burst loss. Harness-side experiment only;
// no production code or constant is changed.
//
// The link is offered/0.60 (67% headroom): at the raised 30%
// cap the wire demand reaches ~1.44x offered, so on the main
// matrix's 18%-headroom link the wire — not the cap — would
// bind and the yield wrapper would throttle the very
// redundancy being priced. At 67% headroom even the 30% cap's
// full spend fits under the link with margin.
func TestBenchCap20(t *testing.T) {
	if os.Getenv("MUSESS_FEC_BENCH_CAP20") == "" {
		t.Skip("set MUSESS_FEC_BENCH_CAP20=1 to run the cap experiment")
	}
	const count = 4000
	const size = 1200
	const offered = 20.0
	const link = offered / 0.60
	const reps = 3

	mkClone := func(capV float64) (Controller, *estimatorClone) {
		est := &estimatorClone{cap: capV}
		return &yieldClone{inner: est, capV: capV, factor: 1}, est
	}
	type capCfg struct {
		label string
		build func() (Controller, *estimatorClone)
	}
	configs := []capCfg{
		{"rs + estimator cap15 (production)", func() (Controller, *estimatorClone) {
			return NewController("estimator", 0), nil
		}},
		{"rs + estimator cap15 (clone, fidelity)", func() (Controller, *estimatorClone) {
			return mkClone(0.15)
		}},
		{"rs + estimator cap30 (clone)", func() (Controller, *estimatorClone) {
			return mkClone(0.30)
		}},
	}
	for _, burst := range []bool{false, true} {
		kind := "uniform"
		if burst {
			kind = "burst"
		}
		fmt.Printf("\n=== cap experiment at 20%% loss (%s), %d reps ===\n", kind, reps)
		for _, cfg := range configs {
			var ds, gs, os_ []float64
			var uncapped float64
			for rep := 0; rep < reps; rep++ {
				ctrl, est := cfg.build()
				res := runTransfer(t, NewRSCodec(16), ctrl, 0.20, burst, offered, link, count, size, int64(1234+rep*7919))
				res.label = cfg.label
				fmt.Printf("rep %d ", rep)
				printCell(res, 0.20)
				ds = append(ds, res.delivery*100)
				gs = append(gs, res.goodputMbps)
				os_ = append(os_, res.overhead*100)
				if est != nil {
					uncapped = est.UncappedRequest() * 100
				}
			}
			fmt.Printf("%-38s delivery median %6.2f (%5.2f-%5.2f)  goodput median %6.2f  overhead median %5.2f",
				cfg.label, median(ds), minOf(ds), maxOf(ds), median(gs), median(os_))
			if uncapped > 0 {
				fmt.Printf("  uncapped request (last rep) %.1f%%", uncapped)
			}
			fmt.Println()
		}
	}
}

func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func minOf(xs []float64) float64 {
	m := xs[0]
	for _, x := range xs[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

func maxOf(xs []float64) float64 {
	m := xs[0]
	for _, x := range xs[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

// Codec CPU cost: encode+reconstruct throughput on 16x1400B groups.
func BenchmarkCodecEncode(b *testing.B) {
	data := make([][]byte, 16)
	for i := range data {
		data[i] = make([]byte, 1400)
		rand.New(rand.NewSource(int64(i))).Read(data[i])
	}
	b.Run("xor", func(b *testing.B) {
		codec := XORCodec{}
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			if _, err := codec.Encode(data, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reed-solomon-r3", func(b *testing.B) {
		codec := NewRSCodec(16)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			if _, err := codec.Encode(data, 3); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCodecReconstruct(b *testing.B) {
	data := make([][]byte, 16)
	for i := range data {
		data[i] = make([]byte, 1400)
		rand.New(rand.NewSource(int64(i))).Read(data[i])
	}
	b.Run("xor-1-loss", func(b *testing.B) {
		codec := XORCodec{}
		parity, _ := codec.Encode(data, 1)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			shards := append(cloneShards(data), parity[0])
			shards[3] = nil
			if _, err := codec.Reconstruct(shards, 16, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reed-solomon-3-loss", func(b *testing.B) {
		codec := NewRSCodec(16)
		parity, _ := codec.Encode(data, 3)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			shards := append(cloneShards(data), cloneShards(parity)...)
			shards[2] = nil
			shards[9] = nil
			shards[14] = nil
			if _, err := codec.Reconstruct(shards, 16, 3); err != nil {
				b.Fatal(err)
			}
		}
	})
}
