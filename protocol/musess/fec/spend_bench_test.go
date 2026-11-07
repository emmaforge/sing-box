package fec

// Benchmarks for the small-group spend policy (spend.go) — the
// deferred required companion of flagged observation 3. All
// cells run in the FIXED harness (runTransferMod), paired seeds
// across arms, 3 reps, medians (ranges), sequential. The
// exposing configuration is eager gap synthesis ON throughout:
// without it the controller never engages at trickle and there
// is no spend to price. The harness base pins the milestone-2
// baseline (runTransferMod), so every policy here is still
// opted into explicitly per arm — these benches measure the
// candidates, not the landed defaults (landing_bench_test.go
// covers those). Gate: MUSESS_FEC_SPEND=1.
//
//   MUSESS_FEC_SPEND=1 go test -run TestSpendTrickle -v ./protocol/musess/fec/
//   MUSESS_FEC_SPEND=1 go test -run TestSpendTrickle20 -v ./protocol/musess/fec/
//   MUSESS_FEC_SPEND=1 go test -run TestSpendBulk -v ./protocol/musess/fec/
//   MUSESS_FEC_SPEND=1 go test -run TestSpendTraces -v ./protocol/musess/fec/
//   MUSESS_FEC_SPEND=1 go test -run TestSpendHoldWire -v ./protocol/musess/fec/

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"
)

func spendEnabled() bool { return os.Getenv("MUSESS_FEC_SPEND") != "" }

type spendArm struct {
	label string
	codec func() Codec
	mod   func(*Options)
}

func eagerMod(o *Options) { o.NoEagerGapSynthesis = false }

func batchMod(k int, budget time.Duration) func(*Options) {
	return func(o *Options) {
		o.NoEagerGapSynthesis = false
		o.SpendBatchMinK = k
		o.SpendBatchBudget = budget
	}
}

func gateMod(k int, rho float64) func(*Options) {
	return func(o *Options) {
		o.NoEagerGapSynthesis = false
		o.SpendMinGroupK = k
		o.SpendGateRho = rho
	}
}

func rsCodec() Codec { return NewRSCodec(16) }

func spendArms() []spendArm {
	return []spendArm{
		{"eager current", rsCodec, eagerMod},
		{"batch k4 b40", rsCodec, batchMod(4, 40*time.Millisecond)},
		{"batch k8 b80", rsCodec, batchMod(8, 80*time.Millisecond)},
		{"batch k12 b130", rsCodec, batchMod(12, 130*time.Millisecond)},
		{"gate kmin4 r.12", rsCodec, gateMod(4, 0.12)},
		{"hybrid b8+gate8", rsCodec, func(o *Options) {
			o.NoEagerGapSynthesis = false
			o.SpendBatchMinK = 8
			o.SpendBatchBudget = 80 * time.Millisecond
			o.SpendMinGroupK = 8
			o.SpendGateRho = 0.12
		}},
		{"credit", func() Codec { return NewCreditCodec(NewRSCodec(16)) }, eagerMod},
	}
}

type spendSummary struct {
	d, g, o, p50, p95 []float64
}

func (s *spendSummary) add(r benchResult) {
	s.d = append(s.d, r.delivery*100)
	s.g = append(s.g, r.goodputMbps)
	s.o = append(s.o, r.overhead*100)
	s.p50 = append(s.p50, r.p50Ms)
	s.p95 = append(s.p95, r.p95Ms)
}

func (s *spendSummary) line(label string) string {
	return fmt.Sprintf("%-18s delivery %6.2f (%5.2f-%5.2f)  goodput %5.2f  p50 %8.1fms  p95 %8.1fms  overhead %5.2f%% (medians)",
		label, median(s.d), minOf(s.d), maxOf(s.d), median(s.g), median(s.p50), median(s.p95), median(s.o))
}

// TestSpendTrickle is the main cell: trickle workload
// (100 msg/s, 300x1200B, 5% uniform loss — the fixed harness's
// trickle parameters) with eager synthesis on, rs + estimator,
// across the spend policies; plus the eager no-FEC reference
// and a fixed-step subset for the controller-composition check.
func TestSpendTrickle(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	const count = 300
	const size = 1200
	const reps = 3
	arms := spendArms()

	fmt.Println("\n=== spend: trickle (100 msg/s, 300x1200B, 5% uniform loss), eager ON, rs + estimator, 3 reps paired seeds ===")
	for _, arm := range arms {
		var s spendSummary
		for rep := 0; rep < reps; rep++ {
			res := runTransferMod(t, arm.codec(), NewController("estimator", 0), 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), arm.mod)
			s.add(res)
		}
		fmt.Println(s.line(arm.label))
	}

	fmt.Println("--- reference: eager, no FEC (static 0) ---")
	{
		var s spendSummary
		for rep := 0; rep < reps; rep++ {
			res := runTransferMod(t, rsCodec(), staticController{r: 0}, 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), eagerMod)
			s.add(res)
		}
		fmt.Println(s.line("eager noFEC"))
	}

	fmt.Println("--- composition subset: rs + fixed-step ---")
	for _, arm := range []spendArm{arms[0], arms[2], arms[4]} {
		var s spendSummary
		for rep := 0; rep < reps; rep++ {
			res := runTransferMod(t, arm.codec(), NewController("fixed-step", 0), 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), arm.mod)
			s.add(res)
		}
		fmt.Println(s.line("step " + arm.label))
	}
}

// TestSpendTrickle20 prices the gate's high-loss regime: at 20%
// loss the estimator sits at the 15% cap, above the gate's
// 0.12, so small groups buy parity after all. Trickle
// parameters, loss 0.20, rs + estimator.
func TestSpendTrickle20(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	const count = 300
	const size = 1200
	const reps = 3
	arms := spendArms()
	fmt.Println("\n=== spend: trickle at 20% uniform loss, eager ON, rs + estimator, 3 reps paired seeds ===")
	for _, idx := range []int{0, 2, 4, 5} {
		arm := arms[idx]
		var s spendSummary
		for rep := 0; rep < reps; rep++ {
			res := runTransferMod(t, arm.codec(), NewController("estimator", 0), 0.20, false, 0.96, 1.13, count, size, int64(31337+rep*7919), arm.mod)
			s.add(res)
		}
		fmt.Println(s.line(arm.label))
	}
}

// TestSpendHybrid2 measures the composed regime-boundary arm
// the 20% cell called for: batching (k8/b80) with the hold
// disengaged at targets >= SpendGateRho, plus the emit gate —
// batch and gate below the boundary, today's full-parity
// small groups at or above it. Same paired seeds as
// TestSpendTrickle / TestSpendTrickle20, so its rows compare
// directly against the batch k8 and eager current rows there.
func TestSpendHybrid2(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	const count = 300
	const size = 1200
	const reps = 3
	arms := []spendArm{
		{"hybrid2 gate.12", rsCodec, func(o *Options) {
			o.NoEagerGapSynthesis = false
			o.SpendBatchMinK = 8
			o.SpendBatchBudget = 80 * time.Millisecond
			o.SpendMinGroupK = 8
			o.SpendGateRho = 0.12
		}},
		{"hybrid3 gate.15", rsCodec, func(o *Options) {
			o.NoEagerGapSynthesis = false
			o.SpendBatchMinK = 8
			o.SpendBatchBudget = 80 * time.Millisecond
			o.SpendMinGroupK = 8
			o.SpendGateRho = 0.15
		}},
	}
	fmt.Println("\n=== spend: hybrid2/3 (batch k8 b80 + rho-gate), trickle, eager ON, rs + estimator, 3 reps paired seeds ===")
	for _, arm := range arms {
		for _, loss := range []float64{0.05, 0.20} {
			var s spendSummary
			for rep := 0; rep < reps; rep++ {
				res := runTransferMod(t, arm.codec(), NewController("estimator", 0), loss, false, 0.96, 1.13, count, size, int64(31337+rep*7919), arm.mod)
				s.add(res)
			}
			fmt.Printf("loss=%4.0f%%  %s\n", loss*100, s.line(arm.label))
		}
	}
}

// TestSpendBulk proves the policies do not regress bulk: uniform
// spot cells on the repetitions link (offered/0.70, cap-binding
// regime), rs + estimator, eager on, all arms.
func TestSpendBulk(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	const count = 4000
	const size = 1200
	const reps = 3
	fmt.Println("\n=== spend: bulk no-regression (uniform, repetitions link offered/0.70), eager ON, rs + estimator, 3 reps ===")
	for _, loss := range []float64{0.05, 0.10, 0.20} {
		for _, arm := range spendArms() {
			var rs []benchResult
			for rep := 0; rep < reps; rep++ {
				res := runTransferMod(t, arm.codec(), NewController("estimator", 0), loss, false, 20.0, 20.0/0.70, count, size, int64(1234+rep*7919), arm.mod)
				rs = append(rs, res)
			}
			m := summarise(rs)
			fmt.Printf("loss=%4.0f%%  %-18s delivery %6.2f  goodput %6.2f  overhead %5.2f  finalR %5.1f (medians)\n",
				loss*100, arm.label, m.d, m.g, m.o, m.fr)
		}
	}
}

// TestSpendTraces records the applied-redundancy time series of
// the estimator stack (yield wrapper included — traceController
// sits outside it) for the composition check: batching must
// leave the controller's view of the world unchanged in shape,
// and the gate must not induce flapping in the asked series.
func TestSpendTraces(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	arms := spendArms()
	fmt.Println("\n=== spend: controller traces, rs + estimator trickle (seed 31337) ===")
	for _, idx := range []int{0, 2, 4, 5, 6} {
		arm := arms[idx]
		tc := &traceController{inner: NewController("estimator", 0), start: time.Now()}
		res := runTransferMod(t, arm.codec(), tc, 0.05, false, 0.96, 1.13, 300, 1200, 31337, arm.mod)
		fmt.Printf("arm %-18s delivery %.2f%% overhead %.2f%%\n", arm.label, res.delivery*100, res.overhead*100)
		tc.report(arm.label)
		// Flap check: after the first window that engages
		// redundancy (>0), count windows that fall back to
		// exactly 0 — sustained oscillation would show up as
		// repeated engage/disengage cycles.
		tc.mu.Lock()
		engaged := false
		flaps := 0
		var rMin, rMax float64
		for _, e := range tc.evts {
			if e.redundAfter > 0 {
				if !engaged {
					engaged = true
					rMin, rMax = e.redundAfter, e.redundAfter
				}
				if e.redundAfter < rMin {
					rMin = e.redundAfter
				}
				if e.redundAfter > rMax {
					rMax = e.redundAfter
				}
			} else if engaged {
				flaps++
			}
		}
		tc.mu.Unlock()
		fmt.Printf("    engaged range [%.3f, %.3f], post-engagement zero windows (flaps): %d\n", rMin, rMax, flaps)
	}
}

// TestSpendHoldWire prices batching on the wire with nothing
// else in the path: a sender Conn over a raw net.Pipe (no loss,
// no shim, no receiver processing), a static 10% controller so
// every group is protected from the first message, and a
// producer at the trickle rate. The measured quantity is the
// per-message hold — WriteMessage time to the message's data
// record appearing on the wire — which is the pure sender-side
// price of each batching setting, uncontaminated by queueing
// or recovery effects. (End-to-end latency, which nets the
// hold against reduced queueing, is the trickle bench's
// p50/p95.)
func TestSpendHoldWire(t *testing.T) {
	if !spendEnabled() {
		t.Skip("set MUSESS_FEC_SPEND=1 to run the spend-policy benchmarks")
	}
	settings := []struct {
		label  string
		minK   int
		budget time.Duration
	}{
		{"current (flush 5ms)", 0, 0},
		{"batch k4 b40", 4, 40 * time.Millisecond},
		{"batch k8 b80", 8, 80 * time.Millisecond},
		{"batch k12 b130", 12, 130 * time.Millisecond},
	}
	fmt.Println("\n=== spend: pure sender hold on the wire (100 msg/s, static rho=0.10, no loss) ===")
	for _, s := range settings {
		holds := measureHold(t, s.minK, s.budget)
		fmt.Printf("%-22s hold p50 %6.1fms  p95 %6.1fms  max %6.1fms  (n=%d)\n",
			s.label, median(holds), pct(holds, 0.95), maxOf(holds), len(holds))
	}
}

func pct(xs []float64, q float64) float64 {
	s := append([]float64(nil), xs...)
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s[int(q*float64(len(s)))]
}

func measureHold(t *testing.T, minK int, budget time.Duration) []float64 {
	t.Helper()
	a, b := net.Pipe()
	opts := Options{
		Mode:             ModePacket,
		MaxShard:         1400,
		FlushInterval:    5 * time.Millisecond,
		FeedbackInterval: 100 * time.Millisecond,
		GroupTimeout:     250 * time.Millisecond,
		// The settings below are the whole policy under test:
		// keep applyDefaults from filling the other spend
		// fields (the landed gate would otherwise join in).
		SpendPolicyOff:   true,
		SpendBatchMinK:   minK,
		SpendBatchBudget: budget,
	}
	sender := NewConn(a, NewRSCodec(16), staticController{r: 0.10}, opts)
	defer sender.Close()

	type arrival struct {
		seq uint32
		at  time.Time
	}
	arrivals := make(chan arrival, 8192)
	go func() {
		for {
			rec, _, err := readRecord(b)
			if err != nil {
				return
			}
			if rec.typ == recordData && len(rec.payload) >= 4 {
				arrivals <- arrival{binary.BigEndian.Uint32(rec.payload[0:4]), time.Now()}
			}
		}
	}()

	const n = 60
	const size = 1200
	payload := make([]byte, size)
	rand.New(rand.NewSource(5)).Read(payload)
	sentAt := make([]time.Time, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		msg := make([]byte, size)
		copy(msg, payload)
		binary.BigEndian.PutUint32(msg[0:4], uint32(i))
		if err := sender.WriteMessage(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		sentAt[i] = time.Now()
		if wait := time.Until(start.Add(time.Duration(i+1) * 10 * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
	}
	wireAt := make(map[uint32]time.Time, n)
	timeout := time.After(10 * time.Second)
	for len(wireAt) < n {
		select {
		case ar := <-arrivals:
			if _, dup := wireAt[ar.seq]; !dup {
				wireAt[ar.seq] = ar.at
			}
		case <-timeout:
			t.Fatalf("only %d of %d messages reached the wire", len(wireAt), n)
		}
	}
	holds := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		holds = append(holds, float64(wireAt[uint32(i)].Sub(sentAt[i]))/1e6)
	}
	return holds
}
