package fec

// Benchmarks for the flagged-observation treatments (see
// experiment.go). Everything runs in the FIXED harness
// (runTransferMod with a nil-equivalent accounting path — the
// only difference from runTransfer is the Options modifier),
// paired seeds across arms, medians over repetitions, sequential
// runs. Gate: MUSESS_FEC_EXP=1.
//
//   MUSESS_FEC_EXP=1 go test -run TestExpYield -v ./protocol/musess/fec/
//   MUSESS_FEC_EXP=1 go test -run TestExpTrickle -v ./protocol/musess/fec/
//   MUSESS_FEC_EXP=1 go test -run TestExpUOBulk -v ./protocol/musess/fec/

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func expEnabled() bool { return os.Getenv("MUSESS_FEC_EXP") != "" }

type med3 struct{ d, g, o, fr float64 }

func summarise(rs []benchResult) med3 {
	var d, g, o, fr []float64
	for _, r := range rs {
		d = append(d, r.delivery*100)
		g = append(g, r.goodputMbps)
		o = append(o, r.overhead*100)
		fr = append(fr, r.finalRedund*100)
	}
	return med3{median(d), median(g), median(o), median(fr)}
}

// TestExpYield measures observation 1 treatments on the fixed
// harness's saturation cell (offered 100 into 23 Mbps, 5% loss —
// the cell where the yield wrapper binds), plus uniform-loss spot
// cells on the repetitions link (43% headroom, cap binding) to
// prove the loss-aware floor does not disturb unsaturated
// behaviour.
func TestExpYield(t *testing.T) {
	if !expEnabled() {
		t.Skip("set MUSESS_FEC_EXP=1 to run the observation experiments")
	}
	const count = 4000
	const size = 1200
	const reps = 3
	arms := []struct {
		label string
		ctrl  func() Controller
	}{
		{"rs+est production", func() Controller { return NewController("estimator", 0) }},
		{"rs+est yield-clone (fidelity)", func() Controller {
			return NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{})
		}},
		{"rs+est yield loss-aware", func() Controller {
			return NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{LossAwareFloor: true})
		}},
		{"rs+est yield floor0.4", func() Controller {
			return NewControllerWithYieldPolicy("estimator", 0, YieldPolicy{FactorFloor: 0.4})
		}},
	}
	fmt.Println("\n=== exp obs1: saturation (offered 100 Mbps into 23 Mbps, 5% uniform loss), 3 reps paired seeds ===")
	fmt.Printf("%-28s %8s %9s %8s %8s\n", "arm", "deliv%", "goodput", "ovhd%", "finalR%")
	for _, arm := range arms {
		var rs []benchResult
		for rep := 0; rep < reps; rep++ {
			res := runTransfer(t, NewRSCodec(16), arm.ctrl(), 0.05, false, 100.0, 23.0, count, size, int64(4242+rep*7919))
			res.label = arm.label
			fmt.Printf("rep %d ", rep)
			printCell(res, 0.05)
			rs = append(rs, res)
		}
		m := summarise(rs)
		fmt.Printf("%-28s %8.2f %9.2f %8.2f %8.1f  (medians)\n", arm.label, m.d, m.g, m.o, m.fr)
	}

	fmt.Println("\n=== exp obs1: uniform spot cells (repetitions link, offered/0.70), production vs loss-aware, 3 reps ===")
	for _, loss := range []float64{0.05, 0.10, 0.20} {
		for _, arm := range arms[:3] {
			if arm.label == "rs+est yield-clone (fidelity)" {
				continue
			}
			var rs []benchResult
			for rep := 0; rep < reps; rep++ {
				res := runTransfer(t, NewRSCodec(16), arm.ctrl(), loss, false, 20.0, 20.0/0.70, count, size, int64(1234+rep*7919))
				rs = append(rs, res)
			}
			m := summarise(rs)
			fmt.Printf("%-28s loss=%4.0f%%  delivery %6.2f  goodput %6.2f  overhead %5.2f  finalR %5.1f (medians)\n",
				arm.label, loss*100, m.d, m.g, m.o, m.fr)
		}
	}
}

// traceController records every feedback window the sender
// consumes, for the observation-3 response traces.
type traceController struct {
	inner Controller
	start time.Time
	mu    sync.Mutex
	evts  []traceEvent
}

type traceEvent struct {
	at          time.Duration
	ratio       float64
	expected    uint32
	lostEvents  uint32
	redundAfter float64
}

func (c *traceController) Name() string         { return "trace+" + c.inner.Name() }
func (c *traceController) Redundancy() float64  { return c.inner.Redundancy() }
func (c *traceController) SetBacklogged(b bool) { c.inner.SetBacklogged(b) }
func (c *traceController) OnFeedback(f Feedback) {
	c.inner.OnFeedback(f)
	c.mu.Lock()
	c.evts = append(c.evts, traceEvent{
		at:          time.Since(c.start),
		ratio:       f.LossRatio(),
		expected:    f.Expected,
		lostEvents:  f.Recovered + f.Lost,
		redundAfter: c.inner.Redundancy(),
	})
	c.mu.Unlock()
}

func (c *traceController) report(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	zeroRun := 0
	firstNZ := -1
	for i, e := range c.evts {
		if e.ratio == 0 && firstNZ < 0 {
			zeroRun++
		}
		if e.ratio > 0 && firstNZ < 0 {
			firstNZ = i
		}
	}
	fmt.Printf("--- trace %s: %d feedback windows, %d leading all-zero windows", label, len(c.evts), zeroRun)
	if firstNZ >= 0 {
		fmt.Printf(", first nonzero at window %d (t=%.2fs, ratio %.3f)", firstNZ, c.evts[firstNZ].at.Seconds(), c.evts[firstNZ].ratio)
	}
	fmt.Println()
	nz := 0
	for i, e := range c.evts {
		if e.ratio > 0 {
			nz++
			if nz <= 14 {
				fmt.Printf("    win %3d t=%5.2fs ratio %.3f exp=%d lostEv=%d -> redundancy %.3f\n",
					i, e.at.Seconds(), e.ratio, e.expected, e.lostEvents, e.redundAfter)
			}
		}
	}
	fmt.Printf("    (%d nonzero windows total)\n", nz)
}

// TestExpTrickle measures observations 2 and 3 on the fixed
// harness's trickle cell (100 msg/s, 300 messages, 5% uniform
// loss — the cell that produced p50 = 1.5 s in the flagged
// record): delivery-semantics arms (ordered, shorter group
// timeouts, unordered packet delivery, eager gap synthesis, and
// the combination) across the production controller pair and the
// no-FEC baseline, plus sender-side feedback traces for the
// estimator under production vs eager receivers.
func TestExpTrickle(t *testing.T) {
	if !expEnabled() {
		t.Skip("set MUSESS_FEC_EXP=1 to run the observation experiments")
	}
	const count = 300
	const size = 1200
	const reps = 3
	type arm struct {
		label string
		mod   func(*Options)
	}
	gt := func(d time.Duration) func(*Options) {
		return func(o *Options) { o.GroupTimeout = d }
	}
	armsAll := []arm{
		{"ordered GT150 (production)", nil},
		{"UO GT150", func(o *Options) { o.PacketOrdered = false }},
		{"eager GT150", func(o *Options) { o.NoEagerGapSynthesis = false }},
		{"UO+eager GT150", func(o *Options) { o.PacketOrdered = false; o.NoEagerGapSynthesis = false }},
	}
	armsEst := append(append([]arm{}, armsAll...),
		arm{"ordered GT50", gt(50 * time.Millisecond)},
		arm{"ordered GT25", gt(25 * time.Millisecond)},
	)
	configs := []struct {
		label string
		ctrl  func() Controller
		arms  []arm
	}{
		{"none (baseline)", func() Controller { return staticController{r: 0} }, armsAll},
		{"rs + fixed-step", func() Controller { return NewController("fixed-step", 0) }, armsAll},
		{"rs + estimator", func() Controller { return NewController("estimator", 0) }, armsEst},
	}
	fmt.Println("\n=== exp obs2/3: trickle (100 msg/s, 300x1200B, 5% uniform loss), 3 reps paired seeds ===")
	for _, cfg := range configs {
		for _, arm := range cfg.arms {
			var d, p50, p95, o []float64
			for rep := 0; rep < reps; rep++ {
				res := runTransferMod(t, NewRSCodec(16), cfg.ctrl(), 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), arm.mod)
				d = append(d, res.delivery*100)
				p50 = append(p50, res.p50Ms)
				p95 = append(p95, res.p95Ms)
				o = append(o, res.overhead*100)
			}
			fmt.Printf("%-16s %-26s delivery %6.2f (%5.2f-%5.2f)  p50 %8.1fms  p95 %8.1fms  overhead %5.2f%% (medians)\n",
				cfg.label, arm.label, median(d), minOf(d), maxOf(d), median(p50), median(p95), median(o))
		}
	}

	fmt.Println("\n=== exp obs3: sender feedback traces, rs + estimator trickle ===")
	for _, arm := range []arm{armsAll[0], armsAll[2]} {
		tc := &traceController{inner: NewController("estimator", 0), start: time.Now()}
		res := runTransferMod(t, NewRSCodec(16), tc, 0.05, false, 0.96, 1.13, count, size, 31337, arm.mod)
		fmt.Printf("arm %-26s delivery %.2f%% p50 %.1fms p95 %.1fms\n", arm.label, res.delivery*100, res.p50Ms, res.p95Ms)
		tc.report(arm.label)
	}
}

// TestExpUOBulk proves the unordered packet pump does not change
// bulk delivery (it changes *when* messages arrive, not whether):
// uniform spot cells, ordered vs unordered, rs + estimator.
func TestExpUOBulk(t *testing.T) {
	if !expEnabled() {
		t.Skip("set MUSESS_FEC_EXP=1 to run the observation experiments")
	}
	const count = 4000
	const size = 1200
	const reps = 3
	fmt.Println("\n=== exp obs2/3: bulk no-regression (uniform, repetitions link), ordered vs UO vs eager, 3 reps ===")
	for _, loss := range []float64{0.05, 0.10, 0.20} {
		for _, arm := range []struct {
			label string
			mod   func(*Options)
		}{
			{"ordered", nil},
			{"UO", func(o *Options) { o.PacketOrdered = false }},
			{"eager", func(o *Options) { o.NoEagerGapSynthesis = false }},
		} {
			var rs []benchResult
			for rep := 0; rep < reps; rep++ {
				res := runTransferMod(t, NewRSCodec(16), NewController("estimator", 0), loss, false, 20.0, 20.0/0.70, count, size, int64(1234+rep*7919), arm.mod)
				rs = append(rs, res)
			}
			m := summarise(rs)
			fmt.Printf("%-8s loss=%4.0f%%  delivery %6.2f  goodput %6.2f  overhead %5.2f (medians)\n",
				arm.label, loss*100, m.d, m.g, m.o)
		}
	}
}
