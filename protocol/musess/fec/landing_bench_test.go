package fec

// Spot cells for the landed production defaults (2026-11-05,
// impl/README.md "FEC adoptions landed"). The harness base pins
// the milestone-2 baseline; productionMod clears the three
// escape hatches, so these cells run exactly what the musess
// wiring now builds when FEC is engaged: unordered packet
// delivery + eager gap synthesis + the composed spend policy
// (whose field values applyDefaults fills). Reference numbers
// are the prototype measurements being reproduced:
//
//   - trickle 5% with eager+spend (hybrid3 arm of the spend
//     benches): overhead 10.77%, delivery 97.33%, goodput 0.85,
//     p50 124 ms. NOTE: the spend benches ran ordered+eager;
//     the production composition adds unordered delivery,
//     which the spend record explicitly lists as unmeasured —
//     this cell is that composition's first measurement.
//   - trickle with no FEC spend (static 0): the observation-2
//     unordered arm — delivery 94.33%, p50 14.7 ms.
//   - bulk 5/10/20%: every spend-bench arm landed within
//     delivery 97.15–97.30 / 92.90–93.60 / 81.73–82.33 and
//     overhead 7.33–7.63 / 9.27–9.51 / 10.09–10.29; the
//     production profile must stay in that neighbourhood.
//
// Assertions are bands around those references, wide enough
// for harness jitter, tight enough to catch a landing that
// does not reproduce the prototype. Gate: MUSESS_FEC_LAND=1.
//
//   MUSESS_FEC_LAND=1 go test -run TestLanding -v ./protocol/musess/fec/

import (
	"fmt"
	"os"
	"testing"
)

func landingEnabled() bool { return os.Getenv("MUSESS_FEC_LAND") != "" }

// productionMod turns the harness's milestone-2 baseline into
// the adopted production profile.
func productionMod(o *Options) {
	o.PacketOrdered = false
	o.NoEagerGapSynthesis = false
	o.SpendPolicyOff = false
}

func TestLandingTrickleSpend(t *testing.T) {
	if !landingEnabled() {
		t.Skip("set MUSESS_FEC_LAND=1 to run the landing spot cells")
	}
	const count = 300
	const size = 1200
	const reps = 3
	var s spendSummary
	for rep := 0; rep < reps; rep++ {
		res := runTransferMod(t, rsCodec(), NewController("estimator", 0), 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), productionMod)
		s.add(res)
	}
	fmt.Println("\n=== landing: trickle (100 msg/s, 300x1200B, 5% uniform loss), production defaults, rs + estimator, 3 reps paired seeds ===")
	fmt.Println(s.line("production"))
	d, g, o, p50 := median(s.d), median(s.g), median(s.o), median(s.p50)
	if o < 6 || o > 16 {
		t.Fatalf("trickle overhead %.2f%%, want ~10.77 (band 6–16)", o)
	}
	if d < 93.5 || d > 100 {
		t.Fatalf("trickle delivery %.2f%%, want ~97.33 (band 93.5–100)", d)
	}
	if g < 0.75 {
		t.Fatalf("trickle goodput %.2f Mbps, want ~0.85 (floor 0.75)", g)
	}
	if p50 > 500 {
		t.Fatalf("trickle p50 %.0f ms, want ~124 class (ceiling 500)", p50)
	}
}

func TestLandingTrickleUOLatency(t *testing.T) {
	if !landingEnabled() {
		t.Skip("set MUSESS_FEC_LAND=1 to run the landing spot cells")
	}
	const count = 300
	const size = 1200
	const reps = 3
	var s spendSummary
	for rep := 0; rep < reps; rep++ {
		res := runTransferMod(t, rsCodec(), staticController{r: 0}, 0.05, false, 0.96, 1.13, count, size, int64(31337+rep*7919), productionMod)
		s.add(res)
	}
	fmt.Println("\n=== landing: trickle unordered latency (no FEC spend, static 0), production defaults, 3 reps paired seeds ===")
	fmt.Println(s.line("production noFEC"))
	d, p50 := median(s.d), median(s.p50)
	if d < 90 || d > 97.5 {
		t.Fatalf("noFEC trickle delivery %.2f%%, want ~94.33 (band 90–97.5)", d)
	}
	if p50 > 60 {
		t.Fatalf("noFEC trickle p50 %.0f ms, want ~14.7 class (ceiling 60)", p50)
	}
}

func TestLandingBulk(t *testing.T) {
	if !landingEnabled() {
		t.Skip("set MUSESS_FEC_LAND=1 to run the landing spot cells")
	}
	const count = 4000
	const size = 1200
	const reps = 3
	bands := map[float64][2]float64{0.05: {95.5, 99.5}, 0.10: {90.5, 95.5}, 0.20: {79.5, 85.0}}
	fmt.Println("\n=== landing: bulk spot cells (uniform, repetitions link), production defaults, rs + estimator, 3 reps ===")
	for _, loss := range []float64{0.05, 0.10, 0.20} {
		var rs []benchResult
		for rep := 0; rep < reps; rep++ {
			res := runTransferMod(t, rsCodec(), NewController("estimator", 0), loss, false, 20.0, 20.0/0.70, count, size, int64(1234+rep*7919), productionMod)
			rs = append(rs, res)
		}
		m := summarise(rs)
		fmt.Printf("loss=%4.0f%%  delivery %6.2f  goodput %6.2f  overhead %5.2f (medians)\n", loss*100, m.d, m.g, m.o)
		band := bands[loss]
		if m.d < band[0] || m.d > band[1] {
			t.Fatalf("bulk delivery at %v%% loss = %.2f%%, want within %v (spend-bench neighbourhood)", loss*100, m.d, band)
		}
		if m.o > 11.5 {
			t.Fatalf("bulk overhead at %v%% loss = %.2f%%, want <= 11.5 (spend-bench neighbourhood)", loss*100, m.o)
		}
	}
}
