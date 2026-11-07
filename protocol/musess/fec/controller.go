package fec

import "sync"

// StepController is redundancy strategy A: a fixed step table
// driven by the measured loss ratio of each feedback window, with
// hysteresis on the way down (two consecutive lower windows before
// stepping down) so the level does not flap. Stepping up is
// immediate: under-protecting costs retransmissions, over-protecting
// costs a bounded slice of bandwidth.
//
// Steps implement DESIGN.md 5.2: <1% loss -> off; 1-5% -> low
// (5-10%); 5-15% -> up to the ~15% cap.
type StepController struct {
	mu       sync.Mutex
	level    int // index into stepLevels
	downHits int // consecutive windows whose target is below level
}

var stepLevels = []float64{0, 0.05, 0.10, MaxRedundancy}

func NewStepController() *StepController { return &StepController{} }

func (c *StepController) Name() string { return "fixed-step" }

func stepTarget(loss float64) int {
	switch {
	case loss < MinLossToEngage:
		return 0
	case loss < 0.03:
		return 1
	case loss < 0.07:
		return 2
	default:
		return 3
	}
}

func (c *StepController) OnFeedback(f Feedback) {
	if f.Expected == 0 {
		return
	}
	target := stepTarget(f.LossRatio())
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case target > c.level:
		c.level = target
		c.downHits = 0
	case target < c.level:
		c.downHits++
		if c.downHits >= 2 {
			c.level = target
			c.downHits = 0
		}
	default:
		c.downHits = 0
	}
}

func (c *StepController) Redundancy() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return stepLevels[c.level]
}

// SetBacklogged is handled by the shared yield wrapper; the step
// controller itself has no backlog state.
func (c *StepController) SetBacklogged(bool) {}

// EstimatorController is redundancy strategy B: an EWMA loss
// estimator with a direct formula. The parity fraction needed to
// survive a shard-loss probability p is ~p (losses hit data and
// parity uniformly, so recovery needs r/(k+r) >= p); the formula
// adds a safety margin and reacts every window instead of waiting
// for step thresholds — smoother, but it tracks estimator noise
// when the window is small.
type EstimatorController struct {
	mu       sync.Mutex
	estimate float64 // EWMA of the window loss ratio
	seen     bool
}

const (
	estimatorAlpha  = 0.3  // EWMA weight of the newest window
	estimatorMargin = 1.25 // safety factor over the raw estimate
	estimatorBias   = 0.004
)

func NewEstimatorController() *EstimatorController { return &EstimatorController{} }

func (c *EstimatorController) Name() string { return "estimator" }

func (c *EstimatorController) OnFeedback(f Feedback) {
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

func (c *EstimatorController) Redundancy() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.seen || c.estimate < MinLossToEngage {
		return 0
	}
	r := estimatorMargin*c.estimate + estimatorBias
	if r > MaxRedundancy {
		r = MaxRedundancy
	}
	return r
}

func (c *EstimatorController) SetBacklogged(bool) {}

// yieldWrapper is the shared outer shell for both strategies: it
// applies the mode floor (in "on" mode FEC never fully disengages),
// the design cap, and — the DESIGN.md 5.2 saturation rule — scales
// redundancy down while the sender is backlogged, because on a
// saturated link parity bytes crowd out real data and FEC turns
// net-negative. The yield factor halves per feedback window while
// backlogged and recovers x1.5 per window once the backlog clears.
type yieldWrapper struct {
	inner Controller
	floor float64

	mu          sync.Mutex
	factor      float64
	backlogged  bool
	seenBacklog bool
}

// NewController builds a production controller stack for one of the
// two strategies ("fixed-step" or "estimator") and a mode floor:
// floor is 0 in adaptive ("auto") mode and minOnRedundancy in "on"
// mode (the flow has declared itself loss-sensitive; FEC never
// fully disengages unless the link saturates).
func NewController(strategy string, floor float64) Controller {
	var inner Controller
	switch strategy {
	case "estimator":
		inner = NewEstimatorController()
	default:
		inner = NewStepController()
	}
	return &yieldWrapper{inner: inner, floor: floor, factor: 1}
}

const minOnRedundancy = 0.05

// FloorForMode maps a musess fec mode to the controller floor.
func FloorForMode(mode string) float64 {
	if mode == "on" {
		return minOnRedundancy
	}
	return 0
}

func (w *yieldWrapper) Name() string { return w.inner.Name() + "+yield" }

func (w *yieldWrapper) OnFeedback(f Feedback) {
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

func (w *yieldWrapper) SetBacklogged(backlogged bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.backlogged = backlogged
}

func (w *yieldWrapper) Redundancy() float64 {
	w.mu.Lock()
	factor := w.factor
	backlogged := w.backlogged
	w.mu.Unlock()
	r := w.inner.Redundancy() * factor
	if r < w.floor {
		r = w.floor
	}
	// Saturation overrides the floor: on a saturated link even the
	// "on" mode floor must give way (DESIGN.md 5.2 yield rule).
	if backlogged && r > w.inner.Redundancy()*factor {
		r = w.inner.Redundancy() * factor
	}
	if r > MaxRedundancy {
		r = MaxRedundancy
	}
	return r
}
