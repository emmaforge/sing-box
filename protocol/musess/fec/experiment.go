package fec

import "sync"

// Experiment scaffolding for the yield question of flagged
// observation 1 (impl/README.md, "Flagged production
// observations", 2026-11-05). Everything in this file is opt-in:
// production construction paths (NewController) never touch it.
// Observations 2 and 3 were adopted and landed as defaults (see
// endpoint.go's Options); observation 1's verdict was DEFER, so
// this file's treatments remain measurement scaffolding for the
// saturated-lossy-link test that is still missing.

// YieldPolicy parameterises expYieldWrapper, a variant of the
// production yieldWrapper with two experimental knobs:
//
//   - FactorFloor: the static floor of the yield factor
//     (production: 0.2). Raising it is the "shallower blind floor"
//     treatment: simple, but still loss-blind.
//   - LossAwareFloor: when true, the applied redundancy may not be
//     yielded below what the *measured* loss justifies. The
//     wrapper keeps its own EWMA of the window loss ratio from
//     the same Feedback stream (alpha matched to the estimator)
//     and computes a cover floor: the parity fraction at which a
//     group's expected parity count equals its expected loss
//     count, cover = p/(1+p) for loss estimate p (r = k*p implies
//     r/(k+r) = p/(1+p)). Yield then applies only to the margin
//     the inner controller asks for above that cover. The intent
//     is that saturation may still trim the safety margin, but
//     may not disengage protection the measured loss calls for.
type YieldPolicy struct {
	FactorFloor    float64 // 0 selects the production 0.2
	LossAwareFloor bool
}

// expYieldWrapper replicates yieldWrapper's logic exactly (same
// halving/recovery schedule, same mode-floor and saturation
// override semantics) with the YieldPolicy knobs added. With
// YieldPolicy{} it must be indistinguishable from production;
// the fidelity unit test pins that.
type expYieldWrapper struct {
	inner Controller
	floor float64
	pol   YieldPolicy

	mu          sync.Mutex
	factor      float64
	backlogged  bool
	seenBacklog bool
	lossEst     float64
	lossSeen    bool
}

// NewControllerWithYieldPolicy builds a controller stack like
// NewController but with the experimental yield policy. It is
// used by benchmarks and tests only; production uses
// NewController.
func NewControllerWithYieldPolicy(strategy string, floor float64, pol YieldPolicy) Controller {
	var inner Controller
	switch strategy {
	case "estimator":
		inner = NewEstimatorController()
	default:
		inner = NewStepController()
	}
	if pol.FactorFloor <= 0 {
		pol.FactorFloor = 0.2
	}
	return &expYieldWrapper{inner: inner, floor: floor, pol: pol, factor: 1}
}

func (w *expYieldWrapper) Name() string { return w.inner.Name() + "+yield-exp" }

func (w *expYieldWrapper) OnFeedback(f Feedback) {
	w.inner.OnFeedback(f)
	w.mu.Lock()
	defer w.mu.Unlock()
	if f.Expected > 0 {
		sample := f.LossRatio()
		if !w.lossSeen {
			w.lossEst = sample
			w.lossSeen = true
		} else {
			w.lossEst += estimatorAlpha * (sample - w.lossEst)
		}
	}
	if w.backlogged {
		w.factor *= 0.5
		if w.factor < w.pol.FactorFloor {
			w.factor = w.pol.FactorFloor
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

func (w *expYieldWrapper) SetBacklogged(backlogged bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.backlogged = backlogged
}

func (w *expYieldWrapper) Redundancy() float64 {
	w.mu.Lock()
	factor := w.factor
	backlogged := w.backlogged
	lossEst, lossSeen := w.lossEst, w.lossSeen
	w.mu.Unlock()
	inner := w.inner.Redundancy()
	r := inner * factor
	if r < w.floor {
		r = w.floor
	}
	// Saturation overrides the mode floor (production semantics,
	// kept identical): on a saturated link even the "on" mode
	// floor must give way.
	if backlogged && r > inner*factor {
		r = inner * factor
	}
	// Experimental: the measured-loss cover is NOT overridden by
	// saturation — that is the treatment under test. Yield may
	// trim the margin above the cover, never the cover itself.
	if w.pol.LossAwareFloor && lossSeen {
		cover := lossEst / (1 + lossEst)
		if cover > inner {
			cover = inner
		}
		if r < cover {
			r = cover
		}
	}
	if r > MaxRedundancy {
		r = MaxRedundancy
	}
	return r
}

// LossEstimate exposes the wrapper's own feedback EWMA (test and
// benchmark introspection).
func (w *expYieldWrapper) LossEstimate() float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lossEst
}
