package musess

import (
	"testing"
	"time"
)

// mux_health_test.go — unit tests for the loss-time adaptive mux
// bypass tracker (muxSessionHealth, mux.go) and the outbound gate
// (Outbound.muxHealthBypass). All samples here are synthetic
// (noteRTT takes explicit values); the session-level test at the
// bottom checks the real wiring through an echo pair.

func healthWithRTTs(t *testing.T, rtts ...time.Duration) *muxSessionHealth {
	t.Helper()
	h := newMuxSessionHealth(time.Now())
	for _, d := range rtts {
		h.noteRTT(d)
	}
	return h
}

func TestMuxHealthRTTTripAndRecovery(t *testing.T) {
	h := newMuxSessionHealth(time.Now())
	now := time.Now()
	clean := 200 * time.Millisecond
	lossy := 400 * time.Millisecond
	for i := 0; i < 6; i++ {
		h.noteRTT(clean)
	}
	if degraded, _, _ := h.evaluate(0, now); degraded {
		t.Fatal("clean samples tripped the bypass")
	}
	for i := 0; i < 6; i++ {
		h.noteRTT(lossy)
	}
	degraded, changed, reason := h.evaluate(0, now)
	if !degraded || !changed || reason != "rtt" {
		t.Fatalf("lossy samples did not trip: degraded=%v changed=%v reason=%q", degraded, changed, reason)
	}
	// Still degraded while the median is lossy.
	for i := 0; i < 6; i++ {
		h.noteRTT(clean)
	}
	if degraded, _, _ := h.evaluate(0, now); !degraded {
		t.Fatal("recovered too early: median still lossy")
	}
	for i := 0; i < 6; i++ {
		h.noteRTT(clean)
	}
	degraded, changed, _ = h.evaluate(0, now)
	if degraded || !changed {
		t.Fatalf("healthy samples did not clear: degraded=%v changed=%v", degraded, changed)
	}
}

func TestMuxHealthNoTripOnClean(t *testing.T) {
	h := healthWithRTTs(t,
		200*time.Millisecond, 210*time.Millisecond, 205*time.Millisecond,
		200*time.Millisecond, 215*time.Millisecond, 200*time.Millisecond,
		208*time.Millisecond, 202*time.Millisecond, 200*time.Millisecond,
		212*time.Millisecond, 200*time.Millisecond, 206*time.Millisecond,
	)
	if degraded, _, _ := h.evaluate(0, time.Now()); degraded {
		t.Fatal("clean jitter tripped the bypass")
	}
}

func TestMuxHealthNoTripBeforeMinSamples(t *testing.T) {
	h := healthWithRTTs(t,
		200*time.Millisecond, 900*time.Millisecond, 900*time.Millisecond,
		900*time.Millisecond, 900*time.Millisecond,
	)
	if degraded, _, _ := h.evaluate(0, time.Now()); degraded {
		t.Fatal("tripped with fewer than min samples")
	}
}

func TestMuxHealthStallTrip(t *testing.T) {
	start := time.Now()
	h := newMuxSessionHealth(start)
	// No streams open: a stale lastProgress must not trip.
	if degraded, _, _ := h.evaluate(0, start.Add(2*time.Second)); degraded {
		t.Fatal("stall tripped with no open streams")
	}
	// One open stream, no data for over the stall threshold: trip.
	degraded, changed, reason := h.evaluate(1, start.Add(2*time.Second))
	if !degraded || !changed || reason != "stall" {
		t.Fatalf("live stall did not trip: degraded=%v changed=%v reason=%q", degraded, changed, reason)
	}
	// Recovery needs healthy RTT samples and fresh progress; a
	// stall trip with no samples at all cannot clear yet.
	if degraded, _, _ := h.evaluate(0, start.Add(2*time.Second)); !degraded {
		t.Fatal("stall trip cleared with no samples (nothing proved recovery)")
	}
	now := start.Add(3 * time.Second)
	for i := 0; i < 6; i++ {
		h.noteRTT(200 * time.Millisecond)
	}
	h.noteProgress(now)
	if degraded, changed, _ := h.evaluate(0, now); degraded || !changed {
		t.Fatalf("stall trip did not clear after healthy samples: degraded=%v changed=%v", degraded, changed)
	}
}

func TestMuxHealthProbe(t *testing.T) {
	h := healthWithRTTs(t,
		200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond,
		200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond,
		400*time.Millisecond, 400*time.Millisecond, 400*time.Millisecond,
		400*time.Millisecond, 400*time.Millisecond, 400*time.Millisecond,
	)
	now := time.Now()
	if degraded, _, _ := h.evaluate(0, now); !degraded {
		t.Fatal("setup: expected degraded")
	}
	// The trip evaluation does not count as a bypassed dial.
	// The first 7 bypassed dials get no probe ...
	for i := 0; i < 7; i++ {
		if h.probeDue(now) {
			t.Fatalf("probe due after %d bypassed dials (need %d)", i, muxHealthProbeMinDials)
		}
		h.evaluate(0, now)
	}
	// ... the 8th dial is the probe.
	h.evaluate(0, now)
	if !h.probeDue(now) {
		t.Fatal("probe not due after 8 bypassed dials")
	}
	if h.probeDue(now) {
		t.Fatal("second probe in the same interval was due (slot not consumed)")
	}
	// The next probe needs 8 more dials AND the interval.
	for i := 0; i < 8; i++ {
		h.evaluate(0, now.Add(time.Second))
	}
	if h.probeDue(now.Add(time.Second)) {
		t.Fatal("probe due before the interval elapsed")
	}
	for i := 0; i < 8; i++ {
		h.evaluate(0, now.Add(muxHealthProbeInterval+time.Second))
	}
	if !h.probeDue(now.Add(muxHealthProbeInterval + time.Second)) {
		t.Fatal("probe not due after interval + 8 dials")
	}
}

func TestMuxHealthProbeNotDueWhenHealthy(t *testing.T) {
	h := healthWithRTTs(t, 200*time.Millisecond, 200*time.Millisecond)
	if h.probeDue(time.Now()) {
		t.Fatal("probe due while healthy")
	}
}

// TestMuxHealthSessionWiring checks the real path: streams opened
// on a client session record open-to-first-frame samples, the
// server session carries no health tracker, and a healthy pair
// never degrades.
func TestMuxHealthSessionWiring(t *testing.T) {
	client, server := muxEchoPair(t)
	if server.health != nil {
		t.Fatal("server session carries a health tracker (client-only by design)")
	}
	if client.health == nil {
		t.Fatal("client session has no health tracker")
	}
	for i := 0; i < 6; i++ {
		if err := muxRoundTrip(t, client, mustPayload(t, 64*1024, 0x22)); err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
	}
	// A 1 MiB flow still records exactly one RTT sample, like
	// any other stream (the goodput machinery that used to gate
	// on bulk size was removed: see mux.go).
	if err := muxRoundTrip(t, client, mustPayload(t, 1*1024*1024, 0x33)); err != nil {
		t.Fatalf("1 MiB round trip: %v", err)
	}
	baseline, median, n := client.health.snapshot()
	if n != 7 {
		t.Fatalf("expected 7 RTT samples, got %d (baseline=%v median=%v)", n, baseline, median)
	}
	if client.healthDegraded() {
		t.Fatalf("healthy echo pair degraded: %s", client.health.status())
	}
}

// TestMuxHealthOutboundGate checks the outbound-level gate: a
// tripped session bypasses mux except for the first (probe) dial,
// and a healthy session never bypasses.
func TestMuxHealthOutboundGate(t *testing.T) {
	client, _ := muxEchoPair(t)
	h := &Outbound{muxAdaptiveBypass: true, muxSession: client}
	if h.muxHealthBypass() {
		t.Fatal("healthy session bypassed mux")
	}
	for i := 0; i < 6; i++ {
		client.health.noteRTT(200 * time.Millisecond)
	}
	for i := 0; i < 6; i++ {
		client.health.noteRTT(450 * time.Millisecond)
	}
	// The trip evaluation does not count as a bypassed dial, so
	// the first 8 degraded dials bypass; the 9th is the
	// half-open probe; the next dial bypasses again.
	for i := 0; i < 8; i++ {
		if !h.muxHealthBypass() {
			t.Fatalf("degraded dial %d was not bypassed", i+1)
		}
	}
	if h.muxHealthBypass() {
		t.Fatal("9th degraded dial was not let through as a probe")
	}
	if !h.muxHealthBypass() {
		t.Fatal("dial after the probe slot was consumed did not bypass mux")
	}
	// Recovery clears the gate.
	for i := 0; i < 12; i++ {
		client.health.noteRTT(200 * time.Millisecond)
	}
	client.health.noteProgress(time.Now())
	if h.muxHealthBypass() {
		t.Fatal("recovered session still bypasses mux")
	}
}
