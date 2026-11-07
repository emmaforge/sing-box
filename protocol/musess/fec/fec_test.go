package fec

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomShards(t *testing.T, k int, size int) [][]byte {
	t.Helper()
	shards := make([][]byte, k)
	for i := range shards {
		shards[i] = make([]byte, size)
		if _, err := rand.Read(shards[i]); err != nil {
			t.Fatal(err)
		}
	}
	return shards
}

func cloneShards(shards [][]byte) [][]byte {
	out := make([][]byte, len(shards))
	for i, s := range shards {
		out[i] = append([]byte(nil), s...)
	}
	return out
}

func TestXORCodecRecoverOne(t *testing.T) {
	codec := XORCodec{}
	data := randomShards(t, 9, 1400)
	parity, err := codec.Encode(cloneShards(data), 1)
	if err != nil {
		t.Fatal(err)
	}
	for drop := 0; drop < 9; drop++ {
		shards := append(cloneShards(data), parity[0])
		want := shards[drop]
		shards[drop] = nil
		recovered, err := codec.Reconstruct(shards, 9, 1)
		if err != nil {
			t.Fatalf("drop %d: %v", drop, err)
		}
		if recovered != 1 || !bytes.Equal(shards[drop], want) {
			t.Fatalf("drop %d: recovered=%d equal=%v", drop, recovered, bytes.Equal(shards[drop], want))
		}
	}
}

func TestXORCodecTwoLossesUnrecoverable(t *testing.T) {
	codec := XORCodec{}
	data := randomShards(t, 9, 100)
	parity, err := codec.Encode(cloneShards(data), 1)
	if err != nil {
		t.Fatal(err)
	}
	shards := append(cloneShards(data), parity[0])
	shards[2] = nil
	shards[5] = nil
	if _, err := codec.Reconstruct(shards, 9, 1); err != ErrUnrecoverable {
		t.Fatalf("expected ErrUnrecoverable, got %v", err)
	}
}

func TestRSCodecRecoverBursts(t *testing.T) {
	codec := NewRSCodec(16)
	data := randomShards(t, 16, 1400)
	parity, err := codec.Encode(cloneShards(data), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(parity) != 3 {
		t.Fatalf("parity shards: %d", len(parity))
	}
	// Every pattern of up to 3 losses among data shards must recover.
	patterns := [][]int{{0}, {15}, {0, 1}, {3, 7, 15}, {14, 15}, {8}}
	for _, pattern := range patterns {
		shards := append(cloneShards(data), cloneShards(parity)...)
		var wants [][]byte
		for _, drop := range pattern {
			wants = append(wants, shards[drop])
			shards[drop] = nil
		}
		recovered, err := codec.Reconstruct(shards, 16, 3)
		if err != nil {
			t.Fatalf("pattern %v: %v", pattern, err)
		}
		if recovered != len(pattern) {
			t.Fatalf("pattern %v: recovered %d", pattern, recovered)
		}
		for i, drop := range pattern {
			if !bytes.Equal(shards[drop], wants[i]) {
				t.Fatalf("pattern %v: shard %d mismatch", pattern, drop)
			}
		}
	}
	// 4 losses with only 3 parity must fail cleanly.
	shards := append(cloneShards(data), cloneShards(parity)...)
	for _, drop := range []int{0, 1, 2, 3} {
		shards[drop] = nil
	}
	if _, err := codec.Reconstruct(shards, 16, 3); err != ErrUnrecoverable {
		t.Fatalf("expected ErrUnrecoverable, got %v", err)
	}
}

func TestCodecPlans(t *testing.T) {
	xor := XORCodec{}
	if k, r := xor.Plan(0); r != 0 || k <= 0 {
		t.Fatalf("xor plan(0) = %d,%d", k, r)
	}
	if k, r := xor.Plan(0.10); r != 1 || k != 9 {
		t.Fatalf("xor plan(0.10) = %d,%d, want 9,1", k, r)
	}
	rs := NewRSCodec(16)
	if _, r := rs.Plan(0); r != 0 {
		t.Fatalf("rs plan(0) r=%d", r)
	}
	if _, r := rs.Plan(0.05); r != 1 {
		t.Fatalf("rs plan(0.05) r=%d, want 1", r)
	}
	if _, r := rs.Plan(0.15); r != 3 {
		t.Fatalf("rs plan(0.15) r=%d, want 3", r)
	}
}

func feedbackWindow(expected int, lostEvents int) Feedback {
	return Feedback{
		Expected:  uint32(expected),
		Received:  uint32(expected - lostEvents),
		Recovered: uint32(lostEvents),
		Lost:      0,
	}
}

func TestStepController(t *testing.T) {
	c := NewStepController()
	if c.Redundancy() != 0 {
		t.Fatal("starts at 0")
	}
	c.OnFeedback(feedbackWindow(100, 0))
	if c.Redundancy() != 0 {
		t.Fatal("no loss stays off")
	}
	c.OnFeedback(feedbackWindow(100, 8)) // 8% loss -> top step immediately
	if c.Redundancy() != MaxRedundancy {
		t.Fatalf("8%% loss -> %v, want cap", c.Redundancy())
	}
	// Hysteresis: one clean window does not step down, two do.
	c.OnFeedback(feedbackWindow(100, 0))
	if c.Redundancy() != MaxRedundancy {
		t.Fatal("one clean window must not step down")
	}
	c.OnFeedback(feedbackWindow(100, 0))
	if c.Redundancy() != 0 {
		t.Fatalf("two clean windows -> %v, want 0", c.Redundancy())
	}
}

func TestEstimatorController(t *testing.T) {
	c := NewEstimatorController()
	if c.Redundancy() != 0 {
		t.Fatal("no data -> 0")
	}
	for i := 0; i < 6; i++ {
		c.OnFeedback(feedbackWindow(200, 20)) // sustained 10% loss
	}
	// The estimator targets margin x estimate, not the cap:
	// 1.25 * 0.10 + 0.004 = 0.129.
	r := c.Redundancy()
	if r < 0.12 || r > 0.135 {
		t.Fatalf("sustained 10%% loss -> %v, want ~0.129", r)
	}
	for i := 0; i < 6; i++ {
		c.OnFeedback(feedbackWindow(200, 50)) // sustained 25% loss -> capped
	}
	if r := c.Redundancy(); r != MaxRedundancy {
		t.Fatalf("sustained 25%% loss -> %v, want cap %v", r, MaxRedundancy)
	}
	for i := 0; i < 40; i++ {
		c.OnFeedback(feedbackWindow(200, 0))
	}
	if c.Redundancy() != 0 {
		t.Fatalf("long clean run -> %v, want 0", c.Redundancy())
	}
}

func TestYieldWrapperSaturation(t *testing.T) {
	c := NewController("estimator", 0)
	for i := 0; i < 6; i++ {
		c.OnFeedback(feedbackWindow(200, 20))
	}
	base := c.Redundancy()
	if base == 0 {
		t.Fatal("expected nonzero redundancy under loss")
	}
	c.SetBacklogged(true)
	for i := 0; i < 3; i++ {
		c.OnFeedback(feedbackWindow(200, 20))
	}
	if got := c.Redundancy(); got >= base {
		t.Fatalf("backlogged must yield: base %v, got %v", base, got)
	}
	c.SetBacklogged(false)
	for i := 0; i < 6; i++ {
		c.OnFeedback(feedbackWindow(200, 20))
	}
	if got := c.Redundancy(); got != base {
		t.Fatalf("yield must recover: base %v, got %v", base, got)
	}
}

func TestYieldWrapperFloor(t *testing.T) {
	c := NewController("fixed-step", FloorForMode("on"))
	if c.Redundancy() != minOnRedundancy {
		t.Fatalf("on-mode floor: got %v want %v", c.Redundancy(), minOnRedundancy)
	}
	c2 := NewController("fixed-step", FloorForMode("auto"))
	if c2.Redundancy() != 0 {
		t.Fatalf("auto-mode floor: got %v want 0", c2.Redundancy())
	}
}
