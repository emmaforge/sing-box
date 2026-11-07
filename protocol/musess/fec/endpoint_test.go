package fec

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

// staticController pins redundancy for codec/transport tests.
type staticController struct{ r float64 }

func (s staticController) Name() string        { return "static" }
func (s staticController) Redundancy() float64 { return s.r }
func (s staticController) OnFeedback(Feedback) {}
func (s staticController) SetBacklogged(bool)  {}

// dropConn wraps one direction of a connection and drops whole FEC
// records with the given probability (seeded, deterministic). It
// parses the record stream incrementally; feedback records are
// never dropped in these tests unless dropFeedback is set.
type dropConn struct {
	net.Conn
	mu           sync.Mutex
	buf          []byte
	rng          *rand.Rand
	loss         float64
	dropFeedback bool
}

func newDropConn(conn net.Conn, loss float64, seed int64) *dropConn {
	return &dropConn{Conn: conn, rng: rand.New(rand.NewSource(seed)), loss: loss}
}

func (c *dropConn) Write(p []byte) (int, error) {
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
		typ := rec[0]
		if typ == recordFeedback && !c.dropFeedback {
			// pass through
		} else if c.rng.Float64() < c.loss {
			continue // dropped on the floor
		}
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func pipePair() (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return a, b
}

func testOptions(mode Mode) Options {
	return Options{
		Mode:             mode,
		MaxShard:         1400,
		FlushInterval:    2 * time.Millisecond,
		FeedbackInterval: 50 * time.Millisecond,
		GroupTimeout:     100 * time.Millisecond,
		// Pin milestone-2 semantics: these tests exercise
		// mechanisms (codecs, grouping, recovery, feedback),
		// not the adopted policy defaults landed 2026-11-05.
		// Tests for the defaults themselves live in
		// landing_test.go and use productionOptions.
		PacketOrdered:       true,
		NoEagerGapSynthesis: true,
		SpendPolicyOff:      true,
	}
}

// productionOptions is testOptions WITHOUT the milestone-2
// escape hatches: the adopted production defaults (unordered
// packet delivery, eager gap synthesis, composed spend policy)
// exactly as the musess wiring constructs them.
func productionOptions(mode Mode) Options {
	opts := testOptions(mode)
	opts.PacketOrdered = false
	opts.NoEagerGapSynthesis = false
	opts.SpendPolicyOff = false
	return opts
}

func TestEndpointStreamNoLoss(t *testing.T) {
	a, b := pipePair()
	ctrl := staticController{r: 0.10}
	sender := NewConn(a, NewRSCodec(16), ctrl, testOptions(ModeStream))
	receiver := NewConn(b, NewRSCodec(16), staticController{}, testOptions(ModeStream))
	defer sender.Close()
	defer receiver.Close()

	payload := make([]byte, 100*1024)
	rand.New(rand.NewSource(1)).Read(payload)
	go func() {
		sender.Write(payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream payload mismatch")
	}
	stats := sender.Stats()
	if stats.ParityBytesOut == 0 {
		t.Fatal("expected parity bytes with redundancy 0.10")
	}
	if stats.OverheadRatio() <= 0 || stats.OverheadRatio() > 0.20 {
		t.Fatalf("overhead ratio out of expected range: %v", stats.OverheadRatio())
	}
}

func TestEndpointStreamRawMode(t *testing.T) {
	a, b := pipePair()
	sender := NewConn(a, NewRSCodec(16), staticController{r: 0}, testOptions(ModeStream))
	receiver := NewConn(b, NewRSCodec(16), staticController{}, testOptions(ModeStream))
	defer sender.Close()
	defer receiver.Close()

	payload := make([]byte, 64*1024)
	rand.New(rand.NewSource(2)).Read(payload)
	go sender.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("raw stream payload mismatch")
	}
	if stats := sender.Stats(); stats.ParityBytesOut != 0 {
		t.Fatalf("redundancy 0 must not emit parity, got %d", stats.ParityBytesOut)
	}
}

func sendMessages(t *testing.T, c *Conn, count int, size int) [][]byte {
	t.Helper()
	msgs := make([][]byte, count)
	rng := rand.New(rand.NewSource(3))
	for i := range msgs {
		msgs[i] = make([]byte, size)
		rng.Read(msgs[i])
		if err := c.WriteMessage(msgs[i]); err != nil {
			t.Fatal(err)
		}
	}
	return msgs
}

func recvMessages(c *Conn, count int, timeout time.Duration) ([][]byte, error) {
	out := make([][]byte, 0, count)
	deadline := time.Now().Add(timeout)
	for len(out) < count && time.Now().Before(deadline) {
		type res struct {
			msg []byte
			err error
		}
		ch := make(chan res, 1)
		go func() {
			msg, err := c.ReadMessage()
			ch <- res{msg, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				return out, r.err
			}
			out = append(out, r.msg)
		case <-time.After(time.Until(deadline)):
			return out, nil
		}
	}
	return out, nil
}

func TestEndpointPacketLossRecovery(t *testing.T) {
	a, b := pipePair()
	// Loss applies to the sender->receiver direction only.
	lossy := newDropConn(a, 0.10, 42)
	sender := NewConn(lossy, NewRSCodec(16), staticController{r: MaxRedundancy}, testOptions(ModePacket))
	receiver := NewConn(b, NewRSCodec(16), staticController{}, testOptions(ModePacket))
	defer sender.Close()
	defer receiver.Close()

	const count = 3200
	msgs := sendMessages(t, sender, count, 1200)
	got, _ := recvMessages(receiver, count, 10*time.Second)
	delivered := len(got)
	ratio := float64(delivered) / count
	t.Logf("delivered %d/%d = %.4f; receiver stats: %+v", delivered, count, ratio, receiver.Stats())
	// Correct expectation model (verified against per-group
	// outcomes): erasure coding is all-or-nothing per group — a
	// group losing more shards than its parity count loses ALL its
	// missing shards. For RS(16,3) at 10% record loss the residual
	// shard loss is ~2.5%, i.e. delivery ~0.975, not ~0.99.
	if ratio < 0.95 {
		t.Fatalf("delivery ratio %.4f < 0.95 at 10%% loss with 15%% RS redundancy", ratio)
	}
	// Delivered messages must be an in-order subsequence of sent.
	j := 0
	for _, m := range got {
		for j < count && !bytes.Equal(msgs[j], m) {
			j++
		}
		if j >= count {
			t.Fatal("delivered message out of order or corrupted")
		}
		j++
	}
	if receiver.Stats().ShardsRecovered == 0 {
		t.Fatal("expected some shards to be recovered by parity")
	}
}

func TestEndpointPacketNoFECLoss(t *testing.T) {
	a, b := pipePair()
	lossy := newDropConn(a, 0.10, 42)
	sender := NewConn(lossy, NewRSCodec(16), staticController{r: 0}, testOptions(ModePacket))
	receiver := NewConn(b, NewRSCodec(16), staticController{}, testOptions(ModePacket))
	defer sender.Close()
	defer receiver.Close()

	const count = 1600
	sendMessages(t, sender, count, 1200)
	got, _ := recvMessages(receiver, count, 8*time.Second)
	ratio := float64(len(got)) / count
	t.Logf("no-FEC delivery ratio at 10%% loss: %.4f", ratio)
	// Packet mode at redundancy 0 sends raw records: one record per
	// packet, so record loss == packet loss (~10%).
	if ratio < 0.85 || ratio > 0.95 {
		t.Fatalf("delivery ratio %.4f outside expected band around 0.90", ratio)
	}
}

func TestEndpointFeedbackDrivesController(t *testing.T) {
	a, b := pipePair()
	lossy := newDropConn(a, 0.10, 7)
	ctrl := NewController("estimator", 0)
	sender := NewConn(lossy, NewRSCodec(16), ctrl, testOptions(ModePacket))
	receiver := NewConn(b, NewRSCodec(16), staticController{}, testOptions(ModePacket))
	defer sender.Close()
	defer receiver.Close()

	sendMessages(t, sender, 1600, 1200)
	// Let feedback windows accumulate and the estimator react.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sender.Redundancy() > 0.05 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := sender.Redundancy(); got <= 0.05 {
		t.Fatalf("controller did not react to 10%% loss: redundancy %v", got)
	} else {
		t.Logf("controller redundancy after lossy transfer: %v", got)
	}
}

func TestEndpointXORBurstLoss(t *testing.T) {
	a, b := pipePair()
	sender := NewConn(a, XORCodec{}, staticController{r: 0.10}, testOptions(ModePacket))
	receiver := NewConn(b, XORCodec{}, staticController{}, testOptions(ModePacket))
	defer sender.Close()
	defer receiver.Close()

	// No transport loss here: the XOR group mechanics are covered
	// by the codec tests; this checks endpoint behaviour with the
	// XOR codec end to end.
	const count = 900
	msgs := sendMessages(t, sender, count, 1200)
	got, _ := recvMessages(receiver, count, 8*time.Second)
	if len(got) != count {
		t.Fatalf("delivered %d/%d without loss", len(got), count)
	}
	for i := range msgs {
		if !bytes.Equal(got[i], msgs[i]) {
			t.Fatalf("message %d mismatch", i)
		}
	}
}
