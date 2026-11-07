package fec

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the 2026-11-05 landing (impl/README.md, "FEC
// adoptions landed"): the adopted production defaults, and the
// bounded delivered-set that replaced the experiment
// prototype's ever-growing map.

// TestDeliveredWindowMechanics pins the sliding-window bitmap:
// marks, cursor-relative lookup, run advancement across word
// boundaries, and refusal at the window edge.
func TestDeliveredWindowMechanics(t *testing.T) {
	w := newDeliveredWindow()
	if got := w.sizeBytes(); got != uoWindowBits/8 {
		t.Fatalf("window size = %d bytes, want %d", got, uoWindowBits/8)
	}
	const cursor = 100
	if w.contains(cursor, cursor) {
		t.Fatal("fresh window reports group delivered")
	}
	w.mark(cursor, cursor)
	w.mark(cursor+1, cursor)
	w.mark(cursor+3, cursor)
	if !w.contains(cursor+3, cursor) || w.contains(cursor+2, cursor) {
		t.Fatal("mark/contains mismatch around a gap")
	}
	if n := w.advance(); n != 2 {
		t.Fatalf("advance over run of 2 = %d", n)
	}
	// Cursor is now 102: bit 0 is the gap (102), bit 1 is 103.
	if w.contains(103, 102) != true || w.contains(102, 102) != false {
		t.Fatal("window did not slide with the cursor")
	}
	if n := w.advance(); n != 0 {
		t.Fatalf("advance over a gap = %d, want 0", n)
	}
	// IDs below the cursor count as delivered (already passed).
	if !w.contains(50, 102) {
		t.Fatal("below-cursor ID must count as delivered")
	}
	// The window edge: the last slot is markable, beyond it is
	// refused (the pump's lead cap relies on the refusal).
	if !w.mark(102+uoWindowBits-1, 102) {
		t.Fatal("mark at the last window slot refused")
	}
	if w.mark(102+uoWindowBits, 102) {
		t.Fatal("mark beyond the window edge accepted")
	}
	if w.contains(102+uoWindowBits, 102) {
		t.Fatal("contains beyond the window edge = true")
	}

	// A run longer than one word advances in one call and the
	// shift preserves the bits behind the run.
	w2 := newDeliveredWindow()
	for i := 0; i < 200; i++ {
		w2.mark(uint32(i), 0)
	}
	w2.mark(205, 0)
	if n := w2.advance(); n != 200 {
		t.Fatalf("advance over run of 200 = %d", n)
	}
	if !w2.contains(205, 200) || w2.contains(200, 200) {
		t.Fatal("shift lost or invented bits behind a long run")
	}
	if got := w2.sizeBytes(); got != uoWindowBits/8 {
		t.Fatalf("window size after shifts = %d, want %d", got, uoWindowBits/8)
	}
}

// TestProductionOptionDefaults: a bare Options (what the musess
// wiring constructs) yields the adopted production profile, and
// the escape hatches restore milestone-2 behaviour exactly.
func TestProductionOptionDefaults(t *testing.T) {
	a, b := pipePair()
	conn := NewConn(a, NewRSCodec(16), staticController{}, Options{Mode: ModePacket})
	defer conn.Close()
	defer b.Close()
	opts := conn.opts
	if opts.SpendBatchMinK != 8 || opts.SpendBatchBudget != 80*time.Millisecond ||
		opts.SpendMinGroupK != 8 || opts.SpendGateRho != MaxRedundancy {
		t.Fatalf("spend defaults = k%d/%v gate k%d rho %v, want k8/80ms gate k8 rho %v",
			opts.SpendBatchMinK, opts.SpendBatchBudget, opts.SpendMinGroupK, opts.SpendGateRho, MaxRedundancy)
	}
	if !conn.uoActive() {
		t.Fatal("packet mode must default to unordered delivery")
	}
	if !conn.eagerActive() {
		t.Fatal("receiver must default to eager gap synthesis")
	}

	a2, b2 := pipePair()
	stream := NewConn(a2, NewRSCodec(16), staticController{}, Options{Mode: ModeStream})
	defer stream.Close()
	defer b2.Close()
	if stream.uoActive() {
		t.Fatal("stream mode must never deliver unordered (a byte stream cannot skip)")
	}
	if !stream.eagerActive() {
		t.Fatal("stream receiver must default to eager gap synthesis")
	}

	a3, b3 := pipePair()
	m2 := NewConn(a3, NewRSCodec(16), staticController{}, Options{
		Mode:                ModePacket,
		PacketOrdered:       true,
		NoEagerGapSynthesis: true,
		SpendPolicyOff:      true,
	})
	defer m2.Close()
	defer b3.Close()
	if m2.uoActive() || m2.eagerActive() {
		t.Fatal("escape hatches must restore milestone-2 delivery/accounting")
	}
	if m2.opts.SpendBatchMinK != 0 || m2.opts.SpendMinGroupK != 0 || m2.opts.SpendGateRho != 0 {
		t.Fatal("SpendPolicyOff must leave every spend field at zero (milestone-2 pricing)")
	}
}

// seqDropConn drops data records whose payload sequence number
// hits the drop rule — deterministic, and it counts exactly
// which messages it killed (each message is one shard; at r=0 a
// dropped record loses exactly its own message).
type seqDropConn struct {
	net.Conn
	mu      sync.Mutex
	buf     []byte
	dropMod uint32
	dropRem uint32
	dropped atomic.Int64
}

func (c *seqDropConn) Write(p []byte) (int, error) {
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
		if rec[0] == recordData && payloadLen >= 4 {
			seq := binary.BigEndian.Uint32(rec[recordHeaderLen:])
			if seq%c.dropMod == c.dropRem {
				c.dropped.Add(1)
				continue
			}
		}
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// TestDeliveredWindowBoundLongStream is the bound proof: a long
// synthetic packet stream (more groups than the window holds)
// runs over production-default Conns with deterministic record
// loss. Every surviving message must be delivered exactly once,
// and the delivered-set storage must be exactly the constant
// window size at the end — where the prototype's map would have
// held one entry per group for the connection's whole life.
func TestDeliveredWindowBoundLongStream(t *testing.T) {
	const count = 100_000
	const size = 128
	a, b := pipePair()
	dropping := &seqDropConn{Conn: a, dropMod: 89, dropRem: 7}
	opts := productionOptions(ModePacket)
	sender := NewConn(dropping, NewRSCodec(16), staticController{r: 0}, opts)
	receiver := NewConn(b, NewRSCodec(16), staticController{}, opts)
	defer sender.Close()
	defer receiver.Close()

	seen := make([]bool, count)
	var delivered atomic.Int64
	var dup atomic.Int64
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			msg, err := receiver.ReadMessage()
			if err != nil {
				return
			}
			seq := int(binary.BigEndian.Uint32(msg[0:4]))
			if seq < 0 || seq >= count {
				continue
			}
			if seen[seq] {
				dup.Add(1)
			}
			seen[seq] = true
			delivered.Add(1)
		}
	}()

	payload := make([]byte, size)
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint32(payload[0:4], uint32(i))
		if err := sender.WriteMessage(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	sender.Close() // drains the send queue, then closes the pipe
	<-recvDone

	if dup.Load() != 0 {
		t.Fatalf("%d duplicate deliveries (stale-record guard failed)", dup.Load())
	}
	want := int64(count) - dropping.dropped.Load()
	if delivered.Load() != want {
		t.Fatalf("delivered %d, want %d (sent %d, dropped %d)", delivered.Load(), want, count, dropping.dropped.Load())
	}
	for i := 0; i < count; i++ {
		droppedMsg := uint32(i)%89 == 7
		if seen[i] == droppedMsg {
			t.Fatalf("message %d: seen=%v, dropped=%v — delivered set is not exact", i, seen[i], droppedMsg)
		}
	}

	receiver.recvMu.Lock()
	windowBytes := receiver.uoDelivered.sizeBytes()
	cursor := receiver.deliverNext
	groupsSent := sender.Stats().GroupsSent
	receiver.recvMu.Unlock()
	if windowBytes != uoWindowBits/8 {
		t.Fatalf("delivered-set storage = %d bytes after %d groups, want the constant %d",
			windowBytes, groupsSent, uoWindowBits/8)
	}
	if groupsSent <= uoWindowBits {
		t.Fatalf("test premise broken: only %d groups, window holds %d — the stream never outran the window",
			groupsSent, uoWindowBits)
	}
	if uint64(cursor) < groupsSent-1 {
		t.Fatalf("accounting cursor at %d, want it caught up with %d groups sent", cursor, groupsSent)
	}
	t.Logf("groups sent %d, cursor %d, delivered-set storage %d bytes (constant)", groupsSent, cursor, windowBytes)
}
