package fec

import (
	"net"
	"testing"
	"time"
)

// Unit tests for the small-group spend policy experiments
// (spend.go, and the Spend* Options fields in endpoint.go).
// Production defaults are untouched: every Options below sets
// the experiment fields explicitly, and the gate-off case pins
// the milestone-2 behaviour.

func TestCreditCodecSmallGroupAccounting(t *testing.T) {
	cc := NewCreditCodec(NewRSCodec(16))
	if got := cc.ParityFor(1, 0); got != 0 {
		t.Fatalf("credit ParityFor(1, 0) = %d, want 0", got)
	}
	// rho = 6.7% at k=1 banks 0.0718 shards per group: over 200
	// groups the spend must track the target (~14 shards), not
	// the per-group ceil (200).
	total := 0
	for i := 0; i < 200; i++ {
		total += cc.ParityFor(1, 0.067)
	}
	if total < 11 || total > 17 {
		t.Fatalf("credit spend over 200 k=1 groups at rho=0.067 = %d, want ~14", total)
	}
}

func TestCreditCodecDelegatesAtBulkSizes(t *testing.T) {
	cc := NewCreditCodec(NewRSCodec(16))
	inner := NewRSCodec(16)
	for _, tc := range []struct {
		k   int
		rho float64
	}{
		{4, 0.05}, {4, 0.10}, {8, 0.15}, {16, 0.15}, {16, 0.05},
	} {
		if got, want := cc.ParityFor(tc.k, tc.rho), inner.ParityFor(tc.k, tc.rho); got != want {
			t.Fatalf("credit ParityFor(%d, %.2f) = %d, want delegated %d", tc.k, tc.rho, got, want)
		}
	}
	// Delegation must not bank credit: the small-group bank of a
	// fresh codec still starts empty (first ~13 calls at k=1,
	// rho=0.067 spend nothing).
	fresh := NewCreditCodec(NewRSCodec(16))
	fresh.ParityFor(16, 0.15)
	if got := fresh.ParityFor(1, 0.067); got != 0 {
		t.Fatalf("credit ParityFor(1, 0.067) after delegation = %d, want 0 (bank must start empty)", got)
	}
}

// readOneRecord reads a single record from the raw pipe end with
// a deadline, reporting whether one arrived in time.
func readOneRecord(b net.Conn, timeout time.Duration) (record, bool) {
	b.SetReadDeadline(time.Now().Add(timeout))
	defer b.SetReadDeadline(time.Time{})
	rec, _, err := readRecord(b)
	if err != nil {
		return record{}, false
	}
	return rec, true
}

// readGroup reads one whole emitted group (k data records then
// r parity records) from the raw pipe end.
func readGroup(t *testing.T, b net.Conn) []record {
	t.Helper()
	first, ok := readOneRecord(b, 3*time.Second)
	if !ok {
		t.Fatal("no record arrived within 3s")
	}
	if first.typ != recordData {
		t.Fatalf("first record type = %d, want data", first.typ)
	}
	recs := []record{first}
	for len(recs) < first.k+first.r {
		rec, ok := readOneRecord(b, 3*time.Second)
		if !ok {
			t.Fatalf("group incomplete: got %d of %d records", len(recs), first.k+first.r)
		}
		recs = append(recs, rec)
	}
	return recs
}

func spendTestSender(t *testing.T, rho float64, mutate func(*Options)) (*Conn, net.Conn) {
	t.Helper()
	a, b := pipePair()
	opts := testOptions(ModePacket)
	if mutate != nil {
		mutate(&opts)
	}
	sender := NewConn(a, NewRSCodec(16), staticController{r: rho}, opts)
	t.Cleanup(func() { sender.Close() })
	return sender, b
}

func TestSpendGateEndpoint(t *testing.T) {
	gate := func(o *Options) { o.SpendMinGroupK = 4; o.SpendGateRho = 0.12 }

	// Below the gate: a k=1 group at rho=5% rides raw.
	sender, b := spendTestSender(t, 0.05, gate)
	if err := sender.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	recs := readGroup(t, b)
	if len(recs) != 1 || recs[0].k != 1 || recs[0].r != 0 {
		t.Fatalf("gate below-threshold group = %d records, k=%d r=%d; want 1 record, k=1 r=0",
			len(recs), recs[0].k, recs[0].r)
	}

	// Above the gate: same group size at rho=15% buys parity.
	sender2, b2 := spendTestSender(t, 0.15, gate)
	if err := sender2.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	recs = readGroup(t, b2)
	if len(recs) != 2 || recs[0].k != 1 || recs[0].r != 1 || recs[1].typ != recordParity {
		t.Fatalf("gate above-threshold group = %d records, k=%d r=%d; want data+parity, k=1 r=1",
			len(recs), recs[0].k, recs[0].r)
	}

	// Gate off (zero value): production behaviour — parity at
	// any positive target, even for k=1.
	sender3, b3 := spendTestSender(t, 0.05, nil)
	if err := sender3.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	recs = readGroup(t, b3)
	if len(recs) != 2 || recs[0].r != 1 {
		t.Fatalf("gate-off group = %d records, r=%d; want data+parity (production behaviour)", len(recs), recs[0].r)
	}
}

func TestSpendBatchEndpoint(t *testing.T) {
	// Four messages staggered 15ms apart (flush interval is
	// 2ms: unbatched, each would flush alone) must arrive as
	// ONE group of k=4 under a MinK=4 / 600ms-budget hold.
	sender, b := spendTestSender(t, 0.10, func(o *Options) {
		o.SpendBatchMinK = 4
		o.SpendBatchBudget = 600 * time.Millisecond
	})
	for i := 0; i < 4; i++ {
		if err := sender.WriteMessage([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if i < 3 {
			if _, ok := readOneRecord(b, 10*time.Millisecond); ok {
				t.Fatalf("record escaped the batching hold after message %d", i+1)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	recs := readGroup(t, b)
	if recs[0].k != 4 {
		t.Fatalf("batched group k = %d, want 4", recs[0].k)
	}
	for _, rec := range recs {
		if rec.group != recs[0].group {
			t.Fatalf("batched messages split across groups %d and %d", recs[0].group, rec.group)
		}
	}

	// Regime boundary: with SpendGateRho set and the target
	// above it, the batching hold disengages — a message at
	// rho=15% (gate 0.12) flushes immediately as a k=1 group
	// with full parity, never mind MinK and the budget.
	sender3, b3 := spendTestSender(t, 0.15, func(o *Options) {
		o.SpendBatchMinK = 4
		o.SpendBatchBudget = 600 * time.Millisecond
		o.SpendGateRho = 0.12
	})
	if err := sender3.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	recs = readGroup(t, b3)
	if recs[0].k != 1 || recs[0].r != 1 {
		t.Fatalf("regime-boundary group = k=%d r=%d; want k=1 r=1 (hold disengaged at high target)", recs[0].k, recs[0].r)
	}

	// Budget expiry: MinK=8 is unreachable for two messages;
	// the group must still flush once the 120ms budget passes,
	// as one k=2 group.
	sender2, b2 := spendTestSender(t, 0.10, func(o *Options) {
		o.SpendBatchMinK = 8
		o.SpendBatchBudget = 120 * time.Millisecond
	})
	start := time.Now()
	if err := sender2.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, ok := readOneRecord(b2, 25*time.Millisecond); ok {
		t.Fatal("record escaped before the batching budget in the expiry case")
	}
	if err := sender2.WriteMessage([]byte("world")); err != nil {
		t.Fatal(err)
	}
	recs = readGroup(t, b2)
	if recs[0].k != 2 {
		t.Fatalf("budget-expired group k = %d, want 2", recs[0].k)
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("budget-expired group flushed after %v, want >= ~120ms budget", elapsed)
	}
}
