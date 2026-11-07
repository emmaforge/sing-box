package fec

import "sync"

// Small-group spend policy — the deferred companion of flagged
// observation 3 (impl/README.md, "Flagged observations: design
// treatment"). Status since the 2026-11-05 landing: the
// batching + gate composition prototyped in endpoint.go is the
// production default whenever FEC is engaged (applyDefaults
// fills the Spend* fields with the measured values; the
// SpendPolicyOff Options field is the milestone-2 escape
// hatch). The credit codec below remains experiment-only: it
// was measured and rejected (see "Small-group spend policy" in
// the README), and is kept so the falsification stays
// reproducible.
//
// The problem, in numbers: parity is priced per group —
// ParityFor(k, rho) charges at least one whole parity shard for
// any positive target rho — but rho is a byte fraction. The
// minimum nonzero spend on a group is therefore 1/k of the
// group. At trickle the packet plane's groups are k=1 (5 ms
// flush vs 10 ms message spacing), so an engaged controller
// asking for rho ~ 6.7% (the estimator at 5% loss) is charged
// ~100% per protected group; yield throttling and the
// engagement ramp blend that to the measured 34.9–46.8%
// trickle overhead once eager gap synthesis makes the
// controller engage mid-stream. DESIGN 5.4's budget is 8%.
//
// Three candidate policies were analysed; two are prototyped
// in endpoint.go (batching and the minimum-group gate, plus
// their composition), and the third is prototyped here as a
// codec wrapper so the harness can falsify the analysis:
//
//   - Batching (Options.SpendBatchMinK / SpendBatchBudget):
//     hold a protected group until it reaches k >= MinK or its
//     age exceeds Budget, so the one-shard minimum price is
//     amortised over MinK shards. Attacks the quantisation
//     directly; every group stays protected, so the delivery
//     mechanism is unchanged. Its price is bounded added
//     latency, measured on the wire (TestSpendHoldWire) and
//     end-to-end (the trickle bench's latency columns).
//   - Minimum-group gate (Options.SpendMinGroupK /
//     SpendGateRho): a group smaller than MinGroupK buys no
//     parity unless the redundancy target is at least GateRho.
//     Rationale: one parity shard on a k-group is *used* with
//     probability ~1-(1-p)^k; at small k and low loss most
//     parity bytes are provably wasted, while at high loss
//     (target near the cap) each shard's utilisation justifies
//     its 1/k price. Zero added latency, stateless at emit
//     time, so it cannot oscillate against the controller.
//   - Composition (batching + gate, one regime boundary):
//     batching is the low/moderate-loss treatment and the
//     gate's threshold doubles as the boundary at which it
//     stops working — at high loss a batched group at the
//     capped target is under-protected against loss
//     clustering (at 20% loss, P(>=3 losses in k=8) ~ 20% vs
//     r=2), while an unbatched k=1 group taking r=1 recovers
//     whenever its parity shard survives. So: hold and gate
//     below SpendGateRho; above it, emit small groups
//     immediately at full parity (today's behaviour). The
//     benches price both regimes and the composed arm.
//   - Fractional parity credit (creditCodec below): accumulate
//     the exact fractional parity the target implies and spend
//     a whole shard only when the credit reaches one, so the
//     long-run average spend equals the target. Analysis says
//     this optimises the accounting identity, not the outcome:
//     the estimator's formula is a *coverage* fraction for
//     populations where parity spreads across a group, and
//     concentrating the spend on a rho-fraction of k=1 groups
//     recovers only ~rho of the losses (~+0.3pt predicted at
//     5% loss). It is measured anyway — a predicted-dominated
//     arm is cheap, and the prediction itself deserves a check.

// creditSmallK is the group size below which the credit codec
// re-prices parity. Groups at or above it delegate to the
// wrapped codec exactly (bulk behaviour untouched).
const creditSmallK = 4

// creditCodec wraps a Codec and re-prices parity for small
// groups by fractional accumulation across groups. It is
// constructed only by the spend benchmarks/tests. ParityFor is
// called once per emitted group from the sender's send loop;
// the shared-instance harness pattern (one codec for both
// Conns) is safe because only the sending side calls ParityFor.
type creditCodec struct {
	inner Codec

	mu  sync.Mutex
	due float64 // parity shards owed, fractional
}

// NewCreditCodec returns inner with small-group parity priced
// by fractional accumulation (experiment scaffolding).
func NewCreditCodec(inner Codec) Codec {
	return &creditCodec{inner: inner}
}

func (c *creditCodec) Name() string { return c.inner.Name() + "+credit" }

// Plan delegates: group formation is unchanged; only the
// per-group parity price for small groups is re-computed.
func (c *creditCodec) Plan(redundancy float64) (int, int) {
	return c.inner.Plan(redundancy)
}

func (c *creditCodec) Encode(data [][]byte, parityShards int) ([][]byte, error) {
	return c.inner.Encode(data, parityShards)
}

func (c *creditCodec) Reconstruct(shards [][]byte, dataShards int, parityShards int) (int, error) {
	return c.inner.Reconstruct(shards, dataShards, parityShards)
}

// ParityFor implements Codec. For a small group it banks the
// exact fractional parity the target implies —
// rho/(1-rho) shards per data shard — and spends whole shards
// only once the bank reaches one, capped at the wrapped codec's
// own price for the group.
func (c *creditCodec) ParityFor(dataShards int, redundancy float64) int {
	if redundancy <= 0 || dataShards == 0 {
		return 0
	}
	if dataShards >= creditSmallK {
		return c.inner.ParityFor(dataShards, redundancy)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.due += redundancy / (1 - redundancy) * float64(dataShards)
	if c.due < 1 {
		return 0
	}
	spend := int(c.due)
	if maxR := c.inner.ParityFor(dataShards, redundancy); spend > maxR {
		spend = maxR
	}
	c.due -= float64(spend)
	return spend
}
