// Package fec implements the musess application-layer adaptive FEC
// (DESIGN.md ch. 5.2). It is deliberately transport-agnostic: it
// turns an ordered record stream (today: the musess TLS stream;
// later: QUIC streams/datagrams, unchanged) into data shards grouped
// with parity shards, driven by a redundancy controller fed by
// receiver feedback. Nothing in this package knows about TLS, QUIC,
// or sing-box.
//
// Design rules inherited from DESIGN.md ch. 5.2:
//   - application layer only; no transport internals are touched.
//   - adaptive and per-flow: redundancy follows measured loss,
//     is zero below 1% measured loss, and is capped at ~15%.
//   - the sender yields when the link is saturated: redundancy is
//     scaled down while the send queue is backlogged.
package fec

import "errors"

var (
	// ErrUnrecoverable is returned by a codec when a group lost more
	// shards than its parity can rebuild.
	ErrUnrecoverable = errors.New("fec: group lost more shards than parity can recover")
	// ErrGroupLost is surfaced by a stream-mode Conn when a group
	// could not be fully recovered: a byte stream cannot skip.
	ErrGroupLost = errors.New("fec: unrecoverable group in stream mode")
	// ErrClosed is returned by operations on a closed Conn.
	ErrClosed = errors.New("fec: connection closed")
)

// Codec is a forward-erasure coding scheme over equal-length shards.
// The record layer pads data shards to the group maximum before
// calling Encode, so codecs always see equal-length inputs.
type Codec interface {
	// Name identifies the codec in logs, tests and benchmark tables.
	Name() string
	// Plan maps a target redundancy (parity bytes / total bytes,
	// 0..1) to a concrete group shape. parityShards == 0 means the
	// group goes out without parity.
	Plan(redundancy float64) (dataShards int, parityShards int)
	// ParityFor returns the parity count for a group that actually
	// holds dataShards shards (partial groups at flush boundaries
	// are smaller than Plan's target): parity scales with the real
	// group size so a flushed group does not inherit a full-size
	// group's parity bill.
	ParityFor(dataShards int, redundancy float64) int
	// Encode computes parityShards parity shards for one group of
	// len(data) data shards (the shape returned by Plan).
	Encode(data [][]byte, parityShards int) (parity [][]byte, err error)
	// Reconstruct fills missing data shards in place. shards has
	// length dataShards+parityShards; entries [0:dataShards] are
	// data (nil = missing), the rest are parity (nil = missing).
	// It returns how many data shards were recovered.
	Reconstruct(shards [][]byte, dataShards int, parityShards int) (recovered int, err error)
}

// Feedback is one receiver report window: what the receiver saw of
// the sender's data shards since the previous report. Invariant:
// Received + Recovered + Lost == Expected. Recovered shards were
// lost by the transport and rebuilt from parity, so the sender's
// loss estimate must count Recovered + Lost as loss events.
type Feedback struct {
	Expected  uint32
	Received  uint32
	Recovered uint32
	Lost      uint32
}

// LossRatio returns the fraction of data shards the transport
// dropped in this window (recovered shards included: parity saved
// the data, but the loss still happened).
func (f Feedback) LossRatio() float64 {
	if f.Expected == 0 {
		return 0
	}
	return float64(f.Recovered+f.Lost) / float64(f.Expected)
}

// Controller decides the sender's current target redundancy from
// receiver feedback and a sender-side backlog (saturation) signal.
type Controller interface {
	Name() string
	// Redundancy returns the current target parity fraction
	// (parity bytes / total bytes) for new groups.
	Redundancy() float64
	// OnFeedback consumes one receiver report window.
	OnFeedback(f Feedback)
	// SetBacklogged records whether the sender's output queue is
	// currently backlogged (link saturated). Called by the record
	// layer whenever the queue state is observed.
	SetBacklogged(backlogged bool)
}

// MaxRedundancy is the design cap (DESIGN.md 5.2: redundancy is
// capped at ~15%, no unbounded pouring).
const MaxRedundancy = 0.15

// MinLossToEngage is the measured loss below which FEC stays off
// (DESIGN.md 5.2: below 1% loss FEC is pure waste).
const MinLossToEngage = 0.01
