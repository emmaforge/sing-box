package fec

import (
	"sync"

	"github.com/klauspost/reedsolomon"
)

// RSCodec is a Reed-Solomon codec backed by the mature
// klauspost/reedsolomon library (no hand-rolled Galois-field
// code). Plan targets a fixed group size k, so the loss
// granularity and the close-out latency of a group stay constant
// while redundancy adapts through the parity count; the codec
// itself accepts any group size, because the record layer also
// emits smaller partial groups (flush boundaries). It can rebuild
// any combination of lost shards up to the parity count, which is
// what burst loss needs.
type RSCodec struct {
	// DataShards is the planned group size k.
	DataShards int
	encoders   sync.Map // [2]int{k, r} -> reedsolomon.Encoder
}

// NewRSCodec returns an RS codec with the given fixed group size.
func NewRSCodec(dataShards int) *RSCodec {
	if dataShards <= 0 {
		dataShards = 16
	}
	return &RSCodec{DataShards: dataShards}
}

func (c *RSCodec) Name() string { return "reed-solomon" }

// Plan implements Codec. Parity count is quantised: at k=16 the
// achievable redundancies are r/(16+r) = 5.9%, 11.1%, 15.8%, ... —
// the record layer reports the *achieved* redundancy from measured
// bytes, not the target, so the quantisation is visible in results.
func (c *RSCodec) Plan(redundancy float64) (int, int) {
	if redundancy <= 0 {
		return c.DataShards, 0
	}
	r := int(redundancy/(1.0-redundancy)*float64(c.DataShards) + 0.999)
	if r < 1 {
		r = 1
	}
	if r > c.DataShards {
		r = c.DataShards
	}
	return c.DataShards, r
}

// ParityFor implements Codec.
func (c *RSCodec) ParityFor(dataShards int, redundancy float64) int {
	if redundancy <= 0 || dataShards == 0 {
		return 0
	}
	r := int(redundancy/(1.0-redundancy)*float64(dataShards) + 0.999)
	if r < 1 {
		r = 1
	}
	if r > dataShards {
		r = dataShards
	}
	return r
}

func (c *RSCodec) encoder(dataShards int, parityShards int) (reedsolomon.Encoder, error) {
	key := [2]int{dataShards, parityShards}
	if enc, ok := c.encoders.Load(key); ok {
		return enc.(reedsolomon.Encoder), nil
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	c.encoders.Store(key, enc)
	return enc, nil
}

// Encode implements Codec. data shards must all have equal length.
func (c *RSCodec) Encode(data [][]byte, parityShards int) ([][]byte, error) {
	if parityShards == 0 || len(data) == 0 {
		return nil, nil
	}
	enc, err := c.encoder(len(data), parityShards)
	if err != nil {
		return nil, err
	}
	shards := make([][]byte, len(data)+parityShards)
	copy(shards, data)
	for i := len(data); i < len(shards); i++ {
		shards[i] = make([]byte, len(data[0]))
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards[len(data):], nil
}

// Reconstruct implements Codec.
func (c *RSCodec) Reconstruct(shards [][]byte, dataShards int, parityShards int) (int, error) {
	if parityShards == 0 {
		return 0, nil
	}
	missing := 0
	for i := 0; i < dataShards; i++ {
		if shards[i] == nil {
			missing++
		}
	}
	if missing == 0 {
		return 0, nil
	}
	enc, err := c.encoder(dataShards, parityShards)
	if err != nil {
		return 0, err
	}
	// klauspost/reedsolomon v1.12.4 semantics: shards to rebuild
	// must be passed as nil (the library allocates and fills them);
	// a pre-allocated zero buffer is treated as present-but-wrong
	// data and silently "reconstructs" garbage. Verified by test.
	work := make([][]byte, len(shards))
	copy(work, shards)
	if err := enc.Reconstruct(work); err != nil {
		return 0, ErrUnrecoverable
	}
	recovered := 0
	for i := 0; i < dataShards; i++ {
		if shards[i] == nil {
			shards[i] = work[i]
			recovered++
		}
	}
	return recovered, nil
}
