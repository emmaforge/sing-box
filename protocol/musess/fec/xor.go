package fec

// XORCodec is the simple parity codec: one parity shard per group,
// the XOR of all data shards. It can rebuild exactly one lost shard
// per group, so target redundancy is expressed through the group
// size: redundancy ~1/(k+1). Cheap (no field arithmetic, no
// dependencies) but brittle against bursts: two losses in one group
// are unrecoverable.
type XORCodec struct{}

func (XORCodec) Name() string { return "xor" }

// Plan implements Codec. Group size is clamped to [2, 64]: below 2
// the parity costs more than it saves; above 64 a single loss wastes
// a very large group's worth of latency before the group closes.
func (XORCodec) Plan(redundancy float64) (int, int) {
	if redundancy <= 0 {
		return 20, 0
	}
	k := int(1.0/redundancy - 1 + 0.5)
	if k < 2 {
		k = 2
	}
	if k > 64 {
		k = 64
	}
	return k, 1
}

// ParityFor implements Codec: XOR always spends exactly one
// parity shard, and only when the group is big enough for that to
// be sane (a 1-shard group would pay 100% overhead for it).
func (XORCodec) ParityFor(dataShards int, redundancy float64) int {
	if redundancy <= 0 || dataShards < 2 {
		return 0
	}
	return 1
}

// Encode implements Codec. data shards must all have equal length.
func (XORCodec) Encode(data [][]byte, parityShards int) ([][]byte, error) {
	if len(data) == 0 || parityShards == 0 {
		return nil, nil
	}
	if parityShards != 1 {
		return nil, ErrUnrecoverable
	}
	parity := make([]byte, len(data[0]))
	for _, shard := range data {
		if len(shard) != len(parity) {
			return nil, ErrUnrecoverable
		}
		for i := range parity {
			parity[i] ^= shard[i]
		}
	}
	return [][]byte{parity}, nil
}

// Reconstruct implements Codec.
func (XORCodec) Reconstruct(shards [][]byte, dataShards int, parityShards int) (int, error) {
	if parityShards == 0 {
		return 0, nil
	}
	missing := -1
	for i := 0; i < dataShards; i++ {
		if shards[i] == nil {
			if missing >= 0 {
				return 0, ErrUnrecoverable
			}
			missing = i
		}
	}
	if missing < 0 {
		return 0, nil // only parity (or nothing) was lost
	}
	parity := shards[dataShards]
	if parity == nil {
		return 0, ErrUnrecoverable
	}
	rebuilt := append([]byte(nil), parity...)
	for i := 0; i < dataShards; i++ {
		if i == missing {
			continue
		}
		for j := range rebuilt {
			rebuilt[j] ^= shards[i][j]
		}
	}
	shards[missing] = rebuilt
	return 1, nil
}
