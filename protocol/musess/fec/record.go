package fec

import (
	"encoding/binary"
	"io"
)

// Record types on the wire. The format is transport-agnostic: any
// ordered record carrier (the musess TLS stream today, QUIC
// streams/datagrams later) can carry these unchanged.
const (
	recordData     = 0x01 // one data shard of a group
	recordParity   = 0x02 // one parity shard of a group
	recordFeedback = 0x03 // receiver report window (reverse channel)
	recordRaw      = 0x04 // ungrouped pass-through bytes (FEC dormant or oversize)
)

// recordHeaderLen is the fixed record header size:
//
//	[0]    type
//	[1:5]  group ID (feedback: window sequence number)
//	[5]    shard index (data: 0..k-1, parity: 0..r-1)
//	[6]    k, data shards in the group
//	[7]    r, parity shards in the group
//	[8:10] payload length
const recordHeaderLen = 10

type record struct {
	typ     byte
	group   uint32
	index   int
	k       int
	r       int
	payload []byte
}

func writeRecord(w io.Writer, rec record) (int, error) {
	var header [recordHeaderLen]byte
	header[0] = rec.typ
	binary.BigEndian.PutUint32(header[1:5], rec.group)
	header[5] = byte(rec.index)
	header[6] = byte(rec.k)
	header[7] = byte(rec.r)
	binary.BigEndian.PutUint16(header[8:10], uint16(len(rec.payload)))
	if _, err := w.Write(header[:]); err != nil {
		return 0, err
	}
	if len(rec.payload) > 0 {
		if _, err := w.Write(rec.payload); err != nil {
			return 0, err
		}
	}
	return recordHeaderLen + len(rec.payload), nil
}

func readRecord(r io.Reader) (record, int, error) {
	var header [recordHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return record{}, 0, err
	}
	rec := record{
		typ:   header[0],
		group: binary.BigEndian.Uint32(header[1:5]),
		index: int(header[5]),
		k:     int(header[6]),
		r:     int(header[7]),
	}
	length := int(binary.BigEndian.Uint16(header[8:10]))
	if length > 0 {
		rec.payload = make([]byte, length)
		if _, err := io.ReadFull(r, rec.payload); err != nil {
			return record{}, 0, err
		}
	}
	return rec, recordHeaderLen + length, nil
}

// Feedback records carry four big-endian uint32 counters.
func encodeFeedback(f Feedback) []byte {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint32(payload[0:4], f.Expected)
	binary.BigEndian.PutUint32(payload[4:8], f.Received)
	binary.BigEndian.PutUint32(payload[8:12], f.Recovered)
	binary.BigEndian.PutUint32(payload[12:16], f.Lost)
	return payload
}

func decodeFeedback(payload []byte) (Feedback, bool) {
	if len(payload) < 16 {
		return Feedback{}, false
	}
	return Feedback{
		Expected:  binary.BigEndian.Uint32(payload[0:4]),
		Received:  binary.BigEndian.Uint32(payload[4:8]),
		Recovered: binary.BigEndian.Uint32(payload[8:12]),
		Lost:      binary.BigEndian.Uint32(payload[12:16]),
	}, true
}
