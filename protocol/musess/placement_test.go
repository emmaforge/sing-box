package musess

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common"

	utls "github.com/metacubex/utls"
)

// This file is the recorded evidence for the milestone-1 fork-point
// "auth-tag placement in the ClientHello". Three shapes are compared:
//
//	stock  - the tree's uTLS Chrome 120 parrot, untouched
//	P1     - the shipped construction: ML-KEM share/curve removed so the
//	         TLS session share is a plain X25519 share whose private key
//	         doubles as the auth ephemeral; tag in legacy_session_id
//	P2     - the alternative: same filtering, plus a second, separately
//	         generated X25519 share appended for the auth exchange
//
// The test only logs the comparison (run with -v); the numbers it
// prints are quoted in impl/README.md.

func buildHello(t *testing.T, mutate func(spec *utls.ClientHelloSpec)) []byte {
	t.Helper()
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&spec)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	uConfig := &utls.Config{
		ServerName:             "dest.test",
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
	}
	uConn := utls.UClient(clientConn, uConfig, utls.HelloCustom)
	if err = uConn.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, len(uConn.HandshakeState.Hello.Raw))
	copy(raw, uConn.HandshakeState.Hello.Raw)
	return raw
}

// filterParrot applies exactly the spec mutations outbound.go performs
// (minus the session-ID patch, which does not change any parsed field
// the server verifies beyond the session ID itself).
func filterParrot(spec *utls.ClientHelloSpec) {
	for i, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.KeyShareExtension:
			ext.KeyShares = common.Filter(ext.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		case *utls.SupportedCurvesExtension:
			ext.Curves = common.Filter(ext.Curves, func(curve utls.CurveID) bool {
				return curve != utls.X25519MLKEM768
			})
		case *utls.RenegotiationInfoExtension:
			spec.Extensions[i] = &utls.GenericExtension{Id: 65281, Data: []byte{0x00}}
		}
	}
}

func extensionTypes(raw []byte) []uint16 {
	// raw is a handshake message: type(1) len(3) version(2) random(32)
	// sidLen(1)+sid suites(2)+n comp(1)+n extTotal(2) extensions...
	off := 4 + 2 + 32
	sidLen := int(raw[off])
	off += 1 + sidLen
	suitesLen := int(raw[off])<<8 | int(raw[off+1])
	off += 2 + suitesLen
	compLen := int(raw[off])
	off += 1 + compLen
	extTotal := int(raw[off])<<8 | int(raw[off+1])
	off += 2
	end := off + extTotal
	var types []uint16
	for off+4 <= end {
		etype := uint16(raw[off])<<8 | uint16(raw[off+1])
		elen := int(raw[off+2])<<8 | int(raw[off+3])
		types = append(types, etype)
		off += 4 + elen
	}
	return types
}

func describeHello(t *testing.T, name string, raw []byte) {
	t.Helper()
	fields, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("%s: parse: %v", name, err)
	}
	var shares []string
	for _, share := range fields.KeyShares {
		shares = append(shares, fmt.Sprintf("%d(%dB)", share.Group, len(share.Data)))
	}
	t.Logf("%-6s len=%d sidLen=%d suites=%dB versions=%dB shares=%v exts=%v",
		name, len(raw), len(fields.SessionID), len(fields.CipherSuites), len(fields.SupportedVersions), shares, extensionTypes(raw))
}

func TestClientHelloPlacementComparison(t *testing.T) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p2Mutate := func(spec *utls.ClientHelloSpec) {
		filterParrot(spec)
		for _, extension := range spec.Extensions {
			if ks, ok := extension.(*utls.KeyShareExtension); ok {
				ks.KeyShares = append(ks.KeyShares, utls.KeyShare{
					Group: utls.X25519,
					Data:  ephemeral.PublicKey().Bytes(),
				})
			}
		}
	}
	// uTLS randomises GREASE values, extension order and padding per
	// build (as Chrome does), so each shape is built several times:
	// the structural fingerprint is the share/extension multiset, the
	// length is a range.
	for _, variant := range []struct {
		name   string
		mutate func(*utls.ClientHelloSpec)
	}{
		{"stock", nil},
		{"P1", filterParrot},
		{"P2", p2Mutate},
	} {
		for i := 0; i < 3; i++ {
			describeHello(t, variant.name, buildHello(t, variant.mutate))
		}
	}
}

// --- server-side verify cost (the "peek cost" of each shape) --------

func benchFields(b *testing.B, extraShareFirst bool) (*ClientHelloFields, []userEntry, *ecdh.PrivateKey, *ClientSessionAuth) {
	b.Helper()
	serverPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	uuid := "11111111-2222-3333-4444-555555555555"
	secret := "bench-secret"
	sessionAuth, err := NewClientSessionAuth(serverPrivate.PublicKey(), ephemeral, uuid, secret)
	if err != nil {
		b.Fatal(err)
	}
	shares := []KeyShareEntry{{Group: groupX25519, Data: ephemeral.PublicKey().Bytes()}}
	if extraShareFirst {
		junk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		shares = append([]KeyShareEntry{{Group: groupX25519, Data: junk.PublicKey().Bytes()}}, shares...)
	}
	fields := &ClientHelloFields{
		Random:     []byte("0123456789abcdef0123456789abcdef"),
		ServerName: "dest.test",
		KeyShares:  shares,
	}
	fields.SessionID = sessionAuth.SessionID(fields, time.Now())
	users := []userEntry{makeUserEntry("bench", uuid, secret)}
	return fields, users, serverPrivate, sessionAuth
}

// refreshSID gives the fields a fresh random and matching session ID
// per benchmark iteration: a verbatim repeat would (correctly) be
// treated as a replay by the server.
func refreshSID(fields *ClientHelloFields, sessionAuth *ClientSessionAuth, now time.Time, i int) {
	fields.Random[31] = byte(i)
	fields.Random[30] = byte(i >> 8)
	fields.SessionID = sessionAuth.SessionID(fields, now)
}

func BenchmarkVerifyP1SingleShare(b *testing.B) {
	fields, users, serverPrivate, sessionAuth := benchFields(b, false)
	cache := newReplayCache()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refreshSID(fields, sessionAuth, now, i)
		if verifyClientHello(fields, users, serverPrivate, cache, now) == nil {
			b.Fatal("expected verification to succeed")
		}
	}
}

func BenchmarkVerifyP2ExtraShareWorstCase(b *testing.B) {
	fields, users, serverPrivate, sessionAuth := benchFields(b, true)
	cache := newReplayCache()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		refreshSID(fields, sessionAuth, now, i)
		if verifyClientHello(fields, users, serverPrivate, cache, now) == nil {
			b.Fatal("expected verification to succeed")
		}
	}
}

func BenchmarkVerifyGarbageHello(b *testing.B) {
	fields, users, serverPrivate, _ := benchFields(b, true)
	// Corrupt the tag: the server now tries every share and fails.
	fields.SessionID[31] ^= 0xff
	cache := newReplayCache()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if verifyClientHello(fields, users, serverPrivate, cache, now) != nil {
			b.Fatal("expected verification to fail")
		}
	}
}
