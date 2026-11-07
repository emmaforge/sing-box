package musess

import (
	"bytes"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// Unit tests for the early-request sealed header path (rate-attack
// phase 2 landing). The asymmetric peer combinations (early client
// vs stock server, stock client vs early server) are covered at the
// framing level here - readRequestAuto is exactly what an
// early-enabled server runs, and readRequest is exactly what a
// stock server runs - and end-to-end by the e2e configs.

const testFECFlagRequest = fecFlagForward | fecFlagReverse

var (
	earlyTestProofKey = []byte("0123456789abcdef0123456789abcdef")
	earlyTestWrongKey = []byte("fedcba9876543210fedcba9876543210")
	earlyTestDest     = M.ParseSocksaddr("dest.test:8443")
	earlyTestDestUDP  = M.ParseSocksaddr("127.0.0.1:15353")
)

func TestBuildRequestHeaderMatchesWriters(t *testing.T) {
	var plain bytes.Buffer
	if err := writeRequest(&plain, commandTCP, earlyTestDest); err != nil {
		t.Fatal(err)
	}
	built, err := buildRequestHeader(false, commandTCP, earlyTestDest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built, plain.Bytes()) {
		t.Fatalf("v1: built %x, writer %x", built, plain.Bytes())
	}

	var plainV2 bytes.Buffer
	if err := writeRequestV2(&plainV2, commandUDP, earlyTestDestUDP, testFECFlagRequest); err != nil {
		t.Fatal(err)
	}
	builtV2, err := buildRequestHeader(true, commandUDP, earlyTestDestUDP, testFECFlagRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(builtV2, plainV2.Bytes()) {
		t.Fatalf("v2: built %x, writer %x", builtV2, plainV2.Bytes())
	}
}

func TestSealedRequestRoundTrip(t *testing.T) {
	for _, fecEnabled := range []bool{false, true} {
		command := byte(commandTCP)
		destination := earlyTestDest
		if fecEnabled {
			command = commandUDP
			destination = earlyTestDestUDP
		}
		header, err := buildRequestHeader(fecEnabled, command, destination, testFECFlagRequest)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sealRequest(earlyTestProofKey, header)
		if err != nil {
			t.Fatal(err)
		}
		if sealed[0] != sealedRequestMarker {
			t.Fatalf("sealed form must start with the marker byte, got %#x", sealed[0])
		}
		version, gotCommand, flags, gotDest, err := readRequestAuto(bytes.NewReader(sealed), earlyTestProofKey, nil, nil)
		if err != nil {
			t.Fatalf("fec=%v: readRequestAuto: %v", fecEnabled, err)
		}
		if gotCommand != command || gotDest != destination {
			t.Fatalf("fec=%v: got command %d dest %v", fecEnabled, gotCommand, gotDest)
		}
		if fecEnabled {
			if version != framingVersion2 || flags != testFECFlagRequest {
				t.Fatalf("v2: version %d flags %d", version, flags)
			}
		} else {
			if version != framingVersion || flags != 0 {
				t.Fatalf("v1: version %d flags %d", version, flags)
			}
		}
		// Opened with the raw helper, the plaintext must be the header.
		body := sealed[3:]
		opened, err := openSealedRequest(earlyTestProofKey, body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened, header) {
			t.Fatalf("opened %x, want header %x", opened, header)
		}
	}
}

// A tampered sealed request must fail AEAD verification: the server
// treats this exactly like a failed post-auth request and closes,
// it never falls back to forwarding (the connection was already
// authenticated at the TLS layer before the header is read).
func TestSealedRequestTampered(t *testing.T) {
	header, err := buildRequestHeader(true, commandTCP, earlyTestDest, testFECFlagRequest)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealRequest(earlyTestProofKey, header)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"ciphertext byte flipped": func(b []byte) []byte {
			b[len(b)-1] ^= 0x01
			return b
		},
		"nonce byte flipped": func(b []byte) []byte {
			b[3] ^= 0x80 // first nonce byte, after marker+length
			return b
		},
		"auth tag truncated": func(b []byte) []byte {
			return b[:len(b)-4]
		},
		"body too short": func(b []byte) []byte {
			return b[:8]
		},
	}
	for name, mutate := range cases {
		tampered := mutate(append([]byte(nil), sealed...))
		if _, _, _, _, err := readRequestAuto(bytes.NewReader(tampered), earlyTestProofKey, nil, nil); err == nil {
			t.Fatalf("%s: readRequestAuto accepted a tampered sealed request", name)
		}
	}
	// A server holding a different session's proof key (e.g. an
	// impostor that terminated TLS) cannot open the request either.
	if _, _, _, _, err := readRequestAuto(bytes.NewReader(sealed), earlyTestWrongKey, nil, nil); err == nil {
		t.Fatal("readRequestAuto accepted a sealed request under the wrong proof key")
	}
	if _, err := openSealedRequest(earlyTestWrongKey, sealed[3:]); err == nil {
		t.Fatal("openSealedRequest accepted the wrong proof key")
	}
}

// Plain headers pass readRequestAuto untouched: an early-enabled
// server keeps serving stock clients, byte for byte.
func TestReadRequestAutoPlainPassthrough(t *testing.T) {
	var v1 bytes.Buffer
	if err := writeRequest(&v1, commandTCP, earlyTestDest); err != nil {
		t.Fatal(err)
	}
	version, command, flags, dest, err := readRequestAuto(bytes.NewReader(v1.Bytes()), earlyTestProofKey, nil, nil)
	if err != nil {
		t.Fatal("v1 plain:", err)
	}
	if version != framingVersion || command != commandTCP || flags != 0 || dest != earlyTestDest {
		t.Fatalf("v1 plain: got v%d cmd %d flags %d dest %v", version, command, flags, dest)
	}

	var v2 bytes.Buffer
	if err := writeRequestV2(&v2, commandUDP, earlyTestDestUDP, testFECFlagRequest); err != nil {
		t.Fatal(err)
	}
	version, command, flags, dest, err = readRequestAuto(bytes.NewReader(v2.Bytes()), earlyTestProofKey, nil, nil)
	if err != nil {
		t.Fatal("v2 plain:", err)
	}
	if version != framingVersion2 || command != commandUDP || flags != testFECFlagRequest || dest != earlyTestDestUDP {
		t.Fatalf("v2 plain: got v%d cmd %d flags %d dest %v", version, command, flags, dest)
	}
}

// The stock server's reader must reject a sealed request exactly
// like any other malformed header (unsupported framing version) -
// this is what an early client sees when the peer has the option
// off, and it happens after authentication, on the authenticated
// path only.
func TestStockReaderRejectsSealedRequest(t *testing.T) {
	header, err := buildRequestHeader(false, commandTCP, earlyTestDest, 0)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealRequest(earlyTestProofKey, header)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := readRequest(bytes.NewReader(sealed)); err == nil {
		t.Fatal("stock readRequest accepted a sealed request")
	}
}

// Sealing is non-deterministic (random nonce) and self-delimiting:
// two seals of the same header differ, and readRequestAuto consumes
// exactly one sealed header, leaving following bytes (the data
// plane) untouched.
func TestSealedRequestStreamBoundary(t *testing.T) {
	header, err := buildRequestHeader(false, commandTCP, earlyTestDest, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, err := sealRequest(earlyTestProofKey, header)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealRequest(earlyTestProofKey, header)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two seals of the same header are identical; nonce is not random")
	}
	tail := []byte("first-data-plane-bytes")
	stream := append(append([]byte(nil), first...), tail...)
	reader := bytes.NewReader(stream)
	if _, _, _, _, err := readRequestAuto(reader, earlyTestProofKey, nil, nil); err != nil {
		t.Fatal(err)
	}
	rest := make([]byte, reader.Len())
	if _, err := reader.Read(rest); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, tail) {
		t.Fatalf("stream boundary: leftover %q, want %q", rest, tail)
	}
}
