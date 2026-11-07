package musess

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// This file implements just enough TLS record / ClientHello parsing for
// musess authentication: the inbound peeks at the first ClientHello to
// decide between local termination (authenticated) and byte-forwarding
// to the real destination (everything else). The parser is deliberately
// shared by the client (which parses its own marshaled ClientHello to
// compute the auth tag) and the server (which parses the wire bytes), so
// both sides always derive byte-identical canonical transcripts.

const (
	tlsRecordHandshake = 22
	tlsHandshakeClientHello = 1
	maxClientHelloBytes = 64 * 1024
)

// KeyShareEntry is one entry of the key_share extension.
type KeyShareEntry struct {
	Group uint16
	Data  []byte
}

// ClientHelloFields carries the parsed fields musess cares about.
type ClientHelloFields struct {
	Random           []byte
	SessionID        []byte
	CipherSuites     []byte // raw suite list bytes (2 bytes per suite)
	SupportedVersions []byte // raw version list bytes (2 bytes per version)
	ServerName       string
	KeyShares        []KeyShareEntry
}

// ReadClientHello reads TLS records from r until one full ClientHello
// handshake message has been reassembled. It returns the raw record
// bytes (exactly as read, for byte-forwarding) together with the parsed
// fields. If the stream does not start with a well-formed ClientHello,
// err is non-nil and raw contains whatever was read before failing;
// callers must treat the connection as unauthenticated either way.
func ReadClientHello(r *bufio.Reader) (raw []byte, fields *ClientHelloFields, err error) {
	var handshake bytes.Buffer
	for {
		header := make([]byte, 5)
		if _, err = io.ReadFull(r, header); err != nil {
			return raw, nil, err
		}
		raw = append(raw, header...)
		if header[0] != tlsRecordHandshake {
			return raw, nil, errors.New("musess: not a handshake record")
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength <= 0 || len(raw)+recordLength > maxClientHelloBytes {
			return raw, nil, errors.New("musess: bad record length")
		}
		payload := make([]byte, recordLength)
		if _, err = io.ReadFull(r, payload); err != nil {
			return raw, nil, err
		}
		raw = append(raw, payload...)
		handshake.Write(payload)
		if handshake.Len() >= 4 {
			hsLength := int(handshake.Bytes()[1])<<16 | int(handshake.Bytes()[2])<<8 | int(handshake.Bytes()[3])
			if handshake.Len() >= 4+hsLength {
				break
			}
		}
		if len(raw) > maxClientHelloBytes {
			return raw, nil, errors.New("musess: client hello too large")
		}
	}
	fields, err = ParseClientHello(handshake.Bytes())
	if err != nil {
		return raw, nil, err
	}
	return raw, fields, nil
}

// ParseClientHello parses a full handshake message (type + length +
// body) as produced by a TLS client.
func ParseClientHello(hs []byte) (*ClientHelloFields, error) {
	if len(hs) < 4 || hs[0] != tlsHandshakeClientHello {
		return nil, errors.New("musess: not a client hello")
	}
	bodyLength := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+bodyLength {
		return nil, errors.New("musess: truncated client hello")
	}
	body := hs[4 : 4+bodyLength]
	pos := 0
	take := func(n int) ([]byte, error) {
		if pos+n > len(body) {
			return nil, errors.New("musess: truncated client hello body")
		}
		b := body[pos : pos+n]
		pos += n
		return b, nil
	}
	fields := &ClientHelloFields{}
	if _, err := take(2); err != nil { // legacy version
		return nil, err
	}
	random, err := take(32)
	if err != nil {
		return nil, err
	}
	fields.Random = random
	sessionIDLength, err := take(1)
	if err != nil {
		return nil, err
	}
	sessionID, err := take(int(sessionIDLength[0]))
	if err != nil {
		return nil, err
	}
	fields.SessionID = sessionID
	suitesLengthBytes, err := take(2)
	if err != nil {
		return nil, err
	}
	suites, err := take(int(binary.BigEndian.Uint16(suitesLengthBytes)))
	if err != nil {
		return nil, err
	}
	fields.CipherSuites = suites
	compressionLength, err := take(1)
	if err != nil {
		return nil, err
	}
	if _, err := take(int(compressionLength[0])); err != nil {
		return nil, err
	}
	if pos == len(body) {
		return fields, nil // no extensions
	}
	extensionsLengthBytes, err := take(2)
	if err != nil {
		return nil, err
	}
	extensions, err := take(int(binary.BigEndian.Uint16(extensionsLengthBytes)))
	if err != nil {
		return nil, err
	}
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		if 4+extLength > len(extensions) {
			return nil, errors.New("musess: truncated extension")
		}
		data := extensions[4 : 4+extLength]
		extensions = extensions[4+extLength:]
		switch extType {
		case 0: // server_name
			if name, ok := parseServerName(data); ok {
				fields.ServerName = name
			}
		case 43: // supported_versions
			if len(data) >= 1 {
				listLength := int(data[0])
				if 1+listLength <= len(data) {
					fields.SupportedVersions = data[1 : 1+listLength]
				}
			}
		case 51: // key_share
			shares, err := parseKeyShares(data)
			if err != nil {
				return nil, err
			}
			fields.KeyShares = shares
		}
	}
	return fields, nil
}

func parseServerName(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLength < len(data) {
		data = data[:listLength]
	}
	for len(data) >= 3 {
		nameType := data[0]
		nameLength := int(binary.BigEndian.Uint16(data[1:3]))
		if 3+nameLength > len(data) {
			return "", false
		}
		if nameType == 0 {
			return string(data[3 : 3+nameLength]), true
		}
		data = data[3+nameLength:]
	}
	return "", false
}

func parseKeyShares(data []byte) ([]KeyShareEntry, error) {
	if len(data) < 2 {
		return nil, errors.New("musess: truncated key_share")
	}
	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLength < len(data) {
		data = data[:listLength]
	}
	var shares []KeyShareEntry
	for len(data) >= 4 {
		group := binary.BigEndian.Uint16(data[0:2])
		keyLength := int(binary.BigEndian.Uint16(data[2:4]))
		if 4+keyLength > len(data) {
			return nil, errors.New("musess: truncated key_share entry")
		}
		shares = append(shares, KeyShareEntry{Group: group, Data: data[4 : 4+keyLength]})
		data = data[4+keyLength:]
	}
	return shares, nil
}

// TranscriptHash hashes the canonical handshake transcript the auth tag
// binds to: the client's random, SNI, cipher suites, supported versions
// and key shares, in wire order. The session ID is deliberately excluded
// (the tag itself lives there); everything a replayer would have to
// change to make a *different* handshake is included, so a tag lifted
// into another handshake never verifies.
func (f *ClientHelloFields) TranscriptHash() [32]byte {
	h := sha256.New()
	writeField := func(b []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(b)))
		h.Write(length[:])
		h.Write(b)
	}
	h.Write([]byte("musess-transcript-v1"))
	writeField(f.Random)
	writeField([]byte(f.ServerName))
	writeField(f.CipherSuites)
	writeField(f.SupportedVersions)
	for _, share := range f.KeyShares {
		var group [2]byte
		binary.BigEndian.PutUint16(group[:], share.Group)
		writeField(append(group[:], share.Data...))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
