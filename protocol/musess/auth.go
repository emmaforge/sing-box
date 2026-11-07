package musess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Authentication design (milestone 1, TCP/TLS path of DESIGN.md ch. 4):
//
// The client hides a 32-byte authentication token in the TLS 1.3
// ClientHello's legacy_session_id, a field that in compatibility mode
// normally carries 32 random bytes:
//
//	[0:4]   unix timestamp, big-endian
//	[4:8]   user hint: first 4 bytes of SHA-256(user uuid)
//	[8:32]  tag: first 24 bytes of HMAC-SHA-256(authKey, transcript)
//
// The tag is computed over the canonical handshake transcript (see
// ClientHelloFields.TranscriptHash), so it is bound to this specific
// handshake: copying the session ID into a different ClientHello does
// not verify. Verbatim replay of the whole ClientHello is caught by
// the timestamp window (+-120s per DESIGN.md 4.3) plus a replay cache:
// a token that verifies but was already seen is treated exactly like
// an unauthenticated connection (forwarded to the destination), never
// errored or dropped differently.
//
// authKey is derived from an X25519 exchange with the server's static
// key, using the private key of the TLS session's own X25519 key share
// (the share the parroted ClientHello already carries; uTLS exposes it
// via HandshakeState.State13.KeyShareKeys.Ecdhe, see outbound
// dialStream). No extra share is added to the hello — this is placement
// P1, chosen on measurement (see impl/README.md): the shipped hello is
// structurally identical to a stock Chrome parrot. The server verifies
// the tag against that same session share. The user's secret is mixed
// into the key derivation, so possessing the server public key alone is
// not enough to forge a tag.

const (
	sessionIDLength  = 32
	tagLength        = 24
	authWindow       = 120 * time.Second
	replayGraceExtra = 60 * time.Second
	groupX25519      = 29
)

type userEntry struct {
	name   string
	uuid   string
	secret string
	hint   [4]byte
}

func makeUserEntry(name, uuid, secret string) userEntry {
	id := uuid
	if id == "" {
		id = name
	}
	sum := sha256.Sum256([]byte(id))
	var hint [4]byte
	copy(hint[:], sum[:4])
	return userEntry{name: name, uuid: uuid, secret: secret, hint: hint}
}

// deriveKeys mixes the ECDH shared secret with the user's secret.
func deriveKeys(shared []byte, secret string) (authKey, proofKey []byte, err error) {
	secretHash := sha256.Sum256([]byte(secret))
	ikm := make([]byte, 0, len(shared)+sha256.Size)
	ikm = append(ikm, shared...)
	ikm = append(ikm, secretHash[:]...)
	authKey, err = hkdf.Key(sha256.New, ikm, []byte("musess-v1"), "musess auth key", 32)
	if err != nil {
		return nil, nil, err
	}
	proofKey, err = hkdf.Key(sha256.New, ikm, []byte("musess-v1"), "musess proof key", 32)
	if err != nil {
		return nil, nil, err
	}
	return authKey, proofKey, nil
}

func computeTag(authKey []byte, transcript [32]byte, timestamp uint32, hint [4]byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(transcript[:])
	var ts [4]byte
	binary.BigEndian.PutUint32(ts[:], timestamp)
	mac.Write(ts[:])
	mac.Write(hint[:])
	return mac.Sum(nil)[:tagLength]
}

// ClientSessionAuth holds everything the outbound needs to build an
// authenticated ClientHello and to verify the server's proof.
type ClientSessionAuth struct {
	authKey  []byte
	proofKey []byte
	userHint [4]byte
}

// NewClientSessionAuth performs the client side of the key agreement:
// ephemeralPrivate is the private key of the TLS session's own X25519
// key share (NOT an extra share added to the hello).
func NewClientSessionAuth(serverPublic *ecdh.PublicKey, ephemeralPrivate *ecdh.PrivateKey, uuid, secret string) (*ClientSessionAuth, error) {
	shared, err := ephemeralPrivate.ECDH(serverPublic)
	if err != nil {
		return nil, err
	}
	authKey, proofKey, err := deriveKeys(shared, secret)
	if err != nil {
		return nil, err
	}
	return &ClientSessionAuth{
		authKey:  authKey,
		proofKey: proofKey,
		userHint: makeUserEntry("", uuid, secret).hint,
	}, nil
}

// SessionID builds the 32-byte legacy_session_id for a ClientHello with
// the given parsed fields (whose own SessionID field is ignored).
func (a *ClientSessionAuth) SessionID(fields *ClientHelloFields, now time.Time) []byte {
	timestamp := uint32(now.Unix())
	transcript := fields.TranscriptHash()
	tag := computeTag(a.authKey, transcript, timestamp, a.userHint)
	sessionID := make([]byte, sessionIDLength)
	binary.BigEndian.PutUint32(sessionID[0:4], timestamp)
	copy(sessionID[4:8], a.userHint[:])
	copy(sessionID[8:32], tag)
	return sessionID
}

// ServerProof computes the post-handshake proof the server sends as the
// first data-plane bytes: it binds the server's static X25519 key to
// this specific TLS session via the TLS exporter.
func ServerProof(proofKey, exporter []byte) []byte {
	mac := hmac.New(sha256.New, proofKey)
	mac.Write([]byte("musess server proof"))
	mac.Write(exporter)
	return mac.Sum(nil)
}

// VerifyServerProof checks a received server proof.
func (a *ClientSessionAuth) VerifyServerProof(proof, exporter []byte) bool {
	expected := ServerProof(a.proofKey, exporter)
	return subtle.ConstantTimeCompare(proof, expected) == 1
}

// --- Early (pipelined) request sealing -------------------------------------
//
// Rate-attack phase 1 diagnosed the stock flow's connection-setup
// cost: it serialises two application flights after the TLS
// handshake (server proof -> client request), each costing a full
// leg RTT before the first data byte can flow. With early_request
// enabled on both peers the client instead sends its request header
// immediately after the handshake, AEAD-sealed under a key derived
// from the session proof key, and verifies the server proof when it
// arrives (the proof still precedes any relayed data in the
// server->client stream, so the client never consumes data from an
// unproven server). Sealing keeps the request's destination
// confidential even if the TLS session were terminated by an
// impostor: without the musess session keys the header is opaque.
// Wire form:
//
//	[0x00][2-byte big-endian length][12-byte nonce][AES-256-GCM ct]
//
// The leading 0x00 is not a valid framing version, so a server with
// early_request enabled can auto-detect sealed vs plain requests;
// a server without it rejects the stream exactly like any other
// malformed header (post-authentication path only).

const sealedRequestMarker = 0x00

func deriveRequestKey(proofKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, proofKey, nil, "musess early request key", 32)
}

func sealRequest(proofKey, header []byte) ([]byte, error) {
	key, err := deriveRequestKey(proofKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(nonce)+len(header)+gcm.Overhead())
	body = append(body, nonce...)
	body = gcm.Seal(body, nonce, header, nil)
	out := make([]byte, 0, 3+len(body))
	out = append(out, sealedRequestMarker)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(body)))
	out = append(out, length[:]...)
	out = append(out, body...)
	return out, nil
}

func openSealedRequest(proofKey, body []byte) ([]byte, error) {
	key, err := deriveRequestKey(proofKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if len(body) < gcm.NonceSize() {
		return nil, errors.New("musess: sealed request too short")
	}
	return gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], nil)
}

// replayCache remembers accepted session IDs until their window ends.
type replayCache struct {
	mutex sync.Mutex
	seen  map[[sessionIDLength]byte]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[[sessionIDLength]byte]time.Time)}
}

// checkAndInsert reports whether sid is fresh (and records it).
func (c *replayCache) checkAndInsert(sid [sessionIDLength]byte, expiry time.Time, now time.Time) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if len(c.seen) > 4096 {
		for key, exp := range c.seen {
			if exp.Before(now) {
				delete(c.seen, key)
			}
		}
	}
	if exp, ok := c.seen[sid]; ok && exp.After(now) {
		return false
	}
	c.seen[sid] = expiry
	return true
}

type verifiedAuth struct {
	user     userEntry
	proofKey []byte
}

// verifyClientHello checks the auth token in a parsed ClientHello.
// It returns nil for every failure mode alike; the caller must treat
// nil as "unauthenticated" and forward the connection untouched.
func verifyClientHello(fields *ClientHelloFields, users []userEntry, serverPrivate *ecdh.PrivateKey, cache *replayCache, now time.Time) *verifiedAuth {
	if len(fields.SessionID) != sessionIDLength {
		return nil
	}
	timestamp := binary.BigEndian.Uint32(fields.SessionID[0:4])
	tagTime := time.Unix(int64(timestamp), 0)
	if tagTime.Before(now.Add(-authWindow)) || tagTime.After(now.Add(authWindow)) {
		return nil
	}
	var hint [4]byte
	copy(hint[:], fields.SessionID[4:8])
	tag := fields.SessionID[8:32]
	transcript := fields.TranscriptHash()
	for _, user := range users {
		if user.hint != hint {
			continue
		}
		for _, share := range fields.KeyShares {
			if share.Group != groupX25519 || len(share.Data) != 32 {
				continue
			}
			publicKey, err := ecdh.X25519().NewPublicKey(share.Data)
			if err != nil {
				continue
			}
			shared, err := serverPrivate.ECDH(publicKey)
			if err != nil {
				continue
			}
			authKey, proofKey, err := deriveKeys(shared, user.secret)
			if err != nil {
				continue
			}
			expected := computeTag(authKey, transcript, timestamp, hint)
			if subtle.ConstantTimeCompare(tag, expected) != 1 {
				continue
			}
			var sid [sessionIDLength]byte
			copy(sid[:], fields.SessionID)
			expiry := tagTime.Add(authWindow + replayGraceExtra)
			if !cache.checkAndInsert(sid, expiry, now) {
				return nil // replay: treated as unauthenticated
			}
			return &verifiedAuth{user: user, proofKey: proofKey}
		}
	}
	return nil
}

// ParsePrivateKey decodes a base64-encoded 32-byte X25519 private key.
func ParsePrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	raw, err := decodeBase64Key(encoded)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// ParsePublicKey decodes a base64-encoded 32-byte X25519 public key.
func ParsePublicKey(encoded string) (*ecdh.PublicKey, error) {
	raw, err := decodeBase64Key(encoded)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

func decodeBase64Key(encoded string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		raw, err := enc.DecodeString(encoded)
		if err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	return nil, errors.New("musess: key must be base64-encoded 32 bytes")
}
