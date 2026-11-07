package musess

// Speculative transport (direction 5 prototype): three independently
// switchable pieces, all default-off, all fail-closed to the plain
// authenticated path.
//
//  1. Warm pool (client): pre-established sessions, handshake +
//     server-proof verification done, request NOT yet sent. A request
//     checks one out and only then sends its (destination-bearing)
//     request header. Idle sessions expire and are closed.
//  2. Safe 0-RTT (both peers): one frame per session carrying ONLY
//     non-authenticated transport-recovery data. The frame is sealed
//     under a key derived from the TLS exporter (session-bound, no
//     user secret involved), carries a one-time nonce, and the server
//     applies its payload only when the nonce is fresh. A replayed,
//     corrupt, or stale frame is discarded and the session proceeds
//     as an ordinary authenticated session: the frame can never
//     authenticate, route, or serve a request.
//  3. Racing (client): dial the primary and alternate endpoints for
//     the same server in parallel; first session to finish handshake
//     + proof wins, losers are closed at once. Wasted bytes are
//     counted on the losing legs.
//
// None of the three touches the ClientHello, the auth token, the
// server proof, the fallback byte-forward, or the framing versions:
// with all three off the wire behaviour is byte-identical to M1.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// ---------------------------------------------------------------------------
// 0-RTT frame
// ---------------------------------------------------------------------------

// zeroRTTMarker is the first byte of a 0-RTT frame on the authenticated
// TLS stream. It collides with no framing version (0x01/0x02) and no
// sealed-request marker (0x00), so readRequestAuto can dispatch on it.
const zeroRTTMarker = 0x03

const (
	zeroRTTNonceLength = 16
	// zeroRTTWindow bounds how long a nonce stays in the seen-set.
	zeroRTTWindow = 120 * time.Second
	// zeroRTTMaxBody caps the sealed frame body (nonce + ciphertext).
	zeroRTTMaxBody = 512
)

// zeroRTTPayload is the (non-authenticated) transport-recovery data a
// 0-RTT frame may carry. Deliberately tiny and opaque: it holds no
// identity, no secret, no destination, and no request — only hints a
// server may use to restore transport state (here: the FEC mode the
// client prefers and a spare byte for future hints). The server MUST
// NOT let it influence authentication or routing.
type zeroRTTPayload struct {
	// FECModeHint mirrors the client's configured FEC mode at the
	// time the frame was built (0 = off, 1 = auto, 2 = on). A
	// hint only: the real FEC negotiation still happens through
	// the authenticated request header.
	FECModeHint byte
	Reserved    byte
}

func (p zeroRTTPayload) encode() []byte { return []byte{p.FECModeHint, p.Reserved} }

func decodeZeroRTTPayload(body []byte) (zeroRTTPayload, error) {
	if len(body) != 2 {
		return zeroRTTPayload{}, errors.New("musess: 0-RTT payload has wrong length")
	}
	return zeroRTTPayload{FECModeHint: body[0], Reserved: body[1]}, nil
}

// zeroRTTKey derives the frame key from the TLS exporter. The exporter
// is bound to this TLS session and known only to its two endpoints, so
// the frame is confidential to the session — but the key involves no
// user secret and no auth token, so decrypting a frame proves nothing
// about who the peer is.
func zeroRTTKey(exporter []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, exporter, nil, "musess zero-rtt key", 32)
}

// sealZeroRTTFrame renders one 0-RTT frame: [marker][2-byte length]
// [16-byte one-time nonce][12-byte GCM nonce][AES-256-GCM
// ciphertext of the payload]. The one-time nonce is the replay
// identity; the GCM nonce is separate (GCM wants 12 bytes) and
// random per frame.
func sealZeroRTTFrame(exporter []byte, payload zeroRTTPayload) ([]byte, []byte, error) {
	key, err := zeroRTTKey(exporter)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, zeroRTTNonceLength)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	gcmNonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(gcmNonce); err != nil {
		return nil, nil, err
	}
	body := make([]byte, 0, len(nonce)+len(gcmNonce)+len(payload.encode())+gcm.Overhead())
	body = append(body, nonce...)
	body = append(body, gcmNonce...)
	body = gcm.Seal(body, gcmNonce, payload.encode(), nil)
	out := make([]byte, 0, 3+len(body))
	out = append(out, zeroRTTMarker)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(body)))
	out = append(out, length[:]...)
	out = append(out, body...)
	return out, nonce, nil
}

// openZeroRTTFrame decrypts a frame body (nonce + ciphertext) and
// returns the nonce and payload. It authenticates the frame to the
// TLS session (via the exporter key) but says nothing about the peer.
func openZeroRTTFrame(exporter, body []byte) ([]byte, zeroRTTPayload, error) {
	if len(body) < zeroRTTNonceLength+12 {
		return nil, zeroRTTPayload{}, errors.New("musess: 0-RTT frame too short")
	}
	key, err := zeroRTTKey(exporter)
	if err != nil {
		return nil, zeroRTTPayload{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, zeroRTTPayload{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, zeroRTTPayload{}, err
	}
	nonce := body[:zeroRTTNonceLength]
	gcmNonce := body[zeroRTTNonceLength : zeroRTTNonceLength+gcm.NonceSize()]
	plain, err := gcm.Open(nil, gcmNonce, body[zeroRTTNonceLength+gcm.NonceSize():], nil)
	if err != nil {
		return nil, zeroRTTPayload{}, err
	}
	payload, err := decodeZeroRTTPayload(plain)
	if err != nil {
		return nil, zeroRTTPayload{}, err
	}
	return nonce, payload, nil
}

// zeroRTTRegistry is the server-side one-time-nonce store. A nonce
// that verifies (decrypts) but was already seen is a replay: the
// caller must treat the frame as if it had never arrived.
type zeroRTTRegistry struct {
	mutex sync.Mutex
	seen  map[[zeroRTTNonceLength]byte]time.Time
}

func newZeroRTTRegistry() *zeroRTTRegistry {
	return &zeroRTTRegistry{seen: make(map[[zeroRTTNonceLength]byte]time.Time)}
}

// checkAndInsert reports whether nonce is fresh (and records it).
func (r *zeroRTTRegistry) checkAndInsert(nonce []byte, now time.Time) bool {
	if len(nonce) != zeroRTTNonceLength {
		return false
	}
	var key [zeroRTTNonceLength]byte
	copy(key[:], nonce)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(r.seen) > 4096 {
		for k, exp := range r.seen {
			if exp.Before(now) {
				delete(r.seen, k)
			}
		}
	}
	if exp, ok := r.seen[key]; ok && exp.After(now) {
		return false
	}
	r.seen[key] = now.Add(zeroRTTWindow)
	return true
}

// zeroRTTServer is the inbound's 0-RTT state: the nonce registry plus
// counters. AcceptFrame decrypts one frame body and, only for a fresh
// nonce, returns its payload; every other outcome reports
// "no usable 0-RTT data" and the caller carries on with the normal
// authenticated request as if nothing had been sent.
type zeroRTTServer struct {
	registry *zeroRTTRegistry
	accepted atomic.Int64
	replayed atomic.Int64
	invalid  atomic.Int64
	// apply, when false, means the transport state is recorded but
	// not acted on (server zero_rtt option off). The frame is
	// still parsed and its nonce still consumed, so behaviour is
	// identical from the client's point of view.
	apply bool
}

func newZeroRTTServer(apply bool) *zeroRTTServer {
	return &zeroRTTServer{registry: newZeroRTTRegistry(), apply: apply}
}

// AcceptFrame returns (payload, fresh, applied). fresh=false means the
// frame carried nothing usable (replay, corrupt, or wrong length);
// the session must continue exactly like a session without 0-RTT.
func (s *zeroRTTServer) AcceptFrame(exporter, body []byte) (zeroRTTPayload, bool, bool) {
	nonce, payload, err := openZeroRTTFrame(exporter, body)
	if err != nil {
		s.invalid.Add(1)
		return zeroRTTPayload{}, false, false
	}
	if !s.registry.checkAndInsert(nonce, time.Now()) {
		s.replayed.Add(1)
		return zeroRTTPayload{}, false, false
	}
	s.accepted.Add(1)
	return payload, true, s.apply
}

// ---------------------------------------------------------------------------
// Warm pool (client)
// ---------------------------------------------------------------------------

// warmSession is a musess session that has completed the TLS handshake
// and server-proof verification, but has not sent any request yet.
// proofKey is retained so checkout can seal an early request; the
// exporter is retained so checkout can seal a 0-RTT frame; raw is the
// underlying TCP connection (the TLS conn wraps it) so checkout can
// hand it to the deshell client wrapper when the server agrees to
// deshell on a pooled session.
type warmSession struct {
	conn      net.Conn
	raw       net.Conn
	proofKey  []byte
	exporter  []byte
	createdAt time.Time
}

// warmPoolStats is the observable pool behaviour, for tests and logs.
type warmPoolStats struct {
	Hits      int64
	Misses    int64
	Establish int64 // sessions successfully established (warmup + refill)
	Expired   int64 // pooled sessions closed idle-expired
	Closed    int64 // pooled sessions closed because the pool was full
}

// warmPool keeps up to max pre-established sessions. It is safe for
// concurrent use. The warmer goroutine is started by Start and stops
// when ctx ends.
type warmPool struct {
	mutex   sync.Mutex
	max     int
	idleTTL time.Duration
	items   []*warmSession
	// inflight counts establishes currently running (parallel
	// refill): topUp never starts more than the pool is short,
	// so a slow or dead server cannot pile up goroutines tick
	// after tick.
	inflight int
	stats    warmPoolStats
	statsMu  sync.Mutex

	establish func(ctx context.Context) (*warmSession, error)
	logger    logger.ContextLogger

	// ctx is the service ctx from Start: checkout-triggered refills
	// run under it. Nil when the warmer was never started (tests).
	ctx context.Context

	startOnce sync.Once
}

func newWarmPool(max int, idleTTL time.Duration, establish func(ctx context.Context) (*warmSession, error), log logger.ContextLogger) *warmPool {
	if idleTTL <= 0 {
		idleTTL = 10 * time.Second
	}
	return &warmPool{max: max, idleTTL: idleTTL, establish: establish, logger: log}
}

// Start launches the background warmer, which tops the pool up to max.
// It is idempotent; ctx cancellation stops the loop.
func (p *warmPool) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		p.ctx = ctx
		go p.warmer(ctx)
	})
}

func (p *warmPool) warmer(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.drain()
			return
		case <-ticker.C:
			p.topUp(ctx)
		}
	}
}

// topUp refills the pool up to max, establishing every missing
// session in parallel (merge-time fix for the prototype's serial
// refill: one session per 200 ms tick could not keep up with
// request rates at low RTT — delay25 p95 never improved — because
// each establish takes ~one handshake RTT. Parallel refill matches
// the refill rate to the consumption rate; put() still closes any
// surplus if the pool fills meanwhile, and the inflight cap keeps
// a slow or dead server from piling up goroutines tick after tick.
// One burst of handshakes per tick is bounded by the pool size
// (2 as tested), not by the tick count.
func (p *warmPool) topUp(ctx context.Context) {
	p.mutex.Lock()
	need := p.max - len(p.items) - p.inflight
	p.mutex.Unlock()
	if need <= 0 {
		return
	}
	for i := 0; i < need; i++ {
		p.mutex.Lock()
		p.inflight++
		p.mutex.Unlock()
		go func() {
			defer func() {
				p.mutex.Lock()
				p.inflight--
				p.mutex.Unlock()
			}()
			session, err := p.establish(ctx)
			if err != nil {
				return
			}
			p.bumpEstablish()
			p.put(session)
		}()
	}
}

// get returns a live pooled session, or nil. Expired sessions found
// on the way are closed and counted.
func (p *warmPool) get() *warmSession {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := time.Now()
	for len(p.items) > 0 {
		last := p.items[len(p.items)-1]
		p.items = p.items[:len(p.items)-1]
		if now.Sub(last.createdAt) > p.idleTTL {
			last.conn.Close()
			p.bumpExpired()
			continue
		}
		p.bumpHit()
		// Refill eagerly on checkout: waiting for the next 200 ms
		// tick would leave the pool short for a whole tick, which
		// is what produced the delay25 p95 tail even after the
		// refill went parallel. topUp is capped by the inflight
		// count, so a refill already running is not duplicated;
		// the goroutine blocks on the pool mutex until this get
		// returns, so no lock is held across the spawn.
		if p.ctx != nil {
			go p.topUp(p.ctx)
		}
		return last
	}
	p.bumpMiss()
	return nil
}

// put stores a fresh session, or closes it if the pool is full or
// the session is already stale.
func (p *warmPool) put(session *warmSession) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.items) >= p.max || time.Since(session.createdAt) > p.idleTTL {
		session.conn.Close()
		p.bumpClosed()
		return
	}
	p.items = append(p.items, session)
}

// drain closes every pooled session (shutdown path).
func (p *warmPool) drain() {
	p.mutex.Lock()
	items := p.items
	p.items = nil
	p.mutex.Unlock()
	for _, item := range items {
		item.conn.Close()
	}
}

// bump helpers keep the stats lock separate from the pool lock so a
// stats snapshot never blocks checkout.
func (p *warmPool) bumpHit()     { p.statsMu.Lock(); p.stats.Hits++; p.statsMu.Unlock() }
func (p *warmPool) bumpMiss()    { p.statsMu.Lock(); p.stats.Misses++; p.statsMu.Unlock() }
func (p *warmPool) bumpExpired() { p.statsMu.Lock(); p.stats.Expired++; p.statsMu.Unlock() }
func (p *warmPool) bumpClosed()  { p.statsMu.Lock(); p.stats.Closed++; p.statsMu.Unlock() }
func (p *warmPool) bumpEstablish() {
	p.statsMu.Lock()
	p.stats.Establish++
	p.statsMu.Unlock()
}

// Stats returns a copy of the pool counters.
func (p *warmPool) Stats() warmPoolStats {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	return p.stats
}

// ---------------------------------------------------------------------------
// Racing (client)
// ---------------------------------------------------------------------------

// countingConn wraps a raw TCP connection and counts bytes written and
// read. It exists so a racing leg can report exactly how many bytes a
// losing leg wasted.
type countingConn struct {
	net.Conn
	written atomic.Int64
	read    atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// WastedBytes is the total bytes moved on this connection.
func (c *countingConn) WastedBytes() int64 {
	return c.written.Load() + c.read.Load()
}

// raceStats counts what racing cost. A losing leg's bytes are waste:
// the winner's bytes are the useful handshake, the losers' are not.
type raceStats struct {
	Races       int64 // dials that raced (>= 2 legs)
	WonByFirst  int64 // races where the primary leg won
	WonByAlt    int64 // races where an alternate leg won
	WastedBytes int64 // total bytes on losing legs
}

var globalRaceStats raceStats

// RaceStats returns a copy of the process-wide race counters (the
// outbound has one instance per config, but the counters are cheap
// to keep global so tests and logs read them without plumbing).
func RaceStats() raceStats {
	return raceStats{
		Races:       atomic.LoadInt64(&globalRaceStats.Races),
		WonByFirst:  atomic.LoadInt64(&globalRaceStats.WonByFirst),
		WonByAlt:    atomic.LoadInt64(&globalRaceStats.WonByAlt),
		WastedBytes: atomic.LoadInt64(&globalRaceStats.WastedBytes),
	}
}

// ResetRaceStats zeroes the process-wide race counters. Tests only.
func ResetRaceStats() {
	atomic.StoreInt64(&globalRaceStats.Races, 0)
	atomic.StoreInt64(&globalRaceStats.WonByFirst, 0)
	atomic.StoreInt64(&globalRaceStats.WonByAlt, 0)
	atomic.StoreInt64(&globalRaceStats.WastedBytes, 0)
}
