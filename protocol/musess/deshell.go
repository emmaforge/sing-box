// Direction 4 prototype: XTLS-Vision-style post-handshake "deshell"
// (zero-copy TCP fast path).
//
// Idea (BOLD-RETHINK.md direction 4): after the musess handshake and
// server proof, if the inner traffic is confirmed TLS 1.3, stop
// proxy-layer re-encryption and forward the raw TCP stream with the
// Linux kernel splice() that sing's bufio.Copy already performs when
// both ends of a copy expose a syscall.RawConn. The win is CPU (no
// AES-GCM decrypt + encrypt per byte, no userspace copy) and, on a
// fast link, goodput.
//
// How it works, and why the switch must happen mid-relay:
//   - The inner ClientHello does not exist until the application
//     writes it, which is after dialStream returns and the router
//     starts copying. So neither peer can decide before the relay
//     starts; the decision is made by the connection wrapper below,
//     while the first inner bytes flow through it.
//   - Negotiation is only capability: the client sets deshellFlag
//     (0x04) in the v2 request header; the server sets
//     deshellStatusFlag (0x02) in the v2 status byte when it is
//     willing and FEC is not active. Neither side switches on the
//     negotiation alone.
//   - Server side (read-driven): the wrapper inspects the first
//     inner record as it is read from the outer TLS stream. If it
//     is exactly one complete TLS 1.3 ClientHello record (strict
//     check in isTLS13ClientHello) and no bytes are stranded in the
//     inbound's peek reader, the wrapper writes the go-signal
//     (deshellMagic) through the outer TLS, then switches both
//     directions to the raw TCP socket. The ClientHello bytes
//     themselves are delivered to the copy loop first, so the
//     destination receives them before the spliced stream.
//   - Client side (signal-driven): the wrapper reads through the
//     outer TLS and watches for the go-signal. When it sees the
//     magic it discards it and switches both directions to the raw
//     TCP socket. Its Write side needs no inspection: a TLS client
//     cannot send anything after the ClientHello until the
//     ServerHello arrives, and the ServerHello only arrives after
//     the client has sent its post-switch ack (below), so by the
//     time the application writes again the Read side has already
//     switched.
//   - Post-switch ack (deshell ack v1; fixes the read-ahead race in
//     DESHELL-MERGE-REPORT.md §6): the client's go-signal read can
//     pull raw bytes that arrive right after the go-signal into the
//     TLS layer's internal buffer (crypto/tls reads up to 512 bytes
//     past the current record), where the raw read can never reach
//     them. On loopback the ServerHello arrives in the same batch
//     as the go-signal, so the switch strands it (~2% of loopback
//     handshakes, 10 s hang). The ack closes that window: the
//     server holds its first downstream raw bytes until the client
//     proves its TLS read-ahead has finished. Negotiation is by
//     version: the client advertises ack support in the v2 request
//     header (deshellAckFlag), the server requires the ack in the
//     v2 status byte (deshellAckStatusFlag). The client sends one
//     ack byte (0x01) on the raw socket immediately after switching;
//     the server consumes it on its upload Read path and releases
//     the held bytes. If no ack arrives within deshellAckTimeout
//     (2 s, longer than any realistic 1-RTT ack round trip) the
//     server releases anyway. An old server never sets
//     the status bit, so a new client sends no ack and behaves
//     exactly as before; an old client never advertises the flag,
//     so a new server never waits for its ack and pays no timeout.
//     The ack byte 0x01 can never start a TLS record (0x14/0x15/
//     0x16/0x17), so the server tells an ack apart from real inner
//     data by content -- a late ack is still consumed correctly,
//     and a non-ack first byte is delivered as data, never eaten.
//   - If the inner traffic is not TLS 1.3, or the go-signal never
//     comes, or the peek reader holds stranded bytes, nothing
//     switches and the connection runs fully encrypted exactly as
//     in milestone 1. Any doubt means NO deshell. A decline still
//     settles the handshake: the server resolves the
//     (never-to-arrive) ack and the client marks the decision
//     final, so NeedHandshakeForRead/Write close and the copy
//     loop leaves its handshake-pending mode for the normal
//     buffered TLS copy. Before this fix a decline left the
//     handshake open forever and the copy loop never settled,
//     costing ~40% goodput and ~2x CPU on declined connections
//     (idle-box full bench 2026-11-07). The raw socket stays
//     hidden (SyscallConn still fails while unswitched), so a
//     declined connection is never spliced raw.
//
// How the splice engages mid-stream: the wrapper implements
// N.EarlyReader / N.EarlyWriter. While the deshell decision is
// pending, NeedHandshakeForRead/Write return true, so the copy
// session's Transfer hook is armed; the first Transfer after the
// decision returns N.ErrHandshakeCompleted, the copy loop refreshes
// and re-attempts copyDirect, and splice() engages because the
// wrapper now exposes the raw socket's RawConn. Before the switch
// SyscallConn returns an error, so copyDirect bails to the buffered
// path and no plaintext is ever exposed to the wrong layer.
//   - With the ack negotiated, the handshake stays open past the
//     decision until the ack is resolved (consumed or timed out):
//     NeedHandshakeForRead/Write keep returning true while the ack
//     is outstanding. This is load-bearing, not cosmetic. The copy
//     loop upgrades to a kernel splice as soon as the handshake
//     reports complete, and a splice bypasses the wrapper's Read
//     and Write entirely -- so without this guard the ack byte
//     would be spliced to the destination as garbage (the upload
//     Read that classifies it would never run) and the ServerHello
//     would be spliced to the client without waiting (the download
//     Write that holds it would never run). Holding the handshake
//     open forces both directions to keep going through the
//     wrapper until the ack is consumed; only then does the loop
//     upgrade, over a clean stream.
//
// Disguise: the inner ClientHello always travels inside the outer
// TLS (the server reads it decrypted, the client writes it
// encrypted). Its SNI is never exposed in plaintext, and the outer
// handshake is byte-identical to milestone 1 (the JA4 of the outer
// hello is unchanged). The only new wire bytes are the v2 flag bit
// (inside the encrypted request header) and the go-signal (inside
// the outer TLS stream, 8 bytes, discarded by the client).
//
// Locking: c.mu guards the Read-side inspection state and is only
// ever held for short state transitions, never across a blocking
// Read or Write, so Close() (which needs c.mu to pick which socket
// to close) can never deadlock against a blocked Read. The only
// cross-goroutine flag is deshelled, always read under c.mu.
// writeMu serialises TLS writes (download-direction Write vs the
// server's go-signal write) so their stream order is deterministic.
// Lock order is c.mu -> writeMu, and Write never holds c.mu while
// acquiring writeMu.
//
// Residual risks (prototype): the switch assumes the inner client
// sends exactly one ClientHello record in its first flight and
// nothing else before the ServerHello (true for every standard TLS
// 1.3 client; a client that pipelines data after the ClientHello
// would have that data read as raw by a switched peer). The
// go-signal check on the client reads the first bytes of each TLS
// record until it has 8 bytes or a definitive mismatch; a real
// server response that is a strict prefix of the 8-byte magic and
// shorter than 8 bytes would stall the first Read (no known
// protocol does this). The client TLS read-ahead race (crypto/tls
// reads up to 512 bytes past the current record, stranding raw
// bytes that arrive in the same batch as the go-signal) is closed
// by the post-switch ack above for peers that negotiated it; with
// an old server (no ack bit) the race remains at its original
// ~2%-on-loopback rate, and with an old client the server pays the
// ack timeout only if the client advertised the flag, which old
// clients never do.

package musess

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// deshellMagic is the go-signal the server writes through the outer
// TLS immediately after switching to the raw stream. It is 8 bytes so
// a real TLS record payload cannot plausibly collide with it, and it
// does not start with 0x16 (a TLS record type), so it can never be
// mistaken for the start of an inner ServerHello.
var deshellMagic = []byte{'D', 'S', 'H', 'L', 0x01, 0x00, 0x00, 0x00}

// deshellAckByte is the one-byte post-switch ack the client sends on
// the raw socket immediately after switching, when the server
// required it (deshell ack v1). Its value 0x01 can never be the first
// byte of a TLS record (0x14/0x15/0x16/0x17), so the server can tell
// an ack apart from real inner data by content.
const deshellAckByte = 0x01

// deshellAckTimeout bounds how long the server holds its first
// downstream raw bytes waiting for the client ack. A conforming
// client sends the ack within ~1 RTT of the go-signal; the timeout
// only fires for a client that advertised the ack but never sent it,
// or a lost ack (impossible on TCP, kept as a safety net). It must
// exceed one RTT -- the ack round trip is go-signal out + ack back
// -- so a slow link cannot make the server give up and splice
// before the ack arrives: a late ack byte forwarded by the splice
// would land in the destination's TLS stream as garbage. 2s covers
// RTTs up to 2s; a new client acks within 1 RTT, so the timer only
// ever fires for clients that never ack.
const deshellAckTimeout = 2 * time.Second

// maxTLSRecordSize is the largest TLS record we will buffer while
// inspecting the first inner record (RFC 8446: 2^14 + 256).
const maxTLSRecordSize = 16384 + 256

type deshellRole int

const (
	deshellRoleServer deshellRole = iota
	deshellRoleClient
)

type deshellConn struct {
	tlsConn net.Conn // outer TLS connection (uTLS client / stdlib server)
	rawConn net.Conn // raw TCP socket underneath the outer TLS
	raw     syscall.RawConn
	role    deshellRole
	logger  logger.ContextLogger
	ctx     context.Context
	// reader is the server inbound's bufio peek reader over rawConn.
	// At switch time it must hold no buffered bytes, or bytes the
	// TLS layer read ahead would be stranded by the switch.
	reader *bufio.Reader
	// serverAgreed is set on the client when the server set the
	// deshell status bit. A client whose server did not agree never
	// looks for the go-signal and never switches.
	serverAgreed bool
	// ackWanted is the negotiated deshell ack v1: on the client it
	// means "send the ack byte right after switching" (the server
	// set deshellAckStatusFlag); on the server it means "expect the
	// ack byte and hold the first downstream raw bytes until it
	// arrives or the timeout fires" (the client set deshellAckFlag).
	// False for old peers on either side: no ack is sent, none is
	// waited for, and the behaviour is exactly the pre-ack one.
	ackWanted bool
	// ackCh is closed when the ack handshake is resolved (ack
	// consumed, timed out, or the connection closed). The server's
	// Write waits on it for the first raw bytes after the switch.
	ackCh chan struct{}
	// ackResolved is true once the ack handshake is over. Guarded
	// by mu. resolveAckLocked is the only writer.
	ackResolved bool
	// ackGot is true once the server consumed an ack byte. Guarded
	// by mu. Test observability (deshellAckGot).
	ackGot bool
	// ackChecked is true once the server has classified the first
	// post-switch upload byte (ack, or real data). Guarded by mu.
	// It is independent of ackResolved: the ack timeout may release
	// the Write side while the ack byte is still sitting in the
	// socket buffer, and the Read side must still consume it when
	// it arrives instead of delivering it as data.
	ackChecked bool
	// ackTimer fires the ack timeout. Started at switch time on the
	// server when ackWanted; nil otherwise. Guarded by mu.
	ackTimer *time.Timer

	// mu guards deshelled, decided, pending, inspectBuf and
	// magicBuf. Held only for short state transitions, never across
	// a blocking Read or Write.
	mu sync.Mutex
	// deshelled is true once the wrapper switches both directions
	// to rawConn. Written only by the Read goroutine.
	deshelled bool
	// decided is true once the deshell decision is final (switched,
	// or inspected the first record and declined). While false the
	// copy session's handshake is pending, which is what makes the
	// copy loop re-attempt splice after the decision.
	decided bool
	// pending holds bytes already read from the outer TLS that must
	// be delivered to the copy loop before any further read.
	pending []byte
	// inspectBuf accumulates the first inner record on the server
	// while the ClientHello check is still undecided.
	inspectBuf []byte
	// magicBuf accumulates a strict prefix of the go-signal on the
	// client when a TLS read returned fewer than 8 bytes.
	magicBuf []byte
	// writeMu serialises TLS writes: the download-direction Write
	// and the server's go-signal write.
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func newServerDeshellConn(ctx context.Context, tlsConn, rawConn net.Conn, reader *bufio.Reader, logger logger.ContextLogger, ackWanted bool) *deshellConn {
	c := &deshellConn{
		tlsConn:   tlsConn,
		rawConn:   rawConn,
		role:      deshellRoleServer,
		logger:    logger,
		ctx:       ctx,
		reader:    reader,
		ackWanted: ackWanted,
		ackCh:     make(chan struct{}),
	}
	c.initRaw()
	return c
}

func newClientDeshellConn(ctx context.Context, tlsConn, rawConn net.Conn, serverAgreed bool, ackWanted bool, logger logger.ContextLogger) *deshellConn {
	c := &deshellConn{
		tlsConn:      tlsConn,
		rawConn:      rawConn,
		role:         deshellRoleClient,
		logger:       logger,
		ctx:          ctx,
		serverAgreed: serverAgreed,
		ackWanted:    ackWanted,
		ackCh:        make(chan struct{}),
	}
	c.initRaw()
	return c
}

// resolveAckLocked ends the ack handshake. Called with c.mu held.
// Idempotent: the channel is closed at most once, and the timer is
// stopped at most once.
func (c *deshellConn) resolveAckLocked() {
	if c.ackResolved {
		return
	}
	c.ackResolved = true
	if c.ackTimer != nil {
		c.ackTimer.Stop()
		c.ackTimer = nil
	}
	close(c.ackCh)
}

// waitForAck blocks until the client ack is resolved (consumed or
// timed out). It holds no lock; the ack timer guarantees it returns
// within deshellAckTimeout of the switch. Called only for raw writes
// after the switch; it is a no-op for the client role, when no ack
// was negotiated, or once the ack is resolved.
func (c *deshellConn) waitForAck() {
	c.mu.Lock()
	if !c.ackWanted || c.role != deshellRoleServer || c.ackResolved {
		c.mu.Unlock()
		return
	}
	ch := c.ackCh
	c.mu.Unlock()
	<-ch
}

// deshellAckGot reports whether the server consumed a client ack
// byte. Test observability only.
func (c *deshellConn) deshellAckGot() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ackGot
}

// deshellAckResolved reports whether the ack handshake is over
// (consumed, timed out, or closed). Test observability only.
func (c *deshellConn) deshellAckResolved() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ackResolved
}

// sendAck writes the post-switch ack byte on the raw socket. Called
// once, right after the client switches, only when the server
// required it. It tells the server the client's TLS read-ahead has
// finished, so the server may release its held first downstream raw
// bytes. Serialised with Write via writeMu; the application cannot
// be writing concurrently (it is blocked reading the ServerHello),
// so this cannot deadlock. A failed ack write is logged, not fatal:
// the connection is broken anyway and the following raw Read will
// report it.
func (c *deshellConn) sendAck() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.rawConn.Write([]byte{deshellAckByte}); err != nil {
		c.logger.DebugContext(c.ctx, "musess: deshell ack write failed: ", err)
	}
}

func (c *deshellConn) initRaw() {
	if sc, ok := c.rawConn.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			c.raw = raw
			return
		}
	}
	// No RawConn (not a plain TCP socket): the wrapper still works,
	// but copyDirect can never splice this side, so the copy loop
	// stays on the buffered raw path after the switch. Switching is
	// still correct; only the zero-copy benefit is lost.
	c.logger.DebugContext(c.ctx, "musess: deshell raw socket has no SyscallConn, splice unavailable on this side")
}

// CanDeshell reports whether the raw socket exposes a RawConn, i.e.
// whether kernel splice can engage for this connection once switched.
func (c *deshellConn) CanDeshell() bool {
	return c.raw != nil
}

// Deshelled reports whether the wrapper has switched to the raw stream.
func (c *deshellConn) Deshelled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deshelled
}

// NeedHandshakeForRead is the EarlyReader hook: while the deshell
// decision is pending the copy session arms its Transfer hook, and
// the first Transfer after the decision returns
// N.ErrHandshakeCompleted, making the copy loop re-attempt
// copyDirect (splice) with the now-exposed raw socket.
// ackPending reports whether this (server) connection is still
// waiting for the client ack: the server negotiated it, but it has
// neither been consumed nor timed out. Server-only: the client
// sends the ack and never waits for one, so it is always false
// there.
func (c *deshellConn) ackPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.role == deshellRoleServer && c.ackWanted && !c.ackResolved
}

func (c *deshellConn) NeedHandshakeForRead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The handshake is not done while the inspection is undecided,
	// nor while the client ack is still outstanding. This second
	// clause is what keeps sing-box's copy loop from upgrading to
	// a kernel splice of the raw socket before the ack byte is
	// consumed: a splice reads straight from the socket and would
	// forward the 0x01 ack byte to the destination as if it were
	// inner TLS data, and the wrapper's Read (the only place the
	// ack is classified) would never run again. Holding the
	// handshake open forces the copy loop to keep calling Read,
	// which routes through readServerAck and consumes the ack;
	// only then does the loop upgrade to the splice, over a clean
	// stream.
	return !c.decided || (c.role == deshellRoleServer && c.ackWanted && !c.ackResolved)
}

// NeedHandshakeForWrite is the EarlyWriter hook, same semantics for
// the direction where this wrapper is the copy destination.
func (c *deshellConn) NeedHandshakeForWrite() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Same splice guard as NeedHandshakeForRead, for the download
	// direction: a splice would write the destination's bytes
	// straight to the raw socket and bypass Write (and its ack
	// wait) entirely, releasing the ServerHello before the ack
	// proves the client's TLS read-ahead has finished. Holding the
	// handshake open forces the copy loop to keep calling Write,
	// which waits for the ack; only then does it upgrade.
	return !c.decided || (c.role == deshellRoleServer && c.ackWanted && !c.ackResolved)
}

func (c *deshellConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		c.mu.Unlock()
		return n, nil
	}
	if c.deshelled {
		role := c.role
		ackWanted := c.ackWanted
		c.mu.Unlock()
		if role == deshellRoleServer && ackWanted {
			// First read(s) after the switch while the ack is
			// still unresolved go through the ack classifier:
			// it consumes the ack byte, or delivers a non-ack
			// first byte as real data.
			return c.readServerAck(p)
		}
		return c.rawConn.Read(p)
	}
	role := c.role
	serverAgreed := c.serverAgreed
	decided := c.decided
	c.mu.Unlock()

	if role == deshellRoleClient {
		if !serverAgreed {
			// The server did not agree: plain TLS pass-through.
			c.mu.Lock()
			c.decided = true
			c.mu.Unlock()
			return c.tlsConn.Read(p)
		}
		if decided {
			// Decision final (non-magic data seen): the go-signal
			// can never arrive now, so read straight from the TLS
			// connection. Routing every Read through
			// readClientSignal after the decision costs a fresh
			// 16 KiB buffer plus two extra copies per chunk
			// (tmp -> chunk -> pending -> p) for the whole
			// connection -- on a declined bulk transfer that is
			// the dominant cost (~4x CPU per byte, 0.42x goodput
			// on loopback), and settling `decided` alone does not
			// remove it: the signal check is only needed while
			// the decision is still pending. This mirrors the
			// server branch below. The pending bytes were already
			// drained at the top of Read, and magicBuf is empty
			// once decided (it is cleared when the non-magic
			// chunk is processed), so no byte is lost or
			// reordered.
			return c.tlsConn.Read(p)
		}
		return c.readClientSignal(p)
	}
	// Server role.
	if decided {
		return c.tlsConn.Read(p)
	}
	return c.readServerInspect(p)
}

// readServerAck handles reads after the server switches while the
// first post-switch upload byte is still unclassified. It reads
// exactly one byte: the ack byte (deshellAckByte) is consumed and
// resolves the ack; any other byte is real inner data (an old client
// that never acks, or a slow client whose ack arrives later), which
// resolves the ack expectation and is delivered to the caller via
// pending. Content classification is exact for TLS inner traffic:
// 0x01 can never start a TLS record, so a late ack is still
// consumed correctly and a non-ack first byte is never eaten. This
// read blocks like any Read until the first post-switch byte
// arrives; the ack timeout only releases the Write side, never this
// side -- a late ack byte must still be consumed here, or it would
// be delivered as data on the next read.
func (c *deshellConn) readServerAck(p []byte) (int, error) {
	c.mu.Lock()
	if c.ackChecked {
		c.mu.Unlock()
		return c.rawConn.Read(p)
	}
	c.mu.Unlock()
	// Blocking 1-byte read (c.mu not held).
	var one [1]byte
	if _, err := io.ReadFull(c.rawConn, one[:]); err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.ackChecked = true
	if one[0] == deshellAckByte {
		c.ackGot = true
		c.resolveAckLocked()
		c.logger.DebugContext(c.ctx, "musess: deshell ack received")
		c.mu.Unlock()
		return c.rawConn.Read(p)
	}
	// Not the ack: real inner data. Stop expecting the ack and
	// deliver this byte (via pending, so a short caller buffer
	// still gets it on the next Read).
	c.resolveAckLocked()
	c.pending = append(c.pending, one[:]...)
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	c.mu.Unlock()
	return n, nil
}

// readServerInspect inspects the first inner record. It loops between
// short locked state checks and blocking TLS reads (never holding
// c.mu across a read). On return it has either switched to raw or
// decided not to, and the first inner bytes are in pending for
// delivery to the copy loop.
func (c *deshellConn) readServerInspect(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.decided {
			if len(c.pending) > 0 {
				n := copy(p, c.pending)
				c.pending = c.pending[n:]
				c.mu.Unlock()
				return n, nil
			}
			deshelled := c.deshelled
			c.mu.Unlock()
			if deshelled {
				return c.rawConn.Read(p)
			}
			return c.tlsConn.Read(p)
		}
		// Try to decide from the bytes accumulated so far.
		if len(c.inspectBuf) >= 5 {
			if !isTLSRecordHeader(c.inspectBuf) {
				c.finishInspectionLocked(false, "first inner bytes are not a TLS handshake record")
				c.mu.Unlock()
				continue
			}
			recLen := int(c.inspectBuf[3])<<8 | int(c.inspectBuf[4])
			total := 5 + recLen
			if total > maxTLSRecordSize+5 {
				c.finishInspectionLocked(false, "first inner record too large")
				c.mu.Unlock()
				continue
			}
			if len(c.inspectBuf) >= total {
				record := c.inspectBuf[:total]
				// finishInspectionLocked queues the whole
				// inspectBuf (the record plus any bytes that
				// arrived after it) into pending for delivery
				// to the copy loop; do not trim it first.
				if !isTLS13ClientHello(record) {
					c.finishInspectionLocked(false, "first inner record is not a TLS 1.3 ClientHello")
					c.mu.Unlock()
					continue
				}
				if c.reader != nil && c.reader.Buffered() > 0 {
					c.finishInspectionLocked(false, "peek reader holds stranded bytes")
					c.mu.Unlock()
					continue
				}
				// Switch. The go-signal goes out through the outer
				// TLS before the ClientHello bytes are returned,
				// so the client switches before the destination's
				// ServerHello can reach it.
				if err := c.writeGoSignalLocked(); err != nil {
					c.finishInspectionLocked(false, "go-signal write failed")
					c.mu.Unlock()
					continue
				}
				c.finishInspectionLocked(true, "")
				c.mu.Unlock()
				continue
			}
		}
		if len(c.inspectBuf) > maxTLSRecordSize+5 {
			c.finishInspectionLocked(false, "first inner record too large")
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		// Blocking read (c.mu not held).
		tmp := make([]byte, 16384)
		n, err := c.tlsConn.Read(tmp)
		if n > 0 {
			c.mu.Lock()
			c.inspectBuf = append(c.inspectBuf, tmp[:n]...)
			c.mu.Unlock()
		}
		if err != nil {
			// The inner stream errored (or closed) before a full
			// record arrived: decline deshell and deliver whatever
			// was read, then report the error on the next Read.
			c.mu.Lock()
			c.finishInspectionLocked(false, "inner stream ended during inspection")
			if len(c.pending) > 0 {
				m := copy(p, c.pending)
				c.pending = c.pending[m:]
				c.mu.Unlock()
				return m, nil
			}
			c.mu.Unlock()
			return 0, err
		}
	}
}

// readClientSignal watches the outer TLS stream for the server's
// go-signal. A chunk that is a strict prefix of the magic is buffered
// until the rest arrives; anything else is real inner data and is
// delivered immediately.
func (c *deshellConn) readClientSignal(p []byte) (int, error) {
	// Blocking read (c.mu not held).
	tmp := make([]byte, 16384)
	n, err := c.tlsConn.Read(tmp)
	if n > 0 {
		c.mu.Lock()
		chunk := append(append([]byte(nil), c.magicBuf...), tmp[:n]...)
		c.magicBuf = nil
		if len(chunk) >= len(deshellMagic) {
			if string(chunk[:len(deshellMagic)]) == string(deshellMagic) {
				c.deshelled = true
				c.decided = true
				ackWanted := c.ackWanted
				c.logger.InfoContext(c.ctx, "musess: deshell engaged (client): inner TLS 1.3 confirmed, raw splice from here on")
				rest := chunk[len(deshellMagic):]
				if len(rest) > 0 {
					// Bytes after the magic in the same read are
					// real inner data that arrived through TLS;
					// deliver them before any raw read.
					c.pending = append(c.pending, rest...)
					m := copy(p, c.pending)
					c.pending = c.pending[m:]
					c.mu.Unlock()
					if ackWanted {
						// Prove the TLS read-ahead has finished
						// before the server releases its held
						// first downstream raw bytes.
						c.sendAck()
					}
					return m, nil
				}
				c.mu.Unlock()
				if ackWanted {
					c.sendAck()
				}
				return c.rawConn.Read(p)
			}
			// Not the magic: real inner data. Deliver it all.
			// The decision is final -- no go-signal is coming,
			// this is ordinary TLS data -- so mark it decided:
			// otherwise NeedHandshakeForRead/Write stay true
			// forever and the copy loop never leaves its
			// handshake-pending mode (decline bug, idle-box full
			// bench 2026-11-07). This only settles the handshake
			// state; the data path is unchanged (the bytes below
			// are delivered exactly as before), and the raw
			// socket stays hidden (SyscallConn still fails while
			// unswitched).
			c.decided = true
			c.pending = append(c.pending, chunk...)
			m := copy(p, c.pending)
			c.pending = c.pending[m:]
			c.mu.Unlock()
			return m, nil
		}
		if isMagicPrefix(chunk) {
			c.magicBuf = chunk
			c.mu.Unlock()
			// Read more to complete (or rule out) the magic.
			return c.readClientSignal(p)
		}
		// Short chunk that is not a magic prefix: real inner
		// data, and the decision is final for the same reason as
		// above (a stream that does not start with the magic can
		// never become the magic). The magic-prefix branch above
		// is the only one that must NOT settle: the decision is
		// still pending there.
		c.decided = true
		c.pending = append(c.pending, chunk...)
		m := copy(p, c.pending)
		c.pending = c.pending[m:]
		c.mu.Unlock()
		return m, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// finishInspectionLocked ends the server-side inspection. It is
// called with c.mu held. When switchToRaw is true the wrapper is now
// raw; either way the inspected bytes are queued in pending for
// delivery to the copy loop.
func (c *deshellConn) finishInspectionLocked(switchToRaw bool, reason string) {
	c.pending = append(c.pending, c.inspectBuf...)
	c.inspectBuf = nil
	c.decided = true
	if switchToRaw {
		c.deshelled = true
		c.logger.InfoContext(c.ctx, "musess: deshell engaged (server): inner TLS 1.3 confirmed, raw splice from here on")
		if c.role == deshellRoleServer && c.ackWanted {
			// Start the ack timeout: if the client never acks,
			// the first downstream raw bytes are released after
			// deshellAckTimeout instead of hanging. The timer is
			// stopped when the ack is consumed.
			c.ackTimer = time.AfterFunc(deshellAckTimeout, func() {
				c.mu.Lock()
				c.resolveAckLocked()
				c.mu.Unlock()
			})
		}
	} else {
		// Declined: no switch, so no ack can ever arrive -- the
		// client never switches and never sends one, and the
		// server never runs the ack classifier (readServerAck is
		// only reached when deshelled). Resolve the ack handshake
		// here: otherwise ackResolved stays false forever (the
		// ack timer is started only on the switch branch) and
		// NeedHandshakeForRead/Write stay true forever, so the
		// copy loop never leaves its handshake-pending mode and
		// the declined connection pays ~40% goodput and ~2x CPU
		// (idle-box full bench 2026-11-07). Resolving releases
		// nothing: on decline the server's Write never waits for
		// the ack (waitForAck runs only on the deshelled fast
		// path), and the inspected bytes were already queued in
		// pending above for delivery before any further read.
		// SyscallConn still refuses the raw socket (deshelled is
		// false), so a declined connection can never be spliced
		// raw -- its bytes on the wire are still outer-TLS
		// ciphertext. The copy loop simply settles into the
		// normal buffered TLS copy, the same path as deshell off.
		c.resolveAckLocked()
		if reason != "" {
			c.logger.DebugContext(c.ctx, "musess: deshell declined (server): ", reason)
		}
	}
}

// writeGoSignalLocked writes the go-signal through the outer TLS. It
// is called with c.mu held, and takes writeMu so the signal can never
// overtake (or be overtaken by) a download-direction TLS write in the
// byte stream.
func (c *deshellConn) writeGoSignalLocked() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.deshelled {
		return nil
	}
	_, err := c.tlsConn.Write(deshellMagic)
	return err
}

func (c *deshellConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Fast path: already deshelled.
	c.mu.Lock()
	deshelled := c.deshelled
	c.mu.Unlock()
	if deshelled {
		// Hold the first downstream raw bytes for the client ack
		// on the server (no-op once resolved, or when no ack was
		// negotiated), so the client's TLS read-ahead can never
		// strand them.
		c.waitForAck()
		return c.rawConn.Write(p)
	}
	// Not deshelled: write through TLS, serialised with the
	// server's go-signal write so the stream order is deterministic.
	// Re-check after acquiring the lock: the Read goroutine may
	// have deshelled (and written the go-signal) while we waited.
	c.writeMu.Lock()
	c.mu.Lock()
	deshelled = c.deshelled
	c.mu.Unlock()
	if deshelled {
		c.writeMu.Unlock()
		c.waitForAck()
		return c.rawConn.Write(p)
	}
	n, err := c.tlsConn.Write(p)
	c.writeMu.Unlock()
	return n, err
}

func (c *deshellConn) Close() error {
	// Unblock a Write that is waiting for the client ack.
	c.mu.Lock()
	c.resolveAckLocked()
	c.mu.Unlock()
	c.closeOnce.Do(func() {
		c.mu.Lock()
		deshelled := c.deshelled
		c.mu.Unlock()
		if deshelled {
			// Raw stream: close the socket only. A TLS Close()
			// would emit a close_notify into the raw byte stream.
			c.closeErr = c.rawConn.Close()
			return
		}
		c.closeErr = c.tlsConn.Close()
	})
	return c.closeErr
}

func (c *deshellConn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *deshellConn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *deshellConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	deshelled := c.deshelled
	c.mu.Unlock()
	if deshelled {
		return c.rawConn.SetDeadline(t)
	}
	return c.tlsConn.SetDeadline(t)
}

func (c *deshellConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	deshelled := c.deshelled
	c.mu.Unlock()
	if deshelled {
		return c.rawConn.SetReadDeadline(t)
	}
	return c.tlsConn.SetReadDeadline(t)
}

func (c *deshellConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	deshelled := c.deshelled
	c.mu.Unlock()
	if deshelled {
		return c.rawConn.SetWriteDeadline(t)
	}
	return c.tlsConn.SetWriteDeadline(t)
}

// SyscallConn exposes the raw socket to sing's copyDirect (kernel
// splice) only after the switch. Before the switch it returns an
// error, so copyDirect bails to the buffered TLS path; after the
// switch it returns the raw socket's RawConn. When the raw socket
// has no RawConn it keeps returning an error and the copy loop stays
// on the buffered raw path (still no TLS crypto, just no splice).
func (c *deshellConn) SyscallConn() (syscall.RawConn, error) {
	c.mu.Lock()
	deshelled := c.deshelled
	c.mu.Unlock()
	if !deshelled || c.raw == nil {
		return nil, errors.New("musess: deshell not engaged")
	}
	return c.raw, nil
}

// isTLSRecordHeader reports whether b starts with a TLS handshake
// record header (type 0x16, record version TLS 1.0 or 1.2).
func isTLSRecordHeader(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0] != 0x16 {
		return false
	}
	if b[1] != 0x03 || (b[2] != 0x01 && b[2] != 0x03) {
		return false
	}
	return true
}

// isMagicPrefix reports whether b is a strict prefix of the go-signal.
func isMagicPrefix(b []byte) bool {
	if len(b) >= len(deshellMagic) {
		return false
	}
	return string(b) == string(deshellMagic[:len(b)])
}

// isTLS13ClientHello reports whether record is exactly one complete
// TLS record carrying a TLS 1.3 ClientHello: handshake type 0x01,
// the handshake message filling the record, and a
// supported_versions extension advertising 0x0304. Any parse failure
// or doubt returns false (no deshell).
func isTLS13ClientHello(record []byte) bool {
	if len(record) < 5+4+2+32+1+2+1+2 {
		return false
	}
	if !isTLSRecordHeader(record) {
		return false
	}
	recLen := int(record[3])<<8 | int(record[4])
	if len(record) != 5+recLen || recLen < 4 {
		return false
	}
	if record[5] != 0x01 { // ClientHello
		return false
	}
	hsLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if hsLen != recLen-4 {
		return false
	}
	body := record[9:]
	// legacy_version (2) + random (32).
	pos := 2 + 32
	if pos > len(body) {
		return false
	}
	// legacy_session_id.
	if pos >= len(body) {
		return false
	}
	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return false
	}
	pos += sidLen
	// cipher_suites.
	if pos+2 > len(body) {
		return false
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+csLen > len(body) {
		return false
	}
	pos += csLen
	// legacy_compression_methods.
	if pos >= len(body) {
		return false
	}
	compLen := int(body[pos])
	pos++
	if pos+compLen > len(body) {
		return false
	}
	pos += compLen
	// extensions.
	if pos+2 > len(body) {
		return false
	}
	extTotal := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+extTotal > len(body) {
		return false
	}
	extEnd := pos + extTotal
	for pos+4 <= extEnd {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extLen > extEnd {
			return false
		}
		if extType == 0x002b { // supported_versions
			ext := body[pos : pos+extLen]
			if len(ext) < 1 {
				return false
			}
			listLen := int(ext[0])
			if listLen+1 > len(ext) {
				return false
			}
			for i := 1; i+1 < 1+listLen; i += 2 {
				if ext[i] == 0x03 && ext[i+1] == 0x04 {
					return true
				}
			}
			return false
		}
		pos += extLen
	}
	return false
}
