// mux.go — multiplexed stream sessions over one authenticated musess
// connection (rate-attack phase 2 design, impl/README.md §2, landed
// here with the three landing gaps closed: per-stream flow control,
// FEC composition, and real deadlines).
//
// Wire shape (unchanged from the prototype design):
//   - a musess connection opened with the new command 0x03 becomes a
//     stream session; the request destination is a placeholder, each
//     stream carries its own destination.
//   - frames: [streamID u32][type u8][length u32][payload];
//     open carries [command][SOCKS address], data is chunked at
//     32 KiB, plus close (write-close), reset, and window-update
//     frames. Only the client opens streams (odd IDs); TCP only —
//     a UDP open is answered with a reset.
//   - the outbound keeps one lazily dialed session per outbound
//     (handshake + proof exactly as the plain path, early_request
//     included when enabled), redialed after death with one retry;
//     the inbound routes each stream independently through the
//     normal router.
//
// Landing additions over the prototype:
//   - (a) per-stream flow control: each direction starts with a
//     256 KiB window; the receiver grants more with WINDOW_UPDATE
//     frames as it consumes data. The session reader never blocks
//     on one stream: delivery appends to a per-stream inbox queue
//     (bounded in practice by the sender-side window), so a slow
//     stream cannot stall the session reader and cannot starve
//     other streams — the head-of-line coupling of the prototype
//     is gone by construction.
//   - (b) FEC composition: a mux session is established over the
//     same transport the plain path would use — when FEC is
//     negotiated for the session, the session runs over fec.Conn
//     (see outbound muxSession / inbound serveAuthenticated).
//   - (c) stream deadlines are real: Read/Write observe
//     SetReadDeadline/SetWriteDeadline/SetDeadline instead of
//     being no-ops.
//
// Anything unexpected fails closed: a malformed frame, a window
// violation beyond the sanity cap, or a dead session fails the
// affected stream (or the session) — never a silent downgrade to
// an unprotected or unauthenticated path. The handshake,
// authentication, fallback byte-forwarding and camouflage are
// untouched by this file.

package musess

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	// commandMux opens a stream session on an authenticated musess
	// connection. The request destination is a placeholder (see
	// muxPlaceholderDest); each stream carries its own.
	commandMux = 0x03
)

const (
	muxFrameOpen   = 0x01 // payload: [command][SOCKS address]
	muxFrameData   = 0x02 // payload: stream bytes (<= muxChunkSize)
	muxFrameClose  = 0x03 // write-close: no more data from the sender
	muxFrameReset  = 0x04 // abort the stream, both directions
	muxFrameWindow = 0x05 // payload: uint32 credit bytes
)

const (
	// muxChunkSize is the maximum data-frame payload, per the
	// prototype design.
	muxChunkSize = 32 * 1024
	// muxInitialWindow is the per-stream, per-direction flow-control
	// window granted at open. It is BDP-sized, not chunk-sized:
	// a stream's throughput is capped at window / RTT, so a
	// 256 KiB window at 200 ms RTT caps a stream at ~10 Mbps —
	// the first full bench run proved this the hard way (mux
	// bulk256 at delay100 hit the 90 s timeout while stock did
	// it in 2.5 s). 16 MiB allows ~640 Mbps at 200 ms RTT and
	// is unconstraining at 25 ms. The window is a credit limit,
	// not allocated memory: only in-flight bytes occupy it, and
	// a stalled stream pins at most its current window.
	muxInitialWindow = 64 * 1024 * 1024
	// muxMaxWindow caps receiver-driven window growth (below):
	// 64 MiB allows ~2.5 Gbps at 200 ms RTT.
	muxMaxWindow = 64 * 1024 * 1024
	// muxWindowCreditThreshold is the consumption quantum that
	// triggers a WINDOW_UPDATE frame.
	muxWindowCreditThreshold = 32 * 1024
	// muxMaxFramePayload is a sanity cap: any frame claiming more
	// is a protocol error and kills the session.
	muxMaxFramePayload = 1 << 20
	// muxFrameHeaderLen is the on-wire frame header size.
	muxFrameHeaderLen = 9
)

var (
	// errMuxClosed is returned by stream operations after the
	// session or the stream is closed.
	errMuxClosed = errors.New("musess mux: session closed")
	// errMuxReset is returned by stream operations after the peer
	// reset the stream.
	errMuxReset = errors.New("musess mux: stream reset by peer")
	// muxPlaceholderDest is the request destination of a mux
	// session: it carries no meaning (each stream carries its
	// own); 0.0.0.0:0 is unroutable by construction.
	muxPlaceholderDest = M.Socksaddr{Addr: netip.AddrFrom4([4]byte{0, 0, 0, 0}), Port: 0}
)

// muxSessionHealth is the client-side, loss-time health tracker for
// one mux session. It decides when the shared session has gone bad
// enough that new streams should bypass mux and take the plain path
// (see MusessOutboundOptions.MuxAdaptiveBypass).
//
// What the sandbox can actually observe — and what it cannot:
//   - The loss relay (lossrelay.py) never drops a packet on the
//     wire: it HOLDS 16 KiB chunks (fast-retransmit style ~1 RTT,
//     RTO style 200 ms sometimes) and releases them in order, so
//     the observable effect of "loss" is delay inflation and
//     head-of-line stalls, never a kernel-visible drop. The client
//     kernel's TCP sees a slow peer, not packet loss (the relay
//     ACKs promptly), so TCP_INFO retransmit counters would NOT
//     see it either. This tracker therefore uses only
//     application-level observables, all measured in-process:
//     (1) open-to-first-frame RTT inflation, (2) live stream
//     stalls (no data while streams are open). It never claims
//     to see packet loss.
//   - The RTT baseline is the MINIMUM open RTT seen recently:
//     under loss some opens still get lucky (no held chunk), so
//     the minimum approximates the clean RTT even when the
//     session boots under loss, where a "first N samples"
//     baseline would be polluted. The trip rule is an ABSOLUTE
//     delta over that baseline (not a ratio): the open-to-first-
//     data latency legitimately differs a little by stream kind
//     (a TLS fetch's first data comes after one extra inner
//     flight, ~1 one-way delay more than a raw bulk stream),
//     while loss adds ~1 RTT (200 ms at delay100) or an RTO
//     (200 ms) per held chunk, so the loss inflation dwarfs the
//     kind offset.
//   - A session-goodput signal was tried and REMOVED (it caused
//     two false trips and zero true ones): a 1 s delivery window
//     cannot tell "link collapsed" from "box busy" or from a
//     legitimately slower workload. In r2 delay100, a box-wide
//     CPU spike slowed TLS rep3 for EVERY leg (ss 1503->759,
//     off 1474->613, mux 1321->743 Mbps) while RTT stayed
//     201-206 ms; the goodput window read that as a collapse
//     and tripped. Throughput collapse without RTT inflation is
//     CPU contention, not link loss — and bypassing to the plain
//     path (which needs the same CPU) cannot help it. The two
//     remaining signals (RTT inflation, live stall) both
//     measure the LINK, not the box.
//   - Recovery needs a live signal, but a degraded session gets
//     no new streams to sample from. Half-open probing fixes
//     that: while degraded, a probe dial is let through only
//     after both a 30 s interval and 8 bypassed dials since the
//     last probe, so the session can prove it recovered without
//     the probe swallowing the bypass when dials are sparse.
const (
	// muxHealthMinSamples is the number of open-RTT samples
	// needed before any trip decision (guards the cold start,
	// where the first opens are handshake-dominated).
	muxHealthMinSamples = 6
	// muxHealthBaselineWindow is how many recent RTT samples the
	// baseline minimum is taken over.
	muxHealthBaselineWindow = 32
	// muxHealthMedianWindow is how many recent RTT samples the
	// trip/clear median is taken over.
	muxHealthMedianWindow = 12
	// muxHealthTripDelta: trip when the recent RTT median
	// exceeds the baseline by this much.
	muxHealthTripDelta = 150 * time.Millisecond
	// muxHealthClearDelta: clear when the recent RTT median is
	// back within this much of the baseline (hysteresis gap vs
	// the trip delta, so the flag does not flap).
	muxHealthClearDelta = 75 * time.Millisecond
	// muxHealthStallAfter: a live stall is declared when open
	// streams have seen no data for this long.
	muxHealthStallAfter = 750 * time.Millisecond
	// muxHealthProbeInterval / muxHealthProbeMinDials: while
	// degraded, a half-open probe dial is let through only when
	// BOTH have passed since the last probe: the interval AND
	// this many mux-candidate dials. The count matters: with
	// sparse dials (one bulk dial every ~10 s, as in the bench
	// rep loop) a purely time-based probe lets EVERY dial
	// through as a probe and the bypass never engages — the
	// exact failure seen in r1 (bulk256 adapt == mux). The
	// probe's only job is recovery detection, so it stays rare.
	muxHealthProbeInterval = 30 * time.Second
	muxHealthProbeMinDials = 8
)

type muxSessionHealth struct {
	mu sync.Mutex
	// rttSamples holds recent open-to-first-frame latencies,
	// oldest first, capped at muxHealthBaselineWindow.
	rttSamples []time.Duration
	// lastProgressAt is when any data frame last arrived (or
	// the session start, before any data).
	lastProgressAt time.Time
	// degraded is the current trip state; degradedAt is when
	// it last flipped to true; degradedReason is why.
	degraded       bool
	degradedAt     time.Time
	degradedReason string
	// lastProbeAt is when the last half-open probe dial was let
	// through while degraded; dialsSinceProbe counts
	// mux-candidate dials since then (see probeDue).
	lastProbeAt     time.Time
	dialsSinceProbe int
	// Counters for logs/tests.
	trips      int
	recoveries int
	rttTrips   int
	stallTrips int
}

func newMuxSessionHealth(now time.Time) *muxSessionHealth {
	return &muxSessionHealth{lastProgressAt: now}
}

// noteRTT records one open-to-first-frame latency sample.
func (h *muxSessionHealth) noteRTT(d time.Duration) {
	if d < 0 {
		return
	}
	h.mu.Lock()
	h.rttSamples = append(h.rttSamples, d)
	if len(h.rttSamples) > muxHealthBaselineWindow {
		h.rttSamples = append(h.rttSamples[:0], h.rttSamples[len(h.rttSamples)-muxHealthBaselineWindow:]...)
	}
	h.mu.Unlock()
}

// noteProgress records that a data frame arrived at now.
func (h *muxSessionHealth) noteProgress(now time.Time) {
	h.mu.Lock()
	h.lastProgressAt = now
	h.mu.Unlock()
}

// snapshot returns the current baseline (min recent RTT), recent
// median RTT and sample count.
func (h *muxSessionHealth) snapshot() (baseline, median time.Duration, n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n = len(h.rttSamples)
	if n == 0 {
		return 0, 0, 0
	}
	baseline = h.rttSamples[0]
	for _, d := range h.rttSamples {
		if d < baseline {
			baseline = d
		}
	}
	recent := h.rttSamples
	if len(recent) > muxHealthMedianWindow {
		recent = recent[len(recent)-muxHealthMedianWindow:]
	}
	sorted := append([]time.Duration(nil), recent...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	median = sorted[len(sorted)/2]
	return baseline, median, n
}

// evaluate recomputes the trip state at now given openCount live
// streams. It returns the new state, whether it just changed, and
// the reason. Trip needs enough RTT samples, or a live stall.
// Clearing needs the RTT median back near baseline with no live
// stall.
func (h *muxSessionHealth) evaluate(openCount int, now time.Time) (degraded bool, changed bool, reason string) {
	baseline, median, n := h.snapshot()
	h.mu.Lock()
	defer h.mu.Unlock()
	stalled := openCount > 0 && !h.lastProgressAt.IsZero() && now.Sub(h.lastProgressAt) > muxHealthStallAfter
	// Every evaluation is one mux-candidate dial decision; count
	// them while degraded so probeDue can require a minimum
	// number of bypassed dials between probes.
	if h.degraded {
		h.dialsSinceProbe++
	}
	if !h.degraded {
		if n >= muxHealthMinSamples && median > baseline+muxHealthTripDelta {
			h.degraded, h.degradedAt, h.degradedReason = true, now, "rtt"
			h.trips++
			h.rttTrips++
			return true, true, "rtt"
		}
		if stalled {
			h.degraded, h.degradedAt, h.degradedReason = true, now, "stall"
			h.trips++
			h.stallTrips++
			return true, true, "stall"
		}
		return false, false, ""
	}
	// Already degraded: clear only on a healthy RTT median with
	// no live stall.
	if n >= muxHealthMinSamples && median < baseline+muxHealthClearDelta && !stalled {
		h.degraded = false
		h.degradedReason = ""
		h.recoveries++
		return false, true, ""
	}
	return true, false, h.degradedReason
}

// probeDue reports whether a half-open probe dial is due, and if
// so consumes the slot (only one probe per interval AND per
// minimum dial count — see the muxHealthProbeInterval /
// muxHealthProbeMinDials constants).
func (h *muxSessionHealth) probeDue(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.degraded {
		return false
	}
	if now.Sub(h.lastProbeAt) < muxHealthProbeInterval || h.dialsSinceProbe < muxHealthProbeMinDials {
		return false
	}
	h.lastProbeAt = now
	h.dialsSinceProbe = 0
	return true
}

// status renders a one-line snapshot for logs.
func (h *muxSessionHealth) status() string {
	baseline, median, n := h.snapshot()
	h.mu.Lock()
	defer h.mu.Unlock()
	return "samples=" + itoa(n) +
		" baseline_rtt=" + baseline.String() +
		" median_rtt=" + median.String() +
		" degraded=" + boolStr(h.degraded) +
		" reason=" + h.degradedReason +
		" trips=" + itoa(h.trips) +
		" recoveries=" + itoa(h.recoveries)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// muxStats is the per-session frame accounting, logged at debug
// level when the session closes (and used by the H2 record-shape
// comparison to get the real mux frame-size distribution).
type muxStats struct {
	framesRead     [6]uint64
	framesWritten  [6]uint64
	bytesRead      [6]uint64
	bytesWritten   [6]uint64
	dataFrameSizes [4]uint64 // buckets: <=1K, <=4K, <=16K, <=32K
	windowSent     uint64
	windowRecv     uint64
}

func (s *muxStats) dataBucket(n int) int {
	switch {
	case n <= 1024:
		return 0
	case n <= 4096:
		return 1
	case n <= 16384:
		return 2
	default:
		return 3
	}
}

// muxSession is one multiplexed session over an authenticated
// transport (TLS, or fec.Conn when FEC was negotiated for it).
type muxSession struct {
	conn     net.Conn
	isClient bool
	onOpen   func(stream *muxStream, command byte, destination M.Socksaddr)
	logger   logger.ContextLogger

	writeMu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*muxStream
	nextID  uint32 // client side: next odd stream ID
	closed  bool
	done    chan struct{}
	stats   muxStats
	// health is the loss-time tracker (client side only; nil on
	// the server side, which never decides routing).
	health *muxSessionHealth
}

func newMuxSession(conn net.Conn, isClient bool, onOpen func(*muxStream, byte, M.Socksaddr), logger logger.ContextLogger) *muxSession {
	s := &muxSession{
		conn:     conn,
		isClient: isClient,
		onOpen:   onOpen,
		logger:   logger,
		streams:  make(map[uint32]*muxStream),
		nextID:   1,
		done:     make(chan struct{}),
	}
	if isClient {
		s.health = newMuxSessionHealth(time.Now())
	}
	return s
}

// healthDegraded evaluates the session health (client side only)
// and logs on state change. A server session never degrades: it
// does not decide routing.
func (s *muxSession) healthDegraded() bool {
	if !s.isClient || s.health == nil {
		return false
	}
	s.mu.Lock()
	openCount := len(s.streams)
	s.mu.Unlock()
	degraded, changed, reason := s.health.evaluate(openCount, time.Now())
	if changed && s.logger != nil {
		if degraded {
			s.logger.Info("musess: mux session degraded (", reason, "), new streams bypass mux: ", s.health.status())
		} else {
			s.logger.Info("musess: mux session recovered, resuming mux: ", s.health.status())
		}
	}
	return degraded
}

// healthProbeDue reports whether a half-open probe dial is due
// while degraded (see muxSessionHealth.probeDue).
func (s *muxSession) healthProbeDue() bool {
	if !s.isClient || s.health == nil {
		return false
	}
	return s.health.probeDue(time.Now())
}

// start launches the session read loop.
func (s *muxSession) start() {
	go s.readLoop()
}

// Done returns a channel closed when the session dies.
func (s *muxSession) Done() chan struct{} { return s.done }

// Alive reports whether the session is still usable for new streams.
func (s *muxSession) Alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// Close kills the session and fails all open streams.
func (s *muxSession) Close() error {
	s.closeOnce()
	return s.conn.Close()
}

func (s *muxSession) closeOnce() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	streams := make([]*muxStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	close(s.done)
	for _, st := range streams {
		st.fail(errMuxClosed)
	}
	if s.logger != nil {
		st := s.stats
		s.logger.Debug("musess mux session closed: frames read open/data/close/reset/window=",
			st.framesRead[1], "/", st.framesRead[2], "/", st.framesRead[3], "/", st.framesRead[4], "/", st.framesRead[5],
			" written=", st.framesWritten[1], "/", st.framesWritten[2], "/", st.framesWritten[3], "/", st.framesWritten[4], "/", st.framesWritten[5],
			" data-frame sizes <=1K/<=4K/<=16K/<=32K=", st.dataFrameSizes[0], "/", st.dataFrameSizes[1], "/", st.dataFrameSizes[2], "/", st.dataFrameSizes[3],
			" window sent/recv=", st.windowSent, "/", st.windowRecv)
		if s.health != nil {
			s.logger.Debug("musess mux session health: ", s.health.status())
		}
	}
}

// writeFrame serialises one frame onto the session transport.
func (s *muxSession) writeFrame(id uint32, frameType byte, payload []byte) error {
	header := make([]byte, muxFrameHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], id)
	header[4] = frameType
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if !s.Alive() {
		return errMuxClosed
	}
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.stats.framesWritten[frameType]++
	s.stats.bytesWritten[frameType] += uint64(len(payload))
	if frameType == muxFrameData {
		s.stats.dataFrameSizes[s.stats.dataBucket(len(payload))]++
	}
	if frameType == muxFrameWindow {
		s.stats.windowSent++
	}
	s.mu.Unlock()
	return nil
}

// openStream opens a new stream (client side only) for the given
// command and destination. The open frame is sent and the stream
// is usable immediately; a peer reset surfaces as a Read/Write
// error on the stream.
func (s *muxSession) openStream(command byte, destination M.Socksaddr) (*muxStream, error) {
	if !s.isClient {
		return nil, errors.New("musess mux: only the client opens streams")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errMuxClosed
	}
	id := s.nextID
	s.nextID += 2
	stream := newMuxStream(s, id)
	// Plain assignment, no stream lock: the stream is not yet
	// in the map, so no other goroutine can observe it; the map
	// store below (under the session lock) publishes it, and
	// noteFirstFrame reads openedAt only after fetching the
	// stream through the same lock. (Taking the stream lock
	// here would invert the lock order — Close takes the stream
	// lock and then the session lock in removeStream.)
	stream.openedAt = time.Now()
	s.streams[id] = stream
	s.mu.Unlock()

	payload := bytes.NewBuffer(nil)
	payload.WriteByte(command)
	if err := M.SocksaddrSerializer.WriteAddrPort(payload, destination); err != nil {
		s.removeStream(id)
		return nil, err
	}
	if err := s.writeFrame(id, muxFrameOpen, payload.Bytes()); err != nil {
		s.removeStream(id)
		stream.fail(err)
		return nil, err
	}
	return stream, nil
}

func (s *muxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *muxSession) getStream(id uint32) *muxStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// readLoop is the single session reader. It never blocks on one
// stream: data delivery appends to the stream's inbox queue (the
// sender-side window bounds how much can be in flight), so a
// stream whose consumer is slow cannot stall delivery to other
// streams.
func (s *muxSession) readLoop() {
	defer s.closeOnce()
	defer s.conn.Close()
	header := make([]byte, muxFrameHeaderLen)
	for {
		if _, err := io.ReadFull(s.conn, header); err != nil {
			return
		}
		id := binary.BigEndian.Uint32(header[0:4])
		frameType := header[4]
		length := binary.BigEndian.Uint32(header[5:9])
		if length > muxMaxFramePayload || frameType < muxFrameOpen || frameType > muxFrameWindow {
			return
		}
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				return
			}
		}
		s.mu.Lock()
		s.stats.framesRead[frameType]++
		s.stats.bytesRead[frameType] += uint64(len(payload))
		if frameType == muxFrameData {
			s.stats.dataFrameSizes[s.stats.dataBucket(len(payload))]++
		}
		if frameType == muxFrameWindow {
			s.stats.windowRecv++
		}
		s.mu.Unlock()
		if err := s.dispatch(id, frameType, payload); err != nil {
			return
		}
	}
}

func (s *muxSession) dispatch(id uint32, frameType byte, payload []byte) error {
	// First-frame RTT sample (client side only): the first frame
	// of any kind addressed to a stream completes its
	// open-to-first-frame measurement. The open frame itself is
	// never received by a client, so muxFrameOpen is excluded.
	if s.isClient && frameType != muxFrameOpen && s.health != nil {
		if stream := s.getStream(id); stream != nil {
			if sample, ok := stream.noteFirstFrame(time.Now()); ok {
				s.health.noteRTT(sample)
				if s.logger != nil {
					s.logger.Debug("musess mux health sample rtt=", sample)
				}
			}
		}
	}
	switch frameType {
	case muxFrameOpen:
		if s.isClient || s.onOpen == nil {
			// A server never opens streams; a client never
			// receives opens. Reset the (bogus) stream.
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		if len(payload) < 1 {
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		command := payload[0]
		destination, err := M.SocksaddrSerializer.ReadAddrPort(bytes.NewReader(payload[1:]))
		if err != nil {
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		if command != commandTCP {
			// TCP only: a UDP open is reset, per the design.
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil
		}
		if _, exists := s.streams[id]; exists {
			s.mu.Unlock()
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		stream := newMuxStream(s, id)
		s.streams[id] = stream
		s.mu.Unlock()
		s.onOpen(stream, command, destination)
		return nil
	case muxFrameData:
		stream := s.getStream(id)
		if stream == nil {
			_ = s.writeFrame(id, muxFrameReset, nil)
			return nil
		}
		stream.deliver(payload)
		if s.isClient && s.health != nil {
			s.health.noteProgress(time.Now())
		}
		return nil
	case muxFrameClose:
		if stream := s.getStream(id); stream != nil {
			stream.peerClose()
		}
		return nil
	case muxFrameReset:
		if stream := s.getStream(id); stream != nil {
			stream.peerReset()
		}
		return nil
	case muxFrameWindow:
		if len(payload) != 4 {
			return errors.New("musess mux: malformed window frame")
		}
		if stream := s.getStream(id); stream != nil {
			stream.addWindow(int64(binary.BigEndian.Uint32(payload)))
		}
		return nil
	}
	return nil
}

// muxStream is one multiplexed stream: a net.Conn with per-stream
// flow control in both directions.
type muxStream struct {
	session *muxSession
	id      uint32

	mu          sync.Mutex
	inbox       [][]byte // queued data chunks not yet read
	inboxBytes  int
	readOff     int  // offset into inbox[0]
	readClosed  bool // peer sent close or reset
	readErr     error
	writeClosed bool // local CloseWrite/Close sent
	writeErr    error
	// openedAt is when openStream wrote the open frame;
	// firstFrameAt is when the first frame for this stream
	// arrived. Their difference is the open-to-first-frame RTT
	// sample fed to the session health tracker (client side).
	openedAt      time.Time
	firstFrameAt  time.Time
	sendWindow    int64 // bytes we may still send (granted by peer)
	creditPending int64 // bytes consumed locally, not yet credited
	// Receiver-side window auto-tuning: granted is the total
	// window we have offered the peer (initial + all credits),
	// received is the total bytes the peer has sent, and
	// windowSize is the current window. When the peer has sent
	// a full window's worth (received >= windowSize) the stream
	// is bulk and the window may be its limiter, so the
	// receiver doubles windowSize (up to muxMaxWindow) on the
	// next credit. A stalled stream never grows: it consumes
	// nothing, so it sends no credits.
	granted       int64
	received      int64
	windowSize    int64
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	readNotify    chan struct{} // signalled when inbox/close state changes
	winNotify     chan struct{} // signalled when sendWindow grows
}

func newMuxStream(session *muxSession, id uint32) *muxStream {
	return &muxStream{
		session:    session,
		id:         id,
		sendWindow: muxInitialWindow,
		granted:    muxInitialWindow,
		windowSize: muxInitialWindow,
		readNotify: make(chan struct{}, 1),
		winNotify:  make(chan struct{}, 1),
	}
}

func (s *muxStream) notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// noteFirstFrame records the arrival of the first frame for this
// stream and returns the open-to-first-frame latency. The second
// and later calls return ok=false: exactly one RTT sample per
// stream. A zero openedAt (server-side streams, which never
// opened anything) yields no sample.
func (s *muxStream) noteFirstFrame(now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.firstFrameAt.IsZero() || s.openedAt.IsZero() {
		return 0, false
	}
	s.firstFrameAt = now
	return now.Sub(s.openedAt), true
}

// deliver appends a data frame to the inbox. Never blocks: the
// sender-side window bounds in-flight bytes, and the queue is
// what decouples this stream from the session reader.
func (s *muxStream) deliver(payload []byte) {
	s.mu.Lock()
	if s.closed || s.readClosed {
		s.mu.Unlock()
		return
	}
	s.inbox = append(s.inbox, payload)
	s.inboxBytes += len(payload)
	s.received += int64(len(payload))
	s.mu.Unlock()
	s.notify(s.readNotify)
}

// peerClose marks the read side EOF (peer will send no more data).
func (s *muxStream) peerClose() {
	s.mu.Lock()
	if !s.readClosed {
		s.readClosed = true
		s.readErr = io.EOF
	}
	s.mu.Unlock()
	s.notify(s.readNotify)
}

// peerReset aborts the stream in both directions.
func (s *muxStream) peerReset() {
	s.mu.Lock()
	if !s.readClosed {
		s.readClosed = true
		s.readErr = errMuxReset
	}
	if s.writeErr == nil {
		s.writeErr = errMuxReset
	}
	s.mu.Unlock()
	s.notify(s.readNotify)
	s.notify(s.winNotify)
}

// fail aborts the stream because the session died.
func (s *muxStream) fail(err error) {
	s.mu.Lock()
	if !s.readClosed {
		s.readClosed = true
		s.readErr = err
	}
	if s.writeErr == nil {
		s.writeErr = err
	}
	s.mu.Unlock()
	s.notify(s.readNotify)
	s.notify(s.winNotify)
}

// addWindow grants send credit from a WINDOW_UPDATE frame.
func (s *muxStream) addWindow(credit int64) {
	s.mu.Lock()
	s.sendWindow += credit
	s.mu.Unlock()
	s.notify(s.winNotify)
}

// recvWindowSize reports the receiver-side window for tests.
func (s *muxStream) recvWindowSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.windowSize
}

// sendCredit flushes consumed bytes as a WINDOW_UPDATE frame.
func (s *muxStream) sendCredit(credit int64) {
	if credit <= 0 {
		return
	}
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(credit))
	_ = s.session.writeFrame(s.id, muxFrameWindow, payload[:])
}

func (s *muxStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.inbox) > 0 {
			chunk := s.inbox[0]
			n := copy(p, chunk[s.readOff:])
			s.readOff += n
			if s.readOff >= len(chunk) {
				s.inbox = s.inbox[1:]
				s.readOff = 0
			}
			s.inboxBytes -= n
			s.creditPending += int64(n)
			credit := int64(0)
			if s.creditPending >= muxWindowCreditThreshold {
				credit = s.creditPending
				s.creditPending = 0
				// Receiver-driven window growth: the peer has
				// already sent a full window's worth, so this
				// is a bulk stream and the window may be its
				// limiter. Double the window (up to
				// muxMaxWindow) by adding the growth to this
				// credit. (An instantaneous "peer used the
				// whole granted window" check does not work:
				// with 32 KiB credit quanta the sender is
				// always one credit behind the grant, so it
				// never fires. Cumulative bytes sent is the
				// robust signal.) A stalled stream never
				// grows: it consumes nothing, so it sends no
				// credits and its peer never sends a full
				// window. Growth is bounded: at most two
				// doublings (16 -> 32 -> 64 MiB) per stream.
				if s.received >= s.windowSize && s.windowSize < muxMaxWindow {
					growth := s.windowSize
					if s.windowSize*2 > muxMaxWindow {
						growth = muxMaxWindow - s.windowSize
					}
					s.windowSize += growth
					credit += growth
				}
				s.granted += credit
			}
			s.mu.Unlock()
			// Credit outside the lock: the write path must never
			// be taken while holding the stream lock.
			s.sendCredit(credit)
			return n, nil
		}
		if s.readClosed {
			err := s.readErr
			s.mu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		if s.closed {
			s.mu.Unlock()
			return 0, errMuxClosed
		}
		deadline := s.readDeadline
		notify := s.readNotify
		s.mu.Unlock()

		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(wait)
			select {
			case <-notify:
				timer.Stop()
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			case <-s.session.Done():
				timer.Stop()
				return 0, errMuxClosed
			}
		} else {
			select {
			case <-notify:
			case <-s.session.Done():
				return 0, errMuxClosed
			}
		}
	}
}

func (s *muxStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunkLen := len(p)
		if chunkLen > muxChunkSize {
			chunkLen = muxChunkSize
		}
		// Wait for window.
		for {
			s.mu.Lock()
			if s.writeErr != nil {
				err := s.writeErr
				s.mu.Unlock()
				return total, err
			}
			if s.writeClosed || s.closed {
				s.mu.Unlock()
				return total, errMuxClosed
			}
			if s.sendWindow > 0 {
				if int64(chunkLen) > s.sendWindow {
					chunkLen = int(s.sendWindow)
				}
				s.sendWindow -= int64(chunkLen)
				s.mu.Unlock()
				break
			}
			deadline := s.writeDeadline
			notify := s.winNotify
			s.mu.Unlock()
			if !deadline.IsZero() {
				wait := time.Until(deadline)
				if wait <= 0 {
					return total, os.ErrDeadlineExceeded
				}
				timer := time.NewTimer(wait)
				select {
				case <-notify:
					timer.Stop()
				case <-timer.C:
					return total, os.ErrDeadlineExceeded
				case <-s.session.Done():
					timer.Stop()
					return total, errMuxClosed
				}
			} else {
				select {
				case <-notify:
				case <-s.session.Done():
					return total, errMuxClosed
				}
			}
		}
		if err := s.session.writeFrame(s.id, muxFrameData, p[:chunkLen]); err != nil {
			s.mu.Lock()
			if s.writeErr == nil {
				s.writeErr = err
			}
			s.mu.Unlock()
			return total, err
		}
		p = p[chunkLen:]
		total += chunkLen
	}
	return total, nil
}

// CloseWrite sends the close frame: no more data from this side.
// The read side stays open until the peer closes or resets.
func (s *muxStream) CloseWrite() error {
	s.mu.Lock()
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	s.mu.Unlock()
	return s.session.writeFrame(s.id, muxFrameClose, nil)
}

// Close aborts the stream: half-close the write side, flush any
// pending credit, drop the inbox, and remove the stream from the
// session so its ID is never reused.
func (s *muxStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	wasWriteClosed := s.writeClosed
	s.writeClosed = true
	if !s.readClosed {
		s.readClosed = true
		if s.readErr == nil {
			s.readErr = errMuxClosed
		}
	}
	if s.writeErr == nil {
		s.writeErr = errMuxClosed
	}
	credit := s.creditPending
	s.creditPending = 0
	s.inbox = nil
	s.inboxBytes = 0
	s.mu.Unlock()
	s.session.removeStream(s.id)
	s.notify(s.readNotify)
	s.notify(s.winNotify)
	if credit > 0 {
		s.sendCredit(credit)
	}
	if !wasWriteClosed {
		_ = s.session.writeFrame(s.id, muxFrameClose, nil)
	}
	return nil
}

func (s *muxStream) LocalAddr() net.Addr  { return s.session.conn.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr { return s.session.conn.RemoteAddr() }

func (s *muxStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.mu.Unlock()
	s.notify(s.readNotify)
	s.notify(s.winNotify)
	return nil
}

func (s *muxStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	s.notify(s.readNotify)
	return nil
}

func (s *muxStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	s.notify(s.winNotify)
	return nil
}
