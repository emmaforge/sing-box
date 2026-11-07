package musess

import (
	"context"
	"crypto/ecdh"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	utls "github.com/metacubex/utls"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MusessOutboundOptions](registry, C.TypeMusess, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	dialer       N.Dialer
	serverAddr   M.Socksaddr
	serverName   string
	serverPublic *ecdh.PublicKey
	uuid         string
	secret       string
	fecMode      fecMode
	earlyRequest bool
	deshell      bool
	mux          bool
	muxBypass    []string
	// muxAdaptiveBypass enables the loss-time health bypass
	// (see MusessOutboundOptions.MuxAdaptiveBypass).
	muxAdaptiveBypass bool
	// Speculative direction-5 pieces, all default-off.
	zeroRTT   bool
	raceAddrs []M.Socksaddr
	warmPool  *warmPool

	muxMu      sync.Mutex
	muxSession *muxSession
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MusessOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverPublic, err := ParsePublicKey(options.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "musess: parse public_key")
	}
	serverName := options.ServerName
	if serverName == "" {
		serverName = options.Server
	}
	mode, err := parseFECMode(options.FEC)
	if err != nil {
		return nil, err
	}
	out := &Outbound{
		Adapter:           outbound.NewAdapterWithDialerOptions(C.TypeMusess, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:            logger,
		dialer:            outboundDialer,
		serverAddr:        options.ServerOptions.Build(),
		serverName:        serverName,
		serverPublic:      serverPublic,
		uuid:              options.UUID,
		secret:            options.Secret,
		fecMode:           mode,
		earlyRequest:      options.EarlyRequestEnabled(),
		deshell:           options.Deshell,
		mux:               options.Mux,
		muxBypass:         options.MuxBypass,
		muxAdaptiveBypass: options.MuxAdaptiveBypass,
		zeroRTT:           options.ZeroRTT,
	}
	for _, addr := range options.RaceServers {
		parsed := M.ParseSocksaddr(addr)
		if parsed.IsValid() {
			out.raceAddrs = append(out.raceAddrs, parsed)
		} else {
			return nil, E.New("musess: invalid race_servers address: ", addr)
		}
	}
	if size := options.WarmPoolSize(); size > 0 {
		idleTTL := time.Duration(options.WarmPoolIdleSeconds) * time.Second
		out.warmPool = newWarmPool(size, idleTTL, func(warmCtx context.Context) (*warmSession, error) {
			return out.establishSession(warmCtx, out.serverAddr)
		}, logger)
		// Warm from client startup, not from the first request, so
		// the pool is populated before the first real request
		// arrives. The warmer stops when the service ctx ends.
		out.warmPool.Start(ctx)
	}
	return out, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.mux && !h.muxBypassed(destination) {
			if !h.muxAdaptiveBypass || !h.muxHealthBypass() {
				return h.dialMux(ctx, destination)
			}
			h.logger.DebugContext(ctx, "musess: mux session degraded, bypassing mux for ", destination)
		}
		// Warm pool first: a pre-established session costs no
		// handshake at all. A checkout that fails (stale session)
		// falls through to a fresh dial below.
		if h.warmPool != nil {
			if session := h.warmPool.get(); session != nil {
				stream, fecActive, err := h.finishSession(ctx, session, commandTCP, destination)
				if err == nil {
					if fecActive {
						return newFECConn(stream, h.fecMode, false, h.logger), nil
					}
					return stream, nil
				}
				h.logger.DebugContext(ctx, "musess: pooled session checkout failed, dialing fresh: ", err)
			}
		}
		var stream net.Conn
		var fecActive bool
		var err error
		if len(h.raceAddrs) > 0 {
			stream, fecActive, err = h.dialRaced(ctx, commandTCP, destination)
		} else {
			stream, fecActive, err = h.dialStream(ctx, commandTCP, destination)
		}
		if err != nil {
			return nil, err
		}
		if fecActive {
			return newFECConn(stream, h.fecMode, false, h.logger), nil
		}
		return stream, nil
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return newPacketStreamConn(packetConn.(framedPacketConn), destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

// muxBypassed reports whether destination is on the mux-bypass
// list: an entry matches if it equals the destination's "host:port",
// its host, or its ":port". A bypassed destination takes the plain
// path (warm pool / dialStream) even when mux is on.
// muxHealthBypass reports whether a new stream should skip the
// mux session because the session is currently degraded. No
// session (or a dead one) means no signal, so the stream goes
// through mux and establishes the session. While degraded, a
// half-open probe dial is let through once per probe interval so
// the session can prove it recovered; every other dial bypasses.
func (h *Outbound) muxHealthBypass() bool {
	h.muxMu.Lock()
	session := h.muxSession
	h.muxMu.Unlock()
	if session == nil || !session.Alive() {
		return false
	}
	if !session.healthDegraded() {
		return false
	}
	return !session.healthProbeDue()
}

func (h *Outbound) muxBypassed(destination M.Socksaddr) bool {
	// Host branch: Fqdn for domain destinations, Addr for IP ones.
	// (Addr is the zero netip.Addr for an FQDN destination, whose
	// String() is "invalid IP" — never compare against it.)
	host := destination.Fqdn
	if host == "" {
		host = destination.Addr.String()
	}
	port := ":" + strconv.Itoa(int(destination.Port))
	for _, pattern := range h.muxBypass {
		if pattern == destination.String() || pattern == host || pattern == port {
			return true
		}
	}
	return false
}

// dialMux opens one TCP stream on the outbound's shared mux
// session (one session per outbound, lazily dialed). If the
// session is dead the open fails and the session is redialed
// once, then the open is retried once — a single redial, no
// silent fallback to the plain path.
func (h *Outbound) dialMux(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	session, err := h.getMuxSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := session.openStream(commandTCP, destination)
	if err != nil {
		h.dropMuxSession(session)
		session, err = h.getMuxSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = session.openStream(commandTCP, destination)
		if err != nil {
			return nil, err
		}
	}
	return stream, nil
}

// muxSession returns the outbound's live session, dialing a new
// one (handshake + proof exactly as the plain path, early_request
// included) when there is none or it died. FEC composition: when
// the session negotiates FEC, the session runs over fec.Conn —
// the mux frames are the FEC stream's payload, so the fec option
// is honoured instead of silently ignored. (On the TCP path FEC
// is pure cost with zero benefit — redundancy is always 0 on a
// reliable stream — so leave fec off there; see the Mux option
// comment.) Deshell is never requested for a mux session:
// dialStream requests it only for commandTCP streams.
func (h *Outbound) getMuxSession(ctx context.Context) (*muxSession, error) {
	h.muxMu.Lock()
	defer h.muxMu.Unlock()
	if h.muxSession != nil && h.muxSession.Alive() {
		return h.muxSession, nil
	}
	// Warm pool first (mux-bulk experiment, warm-mux leg): a pooled
	// session has already paid the handshake + proof, so finishing
	// it as a mux session costs only the request round trip instead
	// of a full dial. The pool is warmed from client startup, so
	// the first real request after boot usually finds a session
	// ready. A checkout that fails (stale session) falls through
	// to a fresh dial below — same as the plain path.
	var stream net.Conn
	var fecActive bool
	var err error
	if h.warmPool != nil {
		if session := h.warmPool.get(); session != nil {
			stream, fecActive, err = h.finishSession(ctx, session, commandMux, muxPlaceholderDest)
			if err != nil {
				h.logger.DebugContext(ctx, "musess: pooled mux session checkout failed, dialing fresh: ", err)
				stream = nil
			}
		}
	}
	if stream == nil {
		stream, fecActive, err = h.dialStream(ctx, commandMux, muxPlaceholderDest)
		if err != nil {
			return nil, err
		}
	}
	var transport net.Conn = stream
	if fecActive {
		transport = newFECConn(stream, h.fecMode, false, h.logger)
		h.logger.InfoContext(ctx, "musess: mux session with FEC active")
	}
	session := newMuxSession(transport, true, nil, h.logger)
	session.start()
	h.muxSession = session
	h.logger.InfoContext(ctx, "musess: mux session established")
	return session, nil
}

func (h *Outbound) dropMuxSession(session *muxSession) {
	h.muxMu.Lock()
	defer h.muxMu.Unlock()
	if h.muxSession == session {
		h.muxSession = nil
	}
	session.Close()
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	stream, fecActive, err := h.dialStream(ctx, commandUDP, destination)
	if err != nil {
		return nil, err
	}
	if fecActive {
		return newFECPacketConn(newFECConn(stream, h.fecMode, true, h.logger)), nil
	}
	return newStreamPacketConn(stream), nil
}

// dialStream establishes one authenticated musess TLS connection and
// sends the request header for the given command and destination.
//
// The ClientHello is built with uTLS following the same pattern as
// this tree's REALITY client: the ML-KEM key share is removed so the
// session key share is a plain X25519 share whose private key the
// handshake state exposes; that private key doubles as the musess
// auth ephemeral, binding the auth tag to the very key exchange that
// becomes the TLS session.
//
// This is the stock M1 flight order, unchanged: the early sealed
// request is written before the server proof is read. Only the
// pooled path (establishSession + finishSession) differs, because a
// pooled session has no destination yet when it is established.
func (h *Outbound) dialStream(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, bool, error) {
	return h.dialStreamTo(ctx, command, destination, h.serverAddr)
}

func (h *Outbound) dialStreamTo(ctx context.Context, command byte, destination M.Socksaddr, addr M.Socksaddr) (net.Conn, bool, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, addr)
	if err != nil {
		return nil, false, err
	}
	return h.dialStreamOnConn(ctx, command, destination, rawConn)
}

// dialStreamOnConn runs the M1 handshake + request sequence over an
// already-dialed TCP connection. Racing dials the raw connections
// itself so it can close losing legs; everything else funnels here.
func (h *Outbound) dialStreamOnConn(ctx context.Context, command byte, destination M.Socksaddr, rawConn net.Conn) (net.Conn, bool, error) {
	tlsConn, sessionAuth, err := h.clientHandshake(ctx, rawConn)
	if err != nil {
		rawConn.Close()
		return nil, false, err
	}
	connState := tlsConn.ConnectionState()
	exporter, err := connState.ExportKeyingMaterial("musess", nil, 32)
	if err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: export keying material")
	}
	if h.zeroRTT {
		// Safe 0-RTT: non-authenticated transport-recovery data
		// only, sealed under the exporter key. A server that does
		// not understand it still parses and discards the frame
		// (see readRequestAuto), so this never breaks the session.
		if frame, _, err := sealZeroRTTFrame(exporter, h.zeroRTTPayload()); err == nil {
			if _, err = tlsConn.Write(frame); err != nil {
				tlsConn.Close()
				return nil, false, err
			}
		}
		// A sealing failure is not fatal: the frame carries no
		// auth data, so the session proceeds without it.
	}
	// Deshell (Direction 4): request it only for TCP streams with
	// FEC off (the two are mutually exclusive). It needs a v2 header
	// so the server can answer in the status byte.
	fecEnabled := h.fecMode.enabled()
	deshellRequested := h.deshell && command == commandTCP && !fecEnabled
	wantV2 := fecEnabled || deshellRequested
	var headerFlags byte
	if fecEnabled {
		headerFlags = fecFlagForward | fecFlagReverse
	}
	if deshellRequested {
		headerFlags |= deshellFlag
		// Advertise deshell ack v1: this client sends the
		// post-switch ack when the server asks for it (see
		// deshell.go). An old server ignores the bit and never
		// asks, so the client sends nothing then.
		headerFlags |= deshellAckFlag
	}
	if h.earlyRequest {
		// Pipeline the request header - sealed under the session
		// request key - immediately after the handshake instead of
		// spending one leg flight waiting for the server proof
		// first. The proof is still verified below, before any
		// relayed data is consumed.
		header, err := buildRequestHeader(wantV2, command, destination, headerFlags)
		if err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		sealed, err := sealRequest(sessionAuth.proofKey, header)
		if err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		if _, err = tlsConn.Write(sealed); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
	}
	proof := make([]byte, serverProofLength)
	if _, err = io.ReadFull(tlsConn, proof); err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: read server proof")
	}
	if !sessionAuth.VerifyServerProof(proof, exporter) {
		tlsConn.Close()
		return nil, false, E.New("musess: server proof mismatch (wrong server key or secret?)")
	}
	if !wantV2 {
		if !h.earlyRequest {
			// Milestone-1 wire behaviour, unchanged.
			if err = writeRequest(tlsConn, command, destination); err != nil {
				tlsConn.Close()
				return nil, false, err
			}
		}
		return tlsConn, false, nil
	}
	if !h.earlyRequest {
		if err = writeRequestV2(tlsConn, command, destination, headerFlags); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
	}
	var status [1]byte
	if _, err = io.ReadFull(tlsConn, status[:]); err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: read FEC status")
	}
	if status[0]&fecStatusFlag != 0 {
		h.logger.InfoContext(ctx, "musess: FEC negotiated with server for ", destination)
		return tlsConn, true, nil
	}
	if deshellRequested && status[0]&deshellStatusFlag != 0 {
		// The server agreed to deshell. The wrapper switches to
		// the raw stream once it sees the server's go-signal (see
		// deshell.go); until then it is a plain TLS pass-through.
		// ackWanted is true when the server also set the ack bit:
		// the client sends one ack byte on the raw socket right
		// after switching, so the server knows the client's TLS
		// read-ahead has finished before it releases its held
		// first downstream raw bytes. An old server never sets
		// the bit and the client sends nothing, exactly as before.
		return newClientDeshellConn(ctx, tlsConn, rawConn, true, status[0]&deshellAckStatusFlag != 0, h.logger), false, nil
	}
	if fecEnabled {
		h.logger.InfoContext(ctx, "musess: server declined FEC, continuing without it")
	} else if deshellRequested {
		h.logger.DebugContext(ctx, "musess: server declined deshell, continuing fully encrypted")
	}
	return tlsConn, false, nil
}

// zeroRTTPayload builds this session's transport-recovery payload:
// the FEC mode hint only. No identity, no secret, no destination,
// no request — by construction.
func (h *Outbound) zeroRTTPayload() zeroRTTPayload {
	var hint byte
	switch h.fecMode.optionString() {
	case "auto":
		hint = 1
	case "on":
		hint = 2
	}
	return zeroRTTPayload{FECModeHint: hint}
}

// establishSession performs the handshake + server-proof verification
// for a warm-pool session and stops there: no request is sent, because
// the session has no destination yet. The proofKey and exporter are
// retained so checkout (finishSession) can seal the request and the
// 0-RTT frame; raw is retained so checkout can hand it to the
// deshell client wrapper when the server agrees to deshell.
func (h *Outbound) establishSession(ctx context.Context, addr M.Socksaddr) (*warmSession, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, addr)
	if err != nil {
		return nil, err
	}
	tlsConn, sessionAuth, err := h.clientHandshake(ctx, rawConn)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	connState := tlsConn.ConnectionState()
	exporter, err := connState.ExportKeyingMaterial("musess", nil, 32)
	if err != nil {
		tlsConn.Close()
		return nil, E.Cause(err, "musess: export keying material")
	}
	proof := make([]byte, serverProofLength)
	if _, err = io.ReadFull(tlsConn, proof); err != nil {
		tlsConn.Close()
		return nil, E.Cause(err, "musess: read server proof")
	}
	if !sessionAuth.VerifyServerProof(proof, exporter) {
		tlsConn.Close()
		return nil, E.New("musess: server proof mismatch (wrong server key or secret?)")
	}
	return &warmSession{conn: tlsConn, raw: rawConn, proofKey: sessionAuth.proofKey, exporter: exporter, createdAt: time.Now()}, nil
}

// finishSession checks a pooled session out for one request: the
// 0-RTT frame (if enabled), then the request header, then the status
// byte. Any failure closes the session and reports the error so the
// caller can fall back to a fresh dial. The header and status
// handling mirror dialStreamOnConn exactly — including the deshell
// negotiation, so a pooled checkout can deshell just like a fresh
// dial (the server agrees in the same status byte; the client
// wrapper needs the pooled session's raw connection).
func (h *Outbound) finishSession(ctx context.Context, session *warmSession, command byte, destination M.Socksaddr) (net.Conn, bool, error) {
	tlsConn := session.conn
	if h.zeroRTT {
		if frame, _, err := sealZeroRTTFrame(session.exporter, h.zeroRTTPayload()); err == nil {
			if _, err = tlsConn.Write(frame); err != nil {
				tlsConn.Close()
				return nil, false, err
			}
		}
	}
	fecEnabled := h.fecMode.enabled()
	deshellRequested := h.deshell && command == commandTCP && !fecEnabled
	wantV2 := fecEnabled || deshellRequested
	var headerFlags byte
	if fecEnabled {
		headerFlags = fecFlagForward | fecFlagReverse
	}
	if deshellRequested {
		headerFlags |= deshellFlag
		headerFlags |= deshellAckFlag
	}
	if h.earlyRequest {
		header, err := buildRequestHeader(wantV2, command, destination, headerFlags)
		if err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		sealed, err := sealRequest(session.proofKey, header)
		if err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		if _, err = tlsConn.Write(sealed); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
	} else if !wantV2 {
		if err := writeRequest(tlsConn, command, destination); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		return tlsConn, false, nil
	} else {
		if err := writeRequestV2(tlsConn, command, destination, headerFlags); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
	}
	if !wantV2 {
		return tlsConn, false, nil
	}
	var status [1]byte
	if _, err := io.ReadFull(tlsConn, status[:]); err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: read FEC status")
	}
	if status[0]&fecStatusFlag != 0 {
		h.logger.InfoContext(ctx, "musess: FEC negotiated with server for ", destination)
		return tlsConn, true, nil
	}
	if deshellRequested && status[0]&deshellStatusFlag != 0 {
		// The server agreed to deshell: same wrapper as a fresh
		// dial, over the pooled session's raw connection.
		return newClientDeshellConn(ctx, tlsConn, session.raw, true, status[0]&deshellAckStatusFlag != 0, h.logger), false, nil
	}
	if fecEnabled {
		h.logger.InfoContext(ctx, "musess: server declined FEC, continuing without it")
	} else if deshellRequested {
		h.logger.DebugContext(ctx, "musess: server declined deshell, continuing fully encrypted")
	}
	return tlsConn, false, nil
}

// dialRaced dials the primary and every alternate endpoint in
// parallel and returns the first session to complete handshake +
// proof + request. Losers are closed at once and their bytes counted
// as waste. If every leg fails, the last error is returned.
func (h *Outbound) dialRaced(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, bool, error) {
	addrs := append([]M.Socksaddr{h.serverAddr}, h.raceAddrs...)
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type legResult struct {
		index     int
		conn      net.Conn
		fecActive bool
		err       error
	}
	results := make(chan legResult, len(addrs))
	// legs tracks each leg's raw counting connection so the winner
	// selection can close every loser promptly.
	legs := make([]*countingConn, len(addrs))
	counted := make([]bool, len(addrs))
	var legsMu sync.Mutex
	// countWaste adds one leg's bytes to the waste total exactly
	// once, however many paths observe the leg finishing.
	countWaste := func(index int) {
		legsMu.Lock()
		defer legsMu.Unlock()
		if index < 0 || index >= len(legs) || counted[index] || legs[index] == nil {
			return
		}
		counted[index] = true
		atomic.AddInt64(&globalRaceStats.WastedBytes, legs[index].WastedBytes())
	}
	for i, addr := range addrs {
		go func(index int, addr M.Socksaddr) {
			rawConn, err := h.dialer.DialContext(raceCtx, N.NetworkTCP, addr)
			if err != nil {
				results <- legResult{index: index, err: err}
				return
			}
			counter := &countingConn{Conn: rawConn}
			legsMu.Lock()
			legs[index] = counter
			legsMu.Unlock()
			conn, fecActive, err := h.dialStreamOnConn(raceCtx, command, destination, counter)
			if err != nil {
				countWaste(index)
				counter.Close()
				results <- legResult{index: index, err: err}
				return
			}
			results <- legResult{index: index, conn: conn, fecActive: fecActive}
		}(i, addr)
	}
	atomic.AddInt64(&globalRaceStats.Races, 1)
	var lastErr error
	received := 0
	for received < len(addrs) {
		result := <-results
		received++
		if result.err != nil {
			lastErr = result.err
			continue
		}
		// Winner found: stop the other legs and close them.
		if result.index == 0 {
			atomic.AddInt64(&globalRaceStats.WonByFirst, 1)
		} else {
			atomic.AddInt64(&globalRaceStats.WonByAlt, 1)
		}
		cancel()
		legsMu.Lock()
		for i, leg := range legs {
			if leg == nil || i == result.index {
				continue
			}
			leg.Close()
		}
		legsMu.Unlock()
		for i := range legs {
			if i != result.index {
				countWaste(i)
			}
		}
		// Drain the remaining results in the background so no
		// goroutine blocks on send; their legs are already closed
		// above (or counted when they report in), so they return
		// promptly.
		remaining := len(addrs) - received
		go func() {
			for k := 0; k < remaining; k++ {
				r := <-results
				if r.index != result.index {
					countWaste(r.index)
				}
			}
		}()
		h.logger.InfoContext(ctx, "musess: race won by leg ", result.index, " of ", len(addrs))
		return result.conn, result.fecActive, nil
	}
	if lastErr == nil {
		lastErr = E.New("musess: all race legs failed")
	}
	return nil, false, lastErr
}

func (h *Outbound) clientHandshake(ctx context.Context, rawConn net.Conn) (*utls.UConn, *ClientSessionAuth, error) {
	uConfig := &utls.Config{
		ServerName:             h.serverName,
		InsecureSkipVerify:     true, // server identity is verified by the musess proof, not by PKI: the presented certificate belongs to the borrowed destination's name and is locally issued (milestone 1; see README)
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
	}
	uConn := utls.UClient(rawConn, uConfig, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		return nil, nil, err
	}
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
			// The parrot's renegotiation_info extension makes uTLS set
			// Config.Renegotiation = RenegotiateOnceAsClient whenever
			// the hello state is (re)built, which disables
			// ConnectionState().ExportKeyingMaterial after the
			// handshake - and the musess server proof is bound to the
			// TLS exporter. A GenericExtension emits the identical
			// wire bytes (type 65281, one zero byte) without the
			// config side effect.
			spec.Extensions[i] = &utls.GenericExtension{Id: 65281, Data: []byte{0x00}}
		}
	}
	if err = uConn.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, nil, err
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) < 39+sessionIDLength {
		return nil, nil, E.New("musess: unexpected client hello layout")
	}
	hello.SessionId = make([]byte, sessionIDLength)
	copy(hello.Raw[39:], hello.SessionId)
	fields, err := ParseClientHello(hello.Raw)
	if err != nil {
		return nil, nil, E.Cause(err, "musess: parse own client hello")
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil || keyShareKeys.Ecdhe == nil {
		return nil, nil, E.New("musess: no X25519 key share in client hello")
	}
	sessionAuth, err := NewClientSessionAuth(h.serverPublic, keyShareKeys.Ecdhe, h.uuid, h.secret)
	if err != nil {
		return nil, nil, err
	}
	sessionID := sessionAuth.SessionID(fields, time.Now())
	hello.SessionId = sessionID
	copy(hello.Raw[39:], sessionID)
	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	return uConn, sessionAuth, nil
}
