package musess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	stdtls "crypto/tls"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MusessInboundOptions](registry, C.TypeMusess, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router       adapter.ConnectionRouterEx
	logger       logger.ContextLogger
	listener     *listener.Listener
	destName     string
	destDialAddr string
	privateKey   *ecdh.PrivateKey
	certificate  stdtls.Certificate
	users        []userEntry
	replay       *replayCache
	fecMode      fecMode
	earlyRequest bool
	deshell      bool
	mux          bool
	// zeroRTT is the inbound's safe-0-RTT state (nonce registry +
	// counters). It is always present so a 0-RTT frame is parsed
	// and discarded safely even when the server does not apply
	// 0-RTT transport state.
	zeroRTT *zeroRTTServer
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MusessInboundOptions) (adapter.Inbound, error) {
	routerEx, ok := router.(adapter.ConnectionRouterEx)
	if !ok {
		return nil, E.New("musess: router does not support connection routing")
	}
	if options.Dest == "" {
		return nil, E.New("musess: dest is required")
	}
	privateKey, err := ParsePrivateKey(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "musess: parse private_key")
	}
	certificate, err := stdtls.LoadX509KeyPair(options.CertificatePath, options.KeyPath)
	if err != nil {
		return nil, E.Cause(err, "musess: load certificate")
	}
	destPort := options.DestPort
	if destPort == 0 {
		destPort = 443
	}
	destHost := options.DestAddress
	if destHost == "" {
		destHost = options.Dest
	}
	mode, err := parseFECMode(options.FEC)
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter:      inbound.NewAdapter(C.TypeMusess, tag),
		router:       routerEx,
		logger:       logger,
		destName:     options.Dest,
		destDialAddr: net.JoinHostPort(destHost, strconv.Itoa(int(destPort))),
		privateKey:   privateKey,
		certificate:  certificate,
		replay:       newReplayCache(),
		fecMode:      mode,
		earlyRequest: options.EarlyRequestEnabled(),
		deshell:      options.Deshell,
		mux:          options.Mux,
		zeroRTT:      newZeroRTTServer(options.ZeroRTT),
	}
	for _, user := range options.Users {
		inbound.users = append(inbound.users, makeUserEntry(user.Name, user.UUID, user.Secret))
	}
	if len(inbound.users) == 0 {
		return nil, E.New("musess: at least one user is required")
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener)
}

// prefixConn replays bytes already consumed while peeking (the raw
// ClientHello bytes, followed by anything left in the buffered reader)
// before reading from the socket again.
type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	reader := bufio.NewReaderSize(conn, 16384)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	rawHello, fields, helloErr := ReadClientHello(reader)
	_ = conn.SetReadDeadline(time.Time{})
	var verified *verifiedAuth
	if helloErr == nil && fields != nil {
		verified = verifyClientHello(fields, h.users, h.privateKey, h.replay, time.Now())
	}
	if verified == nil {
		// Unauthenticated, invalid, replayed, or not TLS at all:
		// the connection is forwarded to the real destination and
		// answered by it, byte for byte. Nothing about this path
		// may differ from a direct connection to the destination.
		h.forwardToDest(ctx, conn, reader, rawHello, metadata.Source)
		return
	}
	h.serveAuthenticated(ctx, conn, reader, rawHello, verified, metadata, onClose)
}

func (h *Inbound) forwardToDest(ctx context.Context, conn net.Conn, reader *bufio.Reader, rawHello []byte, source M.Socksaddr) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	destConn, err := dialer.DialContext(ctx, N.NetworkTCP, h.destDialAddr)
	if err != nil {
		h.logger.DebugContext(ctx, "musess: forward to ", h.destDialAddr, " failed for ", source, ": ", err)
		conn.Close()
		return
	}
	defer destConn.Close()
	defer conn.Close()
	if len(rawHello) > 0 {
		if _, err = destConn.Write(rawHello); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, destConn)
		done <- struct{}{}
	}()
	go func() {
		// reader still holds any bytes buffered past the ClientHello.
		_, _ = io.Copy(destConn, reader)
		done <- struct{}{}
	}()
	<-done
}

func (h *Inbound) serveAuthenticated(ctx context.Context, conn net.Conn, reader *bufio.Reader, rawHello []byte, verified *verifiedAuth, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	tlsConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{h.certificate},
		MinVersion:   stdtls.VersionTLS13,
	}
	replay := io.MultiReader(bytes.NewReader(rawHello), reader)
	tlsConn := stdtls.Server(&prefixConn{Conn: conn, reader: replay}, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		h.logger.DebugContext(ctx, "musess: TLS handshake with authenticated client failed: ", err)
		conn.Close()
		return
	}
	connState := tlsConn.ConnectionState()
	exporter, err := connState.ExportKeyingMaterial("musess", nil, 32)
	if err != nil {
		h.logger.DebugContext(ctx, "musess: export keying material failed: ", err)
		conn.Close()
		return
	}
	var version, command, flags byte
	var destination M.Socksaddr
	if _, err = tlsConn.Write(ServerProof(verified.proofKey, exporter)); err != nil {
		conn.Close()
		return
	}
	if h.earlyRequest {
		// The proof goes first, in the stock order, on purpose:
		// the flight saving comes from the *client* pipelining its
		// sealed request with its handshake-completing flight
		// (phase 1's model: the critical path runs through the
		// request's arrival here, not the proof's arrival there),
		// so by the time the proof is written the sealed request
		// is already buffered and this read returns immediately.
		// Reading first and proving second - the phase-1
		// experiment's order - deadlocks against a stock client,
		// which waits for the proof before sending anything
		// (verified in phase 2: server-only enable hung the
		// connection until the client gave up). With proof-first,
		// readRequestAuto additionally accepts plain requests, so
		// enabling early_request on the server alone is safe for
		// stock clients; only the client side requires both peers.
		version, command, flags, destination, err = readRequestAuto(tlsConn, verified.proofKey, h.zeroRTT, exporter)
		if err != nil {
			h.logger.DebugContext(ctx, "musess: read early request failed: ", err)
			conn.Close()
			return
		}
	} else {
		// readRequestAuto also accepts plain requests, and a
		// leading safe 0-RTT frame, so a zero_rtt client works
		// against a server with early_request off as well.
		version, command, flags, destination, err = readRequestAuto(tlsConn, verified.proofKey, h.zeroRTT, exporter)
		if err != nil {
			h.logger.DebugContext(ctx, "musess: read request failed: ", err)
			conn.Close()
			return
		}
	}
	// FEC negotiation: a v2 client that set both direction bits
	// gets a one-byte answer — 0x01 if this inbound also has FEC
	// enabled (duplex active), 0x00 otherwise. A v1 client never
	// reads a status byte and never gets one.
	//
	// Deshell (Direction 4) rides the same status byte: bit 0x02
	// agrees to deshell when the option is on, the client requested
	// it, FEC is not active (the two are mutually exclusive), and
	// the command is a TCP stream. Agreeing here only arms the
	// wrapper's inspection; the actual switch happens inside the
	// wrapper once the first inner record proves to be a TLS 1.3
	// ClientHello (see deshell.go).
	//
	// Deshell ack v1 rides the same byte as well: bit 0x04 asks the
	// client for the post-switch ack, but only when the client
	// advertised deshellAckFlag (0x08) in its request header. An old
	// client never advertises it, so a new server never waits for
	// an ack it cannot send and pays no timeout.
	fecActive := false
	deshellAgreed := false
	deshellAckWanted := false
	if version == framingVersion2 {
		fecActive = h.fecMode.enabled() && flags&fecFlagForward != 0 && flags&fecFlagReverse != 0
		status := byte(0x00)
		if fecActive {
			status = fecStatusFlag
		}
		if !fecActive && h.deshell && command == commandTCP && flags&deshellFlag != 0 {
			deshellAgreed = true
			status |= deshellStatusFlag
			if flags&deshellAckFlag != 0 {
				deshellAckWanted = true
				status |= deshellAckStatusFlag
			}
		}
		if _, err = tlsConn.Write([]byte{status}); err != nil {
			conn.Close()
			return
		}
		if flags&fecFlagForward != 0 && !fecActive {
			h.logger.DebugContext(ctx, "musess: client requested FEC but inbound fec mode is ", h.fecMode.optionString())
		}
		if fecActive {
			h.logger.InfoContext(ctx, "musess: FEC duplex active (mode ", h.fecMode.optionString(), ") for ", metadata.Source)
		}
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = verified.user.name
	metadata.Destination = destination
	switch command {
	case commandTCP:
		h.logger.InfoContext(ctx, "[", verified.user.name, "] inbound connection to ", destination)
		if fecActive {
			h.router.RouteConnectionEx(ctx, newFECConn(tlsConn, h.fecMode, false, h.logger), metadata, onClose)
		} else if deshellAgreed {
			h.router.RouteConnectionEx(ctx, newServerDeshellConn(ctx, tlsConn, conn, reader, h.logger, deshellAckWanted), metadata, onClose)
		} else {
			h.router.RouteConnectionEx(ctx, tlsConn, metadata, onClose)
		}
	case commandUDP:
		h.logger.InfoContext(ctx, "[", verified.user.name, "] inbound packet connection to ", destination)
		// A musess UDP stream is an association opened for the
		// destination in its request header (the client creates one
		// stream per destination), so the router may use a connected
		// UDP socket for the outbound hop. Per-packet addresses are
		// still carried in the framing, and the client side never
		// mixes destinations on one stream.
		metadata.UDPConnect = true
		if fecActive {
			h.router.RoutePacketConnectionEx(ctx, newFECPacketConn(newFECConn(tlsConn, h.fecMode, true, h.logger)), metadata, onClose)
		} else {
			h.router.RoutePacketConnectionEx(ctx, newStreamPacketConn(tlsConn), metadata, onClose)
		}
	case commandMux:
		if !h.mux {
			// Fail closed: a mux client against a mux-off server
			// is rejected after authentication, never forwarded
			// and never mistaken for an unauthenticated connection.
			h.logger.DebugContext(ctx, "musess: mux session rejected (mux disabled on this inbound)")
			conn.Close()
			return
		}
		h.logger.InfoContext(ctx, "[", verified.user.name, "] inbound mux session from ", metadata.Source)
		// The data-plane transport: plain TLS, or fec.Conn when FEC
		// was negotiated for this session (mux sessions and plain
		// streams share this transport selection). Deshell never
		// applies here: it is agreed only for commandTCP streams.
		dataConn := net.Conn(tlsConn)
		if fecActive {
			dataConn = newFECConn(tlsConn, h.fecMode, false, h.logger)
		}
		h.serveMuxSession(ctx, dataConn, metadata, verified.user.name, onClose)
	default:
		h.logger.DebugContext(ctx, "musess: unknown command ", command)
		conn.Close()
	}
}

// serveMuxSession serves one multiplexed session: each stream the
// client opens is routed independently through the normal router
// with its own destination. Per-stream onClose is a no-op — the
// outer connection's onClose is invoked exactly once, when the
// session itself ends — so one session's N streams cannot trigger
// N outer-connection close callbacks.
func (h *Inbound) serveMuxSession(ctx context.Context, transport net.Conn, baseMeta adapter.InboundContext, user string, onClose N.CloseHandlerFunc) {
	session := newMuxSession(transport, false, func(stream *muxStream, command byte, destination M.Socksaddr) {
		metadata := baseMeta
		metadata.Destination = destination
		metadata.User = user
		h.logger.InfoContext(ctx, "[", user, "] inbound mux stream to ", destination)
		h.router.RouteConnectionEx(ctx, stream, metadata, func(error) {})
	}, h.logger)
	session.start()
	<-session.Done()
	if onClose != nil {
		onClose(nil)
	}
}
