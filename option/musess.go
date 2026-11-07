package option

// earlyRequestEnabled resolves the tri-state early_request option
// shared by both musess peers: unset (nil) and explicit true both
// enable the feature; only an explicit false disables it. The
// default flipped to on when Emma ratified the rate-attack phase-2
// defaults recommendation (2026-11-05); see
// MusessInboundOptions.EarlyRequest for the rollout rule.
func earlyRequestEnabled(value *bool) bool {
	return value == nil || *value
}

type MusessInboundOptions struct {
	ListenOptions
	// Dest is the borrowed destination site's domain name. Authenticated
	// clients present it as the TLS SNI; unauthenticated connections are
	// forwarded to the real destination.
	Dest string `json:"dest,omitempty"`
	// DestPort is the port of the real destination to forward
	// unauthenticated connections to. Defaults to 443.
	DestPort uint16 `json:"dest_port,omitempty"`
	// DestAddress optionally overrides the address used to dial the real
	// destination (defaults to Dest). Intended for tests and for
	// deployments where the destination must be reached at a fixed IP.
	DestAddress string `json:"dest_address,omitempty"`
	// PrivateKey is the server's X25519 private key, base64-encoded
	// (32 bytes; raw standard or URL encoding both accepted).
	PrivateKey string `json:"private_key,omitempty"`
	// CertificatePath and KeyPath point to the PEM certificate and key
	// the inbound presents to *authenticated* clients when it terminates
	// TLS locally. Unauthenticated connections never see this
	// certificate: they are forwarded to the real destination.
	CertificatePath string       `json:"certificate_path,omitempty"`
	KeyPath         string       `json:"key_path,omitempty"`
	Users           []MusessUser `json:"users,omitempty"`
	// FEC selects the application-layer adaptive FEC (DESIGN.md
	// 5.2): "" or "off" disables it (milestone-1 wire behaviour);
	// "auto" is adaptive and disengages below 1% measured loss;
	// "on" is adaptive with a redundancy floor. FEC is used only
	// when both peers enable it.
	FEC string `json:"fec,omitempty"`
	// Mux enables multiplexed streams over one musess connection
	// (command 0x03, mux.go): many TCP streams share a single
	// authenticated session, so later streams skip the handshake
	// + proof setup. Opt-in, default OFF (ratified 2026-11-05):
	// it taxes bulk throughput and concentrates a user's traffic
	// into one long-lived connection. Where mux is enabled,
	// early_request should be enabled with it (it only
	// accelerates the session's own establishment). FEC composes
	// with mux: a mux session runs over fec.Conn when FEC is
	// negotiated for it — but on the TCP path FEC is pure cost
	// with zero benefit (redundancy is always 0 on a reliable
	// stream), so mux+fec stays off there unless fec is
	// explicitly enabled; do not enable it on TCP.
	// Known limitations (mux landing 2026-11-06,
	// MUX-LANDING-REPORT.md): delay100 bulk256 tax ~13.8% vs
	// stock (1465 vs 1699 Mbps); loss25 mixed load reverses
	// (mux 0.745 s vs stock 0.349 s, 2.1x slower); a held chunk
	// stalls the whole session (session-level shared fate),
	// not just one stream. A mux-enabled client against a server
	// with mux off fails cleanly after authentication (the
	// session is closed), never silently and never forwarded.
	Mux bool `json:"mux,omitempty"`
	// EarlyRequest (rate-attack phase 2, landed from the phase-1
	// experiment): the client pipelines its request header -
	// AEAD-sealed under a key derived from the session proof key -
	// immediately after the TLS handshake, instead of waiting one
	// flight for the server proof first, saving one leg RTT of
	// connection-setup latency. Authenticated path only; the
	// unauthenticated fallback is untouched.
	//
	// Tri-state, DEFAULT ON (ratified 2026-11-05): unset and true
	// enable it, only an explicit false disables it. On the server
	// side enabling it is safe with any client (the proof keeps
	// the stock order and plain requests are still accepted); a
	// client with it enabled against a server that has it disabled
	// fails cleanly after authentication. Rollout rule: deploy
	// servers first, then clients.
	EarlyRequest *bool `json:"early_request,omitempty"`
	// Deshell (Direction 4 prototype, XTLS-Vision-style post-handshake
	// zero-copy fast path): after the musess handshake, if the inner
	// traffic is confirmed TLS 1.3, both peers stop proxy-layer
	// re-encryption and forward the raw TCP stream with kernel
	// splice(). Default off; enable explicitly for measurement.
	// Cost: the deshell ack v1 adds ~+1 RTT to the first byte
	// (delay100 measured +197 ms); bulk goodput is unaffected.
	// Mutually exclusive with FEC (FEC wins when both are set).
	// Disguise is unchanged: the inner ClientHello always travels
	// inside the outer TLS, so its SNI is never exposed in plaintext.
	Deshell bool `json:"deshell,omitempty"`
	// ZeroRTT (speculative direction 5): when true the server
	// applies the transport state carried by a verified fresh
	// 0-RTT frame (see MusessOutboundOptions.ZeroRTT). The frame
	// itself is always parsed and discarded safely whether or not
	// this is set: a 0-RTT frame can never authenticate, route, or
	// serve anything, so a client sending one to a server with
	// this off must still get a normal working session.
	// Default false.
	ZeroRTT bool `json:"zero_rtt,omitempty"`
}

// EarlyRequestEnabled resolves the tri-state EarlyRequest option
// for the inbound: unset and true mean on, explicit false means off.
func (o MusessInboundOptions) EarlyRequestEnabled() bool {
	return earlyRequestEnabled(o.EarlyRequest)
}

type MusessUser struct {
	Name   string `json:"name,omitempty"`
	UUID   string `json:"uuid,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type MusessOutboundOptions struct {
	DialerOptions
	ServerOptions
	// ServerName is the borrowed destination domain presented as SNI.
	ServerName string `json:"server_name,omitempty"`
	// PublicKey is the server's X25519 public key, base64-encoded
	// (32 bytes; raw standard or URL encoding both accepted).
	PublicKey string `json:"public_key,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	Secret    string `json:"secret,omitempty"`
	// FEC: see MusessInboundOptions.FEC. The outbound requests FEC
	// when set to "auto" or "on"; the server may decline, in which
	// case the connection runs without it.
	FEC string `json:"fec,omitempty"`
	// Mux: see MusessInboundOptions.Mux. Opt-in, default off.
	Mux bool `json:"mux,omitempty"`
	// MuxBypass (mux-bulk experiment): destinations that skip the
	// mux session and always take the plain (warm-pool / dialStream)
	// path, even when Mux is on. Each entry is a destination host,
	// a "host:port", or a ":port" (port-only, e.g. ":443" for a
	// bulk endpoint). Rationale: a bulk download pays the mux tax
	// (~34% at delay100) for no benefit — one long flow gains
	// nothing from session reuse — while small flows gain ~2x from
	// it. A byte threshold cannot be known at open time (a
	// download's size is unknowable before the request, and
	// mid-stream migration is infeasible for downloads because the
	// response already flows on the mux stream), so the bypass is
	// config-based: the operator lists the bulk endpoints.
	MuxBypass []string `json:"mux_bypass,omitempty"`
	// MuxAdaptiveBypass (loss-time mux bypass): when true and Mux
	// is on, the client watches the mux session's health and
	// routes NEW streams to the plain path while the session is
	// degraded, instead of the static MuxBypass list. The trigger
	// is application-level only — the sandbox has no true packet
	// loss to observe (the loss relay holds chunks; the kernel
	// sees a slow peer, not drops) — so it uses two in-process
	// observables, all measured on the session itself (mux.go):
	// open-to-first-frame RTT inflation over the session's
	// minimum RTT, and live stalls (open streams, no data). A
	// session-goodput signal was tried and removed: a 1 s
	// delivery window cannot tell link collapse from box CPU
	// contention or from a legitimately slower workload (it
	// false-tripped twice, tripped truly never). Streams already on
	// the session stay there: mid-stream migration is infeasible
	// for downloads (the response already flows on the mux
	// stream), so the bypass only ever affects streams opened
	// after the trip — a bulk transfer that starts under loss
	// still pays the mux tax for its first rep, later reps
	// bypass. While degraded, a probe dial is let through only
	// after both a 30 s interval and 8 bypassed dials since the
	// last probe, so the session can prove it recovered; the
	// session itself is never torn down by this. Opt-in,
	// default off.
	MuxAdaptiveBypass bool `json:"mux_adaptive_bypass,omitempty"`
	// EarlyRequest: see MusessInboundOptions.EarlyRequest.
	// Tri-state, default on; set false only for servers known to
	// have it disabled.
	EarlyRequest *bool `json:"early_request,omitempty"`
	// Deshell (Direction 4 prototype, XTLS-Vision-style post-handshake
	// zero-copy fast path): after the musess handshake, if the inner
	// traffic is confirmed TLS 1.3, both peers stop proxy-layer
	// re-encryption and forward the raw TCP stream with kernel
	// splice(). Default off; enable explicitly for measurement.
	// Cost: the deshell ack v1 adds ~+1 RTT to the first byte
	// (delay100 measured +197 ms); bulk goodput is unaffected.
	// Mutually exclusive with FEC (FEC wins when both are set).
	// Disguise is unchanged: the inner ClientHello always travels
	// inside the outer TLS, so its SNI is never exposed in plaintext.
	Deshell bool `json:"deshell,omitempty"`
	// WarmPool (speculative direction 5): number of pre-established
	// authenticated musess sessions the client keeps warm so a new
	// request can reuse one instead of paying a full handshake.
	// Tri-state, default on: unset means 2; explicit 0 disables
	// the pool; any other value is the pool size. A pooled session
	// has completed the TLS handshake and the server-proof
	// verification but has NOT yet sent any request: the request
	// (destination included) is only sent when a real request
	// checks the session out, so pooling never sends auth data
	// speculatively. Sessions idle longer than
	// WarmPoolIdleSeconds are closed. Pool size 2 is the tested
	// value (SPECULATIVE-REPORT.md §4: delay100 first byte p95
	// −43%, burst −37%, extra traffic +1–2%); the warmer refills
	// all missing slots in parallel (merge-time fix for the
	// prototype's serial refill, which could not keep up at low
	// RTT — delay25 p95 never improved). Default flipped to on by
	// Emma 2026-11-07 (overrides improvement program §5.2 step 6,
	// which held default-on for outside-sandbox validation).
	WarmPool *int `json:"warm_pool,omitempty"`
	// WarmPoolIdleSeconds caps how long a pooled session may sit
	// idle. 0 means the default (10s).
	WarmPoolIdleSeconds int `json:"warm_pool_idle_seconds,omitempty"`
	// ZeroRTT (speculative direction 5): when true the client sends
	// one safe 0-RTT frame per session carrying ONLY
	// non-authenticated transport-recovery data (a one-time nonce
	// plus opaque transport state, sealed under a key derived
	// from the TLS exporter — no user secret, no UUID, no
	// destination, no request). The server verifies the nonce,
	// applies the transport state only if the nonce is fresh, and
	// treats a replayed or corrupt frame as if no 0-RTT data had
	// been sent: the session still needs its normal authenticated
	// request. As a first-byte tool it is KILL by design (0%
	// improvement — it never carries the request, decision #4);
	// keep it as a transport-state channel only. Default false.
	ZeroRTT bool `json:"zero_rtt,omitempty"`
	// RaceServers (speculative direction 5): alternate
	// "host:port" endpoints for the SAME server (same SNI and
	// keys), reached over different paths. When non-empty the
	// client dials the primary and every alternate in parallel
	// and the first session to complete handshake + proof
	// verification wins; losers are closed immediately. Bytes
	// spent on losing legs are counted (see speculative.go).
	// KILL by the strict criterion (extra traffic +12–14% clean
	// / +29% burst vs the ≤5% cap); keep default-off, use only
	// as a pool-miss fallback when explicitly enabled. Do not
	// restate the criterion to turn it on.
	RaceServers []string `json:"race_servers,omitempty"`
}

// EarlyRequestEnabled resolves the tri-state EarlyRequest option
// for the outbound: unset and true mean on, explicit false means off.
func (o MusessOutboundOptions) EarlyRequestEnabled() bool {
	return earlyRequestEnabled(o.EarlyRequest)
}

// WarmPoolSize resolves the tri-state WarmPool option: unset (nil)
// means the default pool size 2; explicit 0 disables the pool;
// any other value is the pool size.
func (o MusessOutboundOptions) WarmPoolSize() int {
	if o.WarmPool == nil {
		return 2
	}
	return *o.WarmPool
}
