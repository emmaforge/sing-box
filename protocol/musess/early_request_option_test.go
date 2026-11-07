package musess

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

// Tri-state resolution of the early_request option (defaults flip,
// ratified 2026-11-05): unset and explicit true enable the feature
// on BOTH peers; only an explicit false disables it. Parsing goes
// through the same UnmarshalExtended path the config loader uses.

func parseInboundEarly(t *testing.T, config string) option.MusessInboundOptions {
	t.Helper()
	parsed, err := singjson.UnmarshalExtended[option.MusessInboundOptions]([]byte(config))
	if err != nil {
		t.Fatalf("unmarshal inbound %s: %v", config, err)
	}
	return parsed
}

func parseOutboundEarly(t *testing.T, config string) option.MusessOutboundOptions {
	t.Helper()
	parsed, err := singjson.UnmarshalExtended[option.MusessOutboundOptions]([]byte(config))
	if err != nil {
		t.Fatalf("unmarshal outbound %s: %v", config, err)
	}
	return parsed
}

func TestEarlyRequestTriStateResolution(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		enabled bool
	}{
		{"unset", `{}`, true},
		{"explicit true", `{"early_request":true}`, true},
		{"explicit false", `{"early_request":false}`, false},
	}
	for _, tc := range cases {
		if got := parseInboundEarly(t, tc.config).EarlyRequestEnabled(); got != tc.enabled {
			t.Fatalf("inbound %s: EarlyRequestEnabled() = %v, want %v", tc.name, got, tc.enabled)
		}
		if got := parseOutboundEarly(t, tc.config).EarlyRequestEnabled(); got != tc.enabled {
			t.Fatalf("outbound %s: EarlyRequestEnabled() = %v, want %v", tc.name, got, tc.enabled)
		}
	}
}

// The wire form must stay stable: an unset option marshals to no
// field at all (old configs round-trip byte-identically), while an
// explicit false survives as "early_request":false instead of
// being dropped by omitempty.
func TestEarlyRequestMarshalStability(t *testing.T) {
	unset, err := json.Marshal(option.MusessOutboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unset), "early_request") {
		t.Fatalf("unset option leaked into JSON: %s", unset)
	}
	disabled := false
	explicit, err := json.Marshal(option.MusessOutboundOptions{EarlyRequest: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(explicit), `"early_request":false`) {
		t.Fatalf("explicit false lost in JSON: %s", explicit)
	}
}

// The four effective client x server combinations, exercised at
// the framing level with exactly the branches the production paths
// take: the outbound writes a sealed header when enabled and a
// plain one when not (dialStream, FEC off); the inbound reads with
// readRequestAuto when enabled and the stock readRequest when not
// (serveAuthenticated). Every combination succeeds except an
// enabled client against a disabled server, which must fail
// cleanly at the header read - the documented rollout hazard that
// the servers-first rule exists to avoid. The peers' option states
// are the tri-state JSON forms, resolved through the same helpers
// the constructors use, so the unset default is covered too.
func TestEarlyRequestCombinationFraming(t *testing.T) {
	states := map[string]string{
		"unset": `{}`,
		"true":  `{"early_request":true}`,
		"false": `{"early_request":false}`,
	}
	for clientName, clientConfig := range states {
		clientOn := parseOutboundEarly(t, clientConfig).EarlyRequestEnabled()
		for serverName, serverConfig := range states {
			serverOn := parseInboundEarly(t, serverConfig).EarlyRequestEnabled()

			var wire bytes.Buffer
			if clientOn {
				header, err := buildRequestHeader(false, commandTCP, earlyTestDest, 0)
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := sealRequest(earlyTestProofKey, header)
				if err != nil {
					t.Fatal(err)
				}
				wire.Write(sealed)
			} else {
				if err := writeRequest(&wire, commandTCP, earlyTestDest); err != nil {
					t.Fatal(err)
				}
			}

			var command byte
			var dest M.Socksaddr
			var err error
			if serverOn {
				_, command, _, dest, err = readRequestAuto(&wire, earlyTestProofKey, nil, nil)
			} else {
				_, command, _, dest, err = readRequest(&wire)
			}

			label := "client=" + clientName + " server=" + serverName
			if clientOn && !serverOn {
				if err == nil {
					t.Fatalf("%s: enabled client against disabled server was accepted, want clean rejection", label)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: read failed: %v", label, err)
			}
			if command != commandTCP || dest != earlyTestDest {
				t.Fatalf("%s: got command %d dest %v", label, command, dest)
			}
		}
	}
}
