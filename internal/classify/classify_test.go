package classify

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/probe"
)

var errProbe = errors.New("test probe failure")

func ok(host string, port int, mapped string, rtt time.Duration) probe.Result {
	return probe.Result{
		Server: probe.Server{Host: host, Port: port},
		Mapped: netip.MustParseAddrPort(mapped),
		RTT:    rtt,
	}
}

func fail(host string, port int) probe.Result {
	return probe.Result{
		Server: probe.Server{Host: host, Port: port},
		Err:    errProbe,
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name         string
		results      []probe.Result
		wantType     NATType
		wantLegacy   string
		wantCGNAT    bool
		wantP2P      string
		wantTURN     bool
		wantWarnings []string // subset; WarnFilteringBehaviorNotTested is always asserted separately
	}{
		{
			name:         "empty input — Blocked",
			results:      nil,
			wantType:     Blocked,
			wantP2P:      "unlikely",
			wantTURN:     true,
			wantWarnings: []string{WarnAllProbesFailed},
		},
		{
			name: "0/2 all errored — Blocked",
			results: []probe.Result{
				fail("google", 19302),
				fail("cloudflare", 3478),
			},
			wantType:     Blocked,
			wantP2P:      "unlikely",
			wantTURN:     true,
			wantWarnings: []string{WarnAllProbesFailed},
		},
		{
			name: "1/2 Google ok, Cloudflare fail — Unknown",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				fail("cloudflare", 3478),
			},
			wantType:     Unknown,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnInsufficientProbes},
		},
		{
			name: "1/2 Cloudflare ok, Google fail — Unknown (ordering mirror)",
			results: []probe.Result{
				fail("google", 19302),
				ok("cloudflare", 3478, "203.0.113.45:51820", 10*time.Millisecond),
			},
			wantType:     Unknown,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnInsufficientProbes},
		},
		{
			name: "2/2 same mapped — EIM",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "203.0.113.45:51820", 20*time.Millisecond),
			},
			wantType:   EndpointIndependentMapping,
			wantLegacy: "cone",
			wantP2P:    "likely",
			wantTURN:   false,
		},
		{
			name: "2/2 differing mapped — ADM-or-stricter",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "203.0.113.45:51822", 20*time.Millisecond),
			},
			wantType:     AddressDependentMapping,
			wantLegacy:   "symmetric",
			wantP2P:      "unlikely",
			wantTURN:     true,
			wantWarnings: []string{WarnADMOrStricter},
		},
		{
			name: "2/2 same mapped + CGNAT — EIM, forecast unknown",
			results: []probe.Result{
				ok("google", 19302, "100.64.1.5:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "100.64.1.5:51820", 20*time.Millisecond),
			},
			wantType:     EndpointIndependentMapping,
			wantLegacy:   "cone",
			wantCGNAT:    true,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnCGNATDetected},
		},
		{
			name: "2/2 differing + CGNAT — ADM, forecast unknown",
			results: []probe.Result{
				ok("google", 19302, "100.64.1.5:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "100.64.1.6:51821", 20*time.Millisecond),
			},
			wantType:     AddressDependentMapping,
			wantLegacy:   "symmetric",
			wantCGNAT:    true,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnADMOrStricter, WarnCGNATDetected},
		},
		{
			name: "1/2 success + CGNAT — Unknown, forecast unknown",
			results: []probe.Result{
				ok("google", 19302, "100.64.1.5:51820", 10*time.Millisecond),
				fail("cloudflare", 3478),
			},
			wantType:     Unknown,
			wantCGNAT:    true,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnInsufficientProbes, WarnCGNATDetected},
		},
		{
			name: "3/3 same mapped — EIM",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "203.0.113.45:51820", 20*time.Millisecond),
				ok("custom", 3478, "203.0.113.45:51820", 30*time.Millisecond),
			},
			wantType:   EndpointIndependentMapping,
			wantLegacy: "cone",
			wantP2P:    "likely",
			wantTURN:   false,
		},
		{
			name: "2/3 same + 1 fail — EIM (failures skipped)",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				fail("cloudflare", 3478),
				ok("custom", 3478, "203.0.113.45:51820", 30*time.Millisecond),
			},
			wantType:   EndpointIndependentMapping,
			wantLegacy: "cone",
			wantP2P:    "likely",
			wantTURN:   false,
		},
		{
			name: "3/3 one differs — ADM",
			results: []probe.Result{
				ok("google", 19302, "203.0.113.45:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "203.0.113.45:51820", 20*time.Millisecond),
				ok("custom", 3478, "203.0.113.45:51899", 30*time.Millisecond),
			},
			wantType:     AddressDependentMapping,
			wantLegacy:   "symmetric",
			wantP2P:      "unlikely",
			wantTURN:     true,
			wantWarnings: []string{WarnADMOrStricter},
		},
		{
			name: "non-CGNAT RFC1918-ish public IP 100.63.x outside 100.64/10 — not CGNAT",
			results: []probe.Result{
				ok("google", 19302, "100.63.255.255:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "100.63.255.255:51820", 20*time.Millisecond),
			},
			wantType:   EndpointIndependentMapping,
			wantLegacy: "cone",
			wantCGNAT:  false,
			wantP2P:    "likely",
			wantTURN:   false,
		},
		{
			name: "upper CGNAT edge 100.127.255.255 — still CGNAT",
			results: []probe.Result{
				ok("google", 19302, "100.127.255.255:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "100.127.255.255:51820", 20*time.Millisecond),
			},
			wantType:     EndpointIndependentMapping,
			wantLegacy:   "cone",
			wantCGNAT:    true,
			wantP2P:      "unknown",
			wantWarnings: []string{WarnCGNATDetected},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.results)

			if got.Type != tc.wantType {
				t.Errorf("Type = %v, want %v", got.Type, tc.wantType)
			}
			if got.LegacyName != tc.wantLegacy {
				t.Errorf("LegacyName = %q, want %q", got.LegacyName, tc.wantLegacy)
			}
			if got.CGNAT != tc.wantCGNAT {
				t.Errorf("CGNAT = %v, want %v", got.CGNAT, tc.wantCGNAT)
			}
			if got.FilteringTested {
				t.Errorf("FilteringTested = true, want false (invariant in v0.1)")
			}
			if got.Forecast.DirectP2P != tc.wantP2P {
				t.Errorf("DirectP2P = %q, want %q", got.Forecast.DirectP2P, tc.wantP2P)
			}
			if got.Forecast.TURNRequired != tc.wantTURN {
				t.Errorf("TURNRequired = %v, want %v", got.Forecast.TURNRequired, tc.wantTURN)
			}
			if !hasWarning(got.Warnings, WarnFilteringBehaviorNotTested) {
				t.Errorf("Warnings missing %q (always required in v0.1); got %v",
					WarnFilteringBehaviorNotTested, got.Warnings)
			}
			for _, want := range tc.wantWarnings {
				if !hasWarning(got.Warnings, want) {
					t.Errorf("Warnings missing %q; got %v", want, got.Warnings)
				}
			}
		})
	}
}

// TestClassify_NilSafe: the brain of the tool must not panic on degenerate
// inputs. Callers may hand us nil or zero-value results in error paths.
func TestClassify_NilSafe(t *testing.T) {
	_ = Classify(nil)
	_ = Classify([]probe.Result{})
	_ = Classify([]probe.Result{{}})            // zero-value result
	_ = Classify([]probe.Result{{}, {}, {}})    // multiple zero-value
}

// TestNATType_String covers every branch.
func TestNATType_String(t *testing.T) {
	cases := map[NATType]string{
		Unknown:                     "Unknown",
		EndpointIndependentMapping:  "Endpoint-Independent Mapping",
		AddressDependentMapping:     "Address-Dependent Mapping",
		AddressPortDependentMapping: "Address and Port-Dependent Mapping",
		Blocked:                     "Blocked",
		NATType(999):                "Unknown", // out-of-range falls through to Unknown
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("NATType(%d).String() = %q, want %q", typ, got, want)
		}
	}
}

func hasWarning(ws []string, w string) bool {
	for _, x := range ws {
		if x == w {
			return true
		}
	}
	return false
}
