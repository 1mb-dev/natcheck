package classify

import (
	"errors"
	"hash/fnv"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/probe"
)

var errProbe = errors.New("test probe failure")

// targetFor gives each host its own synthetic resolved IP, so fixtures with
// different hosts count as distinct servers.
func targetFor(host string, port int) netip.AddrPort {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	sum := h.Sum32()
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(sum >> 8), byte(sum)}), uint16(port))
}

func ok(host string, port int, mapped string, rtt time.Duration) probe.Result {
	return probe.Result{
		Server: probe.Server{Host: host, Port: port},
		Target: targetFor(host, port),
		Mapped: netip.MustParseAddrPort(mapped),
		RTT:    rtt,
	}
}

// fail is a request that was sent and got no reply.
func fail(host string, port int) probe.Result {
	return probe.Result{
		Server: probe.Server{Host: host, Port: port},
		Target: targetFor(host, port),
		Err:    errProbe,
	}
}

// replied is a request that got a reply with no usable mapping.
func replied(host string, port int) probe.Result {
	r := fail(host, port)
	r.Replied = true
	return r
}

// unsent is a request that never left the host: resolve or send failed.
func unsent(host string, port int) probe.Result {
	return probe.Result{
		Server: probe.Server{Host: host, Port: port},
		Err:    errProbe,
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name           string
		results        []probe.Result
		filtering      *probe.FilteringResult
		wantType       NATType
		wantLegacy     string
		wantCGNAT      bool
		wantFiltering  FilteringBehavior
		wantP2P        string
		wantTURN       bool
		wantWarnings   []string // subset assertions
		wantWarnAbsent []string // warnings that must NOT be present
	}{
		{
			name:         "empty input — Blocked, nothing sent",
			results:      nil,
			wantType:     Blocked,
			wantP2P:      "unknown",
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
			name: "0/2 nothing sent — Blocked, unknown",
			results: []probe.Result{
				unsent("google", 19302),
				unsent("cloudflare", 3478),
			},
			wantType:     Blocked,
			wantP2P:      "unknown",
			wantTURN:     true,
			wantWarnings: []string{WarnAllProbesFailed},
		},
		{
			name: "0/2 one sent, one unsent — Blocked, unlikely",
			results: []probe.Result{
				fail("google", 19302),
				unsent("cloudflare", 3478),
			},
			wantType:     Blocked,
			wantP2P:      "unlikely",
			wantTURN:     true,
			wantWarnings: []string{WarnAllProbesFailed},
		},
		{
			name: "0/2 replied without a mapping — Blocked, unknown",
			results: []probe.Result{
				replied("google", 19302),
				replied("cloudflare", 3478),
			},
			wantType:     Blocked,
			wantP2P:      "unknown",
			wantTURN:     false,
			wantWarnings: []string{WarnAllProbesFailed},
		},
		{
			name: "0/2 one replied, one silent — Blocked, unknown",
			results: []probe.Result{
				fail("google", 19302),
				replied("cloudflare", 3478),
			},
			wantType:     Blocked,
			wantP2P:      "unknown",
			wantTURN:     false,
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
			wantP2P:    "possible",
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
			wantP2P:    "possible",
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
			wantP2P:    "possible",
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
			wantP2P:    "possible",
			wantTURN:   false,
		},
		{
			name: "private mapped address — not CGNAT",
			results: []probe.Result{
				ok("google", 19302, "192.168.1.2:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "192.168.1.2:51820", 20*time.Millisecond),
			},
			wantType:       EndpointIndependentMapping,
			wantLegacy:     "cone",
			wantCGNAT:      false,
			wantP2P:        "possible",
			wantTURN:       false,
			wantWarnAbsent: []string{WarnCGNATDetected},
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
		{
			// Reachable EIM+CGNAT+filtering integration: even with EIF data,
			// CGNAT precedence keeps the forecast at "unknown".
			name: "EIM + CGNAT + endpoint-independent filtering — CGNAT precedence holds",
			results: []probe.Result{
				ok("google", 19302, "100.64.1.5:51820", 10*time.Millisecond),
				ok("cloudflare", 3478, "100.64.1.5:51820", 20*time.Millisecond),
			},
			filtering: &probe.FilteringResult{
				Server:        probe.Server{Host: "stun.example.org", Port: 3478},
				Test2Received: true,
				Test3Received: true,
			},
			wantType:       EndpointIndependentMapping,
			wantLegacy:     "cone",
			wantCGNAT:      true,
			wantFiltering:  FilteringEndpointIndependent,
			wantP2P:        "unknown",
			wantWarnings:   []string{WarnCGNATDetected},
			wantWarnAbsent: []string{WarnFilteringBehaviorNotTested},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.results, inFamily(tc.filtering), nil)

			if got.Type != tc.wantType {
				t.Errorf("Type = %v, want %v", got.Type, tc.wantType)
			}
			if got.LegacyName != tc.wantLegacy {
				t.Errorf("LegacyName = %q, want %q", got.LegacyName, tc.wantLegacy)
			}
			if got.CGNAT != tc.wantCGNAT {
				t.Errorf("CGNAT = %v, want %v", got.CGNAT, tc.wantCGNAT)
			}
			if got.Filtering != tc.wantFiltering {
				t.Errorf("Filtering = %v, want %v", got.Filtering, tc.wantFiltering)
			}
			if got.Forecast.DirectP2P != tc.wantP2P {
				t.Errorf("DirectP2P = %q, want %q", got.Forecast.DirectP2P, tc.wantP2P)
			}
			if got.Forecast.TURNRequired != tc.wantTURN {
				t.Errorf("TURNRequired = %v, want %v", got.Forecast.TURNRequired, tc.wantTURN)
			}
			// When no filtering data is supplied, the generic warning must be
			// present (the v0.1 behaviour). When filtering data IS supplied,
			// the per-case wantWarnAbsent assertion governs.
			if tc.filtering == nil && !hasWarning(got.Warnings, WarnFilteringBehaviorNotTested) {
				t.Errorf("Warnings missing %q (required when filtering not tested); got %v",
					WarnFilteringBehaviorNotTested, got.Warnings)
			}
			for _, want := range tc.wantWarnings {
				if !hasWarning(got.Warnings, want) {
					t.Errorf("Warnings missing %q; got %v", want, got.Warnings)
				}
			}
			for _, absent := range tc.wantWarnAbsent {
				if hasWarning(got.Warnings, absent) {
					t.Errorf("Warnings unexpectedly contains %q; got %v", absent, got.Warnings)
				}
			}
		})
	}
}

// TestClassify_NilSafe: the brain of the tool must not panic on degenerate
// inputs. Callers may hand us nil or zero-value results in error paths.
func TestClassify_NilSafe(t *testing.T) {
	_ = Classify(nil, Filtering{}, nil)
	_ = Classify([]probe.Result{}, Filtering{}, nil)
	_ = Classify([]probe.Result{{}}, Filtering{}, nil)         // zero-value result
	_ = Classify([]probe.Result{{}, {}, {}}, Filtering{}, nil) // multiple zero-value
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

// TestFilteringBehavior_String covers every branch.
func TestFilteringBehavior_String(t *testing.T) {
	cases := map[FilteringBehavior]string{
		FilteringUntested:                "untested",
		FilteringEndpointIndependent:     "endpoint-independent",
		FilteringAddressDependent:        "address-dependent",
		FilteringAddressAndPortDependent: "address-and-port-dependent",
		FilteringBehavior(999):           "untested",
	}
	for b, want := range cases {
		if got := b.String(); got != want {
			t.Errorf("FilteringBehavior(%d).String() = %q, want %q", b, got, want)
		}
	}
}

// TestClassify_FilteringMatrix covers FilteringResult → Verdict.Filtering and
// the forecast updates for EIM mappings.
func TestClassify_FilteringMatrix(t *testing.T) {
	eimProbes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.example.org", Port: 3478},
			Target: targetFor("stun.example.org", 3478),
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			Other:  netip.MustParseAddrPort("198.51.100.1:3479"),
		},
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Target: targetFor("stun.l.google.com", 19302),
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
		},
	}
	target := probe.Server{Host: "stun.example.org", Port: 3478}

	cases := []struct {
		name           string
		filtering      *probe.FilteringResult
		wantBehavior   FilteringBehavior
		wantP2P        string
		wantTested     bool
		wantWarnHas    string // warning that must be present
		wantWarnAbsent string // warning that must NOT be present
	}{
		{
			name:           "nil_filtering",
			filtering:      nil,
			wantBehavior:   FilteringUntested,
			wantP2P:        "possible",
			wantWarnHas:    WarnFilteringBehaviorNotTested,
			wantWarnAbsent: WarnFilteringSkippedNoChangeRequest,
		},
		{
			name:           "not_supported",
			filtering:      &probe.FilteringResult{Server: target, Err: probe.ErrFilteringNotSupported},
			wantBehavior:   FilteringUntested,
			wantP2P:        "possible",
			wantWarnHas:    WarnFilteringSkippedNoChangeRequest,
			wantWarnAbsent: WarnFilteringBehaviorNotTested,
		},
		{
			name:           "test1_failed",
			filtering:      &probe.FilteringResult{Server: target, Err: probe.ErrTest1Failed},
			wantBehavior:   FilteringUntested,
			wantP2P:        "possible",
			wantWarnHas:    WarnFilteringBehaviorNotTested,
			wantWarnAbsent: WarnFilteringSkippedNoChangeRequest,
		},
		{
			name: "endpoint_independent",
			filtering: &probe.FilteringResult{
				Server: target, Test2Received: true, Test3Received: true,
			},
			wantBehavior:   FilteringEndpointIndependent,
			wantP2P:        "likely",
			wantTested:     true,
			wantWarnAbsent: WarnFilteringBehaviorNotTested,
		},
		{
			name: "address_dependent",
			filtering: &probe.FilteringResult{
				Server: target, Test2Received: false, Test3Received: true,
			},
			wantBehavior:   FilteringAddressDependent,
			wantP2P:        "possible",
			wantTested:     true,
			wantWarnAbsent: WarnFilteringBehaviorNotTested,
		},
		{
			name: "address_and_port_dependent",
			filtering: &probe.FilteringResult{
				Server: target, Test2Received: false, Test3Received: false,
			},
			wantBehavior:   FilteringAddressAndPortDependent,
			wantP2P:        "possible",
			wantTested:     true,
			wantWarnAbsent: WarnFilteringBehaviorNotTested,
		},
		{
			name: "rfc_impossible_t2_true_t3_false",
			filtering: &probe.FilteringResult{
				Server: target, Test2Received: true, Test3Received: false,
			},
			wantBehavior:   FilteringUntested,
			wantP2P:        "possible",
			wantWarnHas:    WarnFilteringBehaviorNotTested,
			wantWarnAbsent: WarnFilteringSkippedNoChangeRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(eimProbes, inFamily(tc.filtering), nil)
			if got.Filtering != tc.wantBehavior {
				t.Errorf("Filtering = %v, want %v", got.Filtering, tc.wantBehavior)
			}
			if got.Forecast.DirectP2P != tc.wantP2P {
				t.Errorf("DirectP2P = %q, want %q", got.Forecast.DirectP2P, tc.wantP2P)
			}
			if tc.wantTested && got.FilteringTestedAgainst != target {
				t.Errorf("FilteringTestedAgainst = %v, want %v", got.FilteringTestedAgainst, target)
			}
			if !tc.wantTested && got.FilteringTestedAgainst != (probe.Server{}) {
				t.Errorf("FilteringTestedAgainst = %v, want zero", got.FilteringTestedAgainst)
			}
			if tc.wantWarnHas != "" && !hasWarning(got.Warnings, tc.wantWarnHas) {
				t.Errorf("Warnings missing %q; got %v", tc.wantWarnHas, got.Warnings)
			}
			if tc.wantWarnAbsent != "" && hasWarning(got.Warnings, tc.wantWarnAbsent) {
				t.Errorf("Warnings unexpectedly contains %q; got %v", tc.wantWarnAbsent, got.Warnings)
			}
		})
	}
}

func TestClassify_AddressFamilies(t *testing.T) {
	v4a := ok("a", 3478, "203.0.113.45:51820", 10*time.Millisecond)
	v4b := ok("b", 3478, "203.0.113.45:51820", 10*time.Millisecond)
	v4bADM := ok("b", 3478, "203.0.113.45:51821", 10*time.Millisecond)
	cgnA := ok("a", 3478, "100.64.1.5:51820", 10*time.Millisecond)
	cgnB := ok("b", 3478, "100.64.1.5:51820", 10*time.Millisecond)
	v6 := func(host, mapped string) probe.Result {
		return probe.Result{
			Server: probe.Server{Host: host, Port: 3478},
			Target: netip.AddrPortFrom(netip.MustParseAddr("2001:db8:ff::1").Next(), 3478),
			Mapped: netip.MustParseAddrPort(mapped),
			RTT:    10 * time.Millisecond,
		}
	}
	v6c := v6("c", "[2001:db8::1]:51820")
	v6c.Target = netip.MustParseAddrPort("[2001:db8:ff::c]:3478")
	v6d := v6("d", "[2001:db8::1]:51820")
	v6d.Target = netip.MustParseAddrPort("[2001:db8:ff::d]:3478")
	v6dADM := v6d
	v6dADM.Mapped = netip.MustParseAddrPort("[2001:db8::1]:51821")
	untranslated := func(r probe.Result) probe.Result { r.Untranslated = true; return r }
	silent := func(target string, replied bool) probe.Result {
		return probe.Result{Server: probe.Server{Host: "s", Port: 3478}, Target: netip.MustParseAddrPort(target), Replied: replied, Err: errors.New("no response")}
	}
	eif := func(mapped string) *probe.FilteringResult {
		return &probe.FilteringResult{Server: probe.Server{Host: "rfc5780", Port: 3478}, Test1Mapped: netip.MustParseAddrPort(mapped), Test2Received: true, Test3Received: true}
	}
	// at is an IPv4-only server's row: sent to target, mapped to mapped. Under
	// DNS64 its synthesized AAAA leaves from the IPv6 socket and maps IPv4 too.
	at := func(host, target, mapped string) probe.Result {
		return probe.Result{Server: probe.Server{Host: host, Port: 3478}, Target: netip.MustParseAddrPort(target), Mapped: netip.MustParseAddrPort(mapped), RTT: 10 * time.Millisecond}
	}
	clatA, clatB := at("a", "192.0.2.10:3478", "203.0.113.45:51820"), at("b", "192.0.2.20:3478", "203.0.113.45:51820")
	nat64A, nat64B := at("a", "[64:ff9b::c000:20a]:3478", "203.0.113.45:40000"), at("b", "[64:ff9b::c000:214]:3478", "203.0.113.45:40000")

	const fnt, hu = WarnFilteringBehaviorNotTested, WarnHairpinUntested
	cases := []struct {
		name      string
		results   []probe.Result
		filtering Filtering
		wantType  NATType
		wantP2P   string
		wantWarns []string
		check     func(t *testing.T, v Verdict)
	}{
		{name: "both families cone", results: []probe.Result{v4a, v4b, v6c, v6d},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if v.PublicEndpoint != v4a.Mapped || v.IPv4 == nil || v.IPv6 == nil {
					t.Errorf("PublicEndpoint %v, IPv4 %v, IPv6 %v; want IPv4's endpoint and both families", v.PublicEndpoint, v.IPv4, v.IPv6)
				}
			}},
		{name: "IPv4 symmetric, IPv6 cone", results: []probe.Result{v6c, v6d, v4a, v4bADM},
			wantType: AddressDependentMapping, wantP2P: "unlikely", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, WarnADMOrStricter, hu}},
		{name: "IPv4 cone, IPv6 symmetric", results: []probe.Result{v4a, v4b, v6c, v6dADM},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, hu}},
		{name: "IPv4 cone, one IPv6 probe", results: []probe.Result{v4a, v4b, v6c},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, WarnInsufficientProbes, hu}},
		{name: "one IPv4 probe, IPv6 cone", results: []probe.Result{v4a, v6c, v6d},
			wantType: Unknown, wantP2P: "unknown", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, WarnInsufficientProbes, hu}},
		{name: "one probe in each family", results: []probe.Result{v4a, v6c},
			wantType: Unknown, wantP2P: "unknown", wantWarns: []string{fnt, WarnInsufficientProbes, hu}},
		{name: "IPv4 CGNAT, IPv6 symmetric", results: []probe.Result{cgnA, cgnB, v6c, v6dADM},
			wantType: EndpointIndependentMapping, wantP2P: "unknown", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, WarnCGNATDetected, hu}},
		{name: "IPv4 silent, IPv6 cone", results: []probe.Result{silent("192.0.2.1:3478", false), silent("192.0.2.2:3478", false), v6c, v6d},
			wantType: Blocked, wantP2P: "unlikely", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, hu},
			check: func(t *testing.T, v Verdict) {
				if !v.Forecast.TURNRequired || v.IPv4 == nil || v.IPv4.Type != Blocked {
					t.Errorf("TURNRequired %v, IPv4 %+v; want TURN and a Blocked IPv4 family", v.Forecast.TURNRequired, v.IPv4)
				}
			}},
		{name: "IPv4 replied without a mapping, IPv6 cone", results: []probe.Result{silent("192.0.2.1:3478", true), v6c, v6d},
			wantType: Blocked, wantP2P: "unknown", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, hu}},
		{name: "IPv4 unsendable, IPv6 cone", results: []probe.Result{unsent("s", 3478), unsent("t", 3478), v6c, v6d},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnIPv4Untested, hu}},
		{name: "IPv6 silent, IPv4 cone", results: []probe.Result{v4a, v4b, silent("[2001:db8:ff::c]:3478", false)},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if v.IPv6 != nil {
					t.Errorf("IPv6 = %+v, want absent", v.IPv6)
				}
			}},
		{name: "CLAT: IPv4 socket and NAT64 rows both map IPv4", results: []probe.Result{clatA, nat64A, clatB, nat64B},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if v.IPv4 == nil || v.IPv6 != nil || v.PublicEndpoint != clatA.Mapped {
					t.Errorf("IPv4 %v, IPv6 %v, PublicEndpoint %v; want the IPv4 socket's family only", v.IPv4, v.IPv6, v.PublicEndpoint)
				}
			}},
		{name: "CLAT: IPv4 socket symmetric, NAT64 rows agree", results: []probe.Result{clatA, nat64A, at("b", "192.0.2.20:3478", "203.0.113.45:51821"), nat64B},
			wantType: AddressDependentMapping, wantP2P: "unlikely", wantWarns: []string{fnt, WarnADMOrStricter, hu}},
		{name: "NAT64 without CLAT: IPv4 unsendable", results: []probe.Result{unsent("a", 3478), nat64A, unsent("b", 3478), nat64B},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if v.IPv4 == nil || v.PublicEndpoint != nat64A.Mapped {
					t.Errorf("IPv4 %v, PublicEndpoint %v; want an IPv4 family from the NAT64 rows", v.IPv4, v.PublicEndpoint)
				}
			}},
		{name: "NAT64 rows map IPv4, IPv4 socket silent", results: []probe.Result{silent("192.0.2.10:3478", false), nat64A, silent("192.0.2.20:3478", false), nat64B},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if v.IPv4 == nil || v.PublicEndpoint != nat64A.Mapped {
					t.Errorf("IPv4 %v, PublicEndpoint %v; want an IPv4 family from the NAT64 rows", v.IPv4, v.PublicEndpoint)
				}
			}},
		{name: "IPv6 only", results: []probe.Result{v6c, v6d},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnIPv4Untested, hu}},
		{name: "no NAT on IPv6 only", results: []probe.Result{v4a, v4b, untranslated(v6c), untranslated(v6d)},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, hu},
			check: func(t *testing.T, v Verdict) {
				if !hasWarning(v.IPv6.Warnings, WarnNoNAT) || hasWarning(v.IPv4.Warnings, WarnNoNAT) {
					t.Errorf("family warnings IPv4 %v, IPv6 %v; want no_nat on IPv6 only", v.IPv4.Warnings, v.IPv6.Warnings)
				}
			}},
		{name: "no NAT in both families", results: []probe.Result{untranslated(v4a), untranslated(v4b), untranslated(v6c), untranslated(v6d)},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnNoNAT, hu}},
		{name: "filtering measured on IPv4", results: []probe.Result{v4a, v4b, v6c, v6d}, filtering: Filtering{IPv4: eif("203.0.113.45:51820")},
			wantType: EndpointIndependentMapping, wantP2P: "likely", wantWarns: []string{WarnAddressFamiliesDisagree, hu}},
		{name: "filtering measured on IPv6 only", results: []probe.Result{v4a, v4b, v6c, v6d}, filtering: Filtering{IPv6: eif("[2001:db8::1]:51820")},
			wantType: EndpointIndependentMapping, wantP2P: "possible", wantWarns: []string{fnt, WarnAddressFamiliesDisagree, hu},
			check: func(t *testing.T, v Verdict) {
				if v.Filtering != FilteringUntested || v.IPv6.Filtering != FilteringEndpointIndependent || v.IPv6.Forecast.DirectP2P != "likely" {
					t.Errorf("top filtering %v, IPv6 filtering %v forecast %q; want untested, endpoint-independent, likely", v.Filtering, v.IPv6.Filtering, v.IPv6.Forecast.DirectP2P)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.results, tc.filtering, nil)
			if got.Type != tc.wantType || got.Forecast.DirectP2P != tc.wantP2P {
				t.Errorf("Type, DirectP2P = %v, %q; want %v, %q", got.Type, got.Forecast.DirectP2P, tc.wantType, tc.wantP2P)
			}
			if !slices.Equal(got.Warnings, tc.wantWarns) {
				t.Errorf("Warnings = %v, want %v", got.Warnings, tc.wantWarns)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// TestDecideForecast_Precedence covers the forecast decision tree directly.
func TestDecideForecast_Precedence(t *testing.T) {
	cases := []struct {
		name string
		v    Verdict
		want Forecast
	}{
		{"cgnat_overrides_eim_eif", Verdict{Type: EndpointIndependentMapping, CGNAT: true, Filtering: FilteringEndpointIndependent}, Forecast{DirectP2P: "unknown"}},
		{"cgnat_overrides_eim_adf", Verdict{Type: EndpointIndependentMapping, CGNAT: true, Filtering: FilteringAddressDependent}, Forecast{DirectP2P: "unknown"}},
		{"blocked_no_cgnat", Verdict{Type: Blocked}, Forecast{DirectP2P: "unlikely", TURNRequired: true}},
		{"blocked_nothing_sent", Verdict{Type: Blocked, nothingSent: true}, Forecast{DirectP2P: "unknown", TURNRequired: true}},
		{"blocked_after_reply", Verdict{Type: Blocked, replied: true}, Forecast{DirectP2P: "unknown", TURNRequired: false}},
		{"adm", Verdict{Type: AddressDependentMapping}, Forecast{DirectP2P: "unlikely", TURNRequired: true}},
		{"apdm", Verdict{Type: AddressPortDependentMapping}, Forecast{DirectP2P: "unlikely", TURNRequired: true}},
		{"unknown_mapping", Verdict{Type: Unknown}, Forecast{DirectP2P: "unknown"}},
		{"eim_eif", Verdict{Type: EndpointIndependentMapping, Filtering: FilteringEndpointIndependent}, Forecast{DirectP2P: "likely"}},
		{"eim_untested", Verdict{Type: EndpointIndependentMapping, Filtering: FilteringUntested}, Forecast{DirectP2P: "possible"}},
		{"eim_adf", Verdict{Type: EndpointIndependentMapping, Filtering: FilteringAddressDependent}, Forecast{DirectP2P: "possible"}},
		{"eim_apdf", Verdict{Type: EndpointIndependentMapping, Filtering: FilteringAddressAndPortDependent}, Forecast{DirectP2P: "possible"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideForecast(tc.v)
			if got != tc.want {
				t.Errorf("decideForecast(%+v) = %+v, want %+v", tc.v, got, tc.want)
			}
		})
	}
}

func TestClassify_ServerDiversity(t *testing.T) {
	const mapped = "203.0.113.45:51820"
	at := func(host, target, m string) probe.Result {
		return probe.Result{
			Server: probe.Server{Host: host, Port: 3478},
			Target: netip.MustParseAddrPort(target),
			Mapped: netip.MustParseAddrPort(m),
		}
	}
	noTarget := func(host string) probe.Result {
		return probe.Result{Server: probe.Server{Host: host, Port: 3478}, Mapped: netip.MustParseAddrPort(mapped)}
	}

	cases := []struct {
		name        string
		results     []probe.Result
		wantType    NATType
		wantWarning bool
	}{
		{
			name:        "two names for one IP",
			results:     []probe.Result{at("a", "192.0.2.1:3478", mapped), at("b", "192.0.2.1:3478", mapped)},
			wantType:    Unknown,
			wantWarning: true,
		},
		{
			name:        "two ports on one IP",
			results:     []probe.Result{at("a", "192.0.2.1:3478", mapped), at("a", "192.0.2.1:3479", mapped)},
			wantType:    Unknown,
			wantWarning: true,
		},
		{
			name:     "different mappings from one IP still prove not EIM",
			results:  []probe.Result{at("a", "192.0.2.1:3478", mapped), at("a", "192.0.2.1:3479", "203.0.113.45:51821")},
			wantType: AddressDependentMapping,
		},
		{
			name: "three servers on two IPs",
			results: []probe.Result{
				at("a", "192.0.2.1:3478", mapped), at("b", "192.0.2.1:3479", mapped), at("c", "192.0.2.2:3478", mapped),
			},
			wantType: EndpointIndependentMapping,
		},
		{
			name:        "missing target on one probe fails closed",
			results:     []probe.Result{at("a", "192.0.2.1:3478", mapped), noTarget("b")},
			wantType:    Unknown,
			wantWarning: true,
		},
		{
			name:        "missing targets on all probes fail closed",
			results:     []probe.Result{noTarget("a"), noTarget("b")},
			wantType:    Unknown,
			wantWarning: true,
		},
		{
			name: "diversity is judged per family",
			results: []probe.Result{
				at("a", "192.0.2.1:3478", mapped),
				at("b", "192.0.2.1:3478", mapped),
				at("c", "[2001:db8::1]:3478", "[2001:db8::99]:5000"),
				at("d", "[2001:db8::2]:3478", "[2001:db8::99]:5000"),
			},
			wantType:    Unknown, // IPv4 decides (TestClassify_AddressFamilies)
			wantWarning: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.results, Filtering{}, nil)
			if v.Type != tc.wantType {
				t.Errorf("Type = %v, want %v", v.Type, tc.wantType)
			}
			if got := slices.Contains(v.Warnings, WarnInsufficientServerDiversity); got != tc.wantWarning {
				t.Errorf("warning present = %v, want %v; warnings=%v", got, tc.wantWarning, v.Warnings)
			}
			if tc.wantType == Unknown && v.Forecast.DirectP2P != "unknown" {
				t.Errorf("DirectP2P = %q, want unknown", v.Forecast.DirectP2P)
			}
		})
	}
}

func TestClassify_IPv4UntestedWarning(t *testing.T) {
	v4 := func(host string) probe.Result { return ok(host, 3478, "203.0.113.45:51820", time.Millisecond) }
	v6 := func(host string) probe.Result { return ok(host, 3478, "[2001:db8::1]:51820", time.Millisecond) }

	cases := []struct {
		name    string
		results []probe.Result
		want    bool
	}{
		{"IPv6 only", []probe.Result{v6("a"), v6("b")}, true},
		{"IPv6 answered, IPv4 never sent", []probe.Result{v6("a"), v6("b"), unsent("c", 3478)}, true},
		{"IPv6 answered, IPv4 silent", []probe.Result{v6("a"), v6("b"), fail("c", 3478)}, false},
		{"IPv4 only", []probe.Result{v4("a"), v4("b")}, false},
		{"both families", []probe.Result{v4("a"), v6("b")}, false},
		{"nothing answered", []probe.Result{fail("a", 3478), fail("b", 3478)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.results, Filtering{}, nil)
			if got := slices.Contains(v.Warnings, WarnIPv4Untested); got != tc.want {
				t.Errorf("warning present = %v, want %v; warnings=%v", got, tc.want, v.Warnings)
			}
		})
	}
}

func TestClassify_NoNAT(t *testing.T) {
	untranslated := func(r probe.Result) probe.Result { r.Untranslated = true; return r }
	v4 := func(host string) probe.Result { return ok(host, 3478, "203.0.113.45:51820", time.Millisecond) }
	v6 := func(host string) probe.Result { return ok(host, 3478, "[2001:db8::1]:51820", time.Millisecond) }

	cases := []struct {
		name    string
		results []probe.Result
		want    bool
	}{
		{"every probe untranslated", []probe.Result{untranslated(v6("a")), untranslated(v6("b"))}, true},
		{"one probe, untranslated", []probe.Result{untranslated(v6("a")), unsent("b", 3478)}, true},
		{"one of two untranslated", []probe.Result{untranslated(v4("a")), v4("b")}, false},
		{"none untranslated", []probe.Result{v4("a"), v4("b")}, false},
		{"IPv6 untranslated, IPv4 translated", []probe.Result{untranslated(v6("a")), untranslated(v6("b")), v4("c"), v4("d")}, false},
		{"both families untranslated", []probe.Result{untranslated(v6("a")), untranslated(v4("c"))}, true},
		{"failed probe flagged", []probe.Result{v4("a"), v4("b"), untranslated(fail("c", 3478))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.results, Filtering{}, nil)
			if got := slices.Contains(v.Warnings, WarnNoNAT); got != tc.want {
				t.Errorf("no_nat present = %v, want %v; warnings=%v", got, tc.want, v.Warnings)
			}
			// The warning reports; it does not judge.
			plain := make([]probe.Result, len(tc.results))
			for i, r := range tc.results {
				r.Untranslated = false
				plain[i] = r
			}
			base := Classify(plain, Filtering{}, nil)
			if v.Type != base.Type || v.LegacyName != base.LegacyName || v.Forecast != base.Forecast {
				t.Errorf("verdict moved: %v %q %+v, want %v %q %+v", v.Type, v.LegacyName, v.Forecast, base.Type, base.LegacyName, base.Forecast)
			}
		})
	}
}

func TestClassify_MappingTest(t *testing.T) {
	adm := []probe.Result{
		ok("a", 3478, "203.0.113.45:51820", time.Millisecond),
		ok("b", 3478, "203.0.113.45:51821", time.Millisecond),
	}
	eim := []probe.Result{
		ok("a", 3478, "203.0.113.45:51820", time.Millisecond),
		ok("b", 3478, "203.0.113.45:51820", time.Millisecond),
	}
	single := []probe.Result{ok("a", 3478, "203.0.113.45:51820", time.Millisecond), fail("b", 3478)}
	v6One := ok("c", 3478, "[2001:db8::1]:51820", time.Millisecond)
	v6ADM := []probe.Result{
		ok("c", 3478, "[2001:db8::1]:51820", time.Millisecond),
		ok("d", 3478, "[2001:db8::1]:51821", time.Millisecond),
	}
	mapping := func(test1, altIP, altEndpoint string) *probe.FilteringResult {
		f := &probe.FilteringResult{Test1Mapped: netip.MustParseAddrPort(test1), Err: probe.ErrFilteringNotSupported}
		if altIP != "" {
			f.AltIPMapped = netip.MustParseAddrPort(altIP)
		}
		if altEndpoint != "" {
			f.AltEndpointMapped = netip.MustParseAddrPort(altEndpoint)
		}
		return f
	}
	portDependent := mapping("203.0.113.45:40000", "203.0.113.45:40001", "203.0.113.45:40002")
	addressOnly := mapping("203.0.113.45:40000", "203.0.113.45:40001", "203.0.113.45:40001")

	cases := []struct {
		name       string
		results    []probe.Result
		filtering  *probe.FilteringResult
		wantType   NATType
		wantADMOrS bool
	}{
		{"II and III differ: APDM", adm, portDependent, AddressPortDependentMapping, false},
		{"II and III agree: ADM", adm, addressOnly, AddressDependentMapping, false},
		{"II agrees with I: tests do not apply", adm, mapping("203.0.113.45:40000", "203.0.113.45:40000", "203.0.113.45:40000"), AddressDependentMapping, true},
		{"II agrees with I, III differs: tests do not apply", adm, mapping("203.0.113.45:40000", "203.0.113.45:40000", "203.0.113.45:40002"), AddressDependentMapping, true},
		{"Test III unanswered", adm, mapping("203.0.113.45:40000", "203.0.113.45:40001", ""), AddressDependentMapping, true},
		{"no filtering run", adm, nil, AddressDependentMapping, true},
		{"EIM stays EIM", eim, portDependent, EndpointIndependentMapping, false},
		{"Unknown stays Unknown", single, portDependent, Unknown, false},
		{"tested family decides", append(slices.Clone(adm), v6One), portDependent, AddressPortDependentMapping, false},
		{"other family is ADM too", append(slices.Clone(adm), v6ADM...), portDependent, AddressPortDependentMapping, false},
		{"tests ran on the other family", append(slices.Clone(adm), v6One), mapping("[2001:db8::1]:40000", "[2001:db8::1]:40001", "[2001:db8::1]:40002"), AddressDependentMapping, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.results, inFamily(tc.filtering), nil)
			if v.Type != tc.wantType {
				t.Errorf("Type = %v, want %v", v.Type, tc.wantType)
			}
			if got := slices.Contains(v.Warnings, WarnADMOrStricter); got != tc.wantADMOrS {
				t.Errorf("adm_or_stricter present = %v, want %v; warnings=%v", got, tc.wantADMOrS, v.Warnings)
			}
			if tc.wantType == AddressPortDependentMapping && (v.LegacyName != "symmetric" || v.Forecast.DirectP2P != "unlikely" || !v.Forecast.TURNRequired) {
				t.Errorf("APDM verdict = %q %+v, want symmetric, unlikely, TURN", v.LegacyName, v.Forecast)
			}
		})
	}
}

// inFamily files f under the family of its Test 1 mapping, IPv4 when it has
// none, as cli does with the probe that selected the server.
func inFamily(f *probe.FilteringResult) Filtering {
	if f != nil && f.Test1Mapped.Addr().Is6() {
		return Filtering{IPv6: f}
	}
	return Filtering{IPv4: f}
}
