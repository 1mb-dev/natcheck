// Package classify turns probe results into a NAT-type verdict.
//
// Classification follows RFC 5780 mapping-behavior categories
// (Endpoint-Independent, Address-Dependent, Address and Port-Dependent) and
// emits legacy RFC 3489 terms ("cone", "symmetric") for human readers.
// Optional filtering data (RFC 5780 §4.4) refines the WebRTC forecast when
// the target server supports CHANGE-REQUEST. See docs/design.md.
package classify

import (
	"errors"
	"net/netip"

	"github.com/1mb-dev/natcheck/internal/probe"
)

// NATType is the RFC 5780 mapping-behavior category.
type NATType int

const (
	// Unknown indicates classification could not be determined from the
	// available probes (typically only one successful probe — no comparison
	// point for mapping behavior).
	Unknown NATType = iota

	// EndpointIndependentMapping: same mapped endpoint across servers.
	// RFC 5780. Legacy term "cone".
	EndpointIndependentMapping

	// AddressDependentMapping: mapped endpoint varies by destination address.
	// RFC 5780. v0.1 reports this for any case where mapped endpoints differ
	// across servers; ADM vs APDM cannot be distinguished without
	// CHANGE-REQUEST.
	AddressDependentMapping

	// AddressPortDependentMapping: mapped endpoint varies by destination
	// address and port. RFC 5780. Legacy term "symmetric". v0.1 does not
	// emit this category directly (see AddressDependentMapping note).
	AddressPortDependentMapping

	// Blocked: no probe succeeded. Network rejects outbound STUN, all target
	// servers are unreachable, or the caller's timeout fired too early.
	Blocked
)

// String returns the canonical RFC 5780 name.
func (t NATType) String() string {
	switch t {
	case EndpointIndependentMapping:
		return "Endpoint-Independent Mapping"
	case AddressDependentMapping:
		return "Address-Dependent Mapping"
	case AddressPortDependentMapping:
		return "Address and Port-Dependent Mapping"
	case Blocked:
		return "Blocked"
	default:
		return "Unknown"
	}
}

// FilteringBehavior is the RFC 5780 §4.4 filtering category.
type FilteringBehavior int

const (
	// FilteringUntested is the zero value: no §4.4 sequence ran (server didn't
	// support OTHER-ADDRESS, or filtering wasn't attempted).
	FilteringUntested FilteringBehavior = iota
	// FilteringEndpointIndependent: replies arrive from any source the server
	// is asked to use (Test 2 + Test 3 both received).
	FilteringEndpointIndependent
	// FilteringAddressDependent: replies arrive when source IP matches a peer
	// the client has communicated with (Test 2 dropped, Test 3 received).
	FilteringAddressDependent
	// FilteringAddressAndPortDependent: replies arrive only when both source
	// IP and port match (Test 2 + Test 3 both dropped).
	FilteringAddressAndPortDependent
)

// String returns the canonical wire name (matches the JSON enum).
func (b FilteringBehavior) String() string {
	switch b {
	case FilteringEndpointIndependent:
		return "endpoint-independent"
	case FilteringAddressDependent:
		return "address-dependent"
	case FilteringAddressAndPortDependent:
		return "address-and-port-dependent"
	default:
		return "untested"
	}
}

// Forecast is the WebRTC direct-P2P prediction.
type Forecast struct {
	DirectP2P    string // "likely" | "possible" | "unlikely" | "unknown"
	TURNRequired bool
}

// Verdict is the final classification output.
type Verdict struct {
	Type           NATType
	LegacyName     string // "cone", "symmetric", "" when unknown/blocked
	PublicEndpoint netip.AddrPort
	CGNAT          bool
	// Filtering is the RFC 5780 §4.4 outcome; FilteringUntested when the
	// §4.4 sequence did not run (no OTHER-ADDRESS support, or not attempted).
	Filtering FilteringBehavior
	// FilteringTestedAgainst is the server the §4.4 sequence ran against.
	// Zero-value (Server{}) when filtering was not attempted, or when the
	// server did not advertise OTHER-ADDRESS so no sequence ran.
	FilteringTestedAgainst probe.Server
	Warnings               []string
	Forecast               Forecast
}

// Stable warning vocabulary for the JSON API.
const (
	WarnAllProbesFailed                 = "all_probes_failed"
	WarnADMOrStricter                   = "adm_or_stricter"
	WarnCGNATDetected                   = "cgnat_detected"
	WarnInsufficientProbes              = "insufficient_probes"
	WarnFilteringBehaviorNotTested      = "filtering_behavior_not_tested"
	WarnFilteringSkippedNoChangeRequest = "filtering_skipped_no_change_request"
)

// cgnatPrefix is RFC 6598 shared address space.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// Classify turns probe results into a Verdict. Pure function: no I/O, no
// goroutines, deterministic for a given input.
//
// A probe.Result is treated as successful only when Err == nil AND
// Mapped.IsValid(). This guards against buggy Prober implementations that
// might report nil-error with a zero mapped endpoint.
//
// filtering may be nil; in that case Verdict.Filtering stays Untested and
// the existing WarnFilteringBehaviorNotTested warning is emitted. When
// filtering is non-nil, its Test2/Test3 booleans drive the FilteringBehavior
// and the WebRTC forecast for EIM mappings (RFC 5780 §4.4 outcomes).
func Classify(results []probe.Result, filtering *probe.FilteringResult) Verdict {
	v := classifyMapping(results)
	applyFiltering(&v, filtering)
	v.Forecast = decideForecast(v)
	return v
}

// classifyMapping derives mapping behavior, public endpoint, CGNAT, and the
// initial warning set. Forecast is computed by decideForecast after filtering
// data is folded in.
func classifyMapping(results []probe.Result) Verdict {
	v := Verdict{Warnings: []string{WarnFilteringBehaviorNotTested}}

	var successes []probe.Result
	for _, r := range results {
		if r.Err == nil && r.Mapped.IsValid() {
			successes = append(successes, r)
		}
	}

	switch len(successes) {
	case 0:
		v.Type = Blocked
		v.Warnings = append(v.Warnings, WarnAllProbesFailed)
		return v

	case 1:
		v.Type = Unknown
		v.PublicEndpoint = successes[0].Mapped
		v.Warnings = append(v.Warnings, WarnInsufficientProbes)
		applyCGNAT(&v)
		return v

	default:
		v.PublicEndpoint = successes[0].Mapped
		allSame := true
		for _, r := range successes[1:] {
			if r.Mapped != successes[0].Mapped {
				allSame = false
				break
			}
		}
		if allSame {
			v.Type = EndpointIndependentMapping
			v.LegacyName = "cone"
		} else {
			v.Type = AddressDependentMapping
			v.LegacyName = "symmetric"
			v.Warnings = append(v.Warnings, WarnADMOrStricter)
		}
		applyCGNAT(&v)
		return v
	}
}

// applyFiltering folds *probe.FilteringResult into the verdict. Updates
// v.Filtering, v.FilteringTestedAgainst, and v.Warnings.
//
// (T2=true, T3=false) is RFC-impossible per §4.4 — it implies the server
// contradicted itself or the network corrupted Test 3 only. We drop to
// FilteringUntested rather than over-claim a behavior the data doesn't show.
func applyFiltering(v *Verdict, f *probe.FilteringResult) {
	if f == nil {
		return // Untested; existing WarnFilteringBehaviorNotTested already in v.Warnings.
	}
	if errors.Is(f.Err, probe.ErrFilteringNotSupported) {
		// We tried, the server didn't support it. Replace the generic warning
		// with the more specific one. FilteringTestedAgainst stays zero
		// because no §4.4 sequence ran.
		v.Warnings = replaceWarning(v.Warnings, WarnFilteringBehaviorNotTested, WarnFilteringSkippedNoChangeRequest)
		return
	}
	if f.Err != nil {
		// Test 1 failed or invalid server — leave as Untested with the
		// existing generic warning.
		return
	}
	switch {
	case f.Test2Received && f.Test3Received:
		v.Filtering = FilteringEndpointIndependent
	case !f.Test2Received && f.Test3Received:
		v.Filtering = FilteringAddressDependent
	case !f.Test2Received && !f.Test3Received:
		v.Filtering = FilteringAddressAndPortDependent
	default:
		// (T2=true, T3=false): inconsistent; keep Untested and the generic warning.
		return
	}
	v.FilteringTestedAgainst = f.Server
	v.Warnings = removeWarning(v.Warnings, WarnFilteringBehaviorNotTested)
}

// decideForecast computes the WebRTC forecast from a fully-populated Verdict.
// Precedence (top-down, first match wins):
//  1. CGNAT detected → unknown (v0.1 honesty rule preserved)
//  2. Mapping ADM/APDM/Blocked → unlikely
//  3. Mapping Unknown → unknown
//  4. Mapping EIM with restrictive filtering (ADF/APDF) → possible
//  5. Mapping EIM with EIF or untested filtering → likely
func decideForecast(v Verdict) Forecast {
	if v.CGNAT {
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	}
	switch v.Type {
	case Blocked:
		return Forecast{DirectP2P: "unlikely", TURNRequired: true}
	case AddressDependentMapping, AddressPortDependentMapping:
		return Forecast{DirectP2P: "unlikely", TURNRequired: true}
	case Unknown:
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	case EndpointIndependentMapping:
		switch v.Filtering {
		case FilteringAddressDependent, FilteringAddressAndPortDependent:
			return Forecast{DirectP2P: "possible", TURNRequired: false}
		default:
			return Forecast{DirectP2P: "likely", TURNRequired: false}
		}
	default:
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	}
}

// applyCGNAT sets CGNAT=true and appends the warning when the observed public
// IP falls in RFC 6598 100.64.0.0/10.
func applyCGNAT(v *Verdict) {
	if !v.PublicEndpoint.IsValid() {
		return
	}
	if cgnatPrefix.Contains(v.PublicEndpoint.Addr().Unmap()) {
		v.CGNAT = true
		v.Warnings = append(v.Warnings, WarnCGNATDetected)
	}
}

func replaceWarning(ws []string, old, new string) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		if w == old {
			out = append(out, new)
		} else {
			out = append(out, w)
		}
	}
	return out
}

func removeWarning(ws []string, target string) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		if w != target {
			out = append(out, w)
		}
	}
	return out
}
