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
	// Zero-value (Server{}) when Filtering == FilteringUntested, which
	// happens in any of these cases:
	//   - no FilteringResult was supplied (filtering not attempted);
	//   - the server did not advertise OTHER-ADDRESS (ErrFilteringNotSupported);
	//   - the initial Test 1 binding probe failed (ErrTest1Failed);
	//   - the (T2=true, T3=false) RFC-impossible state was observed.
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
	WarnMixedAddressFamilyProbes        = "mixed_address_family_probes"
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
//
// Address-family handling: probes are grouped by Mapped.Addr().Is4() and
// classified per-group, then combined. Each family observes its own NAT
// (the v4 NAT and v6 router are independent), so cross-family equality
// comparison would always disagree by construction. The combine rule treats
// Unknown as absence of information, not disagreement: a confident verdict
// from one family wins over Unknown from the other; two confident verdicts
// must match or the combined verdict is Unknown.
func classifyMapping(results []probe.Result) Verdict {
	v := Verdict{Warnings: []string{WarnFilteringBehaviorNotTested}}

	var successes []probe.Result
	for _, r := range results {
		if r.Err == nil && r.Mapped.IsValid() {
			successes = append(successes, r)
		}
	}

	if len(successes) == 0 {
		v.Type = Blocked
		v.Warnings = append(v.Warnings, WarnAllProbesFailed)
		return v
	}

	var v4, v6 []probe.Result
	for _, r := range successes {
		if r.Mapped.Addr().Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	multiFamily := len(v4) > 0 && len(v6) > 0

	var v4g, v6g *Verdict
	if len(v4) > 0 {
		g := classifyGroup(v4)
		v4g = &g
	}
	if len(v6) > 0 {
		g := classifyGroup(v6)
		v6g = &g
	}

	combined := combineGroups(v4g, v6g)
	v.Type = combined.Type
	v.LegacyName = combined.LegacyName
	v.PublicEndpoint = successes[0].Mapped // top-level endpoint = first success, regardless of family
	v.CGNAT = combined.CGNAT

	// Warning propagation:
	//   - WarnInsufficientProbes / WarnCGNATDetected propagate independently
	//     from any group (they describe facts true of that group).
	//   - WarnADMOrStricter propagates only when the COMBINED verdict is ADM
	//     (suppressed under disagreement-Unknown — premise no longer holds).
	//   - WarnMixedAddressFamilyProbes fires whenever both families are present.
	if multiFamily {
		v.Warnings = appendUnique(v.Warnings, WarnMixedAddressFamilyProbes)
	}
	for _, g := range []*Verdict{v4g, v6g} {
		if g == nil {
			continue
		}
		for _, w := range g.Warnings {
			if w == WarnADMOrStricter && v.Type != AddressDependentMapping {
				continue
			}
			v.Warnings = appendUnique(v.Warnings, w)
		}
	}

	return v
}

// combineGroups reconciles per-family verdicts. "Unknown is absence of
// information, not disagreement" — a confident verdict beats Unknown; two
// confident verdicts must match or the combined verdict is Unknown.
//
// CGNAT is OR'd across groups (the fact applies if true for any family;
// decideForecast's CGNAT precedence handles the forecast accordingly).
func combineGroups(v4g, v6g *Verdict) Verdict {
	switch {
	case v4g != nil && v6g != nil:
		// Both families present.
		out := Verdict{CGNAT: v4g.CGNAT || v6g.CGNAT}
		switch {
		case v4g.Type == Unknown && v6g.Type == Unknown:
			out.Type = Unknown
		case v4g.Type == Unknown:
			out.Type = v6g.Type
			out.LegacyName = v6g.LegacyName
		case v6g.Type == Unknown:
			out.Type = v4g.Type
			out.LegacyName = v4g.LegacyName
		case v4g.Type == v6g.Type:
			out.Type = v4g.Type
			out.LegacyName = v4g.LegacyName
		default:
			out.Type = Unknown
		}
		return out
	case v4g != nil:
		return *v4g
	case v6g != nil:
		return *v6g
	default:
		// Unreachable: caller ensures at least one group is non-nil.
		return Verdict{Type: Unknown}
	}
}

// appendUnique appends w to ws only if not already present. Preserves order.
func appendUnique(ws []string, w string) []string {
	for _, x := range ws {
		if x == w {
			return ws
		}
	}
	return append(ws, w)
}

// classifyGroup runs the case-1/case-many mapping classification for a
// non-empty set of successful probes. CGNAT detection is applied. Warnings
// returned do NOT include WarnFilteringBehaviorNotTested — that's the
// caller's concern at the combined-verdict level.
func classifyGroup(group []probe.Result) Verdict {
	v := Verdict{}
	switch len(group) {
	case 1:
		v.Type = Unknown
		v.PublicEndpoint = group[0].Mapped
		v.Warnings = append(v.Warnings, WarnInsufficientProbes)
		applyCGNAT(&v)
	default:
		v.PublicEndpoint = group[0].Mapped
		allSame := true
		for _, r := range group[1:] {
			if r.Mapped != group[0].Mapped {
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
	}
	return v
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
