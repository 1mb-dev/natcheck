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
	"slices"

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
	// RFC 5780. Mapped endpoints that differ across servers read ADM with
	// adm_or_stricter, unless applyMappingTest refines it.
	AddressDependentMapping

	// AddressPortDependentMapping: mapped endpoint varies by destination
	// address and port. RFC 5780. Legacy term "symmetric". Only
	// applyMappingTest assigns it.
	AddressPortDependentMapping

	// Blocked: no probe succeeded. Network rejects outbound STUN, all target
	// servers are unreachable or answer without a usable mapping (TestClassify),
	// or the caller's timeout fired too early. An IPv4 family whose requests
	// left without a mapping is Blocked beside a successful IPv6 family
	// (TestClassify_AddressFamilies).
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
	//   - the server cannot run the sequence (ErrFilteringNotSupported);
	//   - the initial Test 1 binding probe failed (ErrTest1Failed);
	//   - the (T2=true, T3=false) RFC-impossible state was observed.
	FilteringTestedAgainst probe.Server
	// Hairpinning is tri-state per docs/design.md:
	//   - nil:    not tested (probe didn't run / socket setup failed)
	//   - &true:  tagged loopback packet arrived
	//   - &false: listen window elapsed without the packet (may be a true
	//             negative OR a per-NAT filtering false-negative on the
	//             hairpin path; see docs/design.md)
	// Carried through Classify unchanged in v0.1.4; forecast logic does NOT
	// shift on this value yet. Hairpinning only matters for same-NAT (LAN)
	// peers, while the natcheck user's question is about inter-NAT WebRTC.
	// Future releases may revisit if real-world data justifies a shift.
	Hairpinning *bool
	Warnings    []string
	Forecast    Forecast

	// IPv4 and IPv6 are the per-family verdicts the top level is taken from;
	// nil for an absent family and on the verdict of a family itself.
	IPv4, IPv6 *Verdict

	// nothingSent is true for Blocked when no request left the host (every
	// Target invalid: resolve or send failed), so nothing was measured.
	nothingSent bool
	// replied is true for Blocked when a target answered a request without a
	// usable mapping (probe.Result.Replied; TestClassify).
	replied bool
}

// Stable warning vocabulary for the JSON API.
const (
	WarnAllProbesFailed                 = "all_probes_failed"
	WarnADMOrStricter                   = "adm_or_stricter"
	WarnCGNATDetected                   = "cgnat_detected"
	WarnInsufficientProbes              = "insufficient_probes"
	WarnFilteringBehaviorNotTested      = "filtering_behavior_not_tested"
	WarnFilteringSkippedNoChangeRequest = "filtering_skipped_no_change_request"
	WarnAddressFamiliesDisagree         = "address_families_disagree"
	WarnHairpinUntested                 = "hairpin_untested"
	WarnInsufficientServerDiversity     = "insufficient_server_diversity"
	WarnIPv4Untested                    = "ipv4_untested"
	WarnNoNAT                           = "no_nat"
)

// cgnatPrefix is RFC 6598 shared address space.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// Filtering holds the RFC 5780 §4.4 result run in each address family, nil
// where none ran, each against a server among that family's Compared probes
// (TestRun_FilteringUsesComparedRows).
type Filtering struct {
	IPv4, IPv6 *probe.FilteringResult
}

// Classify turns probe results into a Verdict. Pure function: no I/O, no
// goroutines, deterministic for a given input.
//
// A probe.Result is treated as successful only when Err == nil AND
// Mapped.IsValid(). This guards against buggy Prober implementations that
// might report nil-error with a zero mapped endpoint.
//
// Successes are grouped by mapped address family and each family is
// classified on its own, with its own filtering result. The top level is
// IPv4's, or IPv6's when IPv4 is absent (docs/design.md § Address families,
// TestClassify_AddressFamilies).
//
// hairpinning may be nil; in that case Verdict.Hairpinning stays nil and
// WarnHairpinUntested is emitted. When hairpinning is non-nil, the value is
// carried through to Verdict.Hairpinning unchanged. It does not shift the
// forecast: hairpinning only matters for same-NAT (LAN) peers, which is not
// the natcheck user's question. See the Verdict field doc and docs/design.md.
func Classify(results []probe.Result, filtering Filtering, hairpinning *probe.HairpinningResult) Verdict {
	v4, v6 := Compared(results, true), Compared(results, false)
	var sent4, replied4 bool
	for _, r := range results {
		if (r.Err != nil || !r.Mapped.IsValid()) && r.Target.IsValid() && r.Target.Addr().Is4() {
			sent4 = true
			replied4 = replied4 || r.Replied
		}
	}

	var v Verdict
	if len(v4) == 0 && len(v6) == 0 {
		v = Verdict{Type: Blocked, Warnings: []string{WarnFilteringBehaviorNotTested, WarnAllProbesFailed}}
		v.nothingSent = !slices.ContainsFunc(results, func(r probe.Result) bool { return r.Target.IsValid() })
		v.replied = slices.ContainsFunc(results, func(r probe.Result) bool { return r.Replied })
		v.Forecast = decideForecast(v)
	} else {
		var f4, f6 *Verdict
		switch {
		case len(v4) > 0:
			f4 = classifyFamily(v4, filtering.IPv4)
		case sent4:
			// A silent IPv6 family stays absent (TestClassify_AddressFamilies).
			f4 = &Verdict{Type: Blocked, Warnings: []string{WarnFilteringBehaviorNotTested, WarnAllProbesFailed}, replied: replied4}
			f4.Forecast = decideForecast(*f4)
		}
		if len(v6) > 0 {
			f6 = classifyFamily(v6, filtering.IPv6)
		}
		v = combineFamilies(f4, f6)
	}
	applyHairpinning(&v, hairpinning)
	return v
}

// Compared returns the successful probes whose mappings are compared for one
// address family: those mapped into it, less any sent from the other family's
// socket, such as DNS64 rows beside a CLAT's IPv4 rows, when one from the
// family's own socket got a mapping. Mappings from two sockets are not
// comparable (TestClassify_AddressFamilies). A row without a Target counts as
// the family's own, so it still fails closed (TestClassify_ServerDiversity).
func Compared(results []probe.Result, is4 bool) []probe.Result {
	var group []probe.Result
	for _, r := range results {
		if r.Err == nil && r.Mapped.IsValid() && r.Mapped.Addr().Is4() == is4 {
			group = append(group, r)
		}
	}
	translated := func(r probe.Result) bool { return r.Target.IsValid() && r.Target.Addr().Is4() != is4 }
	if slices.ContainsFunc(group, func(r probe.Result) bool { return !translated(r) }) {
		group = slices.DeleteFunc(group, translated)
	}
	return group
}

// applyHairpinning folds the hairpin probe outcome into the verdict. When
// hairpinning is nil OR ran but produced no Detected value, emit
// WarnHairpinUntested. When Detected is populated, copy it across.
func applyHairpinning(v *Verdict, hairpinning *probe.HairpinningResult) {
	if hairpinning == nil || hairpinning.Detected == nil {
		v.Warnings = appendUnique(v.Warnings, WarnHairpinUntested)
		return
	}
	d := *hairpinning.Detected
	v.Hairpinning = &d
}

// classifyFamily classifies one address family's successful probes and folds
// in the filtering result run in that family.
func classifyFamily(group []probe.Result, f *probe.FilteringResult) *Verdict {
	v := classifyGroup(group)
	v.Warnings = append([]string{WarnFilteringBehaviorNotTested}, v.Warnings...)
	applyFiltering(&v, f)
	applyMappingTest(&v, f)
	// One probe is enough. The forecast stays the mapping's (TestClassify_NoNAT).
	if !slices.ContainsFunc(group, func(r probe.Result) bool { return !r.Untranslated }) {
		v.Warnings = append(v.Warnings, WarnNoNAT)
	}
	v.Forecast = decideForecast(v)
	return &v
}

// combineFamilies takes the top level from IPv4, or from IPv6 when IPv4 is
// absent (TestClassify_AddressFamilies).
func combineFamilies(f4, f6 *Verdict) Verdict {
	d := f4
	if d == nil {
		d = f6
	}
	v := Verdict{
		Type:                   d.Type,
		LegacyName:             d.LegacyName,
		PublicEndpoint:         d.PublicEndpoint,
		CGNAT:                  d.CGNAT,
		Filtering:              d.Filtering,
		FilteringTestedAgainst: d.FilteringTestedAgainst,
		Forecast:               d.Forecast,
		IPv4:                   f4,
		IPv6:                   f6,
	}
	for _, w := range d.Warnings {
		if w == WarnFilteringBehaviorNotTested || w == WarnFilteringSkippedNoChangeRequest {
			v.Warnings = append(v.Warnings, w)
		}
	}
	if f4 == nil {
		v.Warnings = append(v.Warnings, WarnIPv4Untested)
	}
	if f4 != nil && f6 != nil && f4.Forecast.DirectP2P != f6.Forecast.DirectP2P {
		v.Warnings = append(v.Warnings, WarnAddressFamiliesDisagree)
	}
	noNAT := true
	for _, f := range []*Verdict{f4, f6} {
		if f == nil {
			continue
		}
		noNAT = noNAT && slices.Contains(f.Warnings, WarnNoNAT)
		for _, w := range f.Warnings {
			switch {
			case w == WarnInsufficientProbes, w == WarnInsufficientServerDiversity, w == WarnCGNATDetected,
				w == WarnADMOrStricter && f == d:
				v.Warnings = appendUnique(v.Warnings, w)
			}
		}
	}
	if noNAT {
		v.Warnings = append(v.Warnings, WarnNoNAT)
	}
	return v
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
// non-empty set of successful probes. CGNAT detection is applied.
// Warnings returned do NOT include WarnFilteringBehaviorNotTested;
// classifyFamily adds it.
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
		switch {
		case allSame && distinctTargetIPs(group) < 2:
			// Agreement from one server IP cannot separate EIM from ADM, and
			// a warning alone would still exit 0. A missing Target counts as
			// no IP, so a Prober that omits it cannot earn an EIM verdict.
			v.Type = Unknown
			v.Warnings = append(v.Warnings, WarnInsufficientServerDiversity)
		case allSame:
			v.Type = EndpointIndependentMapping
			v.LegacyName = "cone"
		default:
			v.Type = AddressDependentMapping
			v.LegacyName = "symmetric"
			v.Warnings = append(v.Warnings, WarnADMOrStricter)
		}
		applyCGNAT(&v)
	}
	return v
}

func distinctTargetIPs(group []probe.Result) int {
	ips := make(map[netip.Addr]struct{}, len(group))
	for _, r := range group {
		if r.Target.IsValid() {
			ips[r.Target.Addr()] = struct{}{}
		}
	}
	return len(ips)
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

// applyMappingTest refines an ADM verdict with RFC 5780 §4.3 Tests II and III,
// which differ only in destination port: different mappings make it APDM, equal
// ones leave ADM; either way adm_or_stricter drops. As in RFC 5780, they apply
// only when Test II's mapping differs from Test I's. They never produce EIM and
// never replace Unknown (TestClassify_MappingTest).
func applyMappingTest(v *Verdict, f *probe.FilteringResult) {
	if f == nil || !f.AltIPMapped.IsValid() || !f.AltEndpointMapped.IsValid() || f.AltIPMapped == f.Test1Mapped || v.Type != AddressDependentMapping {
		return
	}
	if f.AltIPMapped != f.AltEndpointMapped {
		v.Type = AddressPortDependentMapping
	}
	v.Warnings = removeWarning(v.Warnings, WarnADMOrStricter)
}

// decideForecast computes the WebRTC forecast from a fully-populated Verdict.
// Precedence (top-down, first match wins):
//  1. CGNAT detected → unknown
//  2. Blocked → unknown when a target replied; else TURN required, and unknown
//     when no request was sent, unlikely when one was
//     (TestDecideForecast_Precedence)
//  3. Mapping ADM/APDM → unlikely
//  4. Mapping Unknown → unknown
//  5. Mapping EIM with endpoint-independent filtering → likely
//  6. Mapping EIM with any other or untested filtering → possible
func decideForecast(v Verdict) Forecast {
	if v.CGNAT {
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	}
	switch v.Type {
	case Blocked:
		// A reply shows UDP works both ways, so neither the forecast nor a
		// relay is measured (TestDecideForecast_Precedence/blocked_after_reply).
		// Nothing sent includes a local firewall refusing UDP, which leaves
		// only a relay.
		if v.replied {
			return Forecast{DirectP2P: "unknown", TURNRequired: false}
		}
		p2p := "unlikely"
		if v.nothingSent {
			p2p = "unknown"
		}
		return Forecast{DirectP2P: p2p, TURNRequired: true}
	case AddressDependentMapping, AddressPortDependentMapping:
		return Forecast{DirectP2P: "unlikely", TURNRequired: true}
	case Unknown:
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	case EndpointIndependentMapping:
		// Untested filtering must not read stronger than measured strict
		// filtering: the same router would otherwise improve by being measured
		// less. Most public STUN servers cannot measure it, so this is what
		// default-server runs get.
		if v.Filtering == FilteringEndpointIndependent {
			return Forecast{DirectP2P: "likely", TURNRequired: false}
		}
		return Forecast{DirectP2P: "possible", TURNRequired: false}
	default:
		return Forecast{DirectP2P: "unknown", TURNRequired: false}
	}
}

// applyCGNAT sets CGNAT=true and appends the warning when the group's first
// mapped address is in RFC 6598 100.64.0.0/10. Public servers never see that
// range; behind a carrier NAT the probes cross it and the mapping verdict
// covers it (TestRun_MappingBehaviorOverRealSockets).
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
