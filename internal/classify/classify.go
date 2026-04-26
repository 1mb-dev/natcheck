// Package classify turns probe results into a NAT-type verdict.
//
// Classification follows RFC 5780 mapping-behavior categories
// (Endpoint-Independent, Address-Dependent, Address and Port-Dependent) and
// emits legacy RFC 3489 terms ("cone", "symmetric") for human readers. See
// docs/design.md for the v0.1 scope and limits.
package classify

import (
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

// Forecast is the WebRTC direct-P2P prediction.
type Forecast struct {
	DirectP2P    string // "likely" | "possible" | "unlikely" | "unknown" (v0.1 emits {likely, unlikely, unknown}; "possible" reserved for v0.2 filtering + CGNAT calibration)
	TURNRequired bool
}

// Verdict is the final classification output.
type Verdict struct {
	Type            NATType
	LegacyName      string // "cone", "symmetric", "" when unknown/blocked
	PublicEndpoint  netip.AddrPort
	CGNAT           bool
	FilteringTested bool // always false in v0.1
	Warnings        []string
	Forecast        Forecast
}

// Stable warning vocabulary for the JSON API.
const (
	WarnAllProbesFailed            = "all_probes_failed"
	WarnADMOrStricter              = "adm_or_stricter"
	WarnCGNATDetected              = "cgnat_detected"
	WarnInsufficientProbes         = "insufficient_probes"
	WarnFilteringBehaviorNotTested = "filtering_behavior_not_tested"
)

// cgnatPrefix is RFC 6598 shared address space.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// Classify turns probe results into a Verdict. Pure function: no I/O, no
// goroutines, deterministic for a given input.
//
// A probe.Result is treated as successful only when Err == nil AND
// Mapped.IsValid(). This guards against buggy Prober implementations that
// might report nil-error with a zero mapped endpoint.
func Classify(results []probe.Result) Verdict {
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
		v.Forecast = Forecast{DirectP2P: "unlikely", TURNRequired: true}
		return v

	case 1:
		v.Type = Unknown
		v.PublicEndpoint = successes[0].Mapped
		v.Warnings = append(v.Warnings, WarnInsufficientProbes)
		applyCGNAT(&v)
		v.Forecast = Forecast{DirectP2P: "unknown", TURNRequired: false}
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
			v.Forecast = Forecast{DirectP2P: "likely", TURNRequired: false}
		} else {
			v.Type = AddressDependentMapping
			v.LegacyName = "symmetric"
			v.Warnings = append(v.Warnings, WarnADMOrStricter)
			v.Forecast = Forecast{DirectP2P: "unlikely", TURNRequired: true}
		}
		applyCGNAT(&v)
		// v0.1: CGNAT forces forecast=unknown regardless of observed mapping —
		// unknown is the honest answer when confident classification isn't possible.
		if v.CGNAT {
			v.Forecast = Forecast{DirectP2P: "unknown", TURNRequired: false}
		}
		return v
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
