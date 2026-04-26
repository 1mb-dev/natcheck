package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/1mb-dev/natcheck/internal/classify"
	"github.com/1mb-dev/natcheck/internal/probe"
)

// probeJSON is the per-probe shape in the JSON report. rtt_ms / mapped are
// omitted for failed probes; error is omitted for successful ones.
type probeJSON struct {
	Server string `json:"server"`
	RTTMs  int64  `json:"rtt_ms,omitempty"`
	Mapped string `json:"mapped,omitempty"`
	Error  string `json:"error,omitempty"`
}

type forecastJSON struct {
	DirectP2P    string `json:"direct_p2p"`
	TURNRequired bool   `json:"turn_required"`
}

// filteringJSON is the v0.1.2-additive top-level "filtering" object.
// tested_against is omitted when behavior == "untested".
type filteringJSON struct {
	Behavior      string `json:"behavior"`
	TestedAgainst string `json:"tested_against,omitempty"`
}

type reportJSON struct {
	NATType        string        `json:"nat_type"`
	NATTypeLegacy  string        `json:"nat_type_legacy"`
	PublicEndpoint string        `json:"public_endpoint"`
	Probes         []probeJSON   `json:"probes"`
	WebRTCForecast forecastJSON  `json:"webrtc_forecast"`
	Warnings       []string      `json:"warnings"`
	Filtering      filteringJSON `json:"filtering"`
}

// natTypeAbbrev is the stable JSON short name for a classify.NATType.
func natTypeAbbrev(t classify.NATType) string {
	switch t {
	case classify.EndpointIndependentMapping:
		return "EIM"
	case classify.AddressDependentMapping:
		return "ADM"
	case classify.AddressPortDependentMapping:
		return "APDM"
	case classify.Blocked:
		return "Blocked"
	default:
		return "Unknown"
	}
}

func renderJSON(w io.Writer, v classify.Verdict, probes []probe.Result) error {
	r := reportJSON{
		NATType:       natTypeAbbrev(v.Type),
		NATTypeLegacy: v.LegacyName,
		WebRTCForecast: forecastJSON{
			DirectP2P:    v.Forecast.DirectP2P,
			TURNRequired: v.Forecast.TURNRequired,
		},
		Warnings:  v.Warnings,
		Probes:    make([]probeJSON, len(probes)),
		Filtering: filteringJSON{Behavior: v.Filtering.String()},
	}
	if v.PublicEndpoint.IsValid() {
		r.PublicEndpoint = v.PublicEndpoint.String()
	}
	if v.Filtering != classify.FilteringUntested && v.FilteringTestedAgainst.Host != "" {
		r.Filtering.TestedAgainst = serverStr(v.FilteringTestedAgainst)
	}
	// Ensure arrays marshal as [] rather than null.
	if r.Warnings == nil {
		r.Warnings = []string{}
	}

	for i, p := range probes {
		pj := probeJSON{Server: serverStr(p.Server)}
		if p.Err != nil {
			pj.Error = p.Err.Error()
		} else {
			pj.RTTMs = p.RTT.Round(time.Millisecond).Milliseconds()
			pj.Mapped = p.Mapped.String()
		}
		r.Probes[i] = pj
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&r)
}
