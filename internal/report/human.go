package report

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/1mb-dev/natcheck/internal/classify"
	"github.com/1mb-dev/natcheck/internal/probe"
)

// natTypeHuman returns the NAT type with legacy term in parens when available.
func natTypeHuman(v classify.Verdict) string {
	name := v.Type.String()
	if v.LegacyName != "" {
		return fmt.Sprintf("%s (%s)", name, v.LegacyName)
	}
	return name
}

// warningText maps a stable warning ID to a short human sentence. Unknown IDs
// fall through to the raw ID so newly introduced warnings surface without
// code changes here.
func warningText(id string) string {
	switch id {
	case classify.WarnFilteringBehaviorNotTested:
		return "Filtering not tested."
	case classify.WarnFilteringSkippedNoChangeRequest:
		return "Filtering skipped: server does not advertise OTHER-ADDRESS."
	case classify.WarnCGNATDetected:
		return "CGNAT detected (IP in 100.64.0.0/10)."
	case classify.WarnADMOrStricter:
		return "Classification is ADM or stricter."
	case classify.WarnAllProbesFailed:
		return "All probes failed."
	case classify.WarnInsufficientProbes:
		return "Insufficient probes to determine mapping behavior."
	default:
		return id
	}
}

func serverStr(s probe.Server) string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

func renderHuman(w io.Writer, v classify.Verdict, probes []probe.Result) error {
	var b strings.Builder

	fmt.Fprintf(&b, "Direct P2P: %s\n", v.Forecast.DirectP2P)
	fmt.Fprintf(&b, "NAT type: %s\n", natTypeHuman(v))
	if v.PublicEndpoint.IsValid() {
		fmt.Fprintf(&b, "Public endpoint: %s\n", v.PublicEndpoint)
	}
	if v.Filtering != classify.FilteringUntested {
		if v.FilteringTestedAgainst.Host != "" {
			fmt.Fprintf(&b, "Filtering: %s (tested against %s)\n",
				v.Filtering, serverStr(v.FilteringTestedAgainst))
		} else {
			fmt.Fprintf(&b, "Filtering: %s\n", v.Filtering)
		}
	}

	if len(probes) > 0 {
		srvs := make([]string, len(probes))
		rtts := make([]string, len(probes))
		maxSrv, maxRTT := 0, 0
		for i, p := range probes {
			srvs[i] = serverStr(p.Server)
			if n := len(srvs[i]); n > maxSrv {
				maxSrv = n
			}
			if p.Err == nil {
				rtts[i] = p.RTT.Round(time.Millisecond).String()
				if n := len(rtts[i]); n > maxRTT {
					maxRTT = n
				}
			}
		}

		b.WriteString("\nProbes:\n")
		for i, p := range probes {
			if p.Err != nil {
				fmt.Fprintf(&b, "  %-*s  error=%s\n", maxSrv, srvs[i], p.Err)
				continue
			}
			fmt.Fprintf(&b, "  %-*s  rtt=%-*s  mapped=%s\n",
				maxSrv, srvs[i], maxRTT, rtts[i], p.Mapped)
		}
	}

	if len(v.Warnings) > 0 {
		b.WriteString("\n")
		for _, id := range v.Warnings {
			fmt.Fprintln(&b, warningText(id))
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}
