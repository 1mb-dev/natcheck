package report

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
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

// warningText maps a stable warning ID to a short human sentence, filled from
// v where the sentence names values. Unknown IDs fall through to the raw ID so
// newly introduced warnings surface without code changes here.
func warningText(id string, v classify.Verdict) string {
	switch id {
	case classify.WarnFilteringBehaviorNotTested:
		return "Filtering not tested."
	case classify.WarnFilteringSkippedNoChangeRequest:
		return "Filtering skipped: server does not support RFC 5780 CHANGE-REQUEST."
	case classify.WarnCGNATDetected:
		return "Mapped address is in 100.64.0.0/10: the server sits inside a carrier or overlay network, so the NAT beyond it is not measured."
	case classify.WarnADMOrStricter:
		return "Classification is ADM or stricter."
	case classify.WarnAllProbesFailed:
		return "All probes failed."
	case classify.WarnInsufficientProbes:
		// Fires whenever any per-family group has fewer than two probes.
		// Under v0.1.3 combine semantics this can co-occur with a confident
		// combined verdict (when the other family had two probes that agreed);
		// the text must not imply the verdict itself is unknown.
		return "Insufficient probes for one or more address families."
	case classify.WarnAddressFamiliesDisagree:
		return fmt.Sprintf("IPv4 reads %s and IPv6 reads %s. The verdict follows IPv4: a peer without IPv6 depends on it, and natcheck does not test the peer.",
			v.IPv4.Forecast.DirectP2P, v.IPv6.Forecast.DirectP2P)
	case classify.WarnHairpinUntested:
		return "Hairpinning not tested (local socket setup, STUN probe or listen read failed, the server reported a mapped address natcheck does not send to, or --timeout ran out)."
	case classify.WarnIPv4Untested:
		return "No IPv4 probe succeeded; this verdict covers IPv6 only."
	case classify.WarnNoNAT:
		return "No NAT on the probed path: the mapped endpoint is this host's own address and port. A firewall may still filter."
	case classify.WarnInsufficientServerDiversity:
		return "Servers share one IP, which cannot show mapping behavior. Use --server values on two different IPs."
	default:
		return id
	}
}

// unsentBesideSent reports whether p's request never left the host while the
// same server's request in another address family did. The JSON report keeps
// such rows; here they would print on every healthy single-family run
// (TestRender_HidesUnsentFamily).
func unsentBesideSent(p probe.Result, probes []probe.Result) bool {
	return !p.Target.IsValid() && slices.ContainsFunc(probes, func(q probe.Result) bool {
		return q.Server == p.Server && q.Target.IsValid()
	})
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
	if v.Hairpinning != nil {
		fmt.Fprintf(&b, "Hairpinning: %t\n", *v.Hairpinning)
	}

	probes = slices.DeleteFunc(slices.Clone(probes), func(p probe.Result) bool { return unsentBesideSent(p, probes) })
	if len(probes) > 0 {
		srvs := make([]string, len(probes))
		rtts := make([]string, len(probes))
		maxSrv, maxRTT := 0, 0
		for i, p := range probes {
			srvs[i] = serverStr(p.Server)
			if _, err := netip.ParseAddr(p.Server.Host); err != nil && p.Target.IsValid() {
				srvs[i] += " (" + p.Target.Addr().String() + ")"
			}
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
			fmt.Fprintln(&b, warningText(id, v))
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}
