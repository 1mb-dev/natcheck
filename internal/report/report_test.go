package report

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/classify"
	"github.com/1mb-dev/natcheck/internal/probe"
)

// Three fixture verdicts cover the JSON/human schema surface:
//   - eim_cone: 2/2 probes agree on a public IPv4 endpoint (happy path)
//   - adm_strict: 2/2 probes disagree (symmetric NAT; TURN required)
//   - blocked: 2/2 probes failed (no network to outbound STUN)

func fixtureEIMCone() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    31 * time.Millisecond,
		},
	}
	return classify.Classify(probes, nil, nil), probes, nil
}

func fixtureADMStrict() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51822"),
			RTT:    31 * time.Millisecond,
		},
	}
	return classify.Classify(probes, nil, nil), probes, nil
}

func fixtureBlocked() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Err:    errors.New("dial udp stun.l.google.com:19302: i/o timeout"),
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Err:    errors.New("dial udp stun.cloudflare.com:3478: i/o timeout"),
		},
	}
	return classify.Classify(probes, nil, nil), probes, nil
}

// fixtureFilteringEIF: EIM mapping + endpoint-independent filtering.
// Forecast: likely (no change vs untested).
func fixtureFilteringEIF() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.example.org", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			Other:  netip.MustParseAddrPort("198.51.100.1:3479"),
			RTT:    18 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
	}
	f := &probe.FilteringResult{
		Server:        probe.Server{Host: "stun.example.org", Port: 3478},
		Test1Mapped:   netip.MustParseAddrPort("203.0.113.45:51820"),
		Test1Other:    netip.MustParseAddrPort("198.51.100.1:3479"),
		Test2Received: true,
		Test3Received: true,
	}
	return classify.Classify(probes, f, nil), probes, f
}

// fixtureFilteringADF: EIM mapping + address-dependent filtering.
// Forecast: possible (Test 2 dropped, Test 3 received).
func fixtureFilteringADF() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.example.org", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			Other:  netip.MustParseAddrPort("198.51.100.1:3479"),
			RTT:    18 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
	}
	f := &probe.FilteringResult{
		Server:        probe.Server{Host: "stun.example.org", Port: 3478},
		Test1Mapped:   netip.MustParseAddrPort("203.0.113.45:51820"),
		Test1Other:    netip.MustParseAddrPort("198.51.100.1:3479"),
		Test2Received: false,
		Test3Received: true,
	}
	return classify.Classify(probes, f, nil), probes, f
}

// hairpinTrue / hairpinFalse return *bool for fixture construction —
// Verdict.Hairpinning is tri-state and the test goldens need both populated
// values.
func hairpinTrue() *bool  { v := true; return &v }
func hairpinFalse() *bool { v := false; return &v }

// fixtureHairpinningDetected: EIM mapping + hairpinning observed. v0.1.4
// does not shift forecast on hairpinning, so the verdict still reads
// `likely` from EIM alone — the new line is purely informational.
func fixtureHairpinningDetected() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    31 * time.Millisecond,
		},
	}
	h := &probe.HairpinningResult{Server: probes[0].Server, Detected: hairpinTrue()}
	return classify.Classify(probes, nil, h), probes, nil
}

// fixtureHairpinningNotDetected: EIM mapping + hairpinning probed but did
// not loop back (genuine negative OR per-NAT filtering false-negative per
// docs/design.md:428).
func fixtureHairpinningNotDetected() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    31 * time.Millisecond,
		},
	}
	h := &probe.HairpinningResult{Server: probes[0].Server, Detected: hairpinFalse()}
	return classify.Classify(probes, nil, h), probes, nil
}

// fixtureHairpinningUntested: hairpin probe attempted but socket setup or
// STUN failed; classifier emits WarnHairpinUntested and JSON hairpinning
// stays null. Exercises the warning-text render path for the new constant.
func fixtureHairpinningUntested() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    31 * time.Millisecond,
		},
	}
	h := &probe.HairpinningResult{Server: probes[0].Server, Err: errors.New("simulated socket setup failure")}
	return classify.Classify(probes, nil, h), probes, nil
}

// fixtureInsufficientProbes: a single successful probe. Combined verdict is
// Unknown but the warning text must signal "partial information," not
// "verdict impossible" — under v0.1.3 combine semantics, the warning fires
// whenever any per-family group has fewer than two probes, which can include
// cases where the other family produced a confident verdict.
func fixtureInsufficientProbes() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
	}
	return classify.Classify(probes, nil, nil), probes, nil
}

// fixtureMixedV4V6Disagree: IPv4 group agrees on EIM, IPv6 group disagrees
// (looks like ADM). Combined verdict is Unknown. Exercises the render path
// for WarnMixedAddressFamilyProbes — the v0.1.3 cross-address-family
// classifier fix had no render regression guard before this fixture.
func fixtureMixedV4V6Disagree() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    31 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun6.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("[2001:db8::1]:51820"),
			RTT:    42 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun6.cloudflare.com", Port: 3478},
			Mapped: netip.MustParseAddrPort("[2001:db8::2]:51821"),
			RTT:    47 * time.Millisecond,
		},
	}
	return classify.Classify(probes, nil, nil), probes, nil
}

// fixtureFilteringAPDF: EIM mapping + address-and-port-dependent filtering.
// Forecast: possible (both Test 2 and Test 3 dropped).
func fixtureFilteringAPDF() (classify.Verdict, []probe.Result, *probe.FilteringResult) {
	probes := []probe.Result{
		{
			Server: probe.Server{Host: "stun.example.org", Port: 3478},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			Other:  netip.MustParseAddrPort("198.51.100.1:3479"),
			RTT:    18 * time.Millisecond,
		},
		{
			Server: probe.Server{Host: "stun.l.google.com", Port: 19302},
			Mapped: netip.MustParseAddrPort("203.0.113.45:51820"),
			RTT:    24 * time.Millisecond,
		},
	}
	f := &probe.FilteringResult{
		Server:        probe.Server{Host: "stun.example.org", Port: 3478},
		Test1Mapped:   netip.MustParseAddrPort("203.0.113.45:51820"),
		Test1Other:    netip.MustParseAddrPort("198.51.100.1:3479"),
		Test2Received: false,
		Test3Received: false,
	}
	return classify.Classify(probes, f, nil), probes, f
}

// compareGolden loads want from path and diff-compares against got. Set
// NATCHECK_UPDATE_GOLDEN=1 to (re)generate the golden file from got.
func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if os.Getenv("NATCHECK_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run with NATCHECK_UPDATE_GOLDEN=1 to create)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output mismatch for %s\n--- got ---\n%s\n--- want ---\n%s",
			path, got, want)
	}
}

func renderToBytes(t *testing.T, v classify.Verdict, probes []probe.Result, _ *probe.FilteringResult, f Format) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, v, probes, f); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.Bytes()
}

func TestRender_Golden(t *testing.T) {
	cases := []struct {
		name    string
		fixture func() (classify.Verdict, []probe.Result, *probe.FilteringResult)
	}{
		{"eim_cone", fixtureEIMCone},
		{"adm_strict", fixtureADMStrict},
		{"blocked", fixtureBlocked},
		{"filtering_eif", fixtureFilteringEIF},
		{"filtering_adf", fixtureFilteringADF},
		{"filtering_apdf", fixtureFilteringAPDF},
		{"mixed_v4v6_disagree", fixtureMixedV4V6Disagree},
		{"insufficient_probes", fixtureInsufficientProbes},
		{"hairpinning_detected", fixtureHairpinningDetected},
		{"hairpinning_not_detected", fixtureHairpinningNotDetected},
		{"hairpinning_untested", fixtureHairpinningUntested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, probes, filtering := tc.fixture()

			human := renderToBytes(t, v, probes, filtering, FormatHuman)
			compareGolden(t, filepath.Join("testdata", "human", tc.name+".golden"), human)

			j := renderToBytes(t, v, probes, filtering, FormatJSON)
			compareGolden(t, filepath.Join("testdata", "json", tc.name+".golden"), j)
		})
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	v, probes, _ := fixtureEIMCone()
	var buf bytes.Buffer
	if err := Render(&buf, v, probes, Format(99)); err == nil {
		t.Fatal("expected error on unknown format, got nil")
	}
}

func TestRender_WarningsAlwaysArray(t *testing.T) {
	// Even for an empty-warnings edge case, JSON should emit "warnings": []
	// not "warnings": null. classify.Classify always seeds with
	// WarnFilteringBehaviorNotTested, but the renderer must be safe for a
	// hypothetical Verdict with nil Warnings too.
	v := classify.Verdict{
		Type:     classify.Blocked,
		Forecast: classify.Forecast{DirectP2P: "unlikely", TURNRequired: true},
		// Warnings intentionally nil.
	}
	var buf bytes.Buffer
	if err := Render(&buf, v, nil, FormatJSON); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"warnings": []`)) {
		t.Errorf("expected empty warnings array, got: %s", buf.String())
	}
}
