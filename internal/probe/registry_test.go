package probe

import (
	"encoding/csv"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// offRegistry rows are in specialRanges but not in either IANA registry.
var offRegistry = []netip.Prefix{
	netip.MustParsePrefix("fec0::/10"), // deprecated site-local, RFC 3879
}

var footnote = regexp.MustCompile(`\s*\[\d+\]`)

type registryRow struct {
	name, termination, reachable string
}

// readRegistry returns every block of the pinned registry CSV at path. A cell
// with several blocks gives one entry per block; [n] footnotes are stripped.
func readRegistry(t *testing.T, path string) map[netip.Prefix]registryRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	recs, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range recs[0] {
		col[h] = i
	}
	for _, h := range []string{"Address Block", "Name", "Termination Date", "Globally Reachable"} {
		if _, ok := col[h]; !ok {
			t.Fatalf("%s: no %q column in %q", path, h, recs[0])
		}
	}
	out := map[netip.Prefix]registryRow{}
	for _, rec := range recs[1:] {
		row := registryRow{
			name:        rec[col["Name"]],
			termination: strings.TrimSpace(rec[col["Termination Date"]]),
			reachable:   strings.TrimSpace(footnote.ReplaceAllString(rec[col["Globally Reachable"]], "")),
		}
		for _, cell := range strings.Split(footnote.ReplaceAllString(rec[col["Address Block"]], ""), ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(cell))
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if _, dup := out[p]; dup {
				t.Fatalf("%s: %v twice", path, p)
			}
			out[p] = row
		}
	}
	return out
}

// TestSpecialRanges_MatchIANARegistry checks specialRanges against the pinned
// IANA IPv4 and IPv6 Special-Purpose Address Registries.
func TestSpecialRanges_MatchIANARegistry(t *testing.T) {
	reg := readRegistry(t, "testdata/iana-ipv4-special-registry.csv")
	for p, r := range readRegistry(t, "testdata/iana-ipv6-special-registry.csv") {
		reg[p] = r
	}
	inTable := map[netip.Prefix]int{}
	for _, r := range specialRanges {
		inTable[r.p]++
		if r.p != r.p.Masked() {
			t.Errorf("%v is not a masked prefix", r.p)
		}
		row, ok := reg[r.p]
		if !ok && !slices.Contains(offRegistry, r.p) {
			t.Errorf("%v is in specialRanges but not in the registry or offRegistry", r.p)
		}
		first, last := r.p.Addr(), lastAddr(r.p)
		switch r.d {
		case std:
			if addrScope(first) == scopePublic || addrScope(last) == scopePublic {
				t.Errorf("%v is std, but netip's predicates give it no scope", r.p)
			}
		case own, public:
			if addrScope(first) < scopePublic || addrScope(last) < scopePublic {
				t.Errorf("%v is %v, but netip's predicates override it", r.p, r.d)
			}
		}
		if r.d == public && ok {
			doc := strings.HasPrefix(row.name, "Documentation")
			ended := row.termination != "" && row.termination != "N/A"
			if row.reachable != "True" && !doc && !ended {
				t.Errorf("%v is public, but the registry says Globally Reachable %q", r.p, row.reachable)
			}
		}
	}
	for p := range reg {
		if inTable[p] != 1 {
			t.Errorf("registry block %v has %d specialRanges rows, want 1", p, inTable[p])
		}
	}
	for p, n := range inTable {
		if n > 1 {
			t.Errorf("%v has %d specialRanges rows", p, n)
		}
	}
}

// TestMappingTestAllowed_SpecialRanges checks each specialRanges row against a
// public target and against a target in the same row.
func TestMappingTestAllowed_SpecialRanges(t *testing.T) {
	public4 := netip.MustParseAddrPort("203.0.113.10:3478")
	public6 := netip.MustParseAddrPort("[2001:db8::10]:3478")
	for i, r := range specialRanges {
		a, ok := ownAddr(i)
		if !ok {
			t.Errorf("%v: every address is in a longer row", r.p)
			continue
		}
		if a.Is4In6() {
			// Unmap runs before the lookup, so the IPv4 rows decide.
			continue
		}
		target := public4
		if a.Is6() {
			target = public6
		}
		other := netip.AddrPortFrom(a, 3479)
		if got, want := mappingTestAllowed(target, other), r.d == public; got != want {
			t.Errorf("%v (%v): mappingTestAllowed(%v, %v) = %v, want %v", r.p, r.d, target, other, got, want)
		}
		same := netip.AddrPortFrom(a, 3478)
		if got, want := mappingTestAllowed(same, other), r.d != never; got != want {
			t.Errorf("%v (%v): mappingTestAllowed(%v, %v) = %v, want %v", r.p, r.d, same, other, got, want)
		}
	}
}

// ownAddr returns the highest address of row i that no longer row contains.
func ownAddr(i int) (netip.Addr, bool) {
	p := specialRanges[i].p
	a := lastAddr(p)
	for a.IsValid() && p.Contains(a) {
		j := specialRange(a, func(disposition) bool { return true })
		if j == i {
			return a, true
		}
		a = specialRanges[j].p.Addr().Prev()
	}
	return netip.Addr{}, false
}

func (d disposition) String() string {
	return [...]string{"std", "own", "never", "public"}[d]
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
