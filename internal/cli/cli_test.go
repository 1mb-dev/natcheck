package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1mb-dev/natcheck/internal/probe"
)

// fakeProber answers from a map keyed by "host:port". delay simulates probe
// work (and lets tests exercise concurrent timing).
type fakeProber struct {
	mu              sync.Mutex
	resultsByServer map[string]probe.Result
	delay           time.Duration
	calls           int
}

func (f *fakeProber) Probe(ctx context.Context, s probe.Server) probe.Result {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return probe.Result{Server: s, Err: ctx.Err()}
		}
	}
	f.mu.Lock()
	f.calls++
	r, ok := f.resultsByServer[serverKey(s)]
	f.mu.Unlock()
	if !ok {
		return probe.Result{Server: s, Err: errors.New("fake: unexpected server")}
	}
	r.Server = s
	return r
}

func serverKey(s probe.Server) string {
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// okProber answers the two default servers with matching mapped endpoints
// (EIM happy path).
func okProber() *fakeProber {
	return &fakeProber{resultsByServer: map[string]probe.Result{
		"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 10 * time.Millisecond},
		"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 20 * time.Millisecond},
	}}
}

func run(t *testing.T, prober probe.Prober, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runWith(context.Background(), args, &out, &errOut, prober)
	return code, out.String(), errOut.String()
}

func TestRun_Version(t *testing.T) {
	code, out, _ := run(t, nil, "--version")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "natcheck") {
		t.Errorf("version output missing %q; got %q", "natcheck", out)
	}
}

func TestRun_Help(t *testing.T) {
	code, _, errOut := run(t, nil, "--help")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(errOut, "Usage") {
		t.Errorf("usage missing; errOut=%q", errOut)
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	code, _, _ := run(t, nil, "--nonsense")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

func TestRun_InvalidTimeout(t *testing.T) {
	code, _, errOut := run(t, nil, "--timeout", "0")
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errOut, "timeout") {
		t.Errorf("errOut missing timeout error; got %q", errOut)
	}
}

func TestRun_InvalidServer(t *testing.T) {
	cases := []string{"bad-format", "host:", "host:bad", "host:99999", ":3478"}
	for _, arg := range cases {
		t.Run(arg, func(t *testing.T) {
			code, _, _ := run(t, nil, "--server", arg)
			if code != 2 {
				t.Errorf("--server %q: code = %d, want 2", arg, code)
			}
		})
	}
}

func TestRun_EIM_Exit0(t *testing.T) {
	code, out, _ := run(t, okProber(), "--timeout", "1s")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "Direct P2P: likely") {
		t.Errorf("missing forecast line; got %q", out)
	}
}

func TestRun_ADM_Exit1(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 10 * time.Millisecond},
		"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51822"), RTT: 20 * time.Millisecond},
	}}
	code, out, _ := run(t, fp)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(out, "Direct P2P: unlikely") {
		t.Errorf("missing forecast line; got %q", out)
	}
}

func TestRun_Blocked_Exit2(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		"stun.l.google.com:19302":  {Err: errors.New("dial udp: connection refused")},
		"stun.cloudflare.com:3478": {Err: errors.New("dial udp: connection refused")},
	}}
	code, _, _ := run(t, fp)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
}

func TestRun_CGNATPlusEIM_Exit1(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("100.64.1.5:51820"), RTT: 10 * time.Millisecond},
		"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("100.64.1.5:51820"), RTT: 20 * time.Millisecond},
	}}
	code, out, _ := run(t, fp)
	if code != 1 {
		t.Errorf("code = %d, want 1 (CGNAT forces forecast=unknown)", code)
	}
	if !strings.Contains(out, "Direct P2P: unknown") {
		t.Errorf("missing unknown forecast; got %q", out)
	}
}

func TestRun_JSON(t *testing.T) {
	code, out, _ := run(t, okProber(), "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(out, `"nat_type": "EIM"`) {
		t.Errorf("JSON output missing nat_type; got %q", out)
	}
}

func TestRun_Verbose(t *testing.T) {
	code, _, errOut := run(t, okProber(), "--verbose")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(errOut, "probe stun.l.google.com:19302:") {
		t.Errorf("verbose log missing for google; got %q", errOut)
	}
	if !strings.Contains(errOut, "probe stun.cloudflare.com:3478:") {
		t.Errorf("verbose log missing for cloudflare; got %q", errOut)
	}
}

func TestRun_ServerOverride(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		"custom.test:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 10 * time.Millisecond},
	}}
	code, _, _ := run(t, fp, "--server", "custom.test:3478")
	// Single probe → Unknown (no comparison) → forecast unknown → exit 1.
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if fp.calls != 1 {
		t.Errorf("expected 1 probe call (custom only), got %d", fp.calls)
	}
}

func TestRun_MultipleServerOverride(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		"a.test:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 10 * time.Millisecond},
		"b.test:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 20 * time.Millisecond},
	}}
	code, _, _ := run(t, fp, "--server", "a.test:3478", "--server", "b.test:3478")
	if code != 0 {
		t.Errorf("code = %d, want 0 (two agreeing custom servers)", code)
	}
	if fp.calls != 2 {
		t.Errorf("expected 2 probe calls, got %d", fp.calls)
	}
}

func TestRun_ConcurrentTiming(t *testing.T) {
	fp := &fakeProber{
		delay: 200 * time.Millisecond,
		resultsByServer: map[string]probe.Result{
			"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 200 * time.Millisecond},
			"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 200 * time.Millisecond},
		},
	}
	start := time.Now()
	code, _, _ := run(t, fp, "--timeout", "1s")
	elapsed := time.Since(start)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("probes did not run concurrently: elapsed=%v (expected ~200ms)", elapsed)
	}
}

func TestRun_TimeoutFires(t *testing.T) {
	fp := &fakeProber{
		delay: 500 * time.Millisecond,
		resultsByServer: map[string]probe.Result{
			"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 500 * time.Millisecond},
			"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 500 * time.Millisecond},
		},
	}
	code, _, _ := run(t, fp, "--timeout", "50ms")
	if code != 2 {
		t.Errorf("code = %d, want 2 (all probes cancelled)", code)
	}
}

func TestRun_ResultOrderMatchesInputOrder(t *testing.T) {
	fp := &fakeProber{resultsByServer: map[string]probe.Result{
		// Give cloudflare faster RTT, but input order is google first.
		"stun.l.google.com:19302":  {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 30 * time.Millisecond},
		"stun.cloudflare.com:3478": {Mapped: netip.MustParseAddrPort("203.0.113.45:51820"), RTT: 10 * time.Millisecond},
	}}
	_, out, _ := run(t, fp)
	googleIdx := strings.Index(out, "stun.l.google.com:19302")
	cloudflareIdx := strings.Index(out, "stun.cloudflare.com:3478")
	if googleIdx < 0 || cloudflareIdx < 0 {
		t.Fatalf("probe lines missing; out=%q", out)
	}
	if googleIdx > cloudflareIdx {
		t.Errorf("expected google before cloudflare in output; got:\n%s", out)
	}
}
