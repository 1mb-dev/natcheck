// Package cli parses flags, orchestrates concurrent STUN probes, and emits
// the final report. Run returns an exit code per docs/design.md:
// 0 = P2P-friendly, 1 = P2P-hostile, 2 = probe or flag error.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1mb-dev/natcheck/internal/classify"
	"github.com/1mb-dev/natcheck/internal/probe"
	"github.com/1mb-dev/natcheck/internal/report"
)

// Version is the natcheck version string. main.go sets this at startup from
// its ldflags-injected variable.
var Version = "dev"

// defaultServers is the two-server default per docs/design.md §Default STUN
// servers.
var defaultServers = []probe.Server{
	{Host: "stun.l.google.com", Port: 19302},
	{Host: "stun.cloudflare.com", Port: 3478},
}

// FilteringFunc runs the RFC 5780 §4.4 filtering classification against a
// single server. Default impl is probe.ProbeFiltering; tests inject stubs.
type FilteringFunc func(ctx context.Context, s probe.Server, timeout time.Duration) probe.FilteringResult

// filteringTimeoutCap bounds the wall-clock spent on the §4.4 sequence so
// it doesn't extend mapping latency unbounded. ProbeFiltering subdivides
// internally across Tests 1/2/3.
const filteringTimeoutCap = 1500 * time.Millisecond

// Run parses args, probes, classifies, renders, and returns an exit code.
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	return runWith(ctx, args, out, errOut, probe.NewSTUN(), probe.ProbeFiltering)
}

// runWith is the testable core with injectable Prober and FilteringFunc.
func runWith(ctx context.Context, args []string, out, errOut io.Writer, prober probe.Prober, filterer FilteringFunc) int {
	opts, err := parseFlags(args, errOut)
	if err != nil {
		// Usage already printed to errOut by flag.Parse.
		return 2
	}
	if opts.helpRequested {
		return 0
	}
	if opts.showVersion {
		_, _ = fmt.Fprintf(out, "natcheck %s\n", Version)
		return 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	results := probeAll(probeCtx, prober, opts.servers)

	if opts.verbose {
		for _, r := range results {
			logProbe(errOut, r)
		}
	}

	// Capability detection: pick the first server whose mapping probe observed
	// OTHER-ADDRESS, then run ProbeFiltering against it. Default servers
	// (Google/Cloudflare) don't advertise OTHER-ADDRESS, so filtering is
	// skipped and adds zero latency for default-server users.
	var filteringResult *probe.FilteringResult
	for _, r := range results {
		if r.Err == nil && r.Other.IsValid() {
			budget := opts.timeout
			if budget > filteringTimeoutCap {
				budget = filteringTimeoutCap
			}
			res := filterer(ctx, r.Server, budget)
			filteringResult = &res
			break
		}
	}

	verdict := classify.Classify(results, filteringResult)

	format := report.FormatHuman
	if opts.json {
		format = report.FormatJSON
	}
	if err := report.Render(out, verdict, results, format); err != nil {
		_, _ = fmt.Fprintf(errOut, "render: %v\n", err)
		return 2
	}

	return exitCode(verdict)
}

// exitCode maps a Verdict to the CLI exit code contract.
func exitCode(v classify.Verdict) int {
	switch {
	case v.Type == classify.Blocked:
		return 2
	case v.Forecast.DirectP2P == "likely" || v.Forecast.DirectP2P == "possible":
		return 0
	default:
		// "unlikely" and "unknown" both indicate the caller should not rely
		// on direct P2P. Exit 1 signals hostile NAT to CI scripts.
		return 1
	}
}

func logProbe(w io.Writer, r probe.Result) {
	addr := net.JoinHostPort(r.Server.Host, strconv.Itoa(r.Server.Port))
	if r.Err != nil {
		_, _ = fmt.Fprintf(w, "probe %s: error: %v\n", addr, r.Err)
		return
	}
	_, _ = fmt.Fprintf(w, "probe %s: rtt=%s mapped=%s\n",
		addr, r.RTT.Round(time.Millisecond), r.Mapped)
}

// probeAll runs one probe per server concurrently under the shared context.
// Results preserve input order — tests and the rendered report both rely on
// this determinism.
func probeAll(ctx context.Context, prober probe.Prober, servers []probe.Server) []probe.Result {
	results := make([]probe.Result, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s probe.Server) {
			defer wg.Done()
			results[i] = prober.Probe(ctx, s)
		}(i, s)
	}
	wg.Wait()
	return results
}

// options is the parsed flag state.
type options struct {
	servers       []probe.Server
	timeout       time.Duration
	json          bool
	verbose       bool
	showVersion   bool
	helpRequested bool
}

// serverList implements flag.Value for a repeatable --server host:port flag.
type serverList []probe.Server

func (s *serverList) String() string {
	parts := make([]string, len(*s))
	for i, sv := range *s {
		parts[i] = net.JoinHostPort(sv.Host, strconv.Itoa(sv.Port))
	}
	return strings.Join(parts, ",")
}

func (s *serverList) Set(value string) error {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", value, err)
	}
	if host == "" {
		return fmt.Errorf("empty host in %q", value)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port in %q: %w", value, err)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("port %d out of range in %q", port, value)
	}
	*s = append(*s, probe.Server{Host: host, Port: port})
	return nil
}

func parseFlags(args []string, errOut io.Writer) (*options, error) {
	fs := flag.NewFlagSet("natcheck", flag.ContinueOnError)
	fs.SetOutput(errOut)

	opts := &options{}
	var servers serverList

	fs.Var(&servers, "server", "STUN server `host:port` (repeatable; overrides defaults)")
	fs.DurationVar(&opts.timeout, "timeout", 5*time.Second, "total mapping-probe `duration` (filtering classification adds up to 1.5s when applicable)")
	fs.BoolVar(&opts.json, "json", false, "emit JSON instead of human-readable report")
	fs.BoolVar(&opts.verbose, "verbose", false, "log each STUN transaction to stderr")
	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		_, _ = fmt.Fprintln(errOut, "Usage: natcheck [flags]")
		_, _ = fmt.Fprintln(errOut)
		_, _ = fmt.Fprintln(errOut, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.helpRequested = true
			return opts, nil
		}
		return nil, err
	}

	if opts.timeout <= 0 {
		_, _ = fmt.Fprintf(errOut, "natcheck: --timeout must be positive, got %s\n", opts.timeout)
		return nil, fmt.Errorf("invalid timeout: %s", opts.timeout)
	}

	if len(servers) > 0 {
		opts.servers = servers
	} else {
		opts.servers = defaultServers
	}

	return opts, nil
}
