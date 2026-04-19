# natcheck - Technical Requirements (v0.1)

> Last updated: 2026-04-19
> Status: Draft (pre-implementation)
> Companion: [PRD.md](PRD.md), [HANDOFF.md](HANDOFF.md)

## Architecture

Single binary, four internal packages. No daemons, no config files by default, no external services beyond the STUN servers being probed.

```
cmd/natcheck/main.go          Entry point, calls cli.Run
internal/cli/                 Flag parsing, orchestration, exit codes
internal/probe/               STUN Binding requests, RTT capture
internal/classify/            Probe results -> NAT-type verdict
internal/report/              Verdict -> human text or JSON
```

## Dependencies

- **Runtime:** `github.com/pion/stun/v2` (or latest compatible). Nothing else for v0.1.
- **Dev:** `golangci-lint` (shared 1mb-dev CI baseline, v2.9.0+).
- **Go version:** 1.25+ (matches 1mb-dev default).

Rejected for v0.1:

- `cobra` / `urfave/cli` - flag package is sufficient for a single-command CLI with < 10 flags.
- `zerolog` / `slog` - `fmt` is sufficient; structured logging arrives if and when the tool gains subcommands.
- `viper` - no config file in v0.1.

## Package contracts

### `internal/probe`

```go
type Server struct {
    Host string
    Port int
}

type Result struct {
    Server    Server
    Mapped    netip.AddrPort  // empty if probe failed
    RTT       time.Duration   // zero if probe failed
    Err       error           // nil on success
}

type Prober interface {
    Probe(ctx context.Context, s Server) Result
}
```

One `Prober` implementation: `stunProber{}` wrapping `pion/stun`. Accepts context for timeout. Returns zero-value `Result` with non-nil `Err` on failure; callers never panic.

### `internal/classify`

```go
type NATType int

const (
    Unknown NATType = iota
    EndpointIndependentMapping  // RFC 5780, "cone"
    AddressDependentMapping     // RFC 5780
    AddressPortDependentMapping // RFC 5780, "symmetric"
    Blocked                     // all probes failed
)

type Verdict struct {
    Type             NATType
    LegacyName       string    // "cone", "symmetric", etc.
    PublicEndpoint   netip.AddrPort
    CGNAT            bool
    FilteringTested  bool      // false in v0.1 always
    Warnings         []string
    Forecast         Forecast
}

type Forecast struct {
    DirectP2P      string // "likely" | "possible" | "unlikely"
    TURNRequired   bool
}

func Classify(results []probe.Result) Verdict
```

Pure function. No I/O. Easiest package to test thoroughly. Table-driven tests cover RFC 5780 classification boundaries, CGNAT detection, probe-failure combinations.

### `internal/report`

```go
type Format int

const (
    FormatHuman Format = iota
    FormatJSON
)

func Render(w io.Writer, v classify.Verdict, probes []probe.Result, format Format) error
```

Human format is hand-rolled string building. JSON format uses `encoding/json` with tagged structs. Schema stability matters; `--json` is a public contract from v0.1 onward.

### `internal/cli`

```go
type Options struct {
    Servers  []probe.Server
    Timeout  time.Duration
    JSON     bool
    Verbose  bool
}

func Run(ctx context.Context, args []string, out, errOut io.Writer) int
```

Returns exit code. Parses flags, defaults servers, runs probes concurrently (one goroutine per server, bounded by timeout), calls classify, calls report. Testable in-process without spawning subprocesses.

## Default STUN servers

v0.1 ships with two defaults, both well-known and free:

1. `stun.l.google.com:19302`
2. `stun.cloudflare.com:3478`

Adding a third would make classification marginally more robust; starting with two and letting users override is sufficient. If a default server times out, we still report what we learned from the others and warn.

## RFC 5780 classification (v0.1 partial)

With only basic STUN Binding responses (no CHANGE-REQUEST), we can determine:

- **Mapping behavior:**
  - Two servers on different IPs, probed from the same local port, return the *same* mapped endpoint -> Endpoint-Independent Mapping
  - Different mapped endpoints -> Address-Dependent or Address-Port-Dependent Mapping (we cannot distinguish ADM from APDM without CHANGE-REQUEST; v0.1 reports "Address-Dependent Mapping or stricter" and emits warning)

- **What we cannot determine in v0.1:**
  - Filtering behavior (requires CHANGE-REQUEST)
  - Hairpinning behavior (requires a helper that echoes to the mapped endpoint)

v0.2 plan: ship `natcheck-server` (or document coturn setup) that supports RFC 5780 attributes, enabling full mapping + filtering classification.

## CGNAT detection

If the observed public IP falls in `100.64.0.0/10` (RFC 6598 shared address space), emit `cgnat_detected` warning. CGNAT typically prevents inbound direct P2P but doesn't prevent outbound STUN. Forecast adjusts: `DirectP2P: possible` when CGNAT detected with EIM, `unlikely` when CGNAT detected with ADM.

## Concurrency model

Probe goroutines run in parallel, one per server, all bounded by a single context timeout. If the global timeout fires, in-flight probes are cancelled and their results recorded as errors. Classification waits for all probes (success or error) before running.

## Testing strategy

- **`internal/probe`:** integration test against a local `pion/stun` test server (spawned in `TestMain`). No network required.
- **`internal/classify`:** table-driven unit tests covering every combination of probe outcomes. Target >= 80% coverage; this is the brain of the tool.
- **`internal/report`:** golden-file tests for human output, schema-stability test for JSON.
- **`internal/cli`:** in-process test with fake prober; asserts exit codes + orchestration.
- **`cmd/natcheck`:** no test; entry point is 3 lines.

No live-network test in CI. Manual verification against real networks before release.

## Build and release

- `make build` -> single binary in repo root, versioned via `-ldflags "-X main.version=..."`
- `make test` -> unit + integration with local test server, no network
- `make lint` -> golangci-lint (v2.9.0 per 1mb-dev shared CI)
- Release: `git tag v0.1.0`, push, `goreleaser` later (v0.2+).

## Non-functional targets

- Cold-start probe completes in < 2s on a healthy network
- Binary size < 15 MB static
- Zero allocations on the probe hot path (nice-to-have, not a gate)
- `--json` schema is a public contract; additive changes only after v0.1

## Security considerations

- No private keys, no credentials, no user data sent to STUN servers beyond the standard Binding request.
- `--server` accepts user input; validate `host:port` shape before handing to `pion/stun`.
- Treat STUN responses as untrusted: `pion/stun` handles parsing. No further eval.
- No subprocess execution. No file I/O beyond reading `--config` (deferred to v0.2+).
