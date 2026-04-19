# natcheck — Architecture

> Status: pre-v0.1 (implementation in progress)
> Last updated: 2026-04-19

Product framing and technical spec for v0.1 in one document. Working notes, per-phase plans, and open decisions live in `todos/HANDOFF.md` and `todos/releases/v0.1.0/` (dev-internal, not tracked in git).

## Problem

Every WebRTC, P2P, or VPN developer hits the same question when connections fail: *"what kind of NAT am I behind, and will my connections work?"* Today, answering that means:

- Running `stun-client` against one or two servers and eyeballing the mapped address
- Finding a dusty online NAT classifier that may or may not still work
- Reading RFC 5780 to understand what "endpoint-independent mapping" means in practice
- Guessing at whether the result means your P2P app will or won't work

The answer exists in scattered pieces. No one tool packages it.

## Audience

Two user personas, both served by the same default invocation:

1. **WebRTC / P2P developer debugging connectivity.** Wants a fast, unambiguous answer: "will direct P2P work from this network, and if not, is TURN required?" Time budget: 5 seconds.
2. **Curious network person.** Wants to understand their home or office NAT in RFC 5780 terms. Time budget: a minute, with willingness to read one paragraph of explanation.

Secondary: CI scripts that want to assert a network's NAT type before running integration tests. Served by `--json` output + well-defined exit codes.

## Value proposition

- **One command, one answer.** `natcheck` with no flags produces a complete report.
- **Human-readable by default, machine-readable on request.** Default output is a screenful; `--json` is pipeable.
- **Honest about limits.** Many public STUN servers don't support RFC 5780 CHANGE-REQUEST, so full classification is sometimes impossible. The tool says so instead of guessing.
- **No setup.** Single binary, no services to run, no config files required.
- **Pion-native.** Built on `pion/stun`, pure Go, single static binary.

## v0.1 scope

In:

- STUN Binding request against 2+ servers (defaults: `stun.l.google.com:19302`, `stun.cloudflare.com:3478`)
- Public endpoint reporting (IP:port as observed by each server)
- Mapping-behavior classification: Endpoint-Independent vs Address/Port-Dependent, based on whether mapped endpoints agree across servers
- RTT measurement per server
- Human-readable default output (one screen)
- `--json` flag for structured output
- `--verbose` flag showing each STUN transaction
- `--server host:port` flag, repeatable, to add or override servers
- `--timeout duration` flag (default 5s)
- `--version`, `--help`
- WebRTC forecast: `likely | possible | unlikely | unknown`
- CGNAT heuristic warning (if mapped IP is in 100.64.0.0/10)
- Exit codes: 0 (P2P-friendly), 1 (P2P-hostile), 2 (probe error)

Out (deferred):

- Filtering behavior (v0.2; requires RFC 5780-capable STUN server — companion `natcheck-server` or coturn setup guide)
- Hairpinning test (v0.2)
- TURN probing (v0.3)
- IPv6 (v0.3 — included if trivial via `pion/stun`, otherwise explicit)
- Multi-interface enumeration (v0.3)
- Homebrew tap (v0.1.1)
- Continuous monitoring / watch mode (maybe; probably never)
- TUI (not planned)
- TCP STUN (not planned)

## Non-goals

- Not a general network diagnostic tool. Scope is NAT and STUN only.
- Not a TURN server or relay. `natcheck` probes; it doesn't serve.
- Not a WebRTC test harness. For end-to-end WebRTC testing, use pion's examples or `webrtc-internals`.

## UX shape

### Default invocation

```
$ natcheck
Direct P2P: likely
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820

Probes:
  stun.l.google.com:19302   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested (v0.1).
```

Forecast leads the output so the WebRTC-dev persona gets the answer on line 1. Classification detail follows for the curious reader.

### JSON invocation

```json
{
  "nat_type": "EIM",
  "nat_type_legacy": "cone",
  "public_endpoint": "203.0.113.45:51820",
  "probes": [
    {"server": "stun.l.google.com:19302", "rtt_ms": 24, "mapped": "203.0.113.45:51820"},
    {"server": "stun.cloudflare.com:3478", "rtt_ms": 31, "mapped": "203.0.113.45:51820"}
  ],
  "webrtc_forecast": {"direct_p2p": "likely", "turn_required": false},
  "warnings": ["filtering_behavior_not_tested"]
}
```

The JSON schema is a public contract from v0.1 onward; only additive changes after release.

### Failure modes

- All probes timeout → exit 2, report per-server errors
- Mapped endpoints disagree across servers → NAT type "Address-Dependent Mapping" (or APDM if we can distinguish; v0.1 reports "ADM or stricter"), exit 1, forecast `unlikely`
- Mapped IP in `100.64.0.0/10` → warning `cgnat_detected`, forecast `unknown` in v0.1 (upgrades to `possible` or `unlikely` post real-network calibration)

## Architecture

Single binary, four internal packages. No daemons, no config files by default, no external services beyond the STUN servers being probed.

```
cmd/natcheck/main.go          Entry point, calls cli.Run
internal/cli/                 Flag parsing, orchestration, exit codes
internal/probe/               STUN Binding requests, RTT capture
internal/classify/            Probe results → NAT-type verdict
internal/report/              Verdict → human text or JSON
```

## Dependencies

- **Runtime:** `github.com/pion/stun/v3` (latest stable). Nothing else for v0.1.
- **Dev:** `golangci-lint` (shared 1mb-dev CI baseline, v2.9.0+).
- **Go version:** 1.25+.

Rejected for v0.1:

- `cobra` / `urfave/cli` — `flag` is sufficient for a single-command CLI with < 10 flags.
- `zerolog` / `slog` — `fmt` is sufficient; structured logging arrives if and when the tool gains subcommands.
- `viper` — no config file in v0.1.

## Package contracts

### `internal/probe`

```go
type Server struct {
    Host string
    Port int
}

type Result struct {
    Server Server
    Mapped netip.AddrPort  // zero if probe failed
    RTT    time.Duration   // zero if probe failed
    Err    error           // nil on success
}

type Prober interface {
    Probe(ctx context.Context, s Server) Result
}
```

One `Prober` implementation: `stunProber` using `pion/stun` primitives (`Build`/`Decode`) over raw UDP. Cancellation is bridged via `conn.SetDeadline` from `ctx.Done`. Returns zero-value `Result` with non-nil `Err` on failure; callers never panic. One-shot — no retransmission; the caller's timeout is the retry budget.

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
    Type            NATType
    LegacyName      string    // "cone", "symmetric", etc.
    PublicEndpoint  netip.AddrPort
    CGNAT           bool
    FilteringTested bool      // false in v0.1 always
    Warnings        []string
    Forecast        Forecast
}

type Forecast struct {
    DirectP2P    string // "likely" | "possible" | "unlikely" | "unknown"
    TURNRequired bool
}

func Classify(results []probe.Result) Verdict
```

Pure function. No I/O. Table-driven tests cover RFC 5780 classification boundaries, CGNAT detection, and the partial-failure matrix (0/N, 1/N both orderings, N/N probes successful).

### `internal/report`

```go
type Format int

const (
    FormatHuman Format = iota
    FormatJSON
)

func Render(w io.Writer, v classify.Verdict, probes []probe.Result, format Format) error
```

Human format is hand-rolled string building, forecast-first. JSON format uses `encoding/json` with tagged structs, pinned by golden-file tests (EIM cone, ADM strict, Blocked) since the schema is a public contract.

### `internal/cli`

```go
type Options struct {
    Servers []probe.Server
    Timeout time.Duration
    JSON    bool
    Verbose bool
}

func Run(ctx context.Context, args []string, out, errOut io.Writer) int
```

Returns exit code. Parses flags, defaults servers, runs probes concurrently (one goroutine per server, bounded by timeout), calls `Classify`, calls `Render`. Testable in-process with a fake `Prober`.

## Default STUN servers

v0.1 ships with two defaults, both well-known and free:

1. `stun.l.google.com:19302`
2. `stun.cloudflare.com:3478`

Adding a third would make classification marginally more robust; two plus `--server` override is sufficient. If a default server times out, we still report what we learned from the others and warn.

## RFC 5780 classification (v0.1 partial)

With only basic STUN Binding responses (no `CHANGE-REQUEST`), we can determine:

- **Mapping behavior:**
  - Two servers on different IPs, probed from the same local port, return the *same* mapped endpoint → Endpoint-Independent Mapping
  - Different mapped endpoints → Address-Dependent or Address-Port-Dependent Mapping. v0.1 cannot distinguish ADM from APDM without `CHANGE-REQUEST`; it reports "ADM or stricter" and emits warning `adm_or_stricter`.

What v0.1 cannot determine:

- Filtering behavior (requires `CHANGE-REQUEST`)
- Hairpinning behavior (requires a helper that echoes to the mapped endpoint)

v0.2 plan: ship `natcheck-server` (or document a coturn setup) that supports RFC 5780 attributes, enabling full mapping + filtering classification.

## CGNAT detection

If the observed public IP falls in `100.64.0.0/10` (RFC 6598 shared address space), emit warning `cgnat_detected`. CGNAT typically prevents inbound direct P2P but doesn't prevent outbound STUN.

v0.1 forecast policy: `DirectP2P: "unknown"` whenever CGNAT is detected. The `possible` / `unlikely` upgrade gates on observed P2P behavior from a real CGNAT network (T-Mobile / Jio / Starlink) during v0.1 QA. Shipping an unvalidated forecast would break the "honest" value prop — `unknown` is the correct answer when we don't know.

## Concurrency model

Probe goroutines run in parallel, one per server, all bounded by a single context timeout. If the global timeout fires, in-flight probes are cancelled and their results recorded as errors. `Classify` waits for all probes (success or error) before running.

## Testing strategy

- **`internal/probe`:** integration tests against an in-process fake STUN responder (spawned per-test). No network required in CI.
- **`internal/classify`:** table-driven unit tests covering every combination of probe outcomes, including the partial-failure matrix (0/2, 1/2 both orderings, 2/2). Target ≥ 80% coverage; this is the brain of the tool.
- **`internal/report`:** golden-file tests for human output; schema-stability golden-file tests for JSON with three fixtures (EIM cone, ADM strict, Blocked).
- **`internal/cli`:** in-process test with a fake `Prober`; asserts exit codes and orchestration.
- **`cmd/natcheck`:** no test; entry point is three lines.

No live-network test in CI. Manual verification against real networks — including at least one CGNAT network — before release; sample outputs committed under `docs/samples/`.

## Build and release

- `make build` → single binary in repo root, versioned via `-ldflags "-X main.version=..."`
- `make test` → unit + integration with in-process test server, no network
- `make lint` → `golangci-lint` (v2.9.0 per 1mb-dev shared CI)
- Release: `git tag v0.1.0`, push. `goreleaser` later (v0.2+).

## Non-functional targets

- Cold-start probe completes in < 2s on a healthy network
- Binary size < 15 MB static
- `--json` schema is a public contract; additive changes only after v0.1
- `internal/classify` test coverage ≥ 80%
- `go install github.com/1mb-dev/natcheck/cmd/natcheck@latest` works with no further setup

## Security considerations

- No private keys, no credentials, no user data sent to STUN servers beyond the standard Binding request.
- `--server` accepts user input; validate `host:port` shape before handing to `pion/stun`.
- Treat STUN responses as untrusted: `pion/stun` handles parsing. No further eval.
- No subprocess execution. No file I/O beyond reading `--config` (deferred to v0.2+).

## Risks

1. **Public STUN servers are rate-limited / unreliable.** Mitigation: default to two servers, support `--server` override, treat probe failures as warnings not fatal where possible.
2. **RFC 5780 classification is incomplete without a cooperating server.** Mitigation: v0.1 is honest about what it cannot determine; v0.2 ships the companion server.
3. **CGNAT is common and complicates NAT classification.** Mitigation: detect `100.64/10` and call it out separately; forecast stays `unknown` until calibrated against real CGNAT traffic.
4. **"cone" and "symmetric" are fuzzy legacy terms.** Mitigation: report both RFC 5780 terms and legacy terms, with a one-line explanation in `--verbose`.
