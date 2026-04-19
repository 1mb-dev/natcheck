# Sample outputs

Real `natcheck` runs captured during v0.1 manual QA. Public IP addresses are
redacted to RFC 5737 (IPv4 `203.0.113.0/24`) and RFC 3849 (IPv6
`2001:db8::/32`) documentation ranges; ports, RTTs, error messages, and
private RFC 1918 source addresses are real.

## Captured

| File | Network | Servers | Outcome |
|------|---------|---------|---------|
| [`dev-machine-default.txt`](dev-machine-default.txt) / [`.json`](dev-machine-default.json) | Residential dual-stack (IPv4 + IPv6) | default (Google + Cloudflare) | IPv6 preferred by DNS; Google IPv6 responds; Cloudflare IPv6 times out → 1/2 probes → `Unknown` verdict, exit 1 |
| [`dev-machine-ipv4.txt`](dev-machine-ipv4.txt) / [`.json`](dev-machine-ipv4.json) | Same network, IPv4-forced via A-record `--server` | Google `74.125.250.129:19302`, Cloudflare `162.159.207.0:3478` | Google IPv4 responds; Cloudflare IPv4 also times out → same `Unknown` verdict |

## Outstanding (require specific network access)

- **CGNAT calibration network** (Linus condition #5 per `todos/releases/v0.1.0/phase-6-qa.md`). Requires tethering to a carrier that uses CGNAT — T-Mobile US, Jio India, Starlink, and similar. Until a real CGNAT sample is captured and the actual direct-P2P behavior is observed, `internal/classify` keeps `Forecast.DirectP2P = "unknown"` whenever CGNAT is detected, and the project README calls out this caveat.
- **Public Wi-Fi / hotspot sample**. Requires access to a captive-portal or hotel-style network.

Contributors can add samples by running `natcheck` and `natcheck --json`, redacting public IPs to documentation ranges, committing the files under this directory, and adding a row to the table above.

## Findings from v0.1 QA

- Cloudflare STUN (`stun.cloudflare.com:3478` → both IPv4 `162.159.207.0` and IPv6 `2606:4700:49::`) was unreachable from the dev network across repeated trials. Could be transient, carrier-level filtering, or Cloudflare rate-limiting this address range. The tool reports the failure honestly: `Unknown` verdict, `insufficient_probes` warning, exit 1. `--server` override is the workaround when a specific default is unreachable.
- IPv6 worked "trivially free" via `pion/stun` + Go's `net` package, despite IPv6 being officially deferred to v0.3 in `docs/design.md`. The dev-machine default run exercised IPv6 end-to-end without any v6-specific code.
- End-to-end latency on the happy-probe leg: 30–70 ms per probe; total wall time bounded by `--timeout` (default 5 s) when the other probe hangs. The PRD target of `< 2 s on a healthy network` holds when both probes succeed; degraded networks see up to `--timeout` wall time.
