# natcheck

NAT type diagnosis CLI. One command tells you why your WebRTC, peer-to-peer, or VPN setup struggles.

> Status: pre-v0.1 (scaffolding). See [`docs/PRD.md`](docs/PRD.md), [`docs/TRD.md`](docs/TRD.md), [`docs/HANDOFF.md`](docs/HANDOFF.md).

## Why

Every WebRTC, P2P, or VPN developer hits the same question: "what kind of NAT am I behind, and will my connections work?" Answering it today means piecing together output from `stun-client`, online tests, and RFC reading. `natcheck` packages the answer into one command with human-readable output and a `--json` mode for scripting.

## Quick start

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest

natcheck
```

Example output:

```
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820
Probes:
  stun.l.google.com:19302  rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478 rtt=31ms  mapped=203.0.113.45:51820

WebRTC forecast:
  Direct P2P: likely
  TURN required: no

Note: filtering behavior not tested (requires RFC 5780-capable STUN server)
```

## Flags

| Flag | Purpose |
|------|---------|
| `--json` | Emit JSON instead of human-readable report |
| `--verbose` | Show each STUN transaction |
| `--server host:port` | Add a custom STUN server (repeatable) |
| `--timeout duration` | Probe timeout, default 5s |
| `--version` | Print version |
| `--help` | Print help |

## Exit codes

- `0` - probe succeeded, NAT is P2P-friendly enough
- `1` - probe succeeded, NAT is hostile to direct P2P (hard NAT or CGNAT)
- `2` - probe failed (no servers reachable, configuration error)

## Stack

Built on [`pion/stun`](https://github.com/pion/stun). Pure Go, no cgo, single binary.

## License

MIT. See [LICENSE](LICENSE).
