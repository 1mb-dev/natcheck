# natcheck

NAT type diagnosis CLI. One command tells you why your WebRTC, P2P, or VPN connections struggle — and whether TURN is required.

Built on [`pion/stun`](https://github.com/pion/stun). Pure Go, single static binary. No cgo, no services, no config.

> Pre-release (v0.1). Spec: [`docs/design.md`](docs/design.md). Samples: [`docs/samples/`](docs/samples/).

## Why natcheck

- **One command, one answer.** No more piecing together `stun-client` output with a dusty online NAT classifier and RFC 5780.
- **Honest outputs.** Reports `unknown` when classification can't be determined from the data, rather than guessing.
- **Human-readable by default, `--json` on request.** Clean output for terminals, schema-stable JSON for CI.

## Quick start

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest

natcheck
```

Example output on a healthy home network:

```
Direct P2P: likely
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820

Probes:
  stun.l.google.com:19302   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested (v0.1).
```

The `Direct P2P:` line leads so you get the answer on line 1.

## Flags

| Flag | Purpose |
|------|---------|
| `--json` | Emit JSON instead of human-readable report |
| `--verbose` | Log each STUN transaction to stderr |
| `--server host:port` | Add a custom STUN server (repeatable; overrides defaults) |
| `--timeout duration` | Total probe timeout (default `5s`) |
| `--version` | Print version and exit |
| `--help` | Print flag reference |

## Exit codes

| Code | Meaning | When |
|------|---------|------|
| `0` | P2P-friendly | `Direct P2P: likely` or `possible` |
| `1` | P2P-hostile | `Direct P2P: unlikely` or `unknown` |
| `2` | Probe or flag error | All probes failed, invalid flag, or bad `--server` |

Scripts that ask "did the tool run?" check `$? -ne 2`. Scripts that ask "can I use direct P2P?" check `$? -eq 0`.

## CI usage

```bash
verdict=$(natcheck --json | jq -r '.webrtc_forecast.direct_p2p')
if [ "$verdict" != "likely" ]; then
  echo "NAT not P2P-friendly: $verdict"
  exit 1
fi
```

The `--json` schema (`nat_type`, `public_endpoint`, `probes[]`, `webrtc_forecast`, `warnings[]`) is a public contract from v0.1 onward — additive changes only after release. Real captures live under [`docs/samples/`](docs/samples/).

## Scope

v0.1 classifies NAT mapping behavior (Endpoint-Independent, Address-Dependent, Address-and-Port-Dependent per RFC 5780) and reports a WebRTC direct-P2P forecast. Filtering behavior and hairpinning are out of scope. On CGNAT networks (`100.64.0.0/10`), the forecast is `unknown`. IPv6 works when the network supports it but is not exhaustively tested.

See [`docs/design.md`](docs/design.md) for full architecture and testing details.

## Acknowledgements

Default STUN servers courtesy of Google (`stun.l.google.com:19302`) and Cloudflare (`stun.cloudflare.com:3478`). For high-frequency automation, self-host [coturn](https://github.com/coturn/coturn) and pass it via `--server`.

## License

MIT. See [LICENSE](LICENSE).
