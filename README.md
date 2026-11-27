# natcheck

NAT type diagnosis CLI. One command tells you why your WebRTC, P2P, or VPN connections struggle — and whether TURN is required.

Built on [`pion/stun`](https://github.com/pion/stun). Pure Go, single static binary. No cgo, no services, no config.

> Spec: [`docs/design.md`](docs/design.md). Samples: [`docs/samples/`](docs/samples/).

## Why natcheck

- **One command, one answer.** No more piecing together `stun-client` output with a dusty online NAT classifier and RFC 5780.
- **Honest outputs.** Reports `unknown` when classification can't be determined from the data, rather than guessing.
- **Human-readable by default, `--json` on request.** Clean output for terminals, schema-stable JSON for CI.

## Quick start

**Homebrew (recommended on macOS):**

```bash
brew install 1mb-dev/tap/natcheck
```

**Go install (any platform with Go 1.26.3+):**

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest
```

Then run:

```bash
natcheck
```

Example output with the default servers:

```
Direct P2P: possible
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820
Hairpinning: false

Probes:
  stun.l.google.com:19302 (192.0.2.10)   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478 (192.0.2.20)  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested.
```

The `Direct P2P:` line leads so you get the answer on line 1. `likely` needs a server that can measure filtering, which the default servers cannot, so `possible` is the most they report.

Pointing `--server` at a STUN server that advertises `OTHER-ADDRESS` (e.g. coturn — see [`docs/coturn-setup.md`](docs/coturn-setup.md)) adds a one-line `Filtering:` verdict per RFC 5780 §4.4. Default servers (Google, Cloudflare) don't, so filtering classification is skipped and adds zero latency for default-server users.

## Flags

| Flag | Purpose |
|------|---------|
| `--json` | Emit JSON instead of human-readable report |
| `--verbose` | Log each STUN transaction to stderr |
| `--server host:port` | Add a custom STUN server (repeatable; overrides defaults) |
| `--timeout duration` | Mapping-probe timeout (default `5s`); filtering and mapping tests add up to 3.75s when a server advertises `OTHER-ADDRESS` |
| `--version` | Print version and exit |
| `--help` | Print flag reference |

## Exit codes

| Code | Meaning | When |
|------|---------|------|
| `0` | P2P-friendly | `Direct P2P: likely` or `possible` |
| `1` | P2P-hostile | `Direct P2P: unlikely` or `unknown`, unless code 2 applies |
| `2` | Probe or flag error | All probes failed, no probe mapped to IPv4 though IPv4 requests left the host ([details](docs/design.md#address-families)), invalid flag, or bad `--server` |

Scripts that ask "did the tool run?" check `$? -ne 2`, and read `webrtc_forecast` only then. Scripts that ask "can I use direct P2P?" check `$? -eq 0`.

## CI usage

```bash
code=0
natcheck --json > natcheck.json || code=$?
if [ "$code" -eq 2 ]; then
  echo "natcheck could not probe"
  exit 2
elif [ "$code" -ne 0 ]; then
  echo "NAT not P2P-friendly: $(jq -r '.webrtc_forecast.direct_p2p' natcheck.json)"
  exit 1
fi
```

The `--json` schema (`nat_type`, `nat_type_legacy`, `public_endpoint`, `probes[]`, `webrtc_forecast`, `warnings[]`, `filtering`, `hairpinning`, `address_families`) is a public contract: changes are additive, except that a warning ID may retire, named in the CHANGELOG entry that retires it. Values and warning IDs are listed in [`docs/design.md`](docs/design.md#json-values). Real captures live under [`docs/samples/`](docs/samples/).

## Scope

natcheck classifies NAT mapping behavior (Endpoint-Independent, Address-Dependent, Address-and-Port-Dependent per RFC 5780) and reports a WebRTC direct-P2P forecast. Filtering behavior (RFC 5780 §4.4) is classified when the configured `--server` advertises `OTHER-ADDRESS`; otherwise the verdict is `untested`. Hairpinning is reported when the probe can run. Behind a carrier-grade NAT the probes cross it, so the verdict covers it; an address family's first mapped address in `100.64.0.0/10` (a `--server` inside a carrier or overlay network) gives that family forecast `unknown`. A dual-stack host is probed in both address families and the verdict follows IPv4; `--json` reports each family under `address_families` ([details](docs/design.md#address-families)).

See [`docs/design.md`](docs/design.md) for full architecture and testing details.

## Acknowledgements

Default STUN servers courtesy of Google (`stun.l.google.com:19302`) and Cloudflare (`stun.cloudflare.com:3478`). For high-frequency automation, self-host [coturn](https://github.com/coturn/coturn) and pass it via `--server`.

## License

MIT. See [LICENSE](LICENSE).
