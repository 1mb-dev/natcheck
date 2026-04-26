---
layout: page
---

A STUN-based NAT diagnostic with a WebRTC direct-P2P forecast.

```
$ natcheck
Direct P2P: likely
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820

Probes:
  stun.l.google.com:19302   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested.
```

Pointing `--server` at a STUN server that advertises `OTHER-ADDRESS` adds a one-line `Filtering:` verdict per RFC 5780 §4.4. See [coturn setup](https://github.com/1mb-dev/natcheck/blob/main/docs/coturn-setup.md).

Built on [`pion/stun`](https://github.com/pion/stun).

## Install

```bash
brew tap 1mb-dev/tap
brew install natcheck
```

or, on any platform with Go 1.25+:

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | P2P-friendly (`likely` or `possible`) |
| `1`  | P2P-hostile (`unlikely` or `unknown`) |
| `2`  | probe or flag error |

`$? -ne 2`: tool ran. `$? -eq 0`: direct P2P available.

## Background

- [NAT types and why WebRTC connections fail]({{ '/nat-types/' | relative_url }}) — RFC 5780 mapping, CGNAT, and when to use TURN.

## Links

- [Source & README](https://github.com/1mb-dev/natcheck)
- [Releases](https://github.com/1mb-dev/natcheck/releases)
- [Architecture & scope](https://github.com/1mb-dev/natcheck/blob/main/docs/design.md)
- [Real-network samples](https://github.com/1mb-dev/natcheck/tree/main/docs/samples)
