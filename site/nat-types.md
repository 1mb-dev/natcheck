---
layout: page
title: "NAT types and why WebRTC connections fail"
description: "Why some WebRTC and P2P sessions can't connect directly. The three RFC 5780 mapping behaviours, CGNAT, and when you need TURN."
permalink: /nat-types/
---

Some fraction of your users can't establish a direct WebRTC or P2P session. They fall back to a relay, or the session fails.

## Mapping: what your NAT shows to the world

Your NAT sits between your laptop and the internet — usually a home router, sometimes an ISP middlebox. When your laptop at `192.168.1.42:51820` sends a packet to a public server, the NAT rewrites the source to one of its public addresses (say `203.0.113.45:51820`) and remembers the mapping for replies.

When the same laptop sends to two different servers from the same local port, the NAT can use the same public port for both or a different port for each. That choice — the **mapping behaviour** — decides whether direct P2P works.

| RFC 5780 | Legacy | Behaviour |
|---|---|---|
| **Endpoint-Independent Mapping** (EIM) | Full Cone | Same public `IP:port` for any destination. |
| **Address-Dependent Mapping** (ADM) | Restricted Cone | Same port per destination IP; new port per new IP. |
| **Address-and-Port-Dependent Mapping** (APDM) | Symmetric | New public port per destination `IP:port`. |

Hole-punching needs the remote peer to predict your public port. APDM defeats that: the port a STUN server reports is not the port your NAT uses when you later contact your peer. ICE cannot hole-punch through APDM — it falls back to relaying via TURN.

## Filtering: who can reach an existing mapping

Once a mapping exists, the NAT chooses which inbound packets to forward.

| RFC 5780 | Filtering |
|---|---|
| **Endpoint-Independent** | Any external host can send to the mapping. |
| **Address-Dependent** | Only hosts you've already sent to can reach you. |
| **Address-and-Port-Dependent** | Only exact `IP:port` tuples you've sent to can reach you. |

Filtering controls whether the first inbound packet from your peer is accepted, and interacts with mapping to decide whether a simultaneous-send hole-punch works.

## Will direct P2P work?

Mapping on both sides is the dominant factor:

- **EIM × EIM:** works reliably.
- **EIM × ADM:** usually works. The EIM side has a predictable endpoint; the ADM side initiates and the EIM learns its source.
- **EIM × APDM:** marginal. Works when the APDM side initiates and the EIM responds to the observed source port; ICE candidate gathering alone is not enough.
- **ADM × ADM:** often works with a reasonable ICE implementation.
- **APDM × ADM or APDM × APDM:** fails. TURN relay required.

## CGNAT is a second NAT in front of yours

Carrier-Grade NAT is a NAT your ISP runs in front of your own NAT. Common on mobile carriers (T-Mobile US, Jio India) and Starlink. Detectable because your public IP falls in `100.64.0.0/10`, the RFC 6598 shared address space.

CGNAT behaviour varies by carrier. Some run permissive EIM CGNATs that hole-punch fine; others run APDM and don't. Without an active probe on the specific carrier, `unknown` is the correct answer.

## STUN, TURN, or neither

- **STUN alone** works when both peers are behind EIM or ADM with reasonable filtering. Google and Cloudflare run public STUN servers for free.
- **TURN** is required when at least one peer is APDM or on a hostile CGNAT. TURN relays the full session, so it costs bandwidth. Don't use public TURN in production — run your own ([coturn](https://github.com/coturn/coturn) is the standard).
- **Neither** when at least one peer has a routable public IP (datacenter, open IPv6). Increasingly common; not yet default for residential users.

"What fraction of my users need TURN" is a question about your user base, not your code.

## Diagnosing a specific network

1. Send STUN Binding requests to two or more STUN servers on different IPs from the same local port.
2. Same mapped public `IP:port` across servers → EIM. Hole-punching friendly.
3. Different mapped ports → ADM or APDM. Distinguishing them requires RFC 5780's `CHANGE-REQUEST` attribute, which most public STUN servers don't support.
4. Public IP in `100.64.0.0/10` → CGNAT. The probe characterises the carrier's NAT, not yours.

[natcheck](https://github.com/1mb-dev/natcheck) runs this probe and reports a direct-P2P forecast with exit codes a CI job can act on. Any STUN client plus the steps above works if you prefer to do it by hand.

```bash
brew tap 1mb-dev/tap
brew install natcheck
natcheck
```

or, with a Go toolchain:

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest
natcheck
```

```
Direct P2P: likely
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820

Probes:
  stun.l.google.com:19302   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested (v0.1).
```

On CGNAT, natcheck reports `unknown` rather than guessing.

## Not covered

- **Hairpinning** — NAT forwarding packets back to another host behind itself.
- **UPnP / NAT-PMP / PCP** — the app requests a mapping instead of inferring one via STUN.
- **ICE** — the algorithm WebRTC runs to try multiple candidate paths.
- **QUIC / WebTransport** — newer transports with different NAT traversal characteristics.

## References

- [RFC 5780 — NAT Behavior Discovery Using STUN](https://www.rfc-editor.org/rfc/rfc5780)
- [RFC 6598 — CGNAT / 100.64.0.0/10](https://www.rfc-editor.org/rfc/rfc6598)
- [pion/stun](https://github.com/pion/stun)
