---
layout: page
title: "NAT types and why WebRTC connections fail"
description: "A reference for WebRTC, P2P, and VPN developers: the four NAT mapping behaviours, why symmetric NAT breaks direct P2P, how CGNAT differs, and when TURN is required."
permalink: /nat-types/
---

You shipped a WebRTC or P2P app. It works on your network and on most users' networks. But for some fraction of users, the direct peer-to-peer connection never completes, and either your app falls back to a relay server or the session just fails. This page is a reference for why that happens and how to tell which case you are in.

It is written for developers debugging their own applications, not for network operators. It uses the RFC 5780 terminology and the older "cone / symmetric" labels side by side, because both still appear in documentation.

## What a NAT actually does

A NAT (Network Address Translator) is the device between your laptop and the public internet — usually a home router or a carrier-grade middlebox. When your laptop at `192.168.1.42:51820` sends a packet to a public server, the NAT rewrites the source address to one of its own public addresses, say `203.0.113.45:51820`, and remembers the mapping so it can rewrite replies back to your laptop.

Direct peer-to-peer works by two NATed clients discovering each other's *public* address and port via a STUN server, then each side sending packets to the other's public endpoint. Whether those packets reach the other side depends entirely on two behaviours the NAT is free to choose for itself: **mapping** and **filtering**.

## Mapping: what address does the NAT show to the world

When your laptop sends packets from `192.168.1.42:51820` to two different servers, the NAT might use the *same* public port for both — or a different public port for each. This is the **mapping behaviour** and it has four variants in RFC 5780:

| RFC 5780 term | Legacy name | Meaning |
|---|---|---|
| **Endpoint-Independent Mapping** (EIM) | Full Cone | Same public `IP:port` regardless of destination. |
| **Address-Dependent Mapping** (ADM) | Restricted Cone | Same public port per destination IP; new port per new IP. |
| **Address-and-Port-Dependent Mapping** (APDM) | Symmetric NAT | New public port per destination `IP:port` — effectively unpredictable from the outside. |
| No NAT | — | Laptop has a public IP directly. |

The first three are all "NATed". The difference matters because peer-to-peer hole-punching requires the remote peer to predict your public port, and **APDM (symmetric NAT) makes that prediction impossible** — your NAT shows a different port to every remote peer, so the port discovered via STUN will not match the port used for the actual peer connection.

## Filtering: who is allowed to reach you

Once a mapping exists, the NAT decides which inbound packets it forwards to your laptop. Three variants:

| RFC 5780 term | Meaning |
|---|---|
| **Endpoint-Independent Filtering** | Any external host can send packets to the mapping. |
| **Address-Dependent Filtering** | Only hosts with an IP you've sent to can reach you. |
| **Address-and-Port-Dependent Filtering** | Only the exact `IP:port` tuples you've sent to can reach you. |

Filtering controls whether the *first packet* from your peer will be accepted — and it interacts with mapping to determine whether a "simultaneous send" hole-punch works.

## The "will WebRTC work" matrix

For direct peer-to-peer to succeed, both sides need a combination that allows hole-punching. The dominant factor is mapping:

- **EIM × EIM:** direct P2P works reliably. Best case.
- **EIM × ADM or APDM:** usually works. The side with the stricter NAT receives first; the permissive side's predictable port lets the simultaneous-send trick punch through.
- **ADM × ADM:** often works with good ICE implementations.
- **APDM × anything:** **direct P2P fails**. The port presented via STUN does not match the port used when actually connecting to the peer, so hole-punching cannot succeed. You need a **TURN** relay.

This is why "behind symmetric NAT" is a death sentence for direct WebRTC: the mapping behaviour is unpredictable, so no amount of clever ICE candidate gathering fixes it.

## CGNAT is a separate problem

Carrier-Grade NAT (CGNAT) is a second layer of NAT run by the ISP itself, typically on mobile carriers and some residential broadband (T-Mobile US, Jio India, Starlink, and others). Your router NATs you once; the carrier NATs you again.

Detectable signal: your public IP falls in the `100.64.0.0/10` range reserved by RFC 6598 for shared CGNAT space. If you see a `100.64.x.x` address, you are behind CGNAT.

Whether direct P2P works on CGNAT depends on the carrier's specific implementation, and the honest answer for most real networks is "it varies". Some carriers run permissive EIM/EIF CGNATs that hole-punch fine. Others run APDM CGNATs that don't. Without an active probe on the carrier in question, the only responsible answer is **unknown** — anything else is guessing.

## So: STUN, TURN, or neither?

- **STUN alone** is enough when both peers are behind EIM/ADM NATs with reasonable filtering. STUN servers are cheap — Google and Cloudflare run public ones for free.
- **TURN is required** when at least one peer is behind APDM (symmetric NAT) or a restrictive CGNAT. TURN relays the whole conversation through a server, so it costs bandwidth and money to operate. You cannot use public TURN servers in production; you run your own ([coturn](https://github.com/coturn/coturn) is the standard).
- **Neither** applies when a peer has a routable public IP (datacenter, IPv6 with no firewall, etc.) — increasingly common but not yet the default for residential users.

The "will my users need TURN" question is really "what fraction of my users are behind APDM or hostile CGNAT" — a number that depends on your user base, not your code.

## Diagnosing the network you're on

To know which bucket a specific network falls into, you probe it with STUN from that network and compare responses across multiple servers. The short version:

1. Send STUN Binding requests to two or more STUN servers on different IPs from the same local port.
2. If all servers report the **same** mapped public `IP:port`: EIM. Hole-punching friendly.
3. If servers report **different** mapped ports: ADM or APDM. The distinction requires RFC 5780's `CHANGE-REQUEST` attribute, which most public STUN servers do not support.
4. If your public IP is in `100.64.0.0/10`: you are behind CGNAT and the above probe is only telling you about the carrier's NAT, not your own.

The tool that motivates this page, [natcheck](https://github.com/1mb-dev/natcheck), runs exactly this probe from your network and reports a WebRTC direct-P2P forecast. If you already know RFC 5780 cold, you do not need it — any STUN client plus some arithmetic gets you there. If you want a one-command answer and CI-friendly exit codes:

```bash
brew tap 1mb-dev/tap
brew install natcheck
natcheck
```

or

```bash
go install github.com/1mb-dev/natcheck/cmd/natcheck@latest
natcheck
```

Sample output:

```
Direct P2P: likely
NAT type: Endpoint-Independent Mapping (cone)
Public endpoint: 203.0.113.45:51820

Probes:
  stun.l.google.com:19302   rtt=24ms  mapped=203.0.113.45:51820
  stun.cloudflare.com:3478  rtt=31ms  mapped=203.0.113.45:51820

Filtering not tested (v0.1).
```

natcheck reports `unknown` on CGNAT instead of guessing, because guessing is how wrong production assumptions get made.

## What this page is not

It is a developer-oriented reference, not a complete treatment of NAT traversal. The parts deliberately skipped:

- **Hairpinning** (NAT forwarding packets back to another host behind the same NAT). Relevant if two clients on the same LAN connect to each other by public address.
- **UPnP / NAT-PMP / PCP** port mapping protocols. These let an application *request* a mapping rather than rely on STUN discovery.
- **ICE** — the algorithm WebRTC uses to try multiple candidate paths (host, server-reflexive via STUN, relayed via TURN) and pick the first that works.
- **QUIC and WebTransport** — newer transports with their own NAT traversal characteristics.

Further reading:

- [RFC 5780 — NAT Behavior Discovery Using STUN](https://www.rfc-editor.org/rfc/rfc5780)
- [RFC 6598 — CGNAT / 100.64.0.0/10](https://www.rfc-editor.org/rfc/rfc6598)
- [pion/stun](https://github.com/pion/stun) — the Go STUN implementation underneath natcheck
