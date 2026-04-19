# natcheck - Product Requirements (v0.1)

> Last updated: 2026-04-19
> Status: Draft (pre-implementation)
> Companion: [TRD.md](TRD.md), [HANDOFF.md](HANDOFF.md)

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

## v0.1 scope (MVP)

In:

- STUN Binding request against 2+ servers (default: `stun.l.google.com:19302`, `stun.cloudflare.com:3478`)
- Public endpoint reporting (IP:port as observed by each server)
- Mapping-behavior classification: Endpoint-Independent vs Address/Port-Dependent, based on whether mapped endpoints agree across servers
- RTT measurement per server
- Human-readable default output (one screen)
- `--json` flag for structured output
- `--verbose` flag showing each STUN transaction
- `--server host:port` flag, repeatable, to add or override servers
- `--timeout duration` flag (default 5s)
- `--version`, `--help`
- WebRTC forecast line: "Direct P2P: likely | possible | unlikely"
- CGNAT heuristic warning (if mapped IP is in 100.64.0.0/10)
- Exit codes: 0 (P2P-friendly), 1 (P2P-hostile), 2 (probe error)

Out (deferred):

- Filtering behavior (requires RFC 5780-capable STUN server; v0.2 with companion `natcheck-server` or coturn setup guide)
- Hairpinning test (v0.2)
- TURN probing (v0.3)
- IPv6 (v0.3 - included if trivial via `pion/stun`, otherwise explicit)
- Multi-interface enumeration (v0.3)
- Continuous monitoring / watch mode (maybe; probably never)
- TUI (not planned)
- TCP STUN (not planned)

## Non-goals

- Not a general network diagnostic tool. Scope is NAT and STUN only.
- Not a TURN server or relay. `natcheck` probes; it doesn't serve.
- Not a WebRTC test harness. For end-to-end WebRTC testing, use pion's examples or webrtc-internals.

## UX shape

Default invocation:

```
$ natcheck
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

JSON invocation:

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

Failure modes:

- All probes timeout -> exit 2, report per-server errors
- Mapped endpoints disagree across servers -> NAT type "Address-Dependent Mapping" (or APDM if we can distinguish), exit 1, WebRTC forecast "unlikely"
- Mapped IP in 100.64.0.0/10 -> warning "cgnat_detected", WebRTC forecast "possible" (CGNAT complicates P2P but doesn't kill it)

## Success criteria

v0.1 ships when:

- Running `natcheck` on a home network returns a correct verdict in under 2 seconds
- Running `natcheck --json` produces schema-stable output suitable for CI assertions
- Default binary size under 15 MB (single static Go binary on `pion/stun` is comfortably under this)
- `go install github.com/1mb-dev/natcheck/cmd/natcheck@latest` works with no further setup
- Test coverage on `internal/classify` >= 80% (covers the logic that most needs it)
- Launch post publishes on blog.vnykmshr.com and content stream picks it up for LinkedIn

## Risks

1. **Public STUN servers are rate-limited / unreliable.** Mitigation: default to 2-3 servers, fall back to `--server` flag for custom, treat probe failures as warnings not fatal where possible.
2. **RFC 5780 classification is incomplete without cooperating server.** Mitigation: v0.1 is honest about what it cannot determine. v0.2 ships companion server.
3. **CGNAT is common and complicates NAT classification.** Mitigation: detect 100.64/10 and call it out separately.
4. **"cone" and "symmetric" are fuzzy legacy terms.** Mitigation: report both RFC 5780 terms and legacy terms, with a one-line explanation in `--verbose`.
