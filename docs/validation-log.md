# Validation log

Append-only. One entry per release-validation session, written at tag time. Records what was proven against what setup, the issues filed, and reference output. Outputs scrubbed per [`.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md); ephemeral test-infrastructure IPs (cloud droplets) redacted to RFC 5737 placeholders rather than kept as observed, since they get reassigned after destroy.

---

## v0.1.2.2 — 2026-04-26

### Setup

- Server: DigitalOcean basic droplet, coturn 4.6.1 (Ubuntu 24.04 apt). Primary public IPv4 + DO Reserved IP aliased to `eth0` via `ip addr add`. Provisioned by [`scripts/validate-coturn.sh`](../scripts/validate-coturn.sh) with `SECOND_IP` set to the Reserved IP.
- Client: residential ISP, dual-stack, observed APDM × APDF.
- Coturn config: [`examples/coturn-natcheck.conf`](../examples/coturn-natcheck.conf) v0.1.2.2 — two `listening-ip` + two `external-ip` pairs + `rfc5780`.

### Verified

- §4.4 wire path: `tcpdump` confirmed coturn responds to Test 2 (CHANGE-IP|CHANGE-PORT) from the Reserved IP on port 3479 and Test 3 (CHANGE-PORT) from the primary public IP on port 3479. Both routable. Drops on the client side reflect the client's NAT filtering.
- Capability detection: triggers on `OTHER-ADDRESS`; default servers (Google `74.125.250.129`, Cloudflare `162.159.207.0`) skipped.
- JSON schema: 16 paths, stable across 3 idempotent back-to-back runs. Filtering verdict + exit code identical run-to-run.
- Exit-code matrix: 0/1/2 contract honored across 6 sub-cases — verdict-driven (forecast `unlikely` → 1), all-probes-fail (→ 2), `--version` (→ 0), `--help` (→ 0), bad flag (→ 2), bad `--server` format (→ 2).
- Stderr separation: `--verbose` log on stderr; stdout JSON parses when redirected.
- Timeouts: `--timeout 1s` exercises §4.4 within deadline; `--timeout 100ms` (sub-RTT) returns `Blocked` with exit 2.
- IPv6 syntax: `--server [<v6>]:3478` parses correctly; clean error when coturn isn't listening on v6.

### Reference output

Capture used IPv4 literals for Google + Cloudflare to work around #14 (cross-address-family mapping). With the natural hostname invocation, Google + Cloudflare resolve via IPv6 while an IPv4-literal coturn probe goes via IPv4 — three mapped endpoints from two different NATs, misclassified as ADM/symmetric. Fix in v0.1.3. A scrubbed `docs/samples/filtering.{txt,json}` lands with #14's fix so the documented invocation matches the capture command.

```json
{
  "nat_type": "ADM",
  "nat_type_legacy": "symmetric",
  "public_endpoint": "203.0.113.45:55027",
  "probes": [
    {"server": "74.125.250.129:19302", "rtt_ms": 35, "mapped": "203.0.113.45:55027"},
    {"server": "162.159.207.0:3478",   "rtt_ms": 19, "mapped": "203.0.113.45:27546"},
    {"server": "198.51.100.99:3478",   "rtt_ms": 67, "mapped": "203.0.113.45:28560"}
  ],
  "webrtc_forecast": {"direct_p2p": "unlikely", "turn_required": true},
  "warnings": ["adm_or_stricter"],
  "filtering": {
    "behavior": "address-and-port-dependent",
    "tested_against": "198.51.100.99:3478"
  }
}
```

### Findings filed

- #14 — cross-address-family mapping comparison produces wrong ADM verdict. Open, v0.1.3.
- #15 — coturn-setup didn't work on single-public-IP VPS. Closed by v0.1.2.2.
- #16 — `validate-coturn.sh` IPv4 detection + log-file path bugs. Closed by v0.1.2.2.

### Coturn version notes

- 4.5/4.6 (Ubuntu 24.04 apt): RFC 5780 enabled by default. `rfc5780` directive logged as `Bad configuration format` — cosmetic, harmless.
- 4.10+ (Homebrew, Docker `coturn/coturn:latest`): RFC 5780 default flipped to OFF; `rfc5780` directive required.
- "Only one IP" warning wording: 4.6 uses `cannot support STUN CHANGE_REQUEST functionality because only one IP address is provided`; 4.10 uses `STUN CHANGE_REQUEST not supported: only one IP address is provided`. `validate-coturn.sh` matches the stable substring `only one IP`.

---

## v0.1.3 — 2026-04-26

### Setup

Same droplet as v0.1.2.2 (DO basic droplet, coturn 4.6.1, primary public IPv4 + DO Reserved IP aliased to `eth0`). Same client (residential ISP, dual-stack, observed APDM × APDF on the IPv6 path). Local natcheck rebuilt from v0.1.3 tag (`make build`); `--version` reports `v0.1.3`.

### Verified

- #14 fix: re-ran the natural invocation (`--server stun.l.google.com:19302 --server stun.cloudflare.com:3478 --server <coturn-ipv4>:3478`) that pre-fix produced wrong ADM-by-cross-family-comparison. Post-fix: classifier correctly groups v6 (Google + Cloudflare) and v4 (coturn singleton) probes; combine emits `mixed_address_family_probes` + `insufficient_probes` + `adm_or_stricter` warnings; combined verdict ADM (derived from v6 group's internal evidence — Google and Cloudflare via IPv6 saw different mapped ports), forecast unlikely, exit 1. Same end-user verdict as the v0.1.2.2 IPv4-literal workaround capture, but the reasoning is now correct (per-family classification rather than cross-family equality).
- Schema additivity: `mixed_address_family_probes` warning value is the only schema delta since v0.1.2; no other field types or values changed.
- Tag versioning: v0.1.3 is 3-segment semver — Go module proxy correctly indexes the tag (verified `go install ...@v0.1.3` resolves to v0.1.3, not a pseudo-version, unlike v0.1.2.1 / v0.1.2.2).

### Reference output

[`docs/samples/filtering.txt`](samples/filtering.txt) / [`.json`](samples/filtering.json) — captured against this droplet with the natural invocation. Public IPs redacted (client v4 → 203.0.113.45, client v6 → 2001:db8::1, droplet → 198.51.100.99); external server IPs (Google, Cloudflare) and ports / RTTs kept as observed.

### Findings filed

- #19 — `report/human.go:warningText` doesn't have a friendly-text case for `mixed_address_family_probes`; falls through to bare-ID display in human output. Open, v0.1.4 polish.

### Sequence shift

`docs/design.md` v0.2 staged-sequence updated: v0.1.3 = #14 fix (this release); hairpinning shifted to v0.1.4; `natcheck server` shifted to v0.1.5; v0.2.0 line unchanged.
