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
