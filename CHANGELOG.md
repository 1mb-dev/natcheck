# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.3] — 2026-04-26

### Fixed

- Cross-address-family probe sets no longer produce a wrong ADM/symmetric verdict. Previously, a probe set mixing IPv6-resolved hostname servers (e.g., `stun.l.google.com`) with IPv4-literal servers (e.g., a self-hosted coturn) compared mapped endpoints across address families and reported ADM because the endpoints differed by construction (each family observes its own NAT). The classifier now groups successes by address family, classifies each group independently, and combines under the rule "Unknown is absence of information, not disagreement": matching verdicts win, two confident verdicts that differ produce Unknown, a confident verdict beats Unknown from the other group. Closes #14.

### Added

- New warning value `mixed_address_family_probes` in `warnings[]`. Emitted whenever successful probes span both IPv4 and IPv6 address families. Additive to the JSON schema.

### Migration note

JSON consumers checking `nat_type == "ADM"` for cross-family probe sets will see `"Unknown"` on the same input under v0.1.3 — the previous verdict was incorrect. Forecast-checking consumers (`webrtc_forecast.direct_p2p`) are mostly unaffected: the dominant cross-family disagreement case stays exit 1 (Unknown → 1, was ADM → 1). The verdict-flip case (genuinely agreed EIM across families, previously ADM, now EIM → exit 0) is the bug being fixed.

### Note on tag versioning

v0.1.3 is the first 3-segment-semver tag after the v0.1.2.x patches; v0.1.2.1 and v0.1.2.2 were 4-segment tags incompatible with Go module versioning (proxy silently substituted a pseudo-version). See those releases' notes. From v0.1.3 onward, tags are 3-segment semver only.

## [0.1.2.2] — 2026-04-26

### Fixed

- `examples/coturn-natcheck.conf` and `docs/coturn-setup.md` now describe and ship the multi-IP conf form (two `listening-ip` + two `external-ip` pairs). v0.1.2.1's single-pair form (`external-ip=PUBLIC/PRIVATE`) only works on AWS/GCP-style topology where the public IP is NAT'd to a separate private NIC IP. On single-public-IP providers (DigitalOcean basic droplet, Linode Nanode, Hetzner single-IP), the public IP IS on eth0 directly and `external-ip=A/A` doesn't satisfy coturn's "two distinct IPs" requirement — coturn logs `WARNING: ... only one IP address is provided` and natcheck reports `filtering: untested`. New per-provider topology table in `docs/coturn-setup.md` with worked DO Reserved IP example.

### Added

- `scripts/validate-coturn.sh`: one-shot SSH-pipe provisioner that installs coturn, writes the conf, opens the firewall, and verifies coturn's startup log for the two warning lines that signal a misconfigured §4.4 path. Honest failure: exits non-zero with `FAIL: ...` if either warning appears, so a misconfigured droplet doesn't silently produce `filtering: untested` samples. Accepts `SECOND_IP=<addr>` env var for single-public-IP providers — aliases the IP to the NIC and uses the multi-IP conf form.

No code or schema delta.

## [0.1.2.1] — 2026-04-26

### Fixed

- `examples/coturn-natcheck.conf` now sets `rfc5780` and uses the `external-ip=public/private` pair form. coturn 4.x defaults RFC 5780 NAT behavior discovery to OFF; without `rfc5780`, coturn silently omits `OTHER-ADDRESS` from Binding responses and natcheck reports `filtering: untested`. A bare `external-ip=PUBLIC` (single value) triggers `STUN CHANGE_REQUEST not supported: only one IP address is provided` even on a single-NIC VM. Both bugs caused users following [`docs/coturn-setup.md`](docs/coturn-setup.md) on a fresh VPS to silently get the v0.1 behavior with no §4.4 classification, despite v0.1.2's headline feature being filtering classification against coturn.
- `docs/coturn-setup.md` adds a verification step that has the user check coturn's stdout for the two specific warning lines that signal a misconfigured §4.4 path.

No code or schema changes — `go install github.com/1mb-dev/natcheck/cmd/natcheck@v0.1.2` produces the same binary as `@v0.1.2.1`.

## [0.1.2] — 2026-04-26

### Added

- RFC 5780 §4.4 filtering classification when the target STUN server advertises `OTHER-ADDRESS`. natcheck runs the three-step CHANGE-REQUEST sequence and reports `endpoint-independent`, `address-dependent`, `address-and-port-dependent`, or `untested` filtering.
- Top-level `"filtering"` object in `--json` output. Always present. `tested_against` field omitted when behavior is `untested`.
- WebRTC forecast value `"possible"` now emitted for EIM mappings combined with restrictive (address-dependent or address-and-port-dependent) filtering.
- `examples/coturn-natcheck.conf` + [`docs/coturn-setup.md`](docs/coturn-setup.md): minimum coturn config for filtering classification and a one-page setup guide.
- `internal/stunserver` package (foundation for v0.1.4's `natcheck server` subcommand).

### Changed

- Default-server users (Google, Cloudflare) see no extra latency: filtering classification is skipped when no probe response advertises `OTHER-ADDRESS`. coturn / `natcheck server` users get filtering automatically.
- `--timeout` flag help: now notes that filtering classification adds up to 1.5s when applicable.

### JSON schema (additive — strict consumers update)

- New top-level key: `"filtering": {"behavior": "...", "tested_against": "..."}`. Always present from this release onward; `tested_against` omitted when `behavior == "untested"`.
- New warning value in `warnings[]`: `"filtering_skipped_no_change_request"` (server response did not include `OTHER-ADDRESS`, so the §4.4 sequence could not run).
- The existing `"filtering_behavior_not_tested"` warning is still emitted when filtering classification was not attempted at all (no server in the probe set advertised `OTHER-ADDRESS`).

Consumers doing strict equality on the entire JSON blob need to expect the new `filtering` key. Field-level consumers (e.g., `jq '.nat_type'`) are unaffected.

### Known limitations (deferred)

- Hairpinning detection — planned for v0.1.3.
- `natcheck server` subcommand — planned for v0.1.4.
- `WarnFilteringPartial` warning (one or more CHANGE-REQUEST probes failed in transit) — current `FilteringResult` shape can't distinguish "filter blocked" from "transport error", so the warning is not emitted. Will return when the probe-side gains the necessary granularity.

## [0.1.1] — 2026-04-19

### Fixed

- `natcheck --version` now reports the correct tag when installed via `go install github.com/1mb-dev/natcheck/cmd/natcheck@vX.Y.Z`. Previously fell back to `"dev"` because ldflags aren't applied by `go install`. Now resolves via `runtime/debug.ReadBuildInfo` when ldflags are absent.

## [0.1.0] — 2026-04-19

Initial release. See [`docs/design.md`](docs/design.md) for scope and architecture.

### Added

- `natcheck` CLI: probes STUN servers and reports NAT mapping classification (EIM / ADM / APDM per RFC 5780) plus a WebRTC direct-P2P forecast.
- Default STUN servers: `stun.l.google.com:19302` and `stun.cloudflare.com:3478`.
- Flags: `--json`, `--verbose`, `--server host:port` (repeatable), `--timeout`, `--version`, `--help`.
- Forecast-first human output; schema-stable JSON via `--json`.
- Exit codes: `0` P2P-friendly, `1` P2P-hostile, `2` probe or flag error.
- CGNAT detection (RFC 6598 `100.64.0.0/10`) with forecast `unknown`.
- IPv4 + IPv6 operation via `pion/stun` and Go's net package.

### Public contracts (stable from v0.1.0)

- `--json` schema: additive changes only.
- Exit-code mapping (0 / 1 / 2).
- Install path: `go install github.com/1mb-dev/natcheck/cmd/natcheck@latest`.

### Dependencies

- Go 1.25+
- [`github.com/pion/stun/v3`](https://github.com/pion/stun)

[Unreleased]: https://github.com/1mb-dev/natcheck/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.3
[0.1.2.2]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.2.2
[0.1.2.1]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.2.1
[0.1.2]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.2
[0.1.1]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.1
[0.1.0]: https://github.com/1mb-dev/natcheck/releases/tag/v0.1.0
