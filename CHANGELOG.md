# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases follow [Semantic Versioning](https://semver.org/).

## [Unreleased] — v0.1.0

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
