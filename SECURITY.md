# Security

## Reporting vulnerabilities

Please report suspected security issues privately via [GitHub Security Advisories](https://github.com/1mb-dev/natcheck/security/advisories/new).

## What natcheck does (and doesn't do) with your data

`natcheck` sends only the standard STUN Binding request to the servers you configure (defaults: `stun.l.google.com:19302`, `stun.cloudflare.com:3478`; or any server passed via `--server`). That request carries no user data, no credentials, and no identifying information beyond your source IP and port — which the STUN server needs to observe in order to reflect it back.

`natcheck` does not:

- Send telemetry or analytics.
- Contact any server other than the configured STUN servers.
- Read or write files outside of standard `go install`-managed locations.
- Execute subprocesses.
- Collect or persist network observations.

Treat `natcheck` output as trusted only to the extent you trust the STUN servers you pointed it at.
