# Contributing

See [`docs/design.md`](docs/design.md) for scope and architecture before making significant changes.

## Build

```
git clone https://github.com/1mb-dev/natcheck
cd natcheck
make build     # or: go build ./...
```

Requirements: Go 1.25+, [golangci-lint](https://golangci-lint.run/) v2.9.0+ for linting.

## Test

```
make test            # go test -race -timeout 60s ./...
make test-coverage   # writes coverage.html
make lint            # golangci-lint run ./...
make tidy            # go mod tidy
```

Regenerate report golden fixtures (only when changing output intentionally):

```
NATCHECK_UPDATE_GOLDEN=1 go test ./internal/report/...
```

## Add a sample

`natcheck` ships with real-network captures under [`docs/samples/`](docs/samples/). Samples from unusual networks — CGNAT carriers, captive portals, degraded links — are especially welcome.

1. Run `natcheck` and `natcheck --json` on the target network.
2. Redact any address that could identify a specific machine: public IPs to RFC 5737 (IPv4 `203.0.113.0/24`) and RFC 3849 (IPv6 `2001:db8::/32`) documentation ranges; private RFC 1918 source addresses to generic placeholders (e.g., `192.168.1.2`). Ports, RTTs, error message shapes, and external STUN server IPs can stay as observed.
3. Commit the `.txt` and `.json` files under `docs/samples/`.
4. Add a row to the table in [`docs/samples/README.md`](docs/samples/README.md).

## Report a bug

Open an issue with:

- `natcheck --version` output.
- `natcheck --verbose --json` output with public IPs redacted.
- Network type (home residential, office, CGNAT carrier, public Wi-Fi, etc.) and what you expected vs. observed.

## Style

- Commits use [conventional commits](https://www.conventionalcommits.org/) prefixes: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`.
- PRs must pass CI (`make test` + `make lint` locally first).
