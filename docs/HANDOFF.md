# natcheck - Handoff

> Last updated: 2026-04-19
> Session: Scaffold + design docs
> Companion: [PRD.md](PRD.md), [TRD.md](TRD.md)

## What exists now

Repo scaffold at `/Users/vmx/workspace/github/1mb-dev/natcheck/`:

```
natcheck/
├── LICENSE                 MIT
├── Makefile                build/test/lint targets (matches lobster)
├── README.md               user-facing doc, references PRD/TRD/HANDOFF
├── go.mod                  github.com/1mb-dev/natcheck, go 1.25
├── .gitignore              standard Go + 1mb-dev conventions
├── cmd/natcheck/main.go    stub entry point, prints scaffold notice, exits 2
├── internal/
│   ├── cli/doc.go          package stub
│   ├── probe/doc.go        package stub
│   ├── classify/doc.go     package stub
│   └── report/doc.go       package stub
└── docs/
    ├── PRD.md              scope, audience, UX, success criteria
    ├── TRD.md              architecture, contracts, deps, tests
    └── HANDOFF.md          this file
```

Git: **initialized locally, no remote**. No `gh repo create`, no push. First commit pending after review.

## What's NOT done yet

- No `pion/stun` import (v0.1 will add exactly one runtime dep)
- No real implementation in any `internal/*` package
- No tests
- No CI wired up (shared 1mb-dev workflows apply once pushed; no rush)
- No GitHub repo created

## Next session: resume here

### Step 0: review the scaffold

1. Skim `docs/PRD.md` - does scope still match intent?
2. Skim `docs/TRD.md` - architecture still sound?
3. If either shifted, update before coding.

### Step 1: `/pb-plan` phased implementation

Run `/pb-plan` with TRD as input. Expected phases:

- **Phase 1** (1-2 hours): `internal/probe` - wire `pion/stun`, implement `Prober`, table-test against local `pion/stun` test server.
- **Phase 2** (1-2 hours): `internal/classify` - pure classification logic, exhaustive table-driven tests.
- **Phase 3** (1 hour): `internal/report` - human + JSON rendering, golden files.
- **Phase 4** (1-2 hours): `internal/cli` - flag parsing, orchestration, exit codes.
- **Phase 5** (30 min): `cmd/natcheck/main.go` - wire `cli.Run`.
- **Phase 6** (30 min): manual verification against real networks.
- **Phase 7**: launch post draft (content stream), `gh repo create`, push.

Total: one weekend for v0.1 per PRD.

### Step 2: external action gate reminders

Before *any* externally-visible action:

- `gh repo create` - requires explicit approval. Visibility default: public (1mb-dev default).
- `git push` - requires explicit approval.
- Launch post to blog / LinkedIn - requires explicit approval.

See `~/.claude/CLAUDE.md` external action gate + `memory/feedback_external_actions.md`. Each action is a separate approval.

### Step 3: content handoff

When v0.1 ships:

- Launch post draft -> `content/posts/vmx/NNN-natcheck.md` via `/new-post`
- Infographic candidate: "NAT types visualized" via `/infographic`
- Cross-post: LinkedIn, X, optional HN (criteria: only if launch feels strong)

## Open questions

1. **Third default STUN server?** TRD ships with two (Google, Cloudflare). Adding a third improves classification robustness at the cost of slower default run. Decide during Phase 1.
2. **IPv6 in v0.1 or v0.3?** TRD defers to v0.3. Reconsider if `pion/stun` makes it trivially free.
3. **CGNAT forecast calibration.** TRD says EIM+CGNAT -> "possible", ADM+CGNAT -> "unlikely". Need to validate against real CGNAT behavior before release.
4. **Go install path:** `github.com/1mb-dev/natcheck/cmd/natcheck@latest` vs root install via `go install github.com/1mb-dev/natcheck@latest`. Lobster uses `cmd/lobster` subpath. Match that convention.

## References

- Ideation session: `vmx/todos/product/pion-ideation-2026-04-19.md`
- Original brief: `vmx/todos/product/pion-portfolio.md`
- Product tracker: `vmx/streams/product/tracker.md` (natcheck row)
- Pion stun: https://github.com/pion/stun
- RFC 5780: https://www.rfc-editor.org/rfc/rfc5780 (NAT behavior discovery)
- RFC 3489: https://www.rfc-editor.org/rfc/rfc3489 (legacy NAT terms)
- RFC 6598: https://www.rfc-editor.org/rfc/rfc6598 (CGNAT / 100.64/10)

## Who picks this up

Next product-stream session. Likely flow:

```
/enter product
# read streams/product/pause.md - points here
cd /Users/vmx/workspace/github/1mb-dev/natcheck
cat docs/HANDOFF.md
/pb-plan docs/TRD.md
```
