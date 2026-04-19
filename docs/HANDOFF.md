# natcheck - Handoff

> Last updated: 2026-04-19 (planning complete)
> Session: Scaffold + design docs + v0.1 plan
> Companion: [PRD.md](PRD.md), [TRD.md](TRD.md)

## Planning status (2026-04-19)

v0.1 plan is locked. Huddle review complete (Maya / Jordan / Kai), Linus signed off conditionally.

**Working tracker** (local, gitignored): `todos/releases/v0.1.0/00-master-tracker.md`. Phase docs in same dir. Huddle notes: `todos/releases/v0.1.0/huddle-2026-04-19.md`.

**Linus sign-off conditions** (folded into phase docs, summarised here so they persist in committed history):

1. CGNAT forecast defaults to `unknown` until Phase 6 real-network calibration upgrades it to `possible` or `unlikely`.
2. `internal/classify` tests cover partial-failure matrix (0/2, 1/2 both orderings, 2/2 probe outcomes).
3. JSON schema pinned via golden-file tests (EIM cone, ADM strict, Blocked all-fail).
4. Human output leads with `Direct P2P: <verdict>` — NAT type and probe table below.
5. Phase 6 includes at least one real CGNAT network test with outcome documented in `docs/samples/cgnat.txt`.
6. README gains a differentiation block + CI usage section **before** `gh repo create`.

**Other locked decisions**: two default STUN servers (no third); IPv6 deferred to v0.3; install path `github.com/1mb-dev/natcheck/cmd/natcheck@latest`; external actions (`gh repo create`, `git push`, launch-post draft, launch-post publish) each require a separate approval.

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

### Step 1: `/pb-plan` phased implementation (DONE 2026-04-19)

Plan locked in `todos/releases/v0.1.0/`. Phase summary (deltas from original draft noted):

- **Phase 1** (1-2 hours): `internal/probe` - wire `pion/stun`, implement `Prober`, table-test against local `pion/stun` test server.
- **Phase 2** (1-2 hours): `internal/classify` - pure classification logic, exhaustive table-driven tests + partial-failure matrix. CGNAT forecast defaults to `unknown`.
- **Phase 3** (1 hour): `internal/report` - human rendering (forecast-first ordering) + JSON with golden-file schema tests.
- **Phase 4** (1-2 hours): `internal/cli` - flag parsing, orchestration, exit codes.
- **Phase 5** (30 min): `cmd/natcheck/main.go` - wire `cli.Run`.
- **Phase 6** (30 min + network): manual verification with explicit pass criteria; at least one CGNAT network test; calibrate or retain `unknown`.
- **Phase 7**: README polish (differentiation + CI usage), `gh repo create`, push, launch post (NAT explainer, tool as CTA — not a dissertation). Each external action separately gated.

Total: one weekend for v0.1 per PRD.

Start Phase 1 by reading `todos/releases/v0.1.0/phase-1-probe.md`.

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
