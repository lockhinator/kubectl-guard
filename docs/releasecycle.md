# The agentic release cycle

This document describes how a single autonomous session drives an entire
milestone (e.g. `v0.5.0`) to completion — ticket by ticket, with review loops,
CI gates, and a final audit — ending with a release PR waiting for a human to
review and merge.

The design goal: **make the human's only happy-path touchpoint the final
release PR**, and make that review fast and boring because everything upstream
of it was implemented, reviewed-until-clean, CI-verified, and audited.

---

## The shape: one session, one milestone

```
SELECT milestone (next unreleased = v0.5.0)
        │
        ▼
  ┌─────────────────────────────────────────────────────┐
  │  while (open, buildable tickets remain in milestone) │
  │                                                       │
  │   1. pick next ticket (dependency + risk order)       │
  │   2. ensure release/vX.Y.Z branch exists              │
  │   3. branch feat/<ticket> off the release branch      │
  │   4. implement the ticket                             │
  │   5. local gates: build · test -race · vet · fmt · lint│
  │   6. REVIEW LOOP: subagent reviews → fix → re-review   │
  │        …until a full pass returns ZERO findings        │
  │   7. verify against the issue's acceptance criteria    │
  │   8. commit (conventional, no self-attribution), push  │
  │   9. open PR: feat/<ticket> → release branch           │
  │  10. wait for CI green (diagnose + fix if red)         │
  │  11. merge PR into release branch (MERGE COMMIT)       │
  │  12. close ticket, comment with the PR link            │
  └─────────────────────────────────────────────────────┘
        │
        ▼
  FINAL AUDIT subagent (completeness + security + green)
        │
        ▼
  open release PR: release/vX.Y.Z → main  ──►  STOP, hand to human
```

After the human merges the release PR, the existing release automation takes
over: release-please opens `chore(main): release vX.Y.Z`, and merging *that*
tags the version and triggers GoReleaser. The loop deliberately stops before
`main`.

---

## Where state lives (why it is cloud-loopable and resumable)

There is **no separate state file**. The loop reconstructs "what is next" from
GitHub on every wake-up:

- **Done** — the ticket's feature PR is merged into the release branch and the
  issue is closed.
- **In progress** — a `feat/<ticket>` branch or an open PR already exists →
  resume it rather than start over.
- **Next** — the lowest-order open ticket in the milestone with no unmet
  dependency.
- **Milestone complete** — no open *buildable* tickets remain.

If a cloud loop dies mid-ticket and restarts, it sees the half-finished
branch/PR and continues. Idempotent by construction.

---

## Ticket ordering

Order by **(1) dependency → (2) risk/size ascending → (3) feature last**, so
small independent fixes land first and the largest feature rebases on a stable
branch. Concrete order for `v0.5.0`:

| Order | Ticket | Why here |
|-------|--------|----------|
| 1 | #71 gate port-forward/proxy | Tiny, isolated (classification map); lowest risk |
| 2 | #80 gate `get --raw` | Small, self-contained parsing + resource match |
| 3 | #89 audit secret redaction | Adds `RedactCommand`; others rebase on it |
| 4 | #74 secure headless bootstrap | `main.go` SetupRequired branch |
| 5 | #23 agent-relay approval flow | The feature — biggest; last, on a stable base |

Because tickets merge sequentially, each new feature branch is cut from the
*updated* release tip, so overlapping edits (e.g. `main.go`, `guard/commands.go`)
are serialized rather than conflicting.

---

## The review loop (the quality gate that replaces per-PR human review)

Per ticket, after local gates pass:

1. Spawn a **review subagent** (Opus/Sonnet per the usage-limit policy — never
   Fable for fan-out) with the diff **and** the issue's acceptance criteria.
   Instruct it to review adversarially across dimensions:
   - correctness / bugs
   - **security** (bypass surface — this is a security tool)
   - completeness vs the acceptance criteria
   - test quality
   - simplicity / reuse
2. It returns ranked findings. The session **fixes** them, re-runs local gates,
   and **re-spawns** the reviewer on the new diff.
3. Loop until a full pass returns **zero actionable findings**. Nits the session
   consciously accepts are logged in the PR body, never silently dropped.
4. **Iteration cap** (e.g. 4). If it has not converged, that is a stop-condition
   → escalate to a human rather than thrash.

For security-sensitive tickets, run a dedicated security-review pass on top of
the general one, and **adversarially verify** each finding (a second agent tries
to refute it) before spending effort fixing — so the loop does not chase
phantom findings.

---

## CI and branch/PR mechanics

- Feature PR titles must be **conventional** (`fix:`, `feat:`, …) so the
  `semantic-pr` check passes.
- Feature PRs merge into the release branch as a **merge commit — never squash**.
  Squashing collapses the conventional commits behind the PR title and breaks
  release-please's version detection (this is exactly how a prior release
  mis-fired). The final release-branch → `main` PR also merges as a merge commit.
- **GitGuardian** is treated as **advisory, not a gate** — it produces
  false positives on `--token`/`--from-literal` phrasing and is not a required
  check.

### Prerequisite (step 0)

`ci.yml` and `semantic-pr.yml` currently trigger only on PRs targeting
`main`/`master`:

```yaml
on:
  pull_request:
    branches: [main, master]
```

A feature PR into `release/v0.5.0` would therefore run **no CI at all**, and the
"wait for CI green" step would have nothing to wait on. **Before the loop can
run, CI must be extended to trigger on `release/**` PR branches.** This is a
tiny setup PR and should be step 0 of the whole cycle.

---

## End of milestone: the audit and the release PR

Once no buildable tickets remain, before opening the release PR the loop runs a
**final audit subagent** that verifies, on the release-branch head:

1. Every milestone ticket's acceptance criteria is actually met in the merged
   code — not merely "PR merged".
2. `go test -race ./...`, `go vet`, and lint are green; no regressions vs `main`.
3. Security posture: the bypass-class fixes genuinely close their holes
   (re-tested end to end).
4. **Feature/bug completeness**: nothing in the milestone was skipped, silently
   dropped, or half-implemented.

That audit becomes the **body of the release PR** (`release: vX.Y.Z`), alongside
a per-ticket summary — so the human opens a completeness report, not a raw diff.
The loop then stops and notifies.

---

## Where it must pause for a human (stop conditions)

- **The final release PR** (by design).
- **Decision / spike tickets** (e.g. a `spike:` ticket): cannot be auto-coded;
  the loop recognizes these by label/title, produces a written recommendation,
  and escalates.
- **Review not converging** after the iteration cap.
- **CI red for a non-code reason** (infra, missing secret, flake it cannot fix).
- **Ambiguous acceptance criteria**, or a ticket that turns out to need a
  product decision.
- Anything touching **external services or destructive operations** beyond the
  repo.

---

## Guardrails baked in

- No self-attribution in commits or PRs.
- Merge-commit, never squash, for release-bound PRs.
- Conventional commit/PR titles (for `semantic-pr` + release-please).
- Subagents run on Sonnet/Opus, never Fable, for any fan-out.
- A mandatory security-review pass on security-relevant tickets.
- GitGuardian treated as advisory.
- The loop never force-pushes and never writes directly to `main`.

---

## How to run it

Three options, increasingly hands-off:

1. **Driven session** — the main loop orchestrates; subagents do implement +
   review; CI-waiting is done by polling. Launch and watch.
2. **Scheduled cloud routine** (cron) — the same driven session, launched
   automatically, running until the milestone's release PR is up, then stopping.
   This is the "put it on a cloud loop" mode.
3. **Per-ticket Workflow** for the implement → review → verify pipeline, with the
   main loop handling git / CI / merge between tickets. (Workflow scripts are
   strong at the bounded implement + review fan-in, weaker at long CI waits.)

Recommended: a resumable **driven session** (option 1), schedulable as a routine
(option 2), with GitHub as the state store.

---

## Honest caveats

- **Inter-ticket conflicts** — mitigated by ordering + rebasing each feature on
  the live release tip, but a large refactor ticket can still force a re-review
  of a later one.
- **Cost** — the review-until-clean loop is the expensive part (multiple Opus
  passes per ticket). Worth it for a security tool, but a cloud loop must have a
  budget ceiling and the iteration caps above.
- **"Green" ≠ "correct"** — CI + review-until-clean + the final audit are strong
  signals, which is precisely why the human still gates the release PR. The
  loop's job is to make that final review fast and boring, not to remove it.
