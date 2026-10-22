# Phases

Phased build of the dependency / base-image gates. This file records what is done
and what still needs to be done, so the work is reviewable branch by branch.

## Phase 1 — tooling as its own repo (DONE)

- `scripts/depcheck.mjs` — freshness + 14-day age gate (PyPI + npm), compromised-release
  denylist, `--json`, exit codes.
- `scripts/imgcheck.mjs` — base-image policy: reject `-rc`/OS-swap/EOL/floating tags + drift.
- `policy/example.deps-policy.json` — template per-repo policy (cooldown, allowlist, overrides).
- `references/policy.md`, `references/runbook.md` — rules + how-to-act-on-findings.
- `SKILL.md` — OpenCode skill; auto-discovered from `~/.agents/skills` + `~/.claude/skills`.
- Published as public repo (public so CI can `git clone` it without credentials).
- Verified green against real repos (`imgcheck --fail` PASS; `depcheck` shows 162 OK).

## Phase 2 — roll out to your repos (NEXT)

- Copy `policy/example.deps-policy.json` into each repo and edit the allowed base images.
- Add `SECURITY.md` in each repo pointing at this repo + its policy file.
- Fix the floating `python:3.12-slim` and `node:22-alpine` bases in the other repos
  (separate, deliberate PRs — not via Snyk fix PRs).

## Phase 3 — CI enforcement (DONE)

- `.github/workflows/deps.yml` in each app repo: clones this repo, runs
  `imgcheck --fail` + `depcheck`, plus `snyk test --severity-threshold=high`.
- Pre-commit hook (local) running the same.

## Phase 4 — supply-chain gate (DONE, v0.2.0)

Triggered by the litellm PyPI compromise (`1.82.7`, `1.82.8` in Mar 2026; `1.107.0`
in Oct 2026). The old gate structurally could not see this class of attack: a fresh
release was advisory (`TOO_NEW` → exit 0), and a deleted release was reported as
merely `OUTDATED` — with no signal that it was malware.

- `policy/compromised.json` — denylist of known-bad releases, seeded with litellm.
- New statuses: `COMPROMISED`, `WITHDRAWN`, `YANKED` (always block, any ecosystem,
  any scope); `UNAGED_NEW_DEP` (a *newly introduced* pin younger than the cooldown
  blocks); `TOO_NEW` stays advisory but now carries `revisitAfter`.
- `--baseline=<rev>` git diff distinguishes a new adoption from an already-committed
  pin. `--strict` escalates transitive findings and fresh pins.
- `safeTarget` never proposes a known-bad/yanked/withdrawn release; `--fix` refuses
  any file holding one.
- Coverage extended to `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, so
  transitive Python deps (how `litellm` usually arrives) are visible.
- `npm test` — 26 tests, stdlib only, offline via a local stub registry.
- **Breaking:** the exit-code contract changed (new blocking statuses). Hence the
  `0.1.0` → `0.2.0` bump; the version is printed in the report header.

## Phase 5 — approved direct deps + integrity (DONE, v0.3.0)

A denylist is retrospective and a cooldown only delays adoption; neither answers
"should this library be in our tree" or "are these the bytes we reviewed".

- `policy/example.approved.json` — approved **direct** dependencies with
  `rationale`/`approvedBy`/`date`/`reviewBy`. Gate is opt-in (`--approved=<path>`
  or `.deps-policy.json → approved`) so existing CI does not go red on upgrade.
- Approval is an orthogonal `APPROVED` column, not a status: an unapproved direct
  dep blocks whatever its freshness state. Transitive deps are not name-gated —
  a 500-entry allowlist is script-seeded and rubber-stamped.
- `--seed-approved` bootstraps the list from the current direct set (one-off,
  local); `depcheck` reports approved-but-unused entries and overdue reviews.
- `NO_HASH` — hashes are required (`--require-hashes` or `--verify-integrity`) but
  missing. Hash extraction added for requirements `--hash=`, `Pipfile.lock`
  `hashes`, `poetry.lock`/`uv.lock` `files[].hash`, `package-lock.json` `integrity`.
- Deliberately **not** done: rejecting "older" versions (age is already handled, and
  old ≠ unsafe), and full-tree approval (use Dependency-Track/SBOM tooling).
- `npm test` — 40 tests, still stdlib only and offline.

## Why a repo (not a single script)

So every machine you code on gets the *same* version: `git pull` and you're
updated. Keeps policy, runbook, and skill in one auditable place.