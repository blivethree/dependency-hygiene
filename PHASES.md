# dependency-hygiene — Phases

Phased build of the dependency / base-image gates. This file records what is
done and what still needs to be done, so the work is reviewable branch by branch.

## Phase 1 — tooling as its own repo (DONE)

- `scripts/depcheck.mjs` — freshness + 14-day age gate (PyPI + npm), `--json`, exit codes.
- `scripts/imgcheck.mjs` — base-image policy: reject `-rc`/OS-swap/EOL/floating tags + drift.
- `policy/retire_app.deps-policy.json` — pilot allowlist + cooldown.
- `references/policy.md`, `references/runbook.md` — rules + how-to-act-on-findings.
- `SKILL.md` — OpenCode skill; auto-discovered from `~/.agents/skills` + `~/.claude/skills`.
- Published as private repo `blivethree/dependency-hygiene`.
- Verified green against `retire_app` (`imgcheck --fail` PASS; `depcheck` shows 8 OK / 1 OUTDATED).

Status check: `imgcheck` PASS on `retire_app` (incl. the pinned `python:3.12-slim-trixie`).

## Phase 2 — roll out to the other repos (NEXT)

- Add `policy/tax_calc.deps-policy.json`, `policy/cloudsizingapp.deps-policy.json`.
- `SECURITY.md` in each app repo pointing at this repo + its policy file.
- Fix the floating `python:3.12-slim` and `node:22-alpine` bases in the other
  repos (separate, deliberate PRs — not via Snyk fix PRs).

## Phase 3 — CI enforcement (TODO)

- `.github/workflows/deps.yml` in each app repo:
  clones this repo, runs `imgcheck --fail` + `depcheck`, plus `snyk test --severity-threshold=high`.
- Pre-commit hook (local) running the same.

## Why a repo (not a single script)

So every machine you code on gets the *same* version: `git pull` and you're
updated. Keeps policy, runbook, and skill in one auditable place.
