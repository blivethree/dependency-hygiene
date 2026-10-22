# Dependency & Base-Image Policy

**Effective:** 2026-10-21 · **Status:** generic tooling — apply per repo via `.deps-policy.json`
**Cooldown:** 14 days (default). Security fixes are an explicit exception — see "Exception."

---

## Core rules

1. **No unpinned base images.** Every `FROM` must name a codename or be pinned by digest.
   - ❌ `python:3.12-slim`, `node:22-alpine` floating
   - ❌ `:latest`
   - ✅ `python:3.12-slim-trixie` or `python:3.12-slim-trixie@sha256:…`
2. **No pre-release bases.** Reject `-rc`, `-beta`, `-alpha`, `-dev`, `aN`/`bN`, `-head`.
3. **No OS-family swap in a fix.** A single PR must not change glibc↔musl (Debian↔Alpine) unless it's a deliberate, reviewed migration with the Dockerfile rewritten.
4. **No EOL distros.** `alpine:3.19`, `buster`, etc. are barred.
5. **Allowed families:** `debian`, `alpine`. `ubuntu`/`rpm` need approval.
6. **Age gate — dependencies:** don't adopt a new package whose latest release is < 14 days old. Bump existing pins only to the newest release that is ≥ 14 days old.
7. **Known-compromised releases are never adoptable.** `policy/compromised.json` lists
   releases withdrawn for malware or a supply-chain compromise. `depcheck` reports them
   as `COMPROMISED` and always fails — for direct *and* transitive deps, in every
   ecosystem, with or without `--strict`.
   - No cooldown exception applies. A CVE fix does **not** license adopting a
     compromised release; there is no safe version of it to run.
   - `WITHDRAWN` (pinned version deleted from the registry) and `YANKED` (release
     yanked by the maintainer) also block. Both are treated as "stop, investigate",
     not "bump and move on".
   - If a compromised release is found pinned, treat it as a **security incident**
     (see `references/runbook.md`), not a dependency bump. The pin is the symptom;
     credential exposure is the finding.
8. **Direct dependencies must be approved (opt-in).** When a repo supplies an
   approved list (`--approved=<path>` or `.deps-policy.json → approved`), every
   **direct** dep that is not on it is unapproved and blocks. The gate is off when no
   list is supplied, so adopting it is a deliberate, per-repo decision.
   - Approval is a review record, not a security control by itself: `litellm` was on
     everyone's approved list when it was taken over. Names answer *"should this be in
     our tree"*; hashes and provenance answer *"are these the bytes we reviewed"*.
   - **Transitive deps are not name-gated.** A 500-entry allowlist is seeded by a
     script and then rubber-stamped; that is a false assurance, not a gate.
   - Name-level approval by default. Add `version`/`versions` to an entry when a bump
     must require a fresh human decision.
   - Entries need `rationale`, `approvedBy`, `date` and `reviewBy` (≈90 days).
     `depcheck` reports approved-but-unused entries (prune them) and overdue reviews.
   - Bootstrap with `depcheck --approved=<path> --seed-approved`, then fill in the
     rationales before committing. Never seed into CI.
9. **Hashes or it didn't happen.** If a `requirements.txt` uses `--require-hashes`,
   every pin must carry at least one `--hash=` (`NO_HASH`, blocking). Lockfiles
   (`poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`) already record
   hashes/integrity — `--verify-integrity` checks any manifest for them.
   - This is the only layer that survives a compromised registry account: a name and
     version can be approved while the published artifact changes underneath it.

### Exception — security fixes may skip the cooldown

A CVE fix overrides the age gate **if**:
- it's a security finding (CVE/Snyk severity ≥ medium), and
- the version is pinned (no floating), and
- it's recorded in `.deps-policy.json → cooldownOverride` with reason + review date, and
- it's reviewed by the 14-day mark (or removed).

A `cooldownOverride` cannot whitelist a `COMPROMISED`, `WITHDRAWN` or `YANKED` release —
those statuses are checked before the override is consulted.

### Pinned versions
- Python: exact pins (`fastapi==0.141.1`). No ranges in committed `requirements.txt`.
- Node: ranges allowed in `package.json` **only if** `package-lock.json` is committed (it must reproduce exact versions).

---

## Per-repo base-image allowlist

Each repo declares its own allowed bases in its own `.deps-policy.json`
(see `policy/example.deps-policy.json` for the template). The CI workflow reads
`policy/<repo>.deps-policy.json` from the tooling repo — copy your repo's policy
there (or keep it in-repo and point CI at it).

---

## Tooling

- `scripts/depcheck.mjs` — dependency freshness + cooldown + compromised-release denylist.
- `scripts/imgcheck.mjs` — base-image policy + drift detection.
- `policy/compromised.json` — known-bad releases (never adoptable).
- `policy/example.approved.json` — approved direct dependencies (opt-in gate).
- `policy/example.deps-policy.json` — template per-repo policy.
- `references/runbook.md` — how to act on findings.
- Global `AGENTS.md` at `~/.config/opencode/AGENTS.md` loads the `dependency-hygiene` skill automatically.

---

## How changes are approved

- Base-image changes, base-image *fixes*, and any `-rc`/OS-family move → **human review required**.
- Dependency bumps within policy → `depcheck`/`imgcheck` green in CI is approval to merge.
- Security exception overrides → quarterly review; entries expire.