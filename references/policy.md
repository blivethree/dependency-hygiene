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

### Exception — security fixes may skip the cooldown

A CVE fix overrides the age gate **if**:
- it's a security finding (CVE/Snyk severity ≥ medium), and
- the version is pinned (no floating), and
- it's recorded in `.deps-policy.json → cooldownOverride` with reason + review date, and
- it's reviewed by the 14-day mark (or removed).

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

- `scripts/depcheck.mjs` — dependency freshness + cooldown.
- `scripts/imgcheck.mjs` — base-image policy + drift detection.
- `policy/example.deps-policy.json` — template per-repo policy.
- `references/runbook.md` — how to act on findings.
- Global `AGENTS.md` at `~/.config/opencode/AGENTS.md` loads the `dependency-hygiene` skill automatically.

---

## How changes are approved

- Base-image changes, base-image *fixes*, and any `-rc`/OS-family move → **human review required**.
- Dependency bumps within policy → `depcheck`/`imgcheck` green in CI is approval to merge.
- Security exception overrides → quarterly review; entries expire.