# Dependency & Base-Image Hygiene — Runbook

This is your field guide for acting on dependency/security notices (Snyk findings,
Dependabot alerts, Code suggestions, or a `depcheck`/`imgcheck` failure). It pairs
with `references/policy.md` and the `dependency-hygiene` skill.

## Two different situations (handle differently)

| Situation | What to do |
|---|---|
| **Stale finding** — Snyk reports a CVE but the package version Snyk names is *already at-or-above* the fixed version in the current image | Rebuild with `docker compose build --pull` and rescan. Do **not** ship a code "fix." |
| **Real finding** — the vulnerable version is genuinely installed | Apply a real fix (pin bump, override, or `--pull`+rescan if it's a base package). |

**Quick stale check:** the Snyk finding line will read `perl/perl-base@5.40.1-6 … Fixed in 5.40.1-6+deb13u1`. If your rebuilt image shows `5.40.1-6+deb13u1` installed, Snyk's view was stale — rebuild/rescan only.

## A) Responding to a Snyk finding

1. Read the finding. Note: package, version, fixed version, severity.
2. Is it a **base-image** finding (Debian/Alpine package, not your app dep)?
   - Yes → go to **Base-image findings**.
   - No → it's a dependency finding → go to **Dependency findings**.
3. Run the checker: `node ~/.agents/skills/dependency-hygiene/scripts/depcheck.mjs` in the repo.
4. Decide + implement (see sections below).
5. Verify: `npm run build`, tests, `depcheck`, `snyk test`.
6. PR against the repo's default branch (**`dev` for repos with a dev branch**). Don't merge Snyk's auto-PR for base images.

### Dependency findings

- **Patch/minor & no major** → `depcheck --fix` (Python) or bump `package.json` (Node). Rebuild + test.
- **Transitive** → prefer an `overrides` entry (npm) or an explicit pin (Python) rather than a parent major bump.
- **Security fix older than cooldown** → exempt it (security exception is policy-approved).
- **No fix available / unreachable / dev-only** → record in the repo policy's allowlist with reason + date, **do not leave it red forever.**

### Base-image findings

1. **Rebuild + rescan first.** Most base-image CVEs clear once you pull the current tag (Debian patches land in newer tag builds).
2. If it persists after rebuild → **it's real.** Then:
   - Is it an **OS-package** CVE (perl, openssl, libc, apt)? → bump the base image tag to the next dated build **only if** that tag is already ≥ the fixed package. Otherwise wait for the tag. Do *not* change language version or OS family to fix it.
   - Is the suggested Snyk fix a **`-rc`, an OS-family swap, or an EOL distro**? → **reject** (see "Rejected fix patterns").
3. Apply: `FROM python:3.12-slim-trixie@sha256:…` (pinned digest). Update the repo's `allowedBaseImages`.
4. Add a **rebuild cadence** (monthly CI) so base CVEs self-clear.

### Dependency (app) findings

1. `depcheck` will say `OUTDATED → bump to X (cooldown-safe) | latest: Y`.
2. Bump to the **cooldown-safe target** unless there's a security reason to jump to latest.
3. Re-run `depcheck` until all green, then `npm ci`/`pip install -r requirements.txt` and test.

## B) Responding to an AI / scanner "fix PR" suggestion

Before merging anything a scanner or AI proposes, run it through `imgcheck` and check these:

### Accepted changes
- Pin-to-cooldown-safe patch/minor bumps, lockfile updates, single-package dependency bumps.
- Pinning a base image **by digest** after a confirmed fix version (e.g. `python:3.12-slim-trixie@sha256:…`).

### Rejected fix patterns (never merge these)
- Any `-rc`/`-beta`/`-alpha`/`-dev`/`aN`/`bN` base tag.
- An OS-family swap in one edit (Debian↔Alpine) — breaks glibc/musl and
  package-manager lines (`apt-get` vs `apk`).
- An EOL distro (e.g. `alpine3.19`).
- A `FROM:`-only edit where the rest of the Dockerfile is not rewritten for
  the new OS family.
- Floating `:latest` or floating family tags (`python:3.12-slim` with no
  codename/digest).

## C) Cooldown exception form (for security fixes)

If a package has no cooldown-safe version (the latest fix is < 14 days old), you
may still adopt it for a **security** reason. Document it in the repo's
`.deps-policy.json` under `cooldownOverride`:

```json
"cooldownOverride": {
  "express": { "version": "5.3.0", "reason": "CVE-2026-13221 fix", "date": "2026-10-15", "reviewBy": "2026-11-15" }
}
```

Review overrides quarterly; remove once the version ages out of cooldown.

## D) CI / tooling

- `depcheck.mjs` + `imgcheck.mjs` run in CI (`deps.yml`) and as a pre-commit hook (local).
- `snyk test --severity-threshold=high` runs in CI; base-image auto-fix PRs are **disabled** in Snyk project settings.
- Rebuild cadence: CI rebuilds base images weekly and re-scans, so base CVEs clear without manual intervention.

## Escalation / decisions

Unclear whether a finding is stale or real → rebuild `--pull` and re-scan; if still
flagged, it's real.
Unsure about an OS-family change → reject by default; propose deliberately.
Policy conflicts with a finding → update the policy repo (this repo) and re-run.