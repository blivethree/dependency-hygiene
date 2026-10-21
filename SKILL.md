---
name: Dependency Hygiene
description: >
  Before adding or upgrading any dependency or base image, check freshness and
  the 14-day age gate, validate any proposed fix (no prerelease/OS-swap/
  EOL bases), and rebuild-and-rescan before patching base-image CVEs. Loads
  the depcheck + imgcheck scripts and the policy/runbook references.
metadata:
  opencode/autoinvoke: true
license: MIT
---

# Dependency Hygiene

You are a careful gatekeeper for dependencies and base images. Apply this
**every time** a dependency or base image is added, upgraded, changed, or
"fixed" — whether proposed by Snyk, Dependabot, another AI, or a human.

## When to activate

- Adding a new library (Python `requirements.txt` or Node `package.json`/lock).
- Bumping any dependency.
- Accepting a Snyk/Dependabot fix PR.
- Changing a `FROM` line.
- Reviewing a base-image CVE.

## Workflow

1. **Locate the policy.** Read `references/policy.md` for this repo's
   allowlist and cooldown (default 14 days; security fixes excepted). Run
   `imgcheck.mjs` against the repo to see the current `FROM` lines and
   whether each is allowed/pinned.

2. **For a dependency adoption/upgrade:**
   - Run `node ~/.agents/skills/dependency-hygiene/scripts/depcheck.mjs` from
     the repo root.
   - Read the status column: `OK`, `OUTDATED`, `TOO_NEW`, `UNPINNED`,
     `PRERELEASE`, `UNRESOLVING`.
   - **Reject** `TOO_NEW` (< 14 days) and `PRERELEASE` unless there is a
     documented security override in `deps-policy.json`.
   - **Bump** `OUTDATED` to the cooldown-safe target the tool suggests.

3. **For a base-image change / Snyk fix PR:**
   - The default Snyk base-image suggestion is frequently wrong — it often
     proposes `-rc` tags, an OS-family swap, or an EOL distro.
   - Apply the **rejected-fix checklist** (see below) before touching the
     Dockerfile.
   - For an OS-package CVE (e.g. `perl-base`, `openssl`), **rebuild with
     `docker compose build --pull` and rescan first.** If the fixed version
     is already installed, the finding was stale — do nothing else. Only
     change the `FROM` if the current tag still lacks the fixed package.

4. **For a Python `requirements.txt`:**
   - Use exact pins (`pkg==1.2.3`). The `depcheck --fix` flag rewrites pins
     to cooldown-safe versions.
   - After changes, re-run `depcheck` until all green, then
     `pip install -r requirements.txt` and test.

5. **For a Node app:**
   - Ranges in `package.json` are fine **only if** `package-lock.json` is
     committed. `depcheck` audits the lockfile.
   - For a transitive CVE, prefer an `overrides` block (see
     `cloudsizingapp` precedent) over a parent major bump.

## Rejected fix patterns (never merge these)

- Any `-rc`/`-beta`/`-alpha`/`-dev`/`aN`/`bN` base tag.
- An OS-family swap in one edit (Debian↔Alpine) — breaks glibc/musl and
  package-manager lines (`apt-get` vs `apk`).
- An EOL distro (e.g. `alpine3.19`).
- A `FROM:`-only edit where the rest of the Dockerfile is not rewritten for
  the new OS family.
- Floating `:latest` or floating family tags (`python:3.12-slim` with no
  codename/digest).

## Security override (exception to the cooldown)

Document in `deps-policy.json`:

```json
"cooldownOverride": {
  "express": { "version": "5.3.0", "reason": "CVE-2026-13221 fix", "date": "2026-10-15", "reviewBy": "2026-11-15" }
}
```

Review quarterly; remove older than the cooldown.

## References (read these when this skill loads)

- `references/runbook.md` — how to act on findings, stale-vs-real decision.
- `references/policy.md` — allowlist, cooldown, exceptions.
- `scripts/depcheck.mjs` — dependency freshness + cooldown.
- `scripts/imgcheck.mjs` — base-image policy + drift detection.

Run the scripts; don't rely on memory alone.
