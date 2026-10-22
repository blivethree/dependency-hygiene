# Dependency & Base-Image Hygiene — Runbook

This is your field guide for acting on dependency/security notices (Snyk findings,
Dependabot alerts, Code suggestions, or a `depcheck`/`imgcheck` failure). It pairs
with `references/policy.md` and the `dependency-hygiene` skill.

## Three different situations (handle differently)

| Situation | What to do |
|---|---|
| **Stale finding** — Snyk reports a CVE but the package version Snyk names is *already at-or-above* the fixed version in the current image | Rebuild with `docker compose build --pull` and rescan. Do **not** ship a code "fix." |
| **Real finding** — the vulnerable version is genuinely installed | Apply a real fix (pin bump, override, or `--pull`+rescan if it's a base package). |
| **Compromised / withdrawn release** — `depcheck` says `COMPROMISED`, `WITHDRAWN` or `YANKED` | **Security incident, not a version bump.** Go to section A2 before touching the pin. |

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

- **`COMPROMISED` / `WITHDRAWN` / `YANKED`** → **stop**, go to **A2**. Never auto-fix these.
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
   The suggested target already excludes known-bad, yanked and withdrawn releases.
3. Re-run `depcheck` until all green, then `npm ci`/`pip install -r requirements.txt` and test.

## A2) Compromised or withdrawn release — incident, not a bump

`depcheck` statuses that land here:

| Status | Meaning |
|---|---|
| `COMPROMISED` | The exact release is listed in `policy/compromised.json` as carrying malware. |
| `WITHDRAWN` | The pinned version is no longer published at all (deleted). Frequently the registry cleanup *after* a compromise. |
| `YANKED` | The maintainer yanked the release. Treat as untrusted until explained. |

All three block the gate for direct **and** transitive deps, in every ecosystem, even
without `--strict`. A transitive hit is normal: you usually don't name the package
yourself (e.g. an agent framework pulls in `litellm`).

**Do not `--fix`, do not "bump and move on".** The bad pin is the symptom; credential
exposure is the finding. Order of work:

1. **Contain.** Stop the affected process/container first. Removing the pin does not
   un-exfiltrate anything — the payload already ran at install time.
2. **Establish the exposure window.** `git log -p -- requirements.txt poetry.lock uv.lock pip freeze.txt`
   plus CI run history. Any install, image build, or `pip install` that resolved the
   bad version is an exposure event.
3. **Rotate, in this order** (payloads like this read local files on a timer):
   - registry publish tokens (PyPI/npm) and GitHub tokens
   - cloud credentials (AWS/SSM profiles, `~/.aws`)
   - SSH private keys and the ssh-agent
   - browser password stores / cookies
   - AI-tool configs and API keys (`~/.config/opencode`, `~/.claude`, `.env`)
   - shell history and any secrets it captured
4. **Look for persistence.** Unexpected `*.pth` files in `site-packages`, `pip list`
   still showing the bad version, cron/systemd/launchd entries, and modified shell rc files.
5. **Then** pin an aged, clean version, `depcheck` green, rebuild images from scratch
   (no layer cache — the bad wheel may be baked in).
6. **Record it.** Note the window, rotation, and the clean version in the repo's
   `.deps-policy.json` / incident log.

### Known case: `litellm` (PyPI)

| Versions | When | What |
|---|---|---|
| `1.82.7`, `1.82.8` | Mar 2026 | PyPI publish token stolen via a compromised Trivy GitHub Action; `.pth` credential stealer. |
| `1.107.0` | 21–22 Oct 2026 | Same actor (TeamPCP), second takeover; wheels **and Docker images**; credential stealer + hourly remote code loader. Deleted from PyPI within ~24h. |

Latest clean stable at the time of writing: `1.106.2`. All three malicious versions are
seeded in `policy/compromised.json`. Advisories:
[StepSecurity](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer),
[Trend Micro](https://www.trendmicro.com/en_us/research/26/c/your-ai-stack-just-handed-over-your-root-keys-inside-the-litellm-pypi-breach.html),
[NHS CC-4761](https://digital.nhs.uk/cyber-alerts/2026/cc-4761).

**Lesson:** the 14-day cooldown would *not* have protected an immediate `--fix` or an
allow-latest install — `1.107.0` was live and adoptable for a day, and `1.82.7/8` were
reported as `TOO_NEW`, which used to be advisory. Only the denylist plus a blocking
`UNAGED_NEW_DEP` catches this class.

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
- `depcheck` compares the working tree against `HEAD` to tell a **newly introduced** fresh
  pin (`UNAGED_NEW_DEP`, blocking) from one that is already committed and merely young
  (`TOO_NEW`, advisory). Shallow CI clones may lack the baseline: pass
  `--baseline=<rev>` or fetch more history; without it, new adoptions degrade to
  `TOO_NEW` with an "adoption age unverified" note.
- `--strict` escalates transitive findings *and* `TOO_NEW`, for repos that want a hard gate.
- **Approval gate (opt-in):** with `--approved=<path>` (or `.deps-policy.json → approved`)
  every **direct** dep must appear in the list, with `rationale`/`approvedBy`/`date`/
  `reviewBy`; otherwise it blocks. Transitive deps are deliberately not name-gated.
  Bootstrap with `--seed-approved` (once, locally — never in CI), then fill in the
  rationales. Stale entries (approved but unused) and overdue `reviewBy` dates are
  reported as advisory so the list can be pruned instead of silently rotting.
- **Integrity:** `--require-hashes` in a `requirements.txt` (or `--verify-integrity`)
  requires a `--hash=` for every pin (`NO_HASH`, blocking). `poetry.lock`/`uv.lock`
  `files = [{hash=…}]`, `Pipfile.lock` `hashes`, and `package-lock.json` `integrity`
  are all inspected. This is the layer that catches a compromised *approved* package;
  a name list cannot.
- Tests: `npm test` (stdlib `node --test`, no installs, no network — a local stub registry
  is used via `DEPCHECK_PYPI_INDEX` / `DEPCHECK_NPM_REGISTRY`).
- `snyk test --severity-threshold=high` runs in CI; base-image auto-fix PRs are **disabled** in Snyk project settings.
- Rebuild cadence: CI rebuilds base images weekly and re-scans, so base CVEs clear without manual intervention.

## Escalation / decisions

Unclear whether a finding is stale or real → rebuild `--pull` and re-scan; if still
flagged, it's real.
Unsure about an OS-family change → reject by default; propose deliberately.
Policy conflicts with a finding → update the policy repo (this repo) and re-run.