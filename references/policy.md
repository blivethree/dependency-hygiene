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
8. **New direct dependencies need review before the PR can merge (opt-in).**
   When a repo supplies an approved list (`--approved=<path>` or
   `.deps-policy.json → approved`), `depcheck` gates direct dependencies. The gate
   is off when no list is supplied, so adopting it is a deliberate, per-repo
   decision.
   - **`--approval-scope=new` (default) gates only a direct dep *name* that is new
     relative to the git baseline.** The pre-existing tree is grandfathered, so
     enabling the gate does not block unrelated work. If no usable baseline exists,
     it fails closed (everything is treated as new).
   - `--approval-scope=all` gates every direct dep; use it for the periodic audit
     and for deploys, not on every PR.
   - **A developer may draft an entry, but it is only an approval once `approvedBy`
     and `date` are filled.** Blank fields keep the build red — that is the pending
     state. Under `--strict`/`--frozen`, `rationale` and `reviewBy` are required too.
   - `approved.json` is owned by security via `CODEOWNERS`; branch protection with
     the `depcheck` check required is the actual control. The reviewed diff is the
     sign-off, and the merge commit is the audit record.
   - Name-level approval by default. Add `version`/`versions` when a bump must
     require a fresh human decision.
   - Bootstrap once, locally, with `--seed-approved` (entries are flagged
     `grandfathered`). **Never seed in CI:** a list that regenerates itself is a
     lockfile, not an approval record. Replace every grandfathered rationale.
   - **Transitive deps are not name-gated.** A 500-entry allowlist is seeded by a
     script and then rubber-stamped; that is false assurance, not a gate. Use the
     SBOM/Dependency-Track for reach.
   - Revoke by removing the entry (or letting a version-pinned approval stop
     matching); the next PR and deploy fail.
   - Approval is a review record, not a security control by itself: `litellm` was on
     everyone's approved list when it was taken over. Names answer *"should this be
     in our tree"*; hashes and provenance answer *"are these the bytes we
     reviewed"*. Full process: `references/approval-workflow.md`.
9. **Hashes or it didn't happen.** If a `requirements.txt` uses `--require-hashes`,
   every pin must carry at least one `--hash=` (`NO_HASH`, blocking). Lockfiles
   (`poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`) already record
   hashes/integrity — `--verify-integrity` checks any manifest for them.
   - This is the only layer that survives a compromised registry account: a name and
     version can be approved while the published artifact changes underneath it.
10. **Deploys verify the approved tree, not a fresh build.** The deploy job runs
    `depcheck --frozen --verify-integrity` against the exact commit/tag being
    shipped. `--frozen` refuses to run without an approved list (exit `2`), forces
    `scope=all` + `--strict`, and exits `2` on an empty scan rather than passing a
    gate on nothing.
    - Overdue `reviewBy` dates stay advisory even in `--frozen`: a lapsed review is
      a ticket, not an outage. Incomplete records (`approvedBy`/`date`, and
      `rationale`/`reviewBy` under strict) do block.
    - Ship the artifact by **digest** and keep its SBOM with it; do not rebuild per
      environment and assume the bytes match what the gate saw.

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
- `references/approval-workflow.md` — request → review → approve → deploy → audit.
- `examples/deps.yml`, `examples/CODEOWNERS` — CI gate + security ownership template.
- `references/runbook.md` — how to act on findings.
- Global `AGENTS.md` at `~/.config/opencode/AGENTS.md` loads the `dependency-hygiene` skill automatically.

---

## How changes are approved

- Base-image changes, base-image *fixes*, and any `-rc`/OS-family move → **human review required**.
- Dependency bumps within policy → `depcheck`/`imgcheck` green in CI is approval to merge.
- **A new direct dependency → security review of `approved.json` before merge** (the
  file is `CODEOWNERS`-owned; the developer drafts the entry, security signs it).
  The merge commit carries the dependency, the justification, and the approver.
- **Revoking an approval → remove/expire the entry.** The next PR and deploy fail;
  that is the intended path.
- Security exception overrides → quarterly review; entries expire.
- Full workflow: `references/approval-workflow.md`.