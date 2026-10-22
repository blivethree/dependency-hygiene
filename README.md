# dependency-hygiene

Small, **dependency-free** (stdlib Node 20+ only) tooling that gates two kinds of
change across your repos:

- **`scripts/depcheck.mjs`** — dependency freshness + 14-day age gate + known-bad
  release denylist + opt-in approval gate for new direct dependencies. Scans
  Python `requirements.txt` / `pyproject.toml` / `Pipfile.lock` / `poetry.lock` /
  `uv.lock` and Node `package-lock.json`.
- **`scripts/imgcheck.mjs`** — base-image policy + drift detection
  (no `-rc`, no OS-family swap, no floating tags, pinned Debian codename/digest).

**Why this exists:** Snyk finds *known CVEs*, but it can't age-gate new
libraries, it won't tell you a release was **compromised or withdrawn**, and it
frequently proposes **invalid base-image "fixes"** (release candidates,
OS-family swaps, EOL distros). This repo is the validation layer. It ships with
the `dependency-hygiene` OpenCode skill + global `AGENTS.md` so the gates run
automatically when you code.

## Install (use on any PC)

No npm publish. Clone a release tag (or a full commit SHA) so the code you run
is identifiable later:

```bash
# one time, any machine — pin a tag or full commit SHA
git clone --branch v0.4.0 --depth 1 https://github.com/<your-org>/dependency-hygiene.git ~/.opencode/dependency-hygiene
# (Node 20+ required; nothing to install)
# update deliberately: git fetch --tags && git checkout vX.Y.Z
```

To use the **OpenCode skill** on this machine:

```bash
mkdir -p ~/.agents/skills ~/.claude/skills
ln -s ~/.opencode/dependency-hygiene ~/.agents/skills/dependency-hygiene
ln -s ~/.opencode/dependency-hygiene ~/.claude/skills/dependency-hygiene
```

Then create `~/.config/opencode/AGENTS.md` (already in this repo's `references/`):

```md
# Dependency & base-image hygiene
- Before adding/upgrading/changing any dependency or base image, load the
  `dependency-hygiene` skill and run `depcheck` + `imgcheck`.
- ...full rules in references/policy.md
```

## Run

```bash
cd /path/to/your/repo            # any repo
DHH=~/.opencode/dependency-hygiene

# dependency check (14-day cooldown + denylist)
node $DHH/scripts/depcheck.mjs . --cooldown=14
node $DHH/scripts/depcheck.mjs . --policy $DHH/policy/example.deps-policy.json --json

# base-image check
node $DHH/scripts/imgcheck.mjs . --policy $DHH/policy/example.deps-policy.json --fail
```

Exit codes: 0 clean, 1 violation, 2 could not run.

### `depcheck` flags

| Flag | Effect |
|---|---|
| `--cooldown=<days>` | Override the 14-day age gate. |
| `--json` | Machine-readable rows (`status`, `revisitAfter`, `skipped`, `compromisedEntries`, `approvalGate`, `approvalRequest`). |
| `--strict` | Escalate transitive findings **and** fresh pins (`TOO_NEW`) to failures. |
| `--fix` | Rewrite exact `pkg==x` pins in `requirements.txt` to the cooldown-safe target, then re-scan. Refuses files containing a `COMPROMISED`/`WITHDRAWN`/`YANKED` row. |
| `--policy=<path>` | Per-repo policy (also auto-read from `<repo>/.deps-policy.json`). |
| `--compromised=<path>` | Extra denylist entries on top of `policy/compromised.json`. |
| `--baseline=<rev>`, `--no-baseline` | Git revision used to detect *newly introduced* pins (default `HEAD`; `origin/$GITHUB_BASE_REF` on GitHub PRs, so a checked-out merge commit does not hide the change). |
| `--approved=<path>` | Turn on the direct-dependency approval gate (also `.deps-policy.json → approved`). |
| `--approval-scope=new\|all` | What the approval gate covers: `new` (default) gates only direct dep names that are new vs the git baseline; `all` gates the whole direct tree. |
| `--print-approval-request` | Print paste-ready approval entries (blank sign-off + registry evidence) for unapproved direct deps. Requires the gate on (exit 2 otherwise); `--json` takes precedence if both are passed. |
| `--seed-approved` | One-off local bootstrap of the approved list from the current direct deps (needs `--approved`). Never run in CI. |
| `--frozen` | Deploy gate: requires an approved list, forces `--approval-scope=all` + `--strict`, and exits 2 rather than pass on an empty scan. |
| `--verify-integrity` | Require hashes/integrity for every pin (`NO_HASH` otherwise). `--require-hashes` in a requirements file does this automatically. |

Env overrides for the registry endpoints (private mirrors, offline tests):
`DEPCHECK_PYPI_INDEX`, `DEPCHECK_NPM_REGISTRY`.

### Approving dependencies (opt-in)

A name list only answers *"should this library be in our tree"*. It does **not**
stop a takeover of an approved package — `litellm` was on everyone's list — so pair
it with hashes (or provenance) for that layer.

The gate is **off** unless a list is supplied. Only **direct** deps are name-gated:
a 500-entry transitive allowlist gets script-seeded and rubber-stamped. Full
process: `references/approval-workflow.md`; CI template: `examples/deps.yml`.

```bash
# one-off bootstrap, then have security review and replace every grandfathered entry
node $DHH/scripts/depcheck.mjs . --approved=approved.json --seed-approved

# everyday PR gate: only direct dep *names* new vs the base branch need approval
node $DHH/scripts/depcheck.mjs . --approved=approved.json

# what the developer pastes into approved.json (blank sign-off = pending)
node $DHH/scripts/depcheck.mjs . --approved=approved.json --print-approval-request

# deploy: gate the whole direct tree, fail closed
node $DHH/scripts/depcheck.mjs . --approved=approved.json --frozen --verify-integrity
```

A developer may draft an entry, but `approvedBy` + `date` are what turn a request
into an approval: leave them blank and the gate stays red. Under `--strict` /
`--frozen`, `rationale` + `reviewBy` are required too. That makes the committed
record the audit evidence, not a formality.

| Field | Meaning |
|---|---|
| `ecosystem`, `name` | What is approved (case/`-_.` normalised). |
| `version` / `versions` | Optional: restrict approval to exact versions, so a bump needs a fresh decision. |
| `approvedBy`, `date` | **Required** sign-off. Blank = pending request. |
| `rationale`, `reviewBy` | Required under `--strict`/`--frozen`; recommended always. Overdue reviews and approved-but-unused entries are reported (advisory). |
| `checks` | Evidence copied from `--print-approval-request` at review time (age, first publish, releases, licence, known-bad). |
| `ticket` | Optional link to the request/change ticket. |
| `grandfathered` | Set by `--seed-approved`; flags entries that were never actually reviewed. |

Scope matters:

- `--approval-scope=new` (default) compares direct dependency **names** against the
  git baseline, so turning the gate on does not turn a legacy repo red. If no
  baseline is available, it fails closed (everything is treated as new).
- `--approval-scope=all` is the audit/deploy view: every direct dep needs a record.
- A version-pinned entry intentionally stops covering a bump; a name-level entry
  keeps covering it (the age/denylist/hash layers handle a bad new release).

See `policy/example.approved.json` for the record shape.

### `depcheck` statuses

| Status | Blocks? | Meaning |
|---|---|---|
| `OK` | – | Pinned version is current or cooldown-safe. |
| `OUTDATED` | direct | Bump to the suggested cooldown-safe target. |
| `TOO_NEW` | `--strict` | Pin is younger than the cooldown but already committed — advisory. |
| `UNAGED_NEW_DEP` | yes | A **newly introduced** pin younger than the cooldown. Revert or wait (`revisitAfter`). |
| `NO_HASH` | direct | Hashes are required but this pin has none — the bytes are unverifiable. |
| `UNPINNED` / `PRERELEASE` / `UNRESOLVING` | direct | Not an exact pin / pre-release / registry lookup failed. |
| `WITHDRAWN` | **always** | Pinned version deleted from the registry. |
| `YANKED` | **always** | Release withdrawn by the maintainer. |
| `COMPROMISED` | **always** | Release listed in `policy/compromised.json` as malware. Incident, not a bump. |

An unapproved direct dep shows `no` in the `APPROVED` column and blocks, whatever
its freshness status. In `--approval-scope=new` a pre-existing dep shows `—` (not
in scope) until you run with `all`. A transitive dep always shows `—` (not
name-gated).

## Policy

- `references/policy.md` — rules, allowlist, exceptions, compromised-release rule.
- `references/approval-workflow.md` — the review/approval/deploy/audit workflow.
- `references/runbook.md` — how to act on Snyk findings / fix PRs / a compromised release.
- `policy/compromised.json` — known-bad releases; never adoptable, no override.
- `policy/example.approved.json` — approved direct dependencies (opt-in gate).
- `policy/example.deps-policy.json` — template per-repo policy. Copy to your
  repo and edit the allowed base images / cooldown.
- `examples/deps.yml`, `examples/CODEOWNERS` — CI gate + security ownership template.

## Tests

```bash
npm test        # stdlib node --test; no installs, no network
# the same suite runs on every PR in .github/workflows/ci.yml
```

Inventory parsing, classification, the denylist, and end-to-end CLI behaviour are
covered against a local stub registry (`DEPCHECK_PYPI_INDEX`).

## OpenCode integration

- `SKILL.md` is auto-discovered from `~/.agents/skills/` (and the Claude
  compat path `~/.claude/skills/`).
- `references/runbook.md` is loaded by the skill.

## CI usage

A per-repo `.github/workflows/deps.yml` clones this repo and runs both
scripts + `snyk test`. The full template (PR gate, approval-request step
summary, frozen deploy job) is `examples/deps.yml`; ownership for
`approved.json` is `examples/CODEOWNERS`.

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
  with: { fetch-depth: 0 }   # scope=new needs the baseline
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
  with: { node-version: 24 }
- run: git clone --branch v0.4.0 --depth 1 https://github.com/<your-org>/dependency-hygiene.git $HOME/dependency-hygiene
- run: node $HOME/dependency-hygiene/scripts/imgcheck.mjs . \
        --policy $HOME/dependency-hygiene/policy/example.deps-policy.json --fail
- run: node $HOME/dependency-hygiene/scripts/depcheck.mjs . \
        --approved=approved.json
```

> **Pin the tool; don't track `main`.** Bump `v0.4.0` deliberately — Dependabot
> updates the action SHAs but not this shell pin. Verify the release checksums
> before running the scripts:
>
> ```bash
> curl -fsSLo /tmp/dh-SHA256SUMS \
>   https://github.com/<your-org>/dependency-hygiene/releases/download/v0.4.0/SHA256SUMS
> (cd "$HOME/dependency-hygiene" && sha256sum -c /tmp/dh-SHA256SUMS)
> ```
>
> **Note:** This repo is **public** on purpose. GitHub Actions runners cannot
> `git clone` a private repo without credentials. If you need a private copy,
> use a PAT or GitHub App token in the workflow instead.
>
> **The gate is only real if branch protection requires the check** and
> `CODEOWNERS` requires a security review of `approved.json`. A script can fail
> a build; it cannot stop a merge or a deploy on its own.

See `TROUBLESHOOTING.md` for the real debugging session that led to this note.

## Security

See `SECURITY.md` for private vulnerability reporting, supported versions, and
the consumer pinning/verification requirements.

## Phases

This repo was built in phases. See `PHASES.md` for the plan and current status.