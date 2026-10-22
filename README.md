# dependency-hygiene

Small, **dependency-free** (stdlib Node 20+ only) tooling that gates two kinds of
change across your repos:

- **`scripts/depcheck.mjs`** — dependency freshness + 14-day age gate + known-bad
  release denylist. Scans Python `requirements.txt` / `pyproject.toml` /
  `Pipfile.lock` / `poetry.lock` / `uv.lock` and Node `package-lock.json`.
- **`scripts/imgcheck.mjs`** — base-image policy + drift detection
  (no `-rc`, no OS-family swap, no floating tags, pinned Debian codename/digest).

**Why this exists:** Snyk finds *known CVEs*, but it can't age-gate new
libraries, it won't tell you a release was **compromised or withdrawn**, and it
frequently proposes **invalid base-image "fixes"** (release candidates,
OS-family swaps, EOL distros). This repo is the validation layer. It ships with
the `dependency-hygiene` OpenCode skill + global `AGENTS.md` so the gates run
automatically when you code.

## Install (use on any PC)

No npm publish. Just clone once per machine and keep it in sync:

```bash
# one time, any machine
git clone https://github.com/<your-org>/dependency-hygiene.git ~/.opencode/dependency-hygiene
# (Node 20+ required; nothing to install)
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
| `--json` | Machine-readable rows (`status`, `revisitAfter`, `skipped`, `compromisedEntries`). |
| `--strict` | Escalate transitive findings **and** fresh pins (`TOO_NEW`) to failures. |
| `--fix` | Rewrite exact `pkg==x` pins in `requirements.txt` to the cooldown-safe target, then re-scan. Refuses files containing a `COMPROMISED`/`WITHDRAWN`/`YANKED` row. |
| `--policy=<path>` | Per-repo policy (also auto-read from `<repo>/.deps-policy.json`). |
| `--compromised=<path>` | Extra denylist entries on top of `policy/compromised.json`. |
| `--baseline=<rev>`, `--no-baseline` | Git revision used to detect *newly introduced* pins (default `HEAD`). |

Env overrides for the registry endpoints (private mirrors, offline tests):
`DEPCHECK_PYPI_INDEX`, `DEPCHECK_NPM_REGISTRY`.

### `depcheck` statuses

| Status | Blocks? | Meaning |
|---|---|---|
| `OK` | – | Pinned version is current or cooldown-safe. |
| `OUTDATED` | direct | Bump to the suggested cooldown-safe target. |
| `TOO_NEW` | `--strict` | Pin is younger than the cooldown but already committed — advisory. |
| `UNAGED_NEW_DEP` | yes | A **newly introduced** pin younger than the cooldown. Revert or wait (`revisitAfter`). |
| `UNPINNED` / `PRERELEASE` / `UNRESOLVING` | direct | Not an exact pin / pre-release / registry lookup failed. |
| `WITHDRAWN` | **always** | Pinned version deleted from the registry. |
| `YANKED` | **always** | Release withdrawn by the maintainer. |
| `COMPROMISED` | **always** | Release listed in `policy/compromised.json` as malware. Incident, not a bump. |

## Policy

- `references/policy.md` — rules, allowlist, exceptions, compromised-release rule.
- `references/runbook.md` — how to act on Snyk findings / fix PRs / a compromised release.
- `policy/compromised.json` — known-bad releases; never adoptable, no override.
- `policy/example.deps-policy.json` — template per-repo policy. Copy to your
  repo and edit the allowed base images / cooldown.

## Tests

```bash
npm test        # stdlib node --test; no installs, no network
```

Inventory parsing, classification, the denylist, and end-to-end CLI behaviour are
covered against a local stub registry (`DEPCHECK_PYPI_INDEX`).

## OpenCode integration

- `SKILL.md` is auto-discovered from `~/.agents/skills/` (and the Claude
  compat path `~/.claude/skills/`).
- `references/runbook.md` is loaded by the skill.

## CI usage

A per-repo `.github/workflows/deps.yml` clones this repo and runs both
scripts + `snyk test`. Example:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with: { node-version: 24 }
- run: git clone --depth 1 https://github.com/<your-org>/dependency-hygiene.git $HOME/dependency-hygiene
- run: node $HOME/dependency-hygiene/scripts/imgcheck.mjs . \
        --policy $HOME/dependency-hygiene/policy/example.deps-policy.json --fail
- run: node $HOME/dependency-hygiene/scripts/depcheck.mjs . \
        --policy $HOME/dependency-hygiene/policy/example.deps-policy.json
```

> **Note:** This repo is **public** on purpose. GitHub Actions runners cannot
> `git clone` a private repo without credentials. If you need a private copy,
> use a PAT or GitHub App token in the workflow instead.

See `TROUBLESHOOTING.md` for the real debugging session that led to this note.

## Phases

This repo was built in phases. See `PHASES.md` for the plan and current status.