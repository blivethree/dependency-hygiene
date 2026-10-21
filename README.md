# dependency-hygiene

Small, **dependency-free** (stdlib Node 20+ only) tooling that gates two kinds of
change across the `blivethree/*` repos:

- **`scripts/depcheck.mjs`** — dependency freshness + 14-day age gate
  (Python `requirements.txt` + Node `package-lock.json`).
- **`scripts/imgcheck.mjs`** — base-image policy + drift detection
  (no `-rc`, no OS-family swap, no floating tags, pinned Debian codename/digest).

**Why this exists:** Snyk finds *known CVEs*, but it can't age-gate new
libraries and it frequently proposes **invalid base-image "fixes"**
(release candidates, OS-family swaps, EOL distros). This repo is the
validation layer. It ships with the `dependency-hygiene` OpenCode skill +
global `AGENTS.md` so the gates run automatically when you code.

## Install (use on any PC)

No npm publish. Just clone once per machine and keep it in sync:

```bash
# one time, any machine that has blivethree repos checked out
git clone git@github.com:blivethree/dependency-hygiene.git ~/.opencode/dependency-hygiene
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
cd /path/to/your/repo            # any blivethree repo
DHH=~/.opencode/dependency-hygiene

# dependency check (14-day cooldown)
node $DHH/scripts/depcheck.mjs . --cooldown=14
node $DHH/scripts/depcheck.mjs . --policy $DHH/policy/<repo>.deps-policy.json --json

# base-image check
node $DHH/scripts/imgcheck.mjs . --policy $DHH/policy/<repo>.deps-policy.json --fail
```

Exit codes: 0 clean, 1 violation, 2 could not run.

## Policy

- `references/policy.md` — rules, allowlist, exceptions.
- `references/runbook.md` — how to act on Snyk findings / fix PRs.
- `policy/<repo>.deps-policy.json` — per-repo overrides (add a file per repo
  you want to enforce).

## OpenCode integration

- `SKILL.md` is auto-discovered from `~/.agents/skills/` (and the Claude
  compat path `~/.claude/skills/`).
- `references/runbook.md` is loaded by the skill.

## CI usage (see Phase 3)

A per-repo `.github/workflows/deps.yml` clones this repo and runs both
scripts + `snyk test`. (Not added yet — coming next.)
