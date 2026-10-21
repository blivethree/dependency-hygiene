# dependency-hygiene

Small, **dependency-free** (stdlib Node 20+ only) tooling that gates two kinds of
change across your repos:

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

# dependency check (14-day cooldown)
node $DHH/scripts/depcheck.mjs . --cooldown=14
node $DHH/scripts/depcheck.mjs . --policy $DHH/policy/example.deps-policy.json --json

# base-image check
node $DHH/scripts/imgcheck.mjs . --policy $DHH/policy/example.deps-policy.json --fail
```

Exit codes: 0 clean, 1 violation, 2 could not run.

## Policy

- `references/policy.md` — rules, allowlist, exceptions.
- `references/runbook.md` — how to act on Snyk findings / fix PRs.
- `policy/example.deps-policy.json` — template per-repo policy. Copy to your
  repo and edit the allowed base images / cooldown.

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