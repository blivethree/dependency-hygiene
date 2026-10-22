# Troubleshooting: GitHub Actions Workflow Failures

This documents a real debugging session that took ~90 minutes to resolve. The symptom
was a GitHub Actions workflow that kept failing with a misleading error message.

## Symptom

A `dependency-hygiene` workflow showed:

```
X This run likely failed because of a workflow file issue.
```

Every run was `failure` with `0s` duration. The annotation pointed at the YAML:

```
Invalid workflow file: .github/workflows/deps.yml#L1
(Line: 67, Col: 13): Unrecognized named-value: 'secrets'.
```

## What I Got Wrong

I spent ~90 minutes chasing the **YAML syntax**. I:

- Rewrote the workflow file repeatedly
- Verified it with Python's `yaml.safe_load` (which said "VALID")
- Removed all `secrets.SNYK_TOKEN` references
- Added `workflow_dispatch` triggers
- Pushed empty commits to trigger runs

**None of it worked.** The YAML was never the problem.

## The Two Real Root Causes

### 1. The tooling repo was private (this was THE blocker)

The workflow step `Install dependency-hygiene tooling` ran:

```bash
git clone --depth 1 https://github.com/<your-org>/dependency-hygiene.git $HOME/dependency-hygiene
```

But the tooling repo was **private**. The GitHub Actions runner has no
credentials, so `git clone` failed with:

```
fatal: could not read Username for 'https://github.com': No such device or address
```

The runner tried to prompt for a username/password interactively, but there's no
terminal in CI — hence `No such device or address`.

**Fix:** Made the tooling repo **public**. It's just scripts (no secrets),
so this is safe.

### 2. `depcheck.mjs` on the remote repo was outdated

The local `depcheck.mjs` had been updated to only **block on direct deps**
(`isBlocking` logic). But the version pushed to the remote tooling repo was an
**older version** that treated ALL violations as blocking, including
transitive PRERELEASE items:

```js
// OLD (remote): blocks on everything
const fail = rows.filter((r) => ["OUTDATED", "PRERELEASE", "UNPINNED", "UNRESOLVING"].includes(r.status));

// NEW (local): only direct deps block
const isBlocking = (r) => {
  if (!["OUTDATED", "PRERELEASE", "UNPINNED", "UNRESOLVING"].includes(r.status)) return false;
  if (r.ecosystem === "pypi") return true;
  if (STRICT) return true;
  return r.direct === "direct";
};
```

So even after fixing #1, `depcheck` still failed because the remote version flagged
3 transitive PRERELEASE items as blocking.

**Fix:** Pushed the updated `depcheck.mjs` to the tooling repo's main branch.

## How I Finally Found It

I stopped guessing and started **reading the actual run logs**:

```bash
curl -s -L -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/<your-org>/<your-repo>/actions/runs/<ID>/jobs" \
  | strings | grep -iE "error|fail|clone|denied|not found|permission|fatal"
```

This revealed:
```
fatal: could not read Username for 'https://github.com': No such device or address
```

And the step-by-step breakdown showed exactly which step failed:

```
- Install dependency-hygiene tooling: failure
- Base-image policy (imgcheck): skipped
- Dependency freshness + age gate (depcheck): skipped
```

The `skipped` steps told me the failure was in the install step, not the YAML.

## Lessons Learned

1. **Read the logs.** Don't guess. The annotation said "workflow file issue" but the
   real error was in the `run:` step, not the YAML.

2. **Check the remote repo state.** I had a local fix that was never pushed. Always
   verify what's actually deployed.

3. **Private repos can't be cloned in CI without credentials.** If a workflow needs
   to `git clone` another repo, that repo must be public (or use a PAT/GitHub App
   token).

4. **Python's `yaml.safe_load` validates YAML syntax, not GitHub Actions validity.**
   GitHub's parser is stricter and can reject things Python accepts.

5. **Empty commits don't always trigger runs.** Use a real file change or
   `workflow_dispatch` to force a run.

## How to Check Run Status

```bash
# List recent runs
gh run list --repo <your-org>/<your-repo> --limit 5

# View a specific run
gh run view <run-id> --repo <your-org>/<your-repo>

# Get job/step breakdown
curl -s -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/<your-org>/<your-repo>/actions/runs/<ID>/jobs" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'{j[\"name\"]}: {j[\"conclusion\"]}') for j in d.get('jobs',[])]"

# Get actual logs
curl -s -L -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/<your-org>/<your-repo>/actions/runs/<ID>/jobs" \
  | strings | grep -iE "error|fail|clone|fatal"
```
## `depcheck` says `OUTDATED` for a version that no longer exists

Symptom: a repo pins a release that has since been **deleted** from the registry (e.g.
`litellm==1.82.8` after the Mar 2026 compromise). `depcheck` ≤ 0.1.x found no age for
the pin, fell through to `OUTDATED → bump to X`, and the result looked like routine
staleness — with no signal that the release was malware.

Since 0.2.0 that case is `WITHDRAWN` and blocks; a denylisted release is `COMPROMISED`.
If you see the old wording, you're running a stale copy — `git pull` the tooling repo.
(CI clones it fresh each run, so this is usually a local or pre-commit copy.)

## `UNAGED_NEW_DEP` on CI but not locally

`depcheck` uses `git show HEAD:<manifest>` to tell a newly introduced pin from one that
was already committed. A manifest created in the same commit has no baseline entry,
which is correct: a genuinely new dependency is flagged even when it was added in an
earlier commit of the same push.

If the manifest is **untracked**, or the repo has no commits, the baseline is
unavailable and fresh pins stay `TOO_NEW` with "adoption age unverified". Options:
`--baseline=<sha>`, `actions/checkout` with `fetch-depth: 0`, or `--no-baseline` if the
repo deliberately carries no history.

## Exit-code contract changed in 0.2.0

`COMPROMISED`, `WITHDRAWN`, `YANKED` and `UNAGED_NEW_DEP` are new blocking statuses;
`TOO_NEW` is advisory unless `--strict`. A CI job green on 0.1.x can go red after the
upgrade — that is intended. To stage the rollout, pin the tooling repo by SHA; the
report header prints `depcheck vX.Y.Z`.

## `APPROVED no` on a dep that was fine yesterday

The approval gate is only active when a list is supplied (`--approved=<path>` or
`.deps-policy.json → approved`). When it is, **any direct dep missing from the list
blocks**, including one that was already there before the list existed.

To bootstrap without hand-writing the file:

```bash
node scripts/depcheck.mjs . --approved=approved.json --seed-approved
```

Then fill in `rationale`/`approvedBy` and commit. Do not run `--seed-approved` in CI:
a list that regenerates itself is a lockfile, not an approval record. Entries for
packages you no longer use show up as `stale` — prune them, don't ignore the line.

A version-pinned entry (`"version": "1.2.3"`) intentionally stops covering a bump:
that is a prompt for a fresh look, not a bug.

## `NO_HASH` after adopting hashes

`NO_HASH` means the file requires hashes (`--require-hashes`) or you passed
`--verify-integrity`, and a pin has none. Restore them from the source of truth —
`pip download --require-hashes`, `uv lock`, `poetry lock` — and re-run. Removing the
`--require-hashes` line to get CI green deletes the only control that notices a
published artifact changing under an approved version.
