# Troubleshooting: GitHub Actions Workflow Failures

This documents a real debugging session that took ~90 minutes to resolve. The symptom
was a GitHub Actions workflow that kept failing with a misleading error message.

## Symptom

The `dependency-hygiene` workflow in `blivethree/Retirement_App` showed:

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
git clone --depth 1 https://github.com/blivethree/dependency-hygiene.git $HOME/dependency-hygiene
```

But `blivethree/dependency-hygiene` was **private**. The GitHub Actions runner has no
credentials, so `git clone` failed with:

```
fatal: could not read Username for 'https://github.com': No such device or address
```

The runner tried to prompt for a username/password interactively, but there's no
terminal in CI — hence `No such device or address`.

**Fix:** Made `blivethree/dependency-hygiene` **public**. It's just scripts (no secrets),
so this is safe.

### 2. `depcheck.mjs` on the remote repo was outdated

The local `depcheck.mjs` had been updated to only **block on direct deps**
(`isBlocking` logic). But the version pushed to the remote `dependency-hygiene` repo
was an **older version** that treated ALL violations as blocking, including
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
3 transitive PRERELEASE items (`effect`, `@rolldown/pluginutils`, `gensync`) as
blocking.

**Fix:** Pushed the updated `depcheck.mjs` to `dependency-hygiene` main.

## How I Finally Found It

I stopped guessing and started **reading the actual run logs**:

```bash
curl -s -L -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/blivethree/Retirement_App/actions/runs/<ID>/jobs" \
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
gh run list --repo blivethree/Retirement_App --limit 5

# View a specific run
gh run view <run-id> --repo blivethree/Retirement_App

# Get job/step breakdown
curl -s -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/blivethree/Retirement_App/actions/runs/<ID>/jobs" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'{j[\"name\"]}: {j[\"conclusion\"]}') for j in d.get('jobs',[])]"

# Get actual logs
curl -s -L -H "Authorization: token $(gh auth token)" \
  "https://api.github.com/repos/blivethree/Retirement_App/actions/runs/<ID>/jobs" \
  | strings | grep -iE "error|fail|clone|fatal"
```