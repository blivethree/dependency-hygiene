# Approval workflow for new dependencies

This is the process side of rule 8 in `references/policy.md`: how a developer adds
a library, how security reviews it, and how the decision becomes an audit record
that a deploy gate can enforce.

**Control objective:** only reviewed libraries reach production, and every
library in the tree has a signed, dated, reasoned approval. This is *policy*
enforcement and an audit trail. Snyk still owns known-CVE detection; `depcheck`
owns "is this allowed, was it reviewed, and are these the bytes we approved".

---

## Roles

| Who | Does |
|---|---|
| **Developer** | Works freely. When a new direct dep is needed, opens the PR and drafts the approval entry (blank sign-off). |
| **Security reviewer** | Checks the evidence, fills `approvedBy`/`date`/`rationale`/`reviewBy`, approves the PR. Owns `approved.json` via `CODEOWNERS`. |
| **CI** | Runs `depcheck --approved=…` on every PR. Fails only for *new* direct dep names (default `--approval-scope=new`), so everyday work is not blocked. |
| **Deploy pipeline** | Runs `depcheck --frozen --verify-integrity` on the exact tag/commit being shipped. Fails closed: no list, no deploy. |
| **Auditor** | Reads `git log -- approved.json`, the PR approvals, the deploy-job logs, and the SBOM. |

---

## The lifecycle

```
developer adds lib ──► CI: UNAPPROVED (scope=new)
        │                      │
        │            --print-approval-request
        │                      ▼
        │        developer pastes entry with
        │        approvedBy:"", date:""  ──► still red (PENDING)
        │                      │
        │            security review + fills record
        │                      ▼
        └──────────► PR approved ──► merge
                                   │  (dep + justification + approver = 1 commit)
                                   ▼
                         deploy: depcheck --frozen
                                   │
                                   ▼
                     artifact by digest + SBOM stored
```

### 1. Develop

Nothing changes locally: the gate is opt-in and, in `scope=new`, only looks at
direct dependency **names** that are new relative to the base branch. Bumping an
already-approved package does not re-open the approval (make it version-pinned
if you want it to).

### 2. CI fails the PR, with a reason

```
Approvals: 1 unapproved direct dep(s) (1 no matching entry, 0 incomplete record)
  unapproved pdf-parse: not on the approved list
UNAPPROVED: add each unapproved direct dep to the list with a rationale, or remove it.
Request the entries with review evidence: --print-approval-request
```

Only **direct** deps are name-gated. Transitive deps are covered by the SBOM and
the hash/age/denylist layers, not by a hand-maintained name list.

### 3. Developer drafts the request

```bash
node scripts/depcheck.mjs . --approved=approved.json --print-approval-request
```

That prints a paste-ready JSON block (also available as
`approvalRequest` in `--json`). Commit it into `approved.json` in the same PR:

```json
{
  "ecosystem": "npm",
  "name": "pdf-parse",
  "rationale": "",
  "approvedBy": "",
  "date": "",
  "reviewBy": "",
  "checks": {
    "requestedVersion": "1.1.1",
    "status": "OK",
    "versionAgeDays": 312.4,
    "firstPublished": "2021-03-02T10:14:00.000Z",
    "releases": 14,
    "license": "MIT",
    "knownBad": false
  }
}
```

**Blank `approvedBy`/`date` is a request, not an approval.** The gate stays red.
That is deliberate: the audit record cannot be half-filled, and a developer
cannot self-approve by pasting a name.

### 4. Security reviews the evidence

Checklist — record what you checked in `rationale`/`checks`, not just "LGTM":

- [ ] **Allowed by policy?** Is this the kind of dependency we accept, or does an
      existing one cover it?
- [ ] **Not known-bad.** `depcheck` status is not `COMPROMISED` / `WITHDRAWN` /
      `YANKED`; for anything on the denylist, stop and treat it as an incident
      (`references/runbook.md` §A2).
- [ ] **Age.** `versionAgeDays` ≥ cooldown (default 14). `firstPublished` and
      `releases` catch a brand-new name that is a typosquat or a takeover.
- [ ] **Licence.** Compatible with how we ship. `checks.license` is a hint; read
      the actual licence for anything unusual.
- [ ] **Bytes are pinnable.** A lockfile hash/integrity exists, or the project
      uses `--require-hashes`. If neither, say so in `rationale` — that is a
      residual risk, not a formality.
- [ ] **Maintainer / advisories.** Check the registry page, the repo, and
      Snyk/GitHub advisories. The tool cannot judge intent.
- [ ] **Scope the approval.** Name-level is the default and the least
      maintenance. Add `"version"`/`"versions"` when you want the next bump to
      come back for a fresh decision (new or single-maintainer packages).

Then fill the record and commit — on the PR branch, or as a separate
security-authored commit if your process requires separation of duties.

### 5. Merge

`approved.json` is listed in `CODEOWNERS` (see `examples/CODEOWNERS`), so the PR
cannot merge without a security reviewer. The merge commit contains:

- the dependency change,
- the justification and review evidence,
- the approver's name and the date.

That commit *is* the audit record. No separate spreadsheet to drift.

### 6. Deploy gate

```bash
node scripts/depcheck.mjs . --approved=approved.json --frozen --verify-integrity
```

`--frozen` means:

- the approved list **must** be present (exit `2` if not — a deploy that cannot
  find its policy does not ship),
- scope is forced to `all`: every direct dep must have a complete record,
- `--strict` is implied: a record missing `rationale` or `reviewBy` blocks,
- an empty scan (wrong directory / no manifest) exits `2` rather than passing.

Then deploy **the artifact you verified**, by digest. Verify the image's SBOM
against the same approved set; do not rebuild per environment and assume the
result is the same bytes. `--frozen` gates the lockfile at build time; the
digest/SBOM check is what ties the running artifact to that build.

### 7. Audit and expiry

```bash
# Who approved what, when (the audit trail)
git log --follow -p -- approved.json

# Current state, machine-readable
node scripts/depcheck.mjs . --approved=approved.json --approval-scope=all --json \
  | jq '.approvalGate, .rows[] | select(.direct=="direct") | {name,current,approved,approvalIssue}'
```

Each direct row also carries `approvalBasis`, which explains *why* it was gated:
`new` (name added in this change), `legacy` (pre-existing and out of scope under
`scope=new`), `pinned` (a version-pinned approval no longer matches), `all`
(`scope=all`), or `no-baseline` (could not compare, so it was treated as new).

- `reviewBy` ≈ 90 days. Overdue reviews are **advisory** (they do not break a
  deploy) so a lapsed review cannot take production down; they show up in the
  report and should become a ticket.
- Approved-but-unused entries are reported as `stale`. Prune them; a list that
  only grows stops being a decision.
- `grandfathered: true` entries came from `--seed-approved` and were never
  actually reviewed. Query for them and schedule real reviews.

---

## Scope: `new` vs `all`

| Scope | Use | Behaviour |
|---|---|---|
| `new` (default) | PR gate | A direct dep needs approval only if its **name** is absent from the direct manifests at the baseline revision. Legacy deps are grandfathered, so turning the gate on does not turn the whole repo red. |
| `all` | Periodic audit, `--frozen` deploy | Every direct dep needs a complete record. Use it to find legacy gaps on purpose, not on every PR. |

If there is no usable git baseline (no commits, untracked manifest, or
`--no-baseline`), `scope=new` fails closed: every direct dep is treated as new
and the report says so. Fetch enough history in CI (`fetch-depth: 0`) or pass
`--baseline=<rev>`.

**PR checkouts:** `actions/checkout` on `pull_request` gives you the merge commit,
so `HEAD` already contains the change. `depcheck` therefore defaults to
`origin/$GITHUB_BASE_REF` when that variable is set; if you use another CI, pass
the target-branch sha explicitly (`--baseline=origin/main` or the PR base sha).
Getting this wrong makes `scope=new` pass while gating nothing.

Version-pinned entries (`"version": "1.2.3"`) stop matching on a bump. That is
intentional: the bump is a new decision — even after the name is already in the
baseline (otherwise pinning would silently stop working after the first merge).
Name-level entries do not re-open on a bump; the age/denylist/hash layers cover a
compromised new release.

---

## Where the list lives

**Recommended: `approved.json` in each repo, owned by security via
`CODEOWNERS`.** The approval travels with the code it describes, and the audit
trail is the repo history.

Alternatives:

- **Separate security-authored PR** (stricter separation of duties): security
  merges the entry first; the developer's PR then passes. More friction, clearer
  "security approved before development finished".
- **Central policy repo**: workable, but the record drifts from the code and
  every audit needs a cross-repo join. If you do this, still record `ticket` and
  keep the central repo CODEOWNERS-protected.

`ticket` is optional but useful when the approval came from a request/change
ticket (Jira, ServiceNow, an incident). It is not a substitute for the git
record.

---

## Enforcement is configuration, not just the script

`depcheck` can **fail a build**. It cannot stop a merge or a deploy by itself.
The actual control is:

1. **Branch protection** on the default branch: required status check for the
   `depcheck` job, no direct pushes, no bypass for admins, dismiss stale
   approvals on new commits.
2. **`CODEOWNERS`** on `approved.json` (and `.deps-policy.json` and
   `policy/compromised.json` if they live in-repo), so touching the record needs
   a security reviewer.
3. **A required deploy job** that runs `--frozen`; production credentials are
   only available to that job.

Without 1–3 the gate is advisory. Document that in the repo's `SECURITY.md`.

---

## Operating rules

- **Never run `--seed-approved` in CI.** A list that regenerates itself is a
  lockfile, not an approval record. It is a one-off local bootstrap; review and
  replace every grandfathered entry.
- **Developers may draft, only security signs.** Blank `approvedBy`/`date`
  keeps the gate red; that is the pending state, not a bug.
- **Revoke by removing the entry** (or letting a version-pinned entry stop
  matching). The next PR and deploy fail; that is the intended revocation path.
- **Do not gate transitive names.** Use the SBOM/Dependency-Track for reach;
  a 500-entry allowlist gets seeded and rubber-stamped.
- **Keep the gate on push to the default branch too**, not just pull requests —
  otherwise a direct push bypasses it.
- **The list answers "allowed", not "safe".** `litellm` was on every approved
  list when it was taken over. Hashes/provenance and the denylist answer the
  other half.

---

## Copy-paste CI wiring

`examples/deps.yml` is a complete workflow template: PR gate, approval-request
step summary, and a frozen deploy gate. `examples/CODEOWNERS` is the ownership
record. Copy both into the app repo and adjust the team slug.

Minimal PR gate:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }          # scope=new needs the baseline
- run: node "$HOME/dependency-hygiene/scripts/depcheck.mjs" . --approved=approved.json
```

Minimal deploy gate (same commit/tag that was built):

```yaml
- run: node "$HOME/dependency-hygiene/scripts/depcheck.mjs" . \
        --approved=approved.json --frozen --verify-integrity
```
