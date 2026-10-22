# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `v0.4.x` | Yes |
| Older tags | No |

Pin a supported release tag or a full commit SHA. Do not track `main` in CI.

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's private vulnerability reporting:

<https://github.com/blivethree/dependency-hygiene/security/advisories/new>

Include:

- the affected tag or commit,
- what an attacker can do (for example, bypass a gate, execute code, or alter
  an approval record),
- a minimal reproduction,
- whether a published release or tag is affected.

Please give us a reasonable window to fix the issue before public disclosure.
We will publish a GitHub security advisory once a fix is available.

## Scope

This repository is a security control that other repositories clone and
execute in CI. Reports are in scope when they affect:

- `scripts/depcheck.mjs` or `scripts/imgcheck.mjs` (gate bypass, fail-open
  behaviour, command injection, unsafe file handling),
- shipped policy or denial-list defaults in `policy/`,
- approval-record validation or the frozen deploy gate,
- release or tag integrity for this repository.

Out of scope: vulnerabilities in a dependency you added to your own project,
and findings that require write access to this repository (report those as a
normal issue if they are not exploitable by an outside party).

## For consumers

- Pin a release tag or full commit SHA; `main` moves.
- Verify the release `SHA256SUMS` before running the scripts.
- Keep production credentials out of the job that executes this tool; run the
  frozen deploy gate in a protected environment.
- If you detect a malicious release or tag, report it privately and stop using
  that ref.

## Known limitations

Approving a dependency name answers "should this be in the tree", not "are
these the exact bytes we reviewed". Keep hash/provenance checks and Snyk
enabled. See `references/approval-workflow.md`.
