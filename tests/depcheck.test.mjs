// Tests for depcheck: classification, manifest parsers, and end-to-end CLI runs.
// Zero dependencies — stdlib node:test + a local stub registry, so no network.
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  classify, compromisedHit, parseLock, parsePipfileLock, parsePyproject, parseRequirements, parseTomlPackages,
} from "../scripts/depcheck.mjs";

const execFileAsync = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("../scripts/depcheck.mjs", import.meta.url));
const TMP_ROOT = process.env.TMPDIR || tmpdir();

// ── fixtures ──
const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString();
const rel = (v, days, extra = {}) => ({ v, lastUpload: daysAgo(days), files: [{ filename: `${v}-cp312-cp312-linux_x86_64.whl` }], ...extra });
const reg = (...rels) => ({ latest: rels[0]?.v ?? null, rels });

const tmpdirs = [];
async function makeDir(files) {
  const dir = await mkdtemp(join(TMP_ROOT, "depcheck-test-"));
  tmpdirs.push(dir);
  for (const [name, text] of Object.entries(files)) await writeFile(join(dir, name), text);
  return dir;
}
async function gitInit(dir, message = "init") {
  const opts = { cwd: dir };
  await execFileAsync("git", ["init", "-q"], opts);
  await execFileAsync("git", ["add", "-A"], opts);
  await execFileAsync("git", ["-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", message], opts);
}

function pypiBody(releases) {
  const versions = Object.keys(releases);
  return {
    info: { version: versions[0] },
    releases: Object.fromEntries(versions.map((v) => {
      const [days, opts = {}] = releases[v];
      // Provide a filename that passes the installable() check in the stub
      // registry. The real PyPI returns filenames like
      // "package-1.0.0-cp312-cp312-linux_x86_64.whl".
      const filename = `${v}-cp312-cp312-linux_x86_64.whl`;
      return [v, [{ upload_time: daysAgo(days), yanked: !!opts.yanked, yanked_reason: opts.yankedReason || null, filename }]];
    })),
  };
}

// Stub PyPI/npm: /<name>/json (PyPI) and /<name> (npm) both resolve to the same body.
async function startRegistry(bodies) {
  const server = createServer((req, res) => {
    const name = decodeURIComponent((req.url || "").split("/")[1] || "");
    const body = bodies[name];
    res.setHeader("content-type", "application/json");
    if (!body) { res.statusCode = 404; res.end("{}"); return; }
    res.end(JSON.stringify(body));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

async function runCLI(dir, registryUrl, args = [], env = {}) {
  // GitHub Actions exports GITHUB_BASE_REF on pull_request. These tests build
  // throwaway git repos, so an inherited base ref would point at a baseline
  // that does not exist. Only use it when a test passes it explicitly.
  const inherited = { ...process.env };
  delete inherited.GITHUB_BASE_REF;
  try {
    const { stdout, stderr } = await execFileAsync("node", [SCRIPT, dir, ...args], {
      env: { ...inherited, DEPCHECK_PYPI_INDEX: registryUrl, DEPCHECK_NPM_REGISTRY: registryUrl, ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout || "", stderr: e.stderr || "" };
  }
}

test.after(async () => { await Promise.all(tmpdirs.map((d) => rm(d, { recursive: true, force: true }))); });

// ── denylist ──
test("denylist: litellm 1.82.7 / 1.82.8 / 1.107.0 are known-bad", () => {
  for (const v of ["1.82.7", "1.82.8", "1.107.0"]) {
    assert.ok(compromisedHit({ ecosystem: "pypi", name: "litellm", current: v }), `${v} should hit`);
  }
  assert.equal(compromisedHit({ ecosystem: "pypi", name: "litellm", current: "1.82.6" }), null);
  assert.equal(compromisedHit({ ecosystem: "pypi", name: "litellm", current: "1.106.2" }), null);
});

test("denylist: name normalisation (PEP 503-ish) and ecosystem scoping", () => {
  assert.ok(compromisedHit({ ecosystem: "pypi", name: "LiteLLM", current: "1.107.0" }));
  // PEP 503 maps `lite_llm` -> `lite-llm`, a different project: match must not be fuzzy.
  assert.equal(compromisedHit({ ecosystem: "pypi", name: "lite_llm", current: "1.107.0" }), null);
  assert.equal(compromisedHit({ ecosystem: "npm", name: "litellm", current: "1.107.0" }), null);
});

test("denylist: unpinned requirements carrying a known-bad name are flagged", () => {
  assert.ok(compromisedHit({ ecosystem: "pypi", name: "litellm", current: null }));
});

// ── classification ──
test("COMPROMISED wins over a failed registry lookup", () => {
  assert.equal(classify({ ecosystem: "pypi", name: "litellm", current: "1.107.0" }, null).status, "COMPROMISED");
});

test("WITHDRAWN: pinned version no longer published", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "0.9.0" }, reg(rel("1.0.0", 30)));
  assert.equal(r.status, "WITHDRAWN");
});

test("YANKED: published but yanked release", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "0.9.0" }, reg(rel("1.0.0", 30), rel("0.9.0", 20, { yanked: true, yankedReason: "malware" })));
  assert.equal(r.status, "YANKED");
  assert.match(r.note, /malware/);
});

test("TOO_NEW: already-pinned fresh latest carries revisitAfter", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "1.1.0" }, reg(rel("1.1.0", 2), rel("1.0.0", 30)));
  assert.equal(r.status, "TOO_NEW");
  assert.match(r.revisitAfter, /^\d{4}-\d{2}-\d{2}$/);
});

test("UNAGED_NEW_DEP: package has no cooldown-safe release at all", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "1.0.0" }, reg(rel("1.1.0", 1), rel("1.0.0", 3)));
  assert.equal(r.status, "UNAGED_NEW_DEP");
});

test("OK: aged pin at latest", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "1.0.0" }, reg(rel("1.0.0", 30)));
  assert.equal(r.status, "OK");
});

test("safeTarget never proposes a compromised release", () => {
  const r = classify(
    { ecosystem: "pypi", name: "litellm", current: "1.82.5" },
    reg(rel("1.82.8", 3), rel("1.82.7", 5), rel("1.82.6", 20), rel("1.82.5", 40)),
  );
  assert.equal(r.status, "OUTDATED");
  assert.equal(r.safeTarget, "1.82.6", "must skip the compromised 1.82.7/1.82.8");
});

test("OUTDATED never advises a downgrade for a fresh-ahead pin", () => {
  const r = classify({ ecosystem: "pypi", name: "acme", current: "1.5.0" }, reg(rel("1.6.0", 2), rel("1.5.0", 3), rel("1.4.0", 30)));
  assert.equal(r.status, "TOO_NEW", "must not suggest bumping down to 1.4.0");
  assert.notEqual(r.safeTarget, "1.4.0");
});

test("UNRESOLVING: registry lookup failed", () => {
  assert.equal(classify({ ecosystem: "pypi", name: "acme", current: "1.0.0" }, null).status, "UNRESOLVING");
});

// ── parsers ──
test("parseRequirements keeps op/version, skips flags and editable installs", () => {
  const deps = parseRequirements([
    "# comment",
    "--index-url https://example.test/simple",
    "-e ./local",
    "fastapi==0.141.1",
    "litellm==1.107.0  # pinned",
    "requests>=2.31",
  ].join("\n"));
  assert.deepEqual(deps.map((d) => [d.name, d.op, d.current]), [
    ["fastapi", "==", "0.141.1"],
    ["litellm", "==", "1.107.0"],
    ["requests", ">=", "2.31"],
  ]);
});

test("parsePipfileLock reads default and develop sections", () => {
  const deps = parsePipfileLock(JSON.stringify({
    default: { litellm: { version: "==1.106.2" } },
    develop: { pytest: { version: "==8.3.0" } },
  }));
  assert.deepEqual(deps.map((d) => [d.name, d.current, d.dev]), [
    ["litellm", "1.106.2", false],
    ["pytest", "8.3.0", true],
  ]);
});

test("parseTomlPackages handles poetry/uv [[package]] stanzas", () => {
  const text = [
    "[[package]]",
    'name = "litellm"',
    'version = "1.106.2"',
    "description = \"\"",
    "",
    "[package.dependencies]",
    'openai = ">=1.0"',
    "",
    "[[package]]",
    'name = "openai"',
    'version = "2.0.0"',
  ].join("\n");
  assert.deepEqual(parseTomlPackages(text).map((d) => [d.name, d.current]), [
    ["litellm", "1.106.2"],
    ["openai", "2.0.0"],
  ]);
});

test("parsePyproject takes exact pins and reports ranged specs as skipped", () => {
  const text = [
    "[project]",
    'dependencies = [',
    '  "litellm==1.106.2",',
    '  "requests>=2.31",',
    "]",
    "",
    "[tool.poetry.dependencies]",
    'python = "^3.12"',
    'httpx = { version = "==0.28.1" }',
  ].join("\n");
  const { deps, skipped } = parsePyproject(text);
  assert.deepEqual(deps.map((d) => [d.name, d.current]), [["litellm", "1.106.2"], ["httpx", "0.28.1"]]);
  assert.ok(skipped.some((s) => s.startsWith("requests")));
  assert.equal(deps.find((d) => d.name === "python"), undefined, "interpreter constraint is not a dependency");
});

test("parseRequirements attaches --hash lines to the preceding pin", () => {
  const deps = parseRequirements([
    "--require-hashes",
    "acme-lib==1.0.0 \\",
    "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "other==2.0.0",
  ].join("\n"));
  assert.equal(deps[0].hashes.length, 2);
  assert.equal(deps[1].hashes.length, 0);
  assert.equal(deps[1].current, "2.0.0");
});

test("parseTomlPackages collects hashes from poetry/uv `files` entries", () => {
  const text = [
    "[[package]]",
    'name = "acme-lib"',
    'version = "1.0.0"',
    "files = [",
    '    {file = "acme_lib-1.0.0.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},',
    "]",
    "",
    "[package.dependencies]",
    'other = ">=1.0"',
  ].join("\n");
  const deps = parseTomlPackages(text);
  assert.equal(deps.length, 1);
  assert.deepEqual(deps[0].hashes, ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
});

test("parseLock keeps npm integrity hashes", () => {
  const deps = parseLock(JSON.stringify({ packages: { "": {}, "node_modules/acme": { version: "1.0.0", integrity: "sha512-abc" } } }));
  assert.deepEqual(deps[0].hashes, ["sha512-abc"]);
});

// ── end-to-end CLI ──
const REGISTRY = {
  "acme-lib": pypiBody({ "1.1.0": [1], "1.0.0": [20], "0.5.0": [40] }),
  "other-lib": pypiBody({ "1.1.0": [1], "1.0.0": [30] }),
  "aged-lib": pypiBody({ "2.0.0": [60], "1.0.0": [90] }),
  litellm: pypiBody({ "1.107.0": [1], "1.106.2": [20], "1.82.8": [210], "1.82.7": [211], "1.82.6": [214] }),
};

test("e2e: COMPROMISED blocks even though the release is also < 14d old", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "litellm==1.107.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 1);
    assert.match(stdout, /COMPROMISED/);
    assert.match(stdout, /SECURITY:/);
  } finally { await stub.close(); }
});

test("e2e: WITHDRAWN blocks a deleted pin", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==0.9.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 1);
    assert.match(stdout, /WITHDRAWN/);
  } finally { await stub.close(); }
});

test("e2e: UNAGED_NEW_DEP blocks a bump onto a fresh release (git baseline)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    await writeFile(join(dir, "requirements.txt"), "acme-lib==1.1.0\n");
    const { code, stdout } = await runCLI(dir, stub.url);
    assert.equal(code, 1);
    assert.match(stdout, /UNAGED_NEW_DEP/);
  } finally { await stub.close(); }
});

test("e2e: UNAGED_NEW_DEP blocks a brand-new dependency at a fresh version", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    await writeFile(join(dir, "requirements.txt"), "acme-lib==1.0.0\nother-lib==1.1.0\n");
    const { code, stdout } = await runCLI(dir, stub.url);
    assert.equal(code, 1);
    assert.match(stdout, /UNAGED_NEW_DEP/);
  } finally { await stub.close(); }
});

test("e2e: an already-committed fresh pin is advisory TOO_NEW (exit 0)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.1.0\n" });
    await gitInit(dir);
    const { code, stdout } = await runCLI(dir, stub.url);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /TOO_NEW/);
  } finally { await stub.close(); }
});

test("e2e: --strict makes an advisory fresh pin fail", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.1.0\n" });
    await gitInit(dir);
    const { code } = await runCLI(dir, stub.url, ["--strict"]);
    assert.equal(code, 1);
  } finally { await stub.close(); }
});

test("e2e: cooldownOverride downgrades a new adoption to advisory", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({
      "requirements.txt": "acme-lib==1.1.0\n",
      ".deps-policy.json": JSON.stringify({ cooldownDays: 14, cooldownOverride: { "acme-lib": { version: "1.1.0", reason: "CVE-test", reviewBy: "2027-01-01" } } }),
    });
    await gitInit(dir);
    const { code, stdout } = await runCLI(dir, stub.url);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /cooldownOverride/);
  } finally { await stub.close(); }
});

test("e2e: --fix bumps to the cooldown-safe target, never the fresh one", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==0.5.0\n" });
    const { code } = await runCLI(dir, stub.url, ["--no-baseline", "--fix"]);
    assert.equal(code, 0);
    assert.equal((await readFile(join(dir, "requirements.txt"), "utf8")).trim(), "acme-lib==1.0.0");
  } finally { await stub.close(); }
});

test("e2e: --fix refuses a file holding a COMPROMISED pin", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "litellm==1.107.0\nacme-lib==0.5.0\n" });
    const { code, stdout, stderr } = await runCLI(dir, stub.url, ["--no-baseline", "--fix"]);
    assert.equal(code, 1);
    assert.equal((await readFile(join(dir, "requirements.txt"), "utf8")).trim(), "litellm==1.107.0\nacme-lib==0.5.0");
    assert.match(stderr, /refusing/);
    assert.doesNotMatch(stdout, /refusing/, "diagnostics stay on stderr so --json stays parseable");
  } finally { await stub.close(); }
});

test("e2e: --policy value is not mistaken for a scan directory", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const policy = join(dir, "policy.json");
    await writeFile(policy, JSON.stringify({ cooldownDays: 14 }));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--policy=${policy}`]);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /scanned 1 file/);
  } finally { await stub.close(); }
});

test("e2e: --json reports denylist size and machine-readable rows", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "litellm==1.107.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", "--json"]);
    assert.equal(code, 1);
    const out = JSON.parse(stdout);
    assert.ok(out.compromisedEntries >= 1);
    assert.equal(out.version, "0.4.0");
    assert.equal(out.rows[0].status, "COMPROMISED");
  } finally { await stub.close(); }
});

// ── approval gate (direct deps only) ──
const approvedList = (entries) => JSON.stringify({ entries });
// A complete, auditable approval record. Tests that mean to exercise approval
// (not request/pending behaviour) should use this.
const approvedEntry = (name, extra = {}) => ({
  ecosystem: "pypi",
  name,
  rationale: "reviewed: fits the policy and is actively maintained",
  approvedBy: "security",
  date: "2026-10-01",
  reviewBy: "2027-01-01",
  ...extra,
});

test("e2e: approval gate is off unless a list is supplied", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /approvals off/);
    assert.doesNotMatch(stdout, /UNAPPROVED/);
  } finally { await stub.close(); }
});

test("e2e: an empty approved list denies every direct dep", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /UNAPPROVED/);
  } finally { await stub.close(); }
});

test("e2e: a name-level approval admits any version of that name", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("acme-lib")]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /yes/);
  } finally { await stub.close(); }
});

test("e2e: a version-pinned approval does not cover a different version", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("acme-lib", { version: "0.5.0" })]));
    const { code } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 1);
  } finally { await stub.close(); }
});

test("e2e: .deps-policy.json can carry the approved list", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({
      "requirements.txt": "acme-lib==1.0.0\n",
      ".deps-policy.json": JSON.stringify({ cooldownDays: 14, approved: [approvedEntry("acme-lib")] }),
    });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /approvals 1/);
  } finally { await stub.close(); }
});

test("e2e: --seed-approved bootstraps the list and then passes", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    const seeded = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`, "--seed-approved"]);
    assert.equal(seeded.code, 0, seeded.stderr);
    const written = JSON.parse(await readFile(file, "utf8"));
    assert.deepEqual(written.entries.map((e) => e.name), ["acme-lib"]);
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 0, stdout);
  } finally { await stub.close(); }
});

test("e2e: stale and overdue approvals are reported, not fatal", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([
      approvedEntry("acme-lib"),
      approvedEntry("ghost-lib", { reviewBy: "2020-01-01" }),
    ]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /stale/);
    assert.match(stdout, /ghost-lib/);
    assert.match(stdout, /review overdue/);
  } finally { await stub.close(); }
});

// ── approval workflow: scope, pending records, request artifact ──
test("e2e: scope=new grandfathers the existing tree but gates a newly added dep", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));

    // Already declared at HEAD: not a new decision, so the empty list is fine.
    let r = await runCLI(dir, stub.url, [`--approved=${file}`]);
    assert.equal(r.code, 0, r.stdout);
    assert.match(r.stdout, /scope=new/);

    // A new name in the diff needs sign-off, even though the tree still builds.
    await writeFile(join(dir, "requirements.txt"), "acme-lib==1.0.0\nother-lib==1.0.0\n");
    r = await runCLI(dir, stub.url, [`--approved=${file}`]);
    assert.equal(r.code, 1, r.stdout);
    assert.match(r.stdout, /unapproved other-lib: not on the approved list/);
    assert.doesNotMatch(r.stdout, /unapproved acme-lib/);
  } finally { await stub.close(); }
});

test("e2e: GITHUB_BASE_REF makes a committed PR change visible to scope=new", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    await execFileAsync("git", ["update-ref", "refs/remotes/origin/main", "HEAD"], { cwd: dir });
    // Simulate the checked-out PR merge commit: the change is already in HEAD.
    await writeFile(join(dir, "requirements.txt"), "acme-lib==1.0.0\nother-lib==1.0.0\n");
    await execFileAsync("git", ["add", "-A"], { cwd: dir });
    await execFileAsync("git", ["-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "pr"], { cwd: dir });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));

    // A HEAD baseline would see other-lib as already committed.
    let r = await runCLI(dir, stub.url, [`--approved=${file}`]);
    assert.equal(r.code, 0, r.stdout);

    // The PR base is the earlier commit: the same tree now has a new name.
    r = await runCLI(dir, stub.url, [`--approved=${file}`], { GITHUB_BASE_REF: "main" });
    assert.equal(r.code, 1, r.stdout);
    assert.match(r.stdout, /unapproved other-lib/);
  } finally { await stub.close(); }
});

test("e2e: scope=all gates the legacy tree too (audit / deploy view)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`, "--approval-scope=all"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /unapproved acme-lib/);
  } finally { await stub.close(); }
});

test("e2e: bumping an approved name does not re-open approval (scope=new)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "aged-lib==1.0.0\n" });
    await gitInit(dir);
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("aged-lib")]));
    await writeFile(join(dir, "requirements.txt"), "aged-lib==2.0.0\n");
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`]);
    assert.equal(code, 0, stdout);
  } finally { await stub.close(); }
});

test("e2e: a version-pinned approval re-gates a bump even when the name is legacy", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "aged-lib==1.0.0\n" });
    await gitInit(dir);
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("aged-lib", { version: "1.0.0" })]));
    await writeFile(join(dir, "requirements.txt"), "aged-lib==2.0.0\n");
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /needs a fresh decision/);
  } finally { await stub.close(); }
});

test("e2e: a blank approver is a pending request, not an approval", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    // Developer pasted the entry but security has not signed it yet.
    await writeFile(file, approvedList([{ ecosystem: "pypi", name: "acme-lib", rationale: "developer note" }]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /incomplete record/);
    assert.match(stdout, /approvedBy \+ date/);
  } finally { await stub.close(); }
});

test("e2e: --json carries a paste-ready approvalRequest with review evidence", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "other-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`, "--json"]);
    assert.equal(code, 1);
    const out = JSON.parse(stdout);
    assert.equal(out.approvalGate.scope, "new");
    assert.deepEqual(out.approvalGate.unapproved, ["other-lib"]);
    const req = out.approvalRequest[0];
    assert.equal(req.name, "other-lib");
    assert.equal(req.approvedBy, "");
    assert.equal(req.date, "");
    assert.equal(req.checks.requestedVersion, "1.0.0");
    assert.equal(req.checks.status, "OK");
    assert.ok(req.checks.versionAgeDays >= 29 && req.checks.versionAgeDays <= 31, req.checks.versionAgeDays);
    assert.equal(req.checks.releases, 2);
    assert.ok(req.checks.firstPublished);
    assert.equal(req.checks.knownBad, false);
  } finally { await stub.close(); }
});

test("e2e: --print-approval-request emits the snippet and keeps the gate red", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "other-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", `--approved=${file}`, "--print-approval-request"]);
    assert.equal(code, 1);
    const snippet = JSON.parse(stdout);
    assert.match(snippet.$comment, /PENDING/);
    assert.equal(snippet.entries.length, 1);
    assert.equal(snippet.entries[0].name, "other-lib");
    assert.equal(snippet.entries[0].approvedBy, "");
  } finally { await stub.close(); }
});

test("e2e: unknown --approval-scope is a usage error", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const { code, stderr } = await runCLI(dir, stub.url, ["--approval-scope=sometimes"]);
    assert.equal(code, 2);
    assert.match(stderr, /must be "new" or "all"/);
  } finally { await stub.close(); }
});

// ── frozen deploy gate ──
test("e2e: --frozen without an approved list refuses to run (exit 2)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const { code, stderr } = await runCLI(dir, stub.url, ["--no-baseline", "--frozen"]);
    assert.equal(code, 2);
    assert.match(stderr, /needs an approved list/);
  } finally { await stub.close(); }
});

test("e2e: --frozen gates the whole tree, not just the diff", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    await gitInit(dir);
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`, "--frozen"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /frozen: deploy gate/);
    assert.match(stdout, /unapproved acme-lib/);
  } finally { await stub.close(); }
});

test("e2e: --frozen passes when every direct dep has a complete approval", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("acme-lib")]));
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`, "--frozen"]);
    assert.equal(code, 0, stdout);
  } finally { await stub.close(); }
});

test("e2e: --frozen rejects a weak record (no rationale/reviewBy)", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([approvedEntry("acme-lib", { rationale: "", reviewBy: "" })]));
    const { code, stdout } = await runCLI(dir, stub.url, [`--approved=${file}`, "--frozen"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /under --strict/);
  } finally { await stub.close(); }
});

test("e2e: --frozen refuses to pass when there is nothing to verify", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "README.md": "not a manifest\n" });
    const file = join(dir, "approved.json");
    await writeFile(file, approvedList([]));
    const { code, stderr } = await runCLI(dir, stub.url, [`--approved=${file}`, "--frozen"]);
    assert.equal(code, 2);
    assert.match(stderr, /nothing/);
    // --json must not turn the same empty scan into a passing report.
    const j = await runCLI(dir, stub.url, [`--approved=${file}`, "--frozen", "--json"]);
    assert.equal(j.code, 2);
  } finally { await stub.close(); }
});

// ── integrity ──
test("e2e: --require-hashes without hashes blocks as NO_HASH", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({ "requirements.txt": "--require-hashes\nacme-lib==1.0.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /NO_HASH/);
  } finally { await stub.close(); }
});

test("e2e: --require-hashes with hashes passes", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({
      "requirements.txt": "--require-hashes\nacme-lib==1.0.0 \\\n    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 0, stdout);
  } finally { await stub.close(); }
});

test("e2e: --verify-integrity flags a lockfile entry with no hash", async () => {
  const stub = await startRegistry(REGISTRY);
  try {
    const dir = await makeDir({
      "requirements.txt": "acme-lib==1.0.0\n",
      "uv.lock": "[[package]]\nname = \"acme-lib\"\nversion = \"1.0.0\"\n",
    });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline", "--verify-integrity"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /NO_HASH/);
  } finally { await stub.close(); }
});

// ── MISSING_RELEASE: pin that has no installable files on PyPI ──
test("e2e: a pin to a version that is not on PyPI is blocked as WITHDRAWN", async () => {
  const stub = await startRegistry({
    "acme-lib": pypiBody({ "1.0.0": [30] }),   // only 1.0.0 exists
  });
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==9.9.9\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /WITHDRAWN/);
    assert.match(stdout, /9\.9\.9/);
  } finally { await stub.close(); }
});

test("e2e: a pin to a version with no installable files is blocked as WITHDRAWN", async () => {
  // Stub registry returns a release but with no files array (simulates a
  // package that exists but has no wheels/sdists). depcheck treats this as
  // a missing/withdrawn release.
  const stub = await startRegistry({
    "acme-lib": {
      info: { version: "1.0.0" },
      releases: {
        "1.0.0": [],   // no files → not installable
      },
    },
  });
  try {
    const dir = await makeDir({ "requirements.txt": "acme-lib==1.0.0\n" });
    const { code, stdout } = await runCLI(dir, stub.url, ["--no-baseline"]);
    assert.equal(code, 1, stdout);
    assert.match(stdout, /WITHDRAWN/);
  } finally { await stub.close(); }
});
