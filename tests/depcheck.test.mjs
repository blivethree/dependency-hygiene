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
  classify, compromisedHit, parsePipfileLock, parsePyproject, parseRequirements, parseTomlPackages,
} from "../scripts/depcheck.mjs";

const execFileAsync = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("../scripts/depcheck.mjs", import.meta.url));
const TMP_ROOT = process.env.TMPDIR || tmpdir();

// ── fixtures ──
const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString();
const rel = (v, days, extra = {}) => ({ v, lastUpload: daysAgo(days), ...extra });
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
      return [v, [{ upload_time: daysAgo(days), yanked: !!opts.yanked, yanked_reason: opts.yankedReason || null }]];
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
  try {
    const { stdout, stderr } = await execFileAsync("node", [SCRIPT, dir, ...args], {
      env: { ...process.env, DEPCHECK_PYPI_INDEX: registryUrl, DEPCHECK_NPM_REGISTRY: registryUrl, ...env },
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

// ── end-to-end CLI ──
const REGISTRY = {
  "acme-lib": pypiBody({ "1.1.0": [1], "1.0.0": [20], "0.5.0": [40] }),
  "other-lib": pypiBody({ "1.1.0": [1], "1.0.0": [30] }),
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
    assert.equal(out.version, "0.2.0");
    assert.equal(out.rows[0].status, "COMPROMISED");
  } finally { await stub.close(); }
});
