// Tests for ghacheck: `uses:` parsing, ref-shape policy, and freshness gating.
// Zero dependencies — stdlib node:test + a local stub GitHub API, so no network.
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SCRIPT = fileURLToPath(new URL("../scripts/ghacheck.mjs", import.meta.url));
const TMP_ROOT = process.env.TMPDIR || tmpdir();

const SHA_OLD = "11d5960a326750d5838078e36cf38b85af677262";
const SHA_V7 = "3d3c42e5aac5ba805825da76410c181273ba90b1";

const daysAgo = (d) => new Date(Date.now() - d * 86400000).toISOString();

const tmpdirs = [];
async function makeWorkflow(text) {
  const dir = await mkdtemp(join(TMP_ROOT, "ghacheck-test-"));
  tmpdirs.push(dir);
  await mkdir(join(dir, ".github", "workflows"), { recursive: true });
  await writeFile(join(dir, ".github", "workflows", "ci.yml"), text);
  return dir;
}

test.after(async () => {
  for (const d of tmpdirs) await rm(d, { recursive: true, force: true });
});

// Stub GitHub API: /repos/<owner>/<repo>/releases/latest
async function startApi(releases) {
  const server = createServer((req, res) => {
    const m = (req.url || "").match(/^\/repos\/([^/]+)\/([^/]+)\/releases\/latest/);
    const key = m ? `${m[1]}/${m[2]}` : null;
    const rel = key ? releases[key] : null;
    res.setHeader("content-type", "application/json");
    if (!rel) { res.statusCode = 404; res.end(JSON.stringify({ message: "Not Found" })); return; }
    res.end(JSON.stringify({ tag_name: rel.tag, published_at: daysAgo(rel.days) }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

async function runCLI(dir, args = [], env = {}) {
  // GITHUB_TOKEN in the ambient env would leak into the API call; drop it.
  const inherited = { ...process.env };
  delete inherited.GITHUB_TOKEN;
  delete inherited.GH_TOKEN;
  try {
    const { stdout, stderr } = await execFileAsync("node", [SCRIPT, dir, ...args], {
      env: { ...inherited, ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout || "", stderr: e.stderr || "" };
  }
}

const wf = (pins) => `jobs:\n  test:\n    steps:\n${pins.map((p) => `      - uses: ${p}`).join("\n")}\n`;

// ── shape policy (offline) ───

test("floating tag is UNSAFE_REF and blocks", async () => {
  const dir = await makeWorkflow(wf(["actions/checkout@v4"]));
  const r = await runCLI(dir, ["--fail"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /UNSAFE_REF/);
  assert.match(r.stdout, /actions\/checkout@v4/);
});

test("branch ref is UNSAFE_REF", async () => {
  const dir = await makeWorkflow(wf(["actions/setup-node@main"]));
  const r = await runCLI(dir, ["--fail"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /UNSAFE_REF/);
});

test("SHA pin without a version comment is advisory, not blocking", async () => {
  const dir = await makeWorkflow(wf([`actions/checkout@${SHA_V7}`]));
  const r = await runCLI(dir, ["--fail"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /UNCOMMENTED_PIN/);
});

test("well-formed SHA pin with comment passes offline", async () => {
  const dir = await makeWorkflow(wf([`actions/checkout@${SHA_V7} # v7.0.1`]));
  const r = await runCLI(dir, ["--fail"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /PASS/);
});

test("local and docker uses are ignored", async () => {
  const dir = await makeWorkflow(wf(["./local-action", "docker://alpine:3.20"]));
  const r = await runCLI(dir, ["--fail"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /no workflow `uses:` pins found/);
});

test("quoted refs and subdirectory actions are parsed", async () => {
  const dir = await makeWorkflow(`jobs:\n  test:\n    steps:\n      - uses: "actions/checkout@${SHA_V7}" # v7.0.1\n      - uses: github/codeql-action/init@${SHA_V7} # v3.0.0\n`);
  const r = await runCLI(dir, ["--fail", "--json"]);
  assert.equal(r.code, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.pins, 2);
});

// ── freshness policy (stub API) ───

test("major gap behind latest is OUTDATED_MAJOR and blocks", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 200 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_OLD} # v4.4.0`]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /OUTDATED_MAJOR/);
    assert.match(r.stdout, /v7\.0\.1/);
  } finally { await api.close(); }
});

test("same-major drift is advisory only", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.1.0", days: 60 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_V7} # v7.0.1`]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /OUTDATED_MINOR/);
  } finally { await api.close(); }
});

test("up-to-date pin passes", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 90 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_V7} # v7.0.1`]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /PASS/);
  } finally { await api.close(); }
});

test("latest younger than the cooldown warns TOO_NEW", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 3 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_V7} # v7.0.1`]));
    const r = await runCLI(dir, ["--fail", "--cooldown=14"], { GHACHECK_API: api.url });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /TOO_NEW/);
  } finally { await api.close(); }
});

test("unresolvable action is advisory, and does not block", async () => {
  const api = await startApi({});
  try {
    const dir = await makeWorkflow(wf([`some/unknown-action@${SHA_V7} # v1.0.0`]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /UNRESOLVED/);
  } finally { await api.close(); }
});

test("resolve without --fail stays advisory even when outdated", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 200 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_OLD} # v4.4.0`]));
    const r = await runCLI(dir, ["--resolve"], { GHACHECK_API: api.url });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /OUTDATED_MAJOR/);
  } finally { await api.close(); }
});

test("different majors across workflows warn PIN_DRIFT", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 90 } });
  try {
    const dir = await mkdtemp(join(TMP_ROOT, "ghacheck-test-"));
    tmpdirs.push(dir);
    await mkdir(join(dir, ".github", "workflows"), { recursive: true });
    await writeFile(join(dir, ".github", "workflows", "a.yml"), wf([`actions/checkout@${SHA_V7} # v7.0.1`]));
    await writeFile(join(dir, ".github", "workflows", "b.yml"), wf([`actions/checkout@${SHA_OLD} # v4.4.0`]));
    const r = await runCLI(dir, ["--fail", "--json"], { GHACHECK_API: api.url });
    const j = JSON.parse(r.stdout);
    assert.ok(j.warnings.some((w) => w.reason === "PIN_DRIFT"));
  } finally { await api.close(); }
});

test("--json reports structured status", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 200 } });
  try {
    const dir = await makeWorkflow(wf([`actions/checkout@${SHA_OLD} # v4.4.0`]));
    const r = await runCLI(dir, ["--fail", "--json"], { GHACHECK_API: api.url });
    const j = JSON.parse(r.stdout);
    assert.equal(j.status, "violations");
    assert.equal(j.workflows, 1);
    assert.equal(j.pins, 1);
    assert.equal(j.violations[0].reason, "OUTDATED_MAJOR");
    assert.equal(j.violations[0].latest, "v7.0.1");
  } finally { await api.close(); }
});

// ── floating refs report shape AND staleness together ───

test("floating ref surfaces major gap alongside UNSAFE_REF", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 200 } });
  try {
    const dir = await makeWorkflow(wf(["actions/checkout@v4"]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /UNSAFE_REF/);
    assert.match(r.stdout, /3 major version\(s\) behind v7\.0\.1/);
  } finally { await api.close(); }
});

test("floating ref already at latest major has no gap note", async () => {
  const api = await startApi({ "actions/checkout": { tag: "v7.0.1", days: 200 } });
  try {
    const dir = await makeWorkflow(wf(["actions/checkout@v7"]));
    const r = await runCLI(dir, ["--fail"], { GHACHECK_API: api.url });
    assert.equal(r.code, 1);
    assert.match(r.stdout, /UNSAFE_REF/);
    assert.doesNotMatch(r.stdout, /major version\(s\) behind/);
  } finally { await api.close(); }
});

test("floating ref to an unresolvable action stays one clean violation", async () => {
  const api = await startApi({});
  try {
    const dir = await makeWorkflow(wf(["some/unknown@v2"]));
    const r = await runCLI(dir, ["--fail", "--json"], { GHACHECK_API: api.url });
    const j = JSON.parse(r.stdout);
    const reasons = j.violations.map((v) => v.reason);
    assert.deepEqual(reasons, ["UNSAFE_REF"]);
    assert.ok(!j.warnings.some((w) => w.reason === "UNRESOLVED"));
  } finally { await api.close(); }
});
