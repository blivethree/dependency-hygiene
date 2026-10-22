#!/usr/bin/env node
// depcheck.mjs — dependency freshness, 14-day age gate, known-compromised denylist.
// Python requirements.txt / pyproject.toml / Pipfile.lock / poetry.lock / uv.lock
// + Node package-lock.json / package.json. Stdlib Node 20+ only (no installs).
//
//   node scripts/depcheck.mjs [paths...] [--cooldown=14] [--json] [--strict] [--fix]
//        [--policy=path] [--compromised=path] [--baseline=rev] [--no-baseline]
//        [--approved=path] [--seed-approved] [--verify-integrity]
//        [--approval-scope=new|all] [--print-approval-request] [--frozen]
//
//   - COMPROMISED / WITHDRAWN / YANKED always block: any ecosystem, any scope.
//   - UNAGED_NEW_DEP blocks a *newly introduced* pin younger than the cooldown
//     (a new dependency, or a bump landing on a fresh release). Existing pins
//     that are merely young are TOO_NEW (advisory).
//   - TOO_NEW is advisory unless --strict; it carries a revisitAfter date.
//   - Transitive deps are advisory by default -> --strict escalates scope+status.
//   - NO_HASH blocks when hashes are required (--require-hashes / --verify-integrity):
//     an unverified pin can be swapped by a compromised registry account.
//   - With --approved (or .deps-policy.json → approved) a direct dep that is not
//     on the list is unapproved -> blocking. Transitive deps are not name-gated:
//     a 500-entry allowlist rots into rubber-stamping.
//   - --approval-scope=new (default) gates only direct dep *names* that are new
//     relative to the git baseline, so a PR adding a library needs sign-off while
//     the pre-existing tree keeps building. --approval-scope=all is the audit /
//     deploy view. An entry with no approvedBy/date is a *request*, not an
//     approval: it stays blocking until a reviewer fills the record.
//   - --frozen is the deploy gate: requires an approved list, forces scope=all +
//     --strict, and exits 2 rather than pass on nothing.
//   - One registry fetch per package name (cached), so big lockfiles stay cheap.
//   exit 0 = clean, 1 = violations, 2 = could not run.
import { execFile } from "node:child_process";
import { realpathSync } from "node:fs";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { argv, cwd, env, exit, stderr, stdout } from "node:process";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const TOOL_ROOT = resolve(SCRIPT_DIR, "..");

// ── args ──
// Flags that take a value; the value must not be mistaken for a scan directory.
const VALUE_FLAGS = new Set(["policy", "cooldown", "compromised", "baseline", "approved", "approval-scope"]);
const rawArgs = argv.slice(2);
const flagValue = (name) => {
  const eq = rawArgs.find((a) => a.startsWith(`--${name}=`));
  if (eq) return eq.slice(name.length + 3);
  const i = rawArgs.indexOf(`--${name}`);
  return i >= 0 ? rawArgs[i + 1] ?? null : null;
};
const hasFlag = (name) => rawArgs.includes(`--${name}`);

const SCAN_DIRS = rawArgs.filter((a, i) => {
  if (a.startsWith("--")) return false;
  const prev = rawArgs[i - 1];
  if (prev?.startsWith("--") && VALUE_FLAGS.has(prev.slice(2))) return false;
  return true;
});
if (!SCAN_DIRS.length) SCAN_DIRS.push(cwd());

const JSON_OUT = hasFlag("json");
const FIX = hasFlag("fix");
const NO_BASELINE = hasFlag("no-baseline");
const SEED_APPROVED = hasFlag("seed-approved");
const VERIFY_INTEGRITY = hasFlag("verify-integrity");
const PRINT_APPROVAL_REQUEST = hasFlag("print-approval-request");
const FROZEN = hasFlag("frozen");
// --frozen is a deploy gate: no advisories, no grandfathering, no passing on an
// empty scan. It implies strictness rather than asking the caller to remember.
const STRICT = hasFlag("strict") || FROZEN;
const APPROVAL_SCOPE_FLAG = flagValue("approval-scope");
if (APPROVAL_SCOPE_FLAG && !["new", "all"].includes(APPROVAL_SCOPE_FLAG)) {
  stderr.write(`depcheck: --approval-scope must be "new" or "all" (got "${APPROVAL_SCOPE_FLAG}")\n`);
  exit(2);
}
const APPROVAL_SCOPE = FROZEN ? "all" : (APPROVAL_SCOPE_FLAG || "new");
// On a PR checkout, HEAD is the merge commit and already contains the change, so
// comparing to HEAD would find nothing new. GitHub exposes the target branch as
// GITHUB_BASE_REF; use origin/<base> when it is available. Locally (and on push)
// HEAD is still the right comparison point for uncommitted work.
const BASELINE_REV = flagValue("baseline") || (env.GITHUB_BASE_REF ? `origin/${env.GITHUB_BASE_REF}` : "HEAD");

const PYPI_INDEX = (env.DEPCHECK_PYPI_INDEX || "https://pypi.org/pypi").replace(/\/+$/, "");
const NPM_REGISTRY = (env.DEPCHECK_NPM_REGISTRY || "https://registry.npmjs.org").replace(/\/+$/, "");

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".cache", ".backups", ".nvm", ".local", ".npm", ".vscode-server", ".docker", ".venv", "venv", "site-packages"]);
const sleep = (ms) => setTimeout(ms).then(() => {});

const isPrerelease = (v) => /(\.|^)(a|b|rc|alpha|beta|dev)(\.|\d|$)/i.test(v) || v.includes("-");
const ageDays = (iso) => (Date.now() - new Date(iso).getTime()) / 86400000;
const gte = (a, b) => {
  const pa = String(a).split(".").map((n) => Number(n) || 0), pb = String(b).split(".").map((n) => Number(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const da = pa[i] || 0, db = pb[i] || 0; if (da !== db) return da - db; } return 0;
};
// PEP 503-ish normalisation so `LiteLLM` and `litellm` match (but not a
// differently-named project such as `lite_llm`, which PEP 503 reads as `lite-llm`).
const normName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, "-");
const normEco = (e) => String(e || "").toLowerCase().replace(/\(.*?\)/g, "").trim();

async function loadJSON(path, fallback = null) {
  try { return JSON.parse(await readFile(path, "utf8")); } catch { return fallback; }
}

// ── config: policy + compromised denylist ──
const TOOL_POLICY = await loadJSON(join(TOOL_ROOT, "policy", "compromised.json"), { entries: [] });
const CLI_POLICY_PATH = flagValue("policy");
const CLI_COMPROMISED_PATH = flagValue("compromised");
const REPO_POLICIES = [];
for (const dir of SCAN_DIRS) {
  const p = resolve(dir, ".deps-policy.json");
  const j = await loadJSON(p);
  if (j) REPO_POLICIES.push(j);
}
const CLI_POLICY = await loadJSON(CLI_POLICY_PATH);
const POLICY = CLI_POLICY || REPO_POLICIES[0] || null;

const COOLDOWN_DAYS = Number(flagValue("cooldown")) || Number(POLICY?.cooldownDays) || 14;
export { COOLDOWN_DAYS };

const CLI_COMPROMISED = await loadJSON(CLI_COMPROMISED_PATH);
const COMPROMISED = [
  ...(TOOL_POLICY.entries || []),
  ...(CLI_COMPROMISED?.entries || []),
  ...(CLI_POLICY?.compromised || []),
  ...REPO_POLICIES.flatMap((p) => p.compromised || []),
].filter((e) => e && e.name).map((e) => ({ ...e, ecosystem: normEco(e.ecosystem || "pypi") }));

// ── config: approved direct dependencies (opt-in gate) ──
// Active only when a list is supplied, so existing CI does not go red on upgrade.
const APPROVED_PATH = flagValue("approved");
const APPROVED_FILE = APPROVED_PATH ? await loadJSON(APPROVED_PATH, undefined) : undefined;
if (APPROVED_PATH && APPROVED_FILE === undefined && !SEED_APPROVED) {
  stderr.write(`depcheck: cannot read approved list: ${APPROVED_PATH} (use --seed-approved to create it)\n`);
  exit(2);
}
const APPROVALS = [
  ...(Array.isArray(APPROVED_FILE) ? APPROVED_FILE : APPROVED_FILE?.entries || []),
  ...(Array.isArray(POLICY?.approved) ? POLICY.approved : []),
].filter((e) => e && e.name).map((e) => ({ ...e, ecosystem: normEco(e.ecosystem || "pypi") }));
const APPROVAL_ON = Boolean(APPROVED_PATH) || Array.isArray(POLICY?.approved);
if (FROZEN && !APPROVAL_ON) {
  stderr.write("depcheck: --frozen needs an approved list (--approved=<path> or .deps-policy.json → approved); refusing to gate a deploy on nothing\n");
  exit(2);
}

// An entry only counts as an approval once it records who signed off and when.
// Blank placeholders are a *request*: that is what a developer commits, and the
// gate stays red until security fills the record. --strict/--frozen also require
// the rationale and a review date, because that is the evidence an auditor asks for.
const REQUIRED_APPROVAL_FIELDS = ["approvedBy", "date"];
const REVIEW_APPROVAL_FIELDS = ["rationale", "reviewBy"];

function approvalNameHit(dep) {
  const eco = normEco(dep.ecosystem), name = normName(dep.name);
  return APPROVALS.find((e) => (!e.ecosystem || e.ecosystem === eco) && normName(e.name) === name);
}

function findApproval(dep) {
  const v = dep.current ? String(dep.current) : null;
  const hit = approvalNameHit(dep);
  if (!hit) return undefined;
  const pinned = hit.version ? [String(hit.version)] : (hit.versions || []).map(String);
  return pinned.length === 0 || (v !== null && pinned.includes(v)) ? hit : undefined;
}

// undefined = gate off / not required. Otherwise the row carries the decision
// plus a human-readable reason, so the JSON is enough to drive a PR comment.
function approvalRecordFor(dep) {
  if (!APPROVAL_ON) return undefined;
  const entry = findApproval(dep);
  if (!entry) {
    const named = approvalNameHit(dep);
    if (named) {
      const pinned = named.version ? [String(named.version)] : (named.versions || []).map(String);
      return { approved: false, issue: `approved only for ${pinned.join(", ") || "a different pin"} — ${dep.current || "this requirement"} needs a fresh decision` };
    }
    return { approved: false, issue: "not on the approved list" };
  }
  const missing = REQUIRED_APPROVAL_FIELDS.filter((f) => !String(entry[f] ?? "").trim());
  if (missing.length) {
    return { approved: false, issue: `approval record incomplete (needs ${missing.join(" + ")})`, entry, missing };
  }
  const weak = REVIEW_APPROVAL_FIELDS.filter((f) => !String(entry[f] ?? "").trim());
  if (STRICT && weak.length) {
    return { approved: false, issue: `approval record incomplete under --strict (needs ${weak.join(" + ")})`, entry, missing: weak };
  }
  return { approved: true, entry, weak };
}

export function compromisedHit(dep) {
  if (!dep?.name) return null;
  const eco = normEco(dep.ecosystem), name = normName(dep.name), v = dep.current ? String(dep.current) : null;
  for (const e of COMPROMISED) {
    if (e.ecosystem && e.ecosystem !== eco) continue;
    if (normName(e.name) !== name) continue;
    const versions = (e.versions || []).map(String);
    if (!v) return e; // an unpinned requirement resolves to *something* — flag it
    if (versions.includes(v)) return e;
    for (const r of e.ranges || []) {
      if (r.introduced && gte(v, r.introduced) >= 0 && (!r.fixed || gte(r.fixed, v) > 0)) return e;
    }
  }
  return null;
}

// ── registry fetch ──
async function getJSON(url) {
  for (let i = 0; i < 3; i++) {
    try { const r = await fetch(url); if (r.ok) return await r.json(); if (r.status === 404) return null; } catch {}
    if (i < 2) await sleep(500 * (i + 1));
  }
  return null;
}

function revisitAfter(rel) {
  const t = new Date(rel.lastUpload).getTime() + COOLDOWN_DAYS * 86400000;
  return new Date(t).toISOString().slice(0, 10);
}

// Licences arrive as SPDX ids, prose, or "UNKNOWN". Keep one short line; the
// reviewer needs a signal, not a 4KB licence dump.
function tidyLicense(l) {
  const t = String(l || "").split("\n")[0].trim();
  if (!t || t.toUpperCase() === "UNKNOWN") return null;
  return t.length > 60 ? `${t.slice(0, 57)}…` : t;
}

async function pypiReleases(name) {
  const d = await getJSON(`${PYPI_INDEX}/${encodeURIComponent(name)}/json`);
  if (!d) return null;
  const rels = [];
  const times = [];
  for (const [v, files] of Object.entries(d.releases || {})) {
    for (const f of files || []) {
      const t = new Date(f.upload_time).getTime();
      if (t) times.push(t);
    }
    if (!files || !files.length || isPrerelease(v)) continue;
    const t = files.map((f) => new Date(f.upload_time).getTime()).filter(Boolean);
    if (!t.length) continue;
    rels.push({
      v,
      lastUpload: new Date(Math.max(...t)).toISOString(),
      yanked: files.every((f) => f.yanked === true),
      yankedReason: files.find((f) => f.yanked_reason)?.yanked_reason || null,
    });
  }
  rels.sort((a, b) => new Date(b.lastUpload) - new Date(a.lastUpload));
  return {
    latest: d.info?.version || rels[0]?.v || null,
    rels,
    firstPublished: times.length ? new Date(Math.min(...times)).toISOString() : null,
    releaseCount: rels.length,
    license: tidyLicense(d.info?.license || d.info?.license_expression),
  };
}

async function npmReleases(name) {
  const d = await getJSON(`${NPM_REGISTRY}/${encodeURIComponent(name)}`);
  if (!d) return null;
  const rels = [];
  const time = d.time || {};
  for (const [v, t] of Object.entries(time)) { if (["created", "modified"].includes(v) || isPrerelease(v)) continue; rels.push({ v, lastUpload: t }); }
  rels.sort((a, b) => new Date(b.lastUpload) - new Date(a.lastUpload));
  const latest = d["dist-tags"]?.latest || rels[0]?.v || null;
  const times = Object.values(time).map((t) => new Date(t).getTime()).filter(Boolean);
  return {
    latest,
    rels,
    firstPublished: time.created || (times.length ? new Date(Math.min(...times)).toISOString() : null),
    releaseCount: rels.length,
    license: tidyLicense(d.license || (latest ? d.versions?.[latest]?.license : null)),
  };
}

const REGISTRY_CACHE = new Map();
async function registryFor(dep) {
  const eco = normEco(dep.ecosystem);
  const key = `${eco}:${normName(dep.name)}`;
  if (!REGISTRY_CACHE.has(key)) {
    REGISTRY_CACHE.set(key, eco === "npm" ? npmReleases(dep.name) : pypiReleases(dep.name));
  }
  return await REGISTRY_CACHE.get(key);
}

// ── classification ──
// Newest release that is (a) past the cooldown, (b) not yanked, (c) not known-bad.
function safeTarget(dep, reg) {
  return reg.rels.find((r) => ageDays(r.lastUpload) >= COOLDOWN_DAYS && !r.yanked && !compromisedHit({ ...dep, current: r.v })) || null;
}

// First sentence only: the table stays readable and --json carries the rest.
const brief = (s) => {
  const t = String(s || "").trim();
  const i = t.indexOf(". ");
  return i > 0 ? t.slice(0, i + 1) : t;
};

export function classify(dep, reg) {
  // Known-bad first: a deleted release also fails the registry lookup below.
  const bad = compromisedHit(dep);
  if (bad) {
    const link = bad.advisories?.[0] ? ` (${bad.advisories[0]})` : "";
    return { status: "COMPROMISED", note: `known-bad release — ${brief(bad.reason) || "see advisory"}${link}` };
  }
  if (!reg) return { status: "UNRESOLVING", note: "registry lookup failed" };
  if (dep.current && isPrerelease(dep.current)) return { status: "PRERELEASE", note: `current ${dep.current} is a pre-release` };
  if (!dep.current) return reg.latest ? { status: "UNPINNED", note: `latest is ${reg.latest}` } : { status: "UNRESOLVING", note: "no registry info" };

  const cur = reg.rels.find((r) => r.v === String(dep.current));
  // Pinned but absent from the registry: deleted/quarantined (the litellm case).
  if (!cur) return { status: "WITHDRAWN", note: `pinned ${dep.current} is no longer published (deleted/quarantined) — do not re-adopt` };
  if (cur.yanked) return { status: "YANKED", note: `release yanked${cur.yankedReason ? `: ${cur.yankedReason}` : ""}` };

  const curAge = ageDays(cur.lastUpload);
  const newest = reg.rels[0];
  if (!newest) return { status: "UNRESOLVING", note: "no stable releases" };
  const safe = safeTarget(dep, reg);

  if (String(dep.current) === newest.v) {
    if (curAge >= COOLDOWN_DAYS) return { status: "OK", note: `latest (${curAge.toFixed(0)}d old)` };
    return { status: "TOO_NEW", note: `latest ${newest.v} is ${curAge.toFixed(0)}d old (< ${COOLDOWN_DAYS}d)`, revisitAfter: revisitAfter(newest) };
  }
  if (!safe) {
    return {
      status: "UNAGED_NEW_DEP",
      note: `no cooldown-safe release; latest ${newest.v} is ${ageDays(newest.lastUpload).toFixed(0)}d old`,
      revisitAfter: revisitAfter(newest),
    };
  }
  if (curAge >= COOLDOWN_DAYS && gte(dep.current, safe.v) >= 0) return { status: "OK", note: `current aged; latest ${newest.v} is fresh` };
  // Never advise a downgrade: a fresh pin that is ahead of the newest aged
  // release is a young pin, not an outdated one.
  if (gte(dep.current, safe.v) > 0) {
    return { status: "TOO_NEW", note: `pinned ${dep.current} is ${curAge.toFixed(0)}d old; newest ${newest.v} also fresh`, revisitAfter: revisitAfter(newest) };
  }
  return { status: "OUTDATED", note: `bump to ${safe.v} (cooldown-safe) | latest: ${newest.v}`, safeTarget: safe.v };
}

// ── parsers ──
// `--hash=` lines follow the requirement they belong to (pip's
// --require-hashes format), including `\` continuations.
export function parseRequirements(text) {
  const deps = [];
  let cur = null;
  for (const line of text.split("\n")) {
    const raw = line.trim();
    if (!raw || raw.startsWith("#")) continue;
    if (raw.startsWith("-e ")) { cur = null; continue; }
    if (raw.startsWith("--")) {
      const h = raw.match(/^--hash=(?:sha256:)?([0-9a-f]{16,})/i);
      if (h && cur) cur.hashes.push(h[1]);
      continue;
    }
    const m = raw.match(/^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(==|~=|>=|<=|!=|>|<|===)?\s*([^;\\\s]*)/);
    if (!m) { cur = null; continue; }
    cur = { ecosystem: "pypi", name: m[1].replace(/\[.*\]$/, ""), op: m[2] || null, current: m[3] || null, hashes: [] };
    deps.push(cur);
  }
  return deps;
}

export function parseLock(text) {
  const lock = JSON.parse(text);
  const deps = [];
  for (const [key, meta] of Object.entries(lock.packages || {})) {
    if (key === "" || !meta || !meta.version) continue;
    deps.push({
      ecosystem: "npm",
      name: key.replace(/^node_modules\//, ""),
      op: "locked",
      current: meta.version,
      dev: !!meta.dev,
      hashes: meta.integrity ? [meta.integrity] : [],
    });
  }
  return deps;
}

export function parsePipfileLock(text) {
  const lock = JSON.parse(text);
  const deps = [];
  for (const section of ["default", "develop"]) {
    for (const [name, meta] of Object.entries(lock[section] || {})) {
      const v = String(meta?.version || "").replace(/^==/, "");
      deps.push({ ecosystem: "pypi", name, op: v ? "==" : null, current: v || null, dev: section === "develop", hashes: meta?.hashes || [] });
    }
  }
  return deps;
}

// poetry.lock and uv.lock both use `[[package]]` stanzas with name/version and
// (normally) `hash = "sha256:…"` entries in the stanza's `files` list.
export function parseTomlPackages(text) {
  const deps = [];
  let cur = null;
  const flush = () => {
    if (cur?.name && cur?.version) deps.push(cur);
    cur = null;
  };
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t === "[[package]]") { flush(); cur = { ecosystem: "pypi", name: null, version: null, op: "locked", current: null, hashes: [] }; continue; }
    if (!cur) continue;
    const m = t.match(/^(name|version)\s*=\s*"([^"]+)"/);
    if (m) {
      cur[m[1]] = m[2];
      if (m[1] === "version") cur.current = m[2];
      continue;
    }
    const h = t.match(/hash\s*=\s*"sha256:([0-9a-f]{16,})"/i);
    if (h) cur.hashes.push(h[1]);
  }
  flush();
  return deps;
}

// Best-effort pyproject.toml: exact pins only. Ranged specs are reported as
// skipped (visible, never guessed) because pyproject is a declaration file, not
// a lock — flagging ranges as violations would fail builds for every normal repo.
export function parsePyproject(text) {
  const deps = [], skipped = [];
  const addSpec = (spec) => {
    const s = String(spec).trim();
    if (!s || s.startsWith("#")) return;
    const m = s.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9_.+\-]+))?/);
    if (!m) { skipped.push(s); return; }
    if (m[2]) deps.push({ ecosystem: "pypi", name: m[1], op: "==", current: m[2] });
    else skipped.push(`${m[1]} (not an exact pin)`);
  };
  let section = "", inArray = false, depth = 0;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (inArray) {
      depth += (line.match(/\[/g) || []).length - (line.match(/\]/g) || []).length;
      for (const q of line.matchAll(/"([^"]+)"/g)) addSpec(q[1]);
      if (depth <= 0) inArray = false;
      continue;
    }
    if (/^\[+/.test(line)) { section = line.replace(/^\[+|\]+$/g, ""); continue; }
    const pep621 = section === "project" && /^dependencies\s*=\s*\[/.test(line);
    const optional = /^project\.optional-dependencies(\..+)?$/.test(section) && /^[A-Za-z0-9_.\-]+\s*=\s*\[/.test(line);
    if (pep621 || optional) {
      depth = (line.match(/\[/g) || []).length - (line.match(/\]/g) || []).length;
      for (const q of line.matchAll(/"([^"]+)"/g)) addSpec(q[1]);
      if (depth > 0) inArray = true;
      continue;
    }
    if (section === "tool.poetry.dependencies" || section === "tool.poetry.dev-dependencies" || /^tool\.poetry\.group\..+\.dependencies$/.test(section)) {
      const t = line.match(/^([A-Za-z0-9_.\-]+)\s*=\s*(.+)$/);
      if (!t || t[1].toLowerCase() === "python") continue;
      const v = t[2].match(/^"==?([0-9][^"]*)"/) || t[2].match(/version\s*=\s*"==?([0-9][^"]*)"/);
      if (v) deps.push({ ecosystem: "pypi", name: t[1], op: "==", current: v[1] });
      else skipped.push(`${t[1]} (not an exact pin)`);
    }
  }
  return { deps, skipped };
}

const MANIFEST_NAMES = new Set(["requirements.txt", "pyproject.toml", "Pipfile.lock", "poetry.lock", "uv.lock", "package.json", "package-lock.json"]);
// Lock/declaration files whose rows are only "direct" if the name is declared elsewhere.
const LOCK_MANIFESTS = new Set(["package-lock.json", "Pipfile.lock", "poetry.lock", "uv.lock"]);
const DIRECT_MANIFESTS = new Set(["requirements.txt", "pyproject.toml", "package.json"]);
// package.json is a name oracle only: ranges are not pins, and auditing it as
// rows would gate repos that have no lockfile. It scopes lockfile rows instead.
const NAME_ONLY_MANIFESTS = new Set(["package.json"]);

export function parseText(name, text) {
  const base = String(name).split("/").pop();
  const skipped = [];
  let deps = [];
  try {
    if (base === "requirements.txt") deps = parseRequirements(text);
    else if (base === "package-lock.json") deps = parseLock(text);
    else if (base === "package.json") deps = parsePackageJson(text);
    else if (base === "Pipfile.lock") deps = parsePipfileLock(text);
    else if (base === "poetry.lock" || base === "uv.lock") deps = parseTomlPackages(text);
    else if (base === "pyproject.toml") { const r = parsePyproject(text); deps = r.deps; skipped.push(...r.skipped); }
  } catch { deps = []; }
  return { deps, skipped };
}

function parsePackageJson(text) {
  const pkg = JSON.parse(text);
  return Object.entries({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) })
    .map(([name, range]) => ({ ecosystem: "npm", name, op: null, current: String(range).replace(/^[~^>=<]+/, "") || null, dev: false }));
}

// ── baseline (git) — needed to tell "newly adopted" from "already pinned" ──
const BASELINE_CACHE = new Map();
async function baselineFor(file) {
  if (NO_BASELINE) return null;
  const abs = resolve(file);
  if (BASELINE_CACHE.has(abs)) return BASELINE_CACHE.get(abs);
  let map = null;
  try {
    const dir = dirname(abs);
    const root = (await execFileAsync("git", ["rev-parse", "--show-toplevel"], { cwd: dir })).stdout.trim();
    const rel = relative(root, abs);
    const text = (await execFileAsync("git", ["show", `${BASELINE_REV}:${rel}`], { cwd: root, maxBuffer: 64 << 20 })).stdout;
    map = new Map(parseText(rel, text).deps.filter((d) => d.current).map((d) => [normName(d.name), String(d.current)]));
  } catch { map = null; }
  BASELINE_CACHE.set(abs, map);
  return map;
}

async function applyAdoptionRule(dep, file, row) {
  if (!["TOO_NEW", "UNAGED_NEW_DEP"].includes(row.status)) return row;
  const override = cooldownOverrideFor(dep);
  if (override) {
    return { ...row, status: "TOO_NEW", note: `cooldownOverride (${override.reason || "documented"})${override.reviewBy ? ` review by ${override.reviewBy}` : ""}` };
  }
  if (row.status === "UNAGED_NEW_DEP") return row;
  const base = await baselineFor(file);
  if (!base) return { ...row, note: `${row.note}; adoption age unverified (no git baseline)` };
  const prev = base.get(normName(dep.name));
  if (prev === String(dep.current)) return row; // already committed: just young
  return {
    ...row,
    status: "UNAGED_NEW_DEP",
    note: `newly pinned ${dep.current} (< ${COOLDOWN_DAYS}d old) — revert or wait${row.revisitAfter ? ` until ${row.revisitAfter}` : ""}`,
  };
}

function cooldownOverrideFor(dep) {
  const o = POLICY?.cooldownOverride;
  if (!o) return null;
  const hit = o[dep.name] || o[normName(dep.name)];
  return hit && String(hit.version) === String(dep.current) ? hit : null;
}

// ── filesystem scan ──
async function walk(dir, out) {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    try { (await stat(full)).isDirectory() ? await walk(full, out) : out.push(full); } catch {}
  }
}
async function findManifests() {
  const all = [];
  for (const d of SCAN_DIRS) await walk(d, all);
  return all
    .filter((f) => MANIFEST_NAMES.has(f.split("/").pop()))
    .filter((f) => !/\.(bak|orig|old)$/.test(f))
    .sort();
}

// ── gating ──
const BLOCKING_ALWAYS = new Set(["COMPROMISED", "WITHDRAWN", "YANKED"]);
const ADVISORY_ONLY = new Set(["TOO_NEW"]);
// Report worst-first so a known-bad pin is never buried under a page of OK rows.
const STATUS_ORDER = {
  COMPROMISED: 0, WITHDRAWN: 1, YANKED: 2, UNAGED_NEW_DEP: 3, NO_HASH: 4,
  OUTDATED: 5, UNPINNED: 6, PRERELEASE: 7, UNRESOLVING: 8, TOO_NEW: 9, OK: 10,
};
function isBlocking(r) {
  // Approval is orthogonal to freshness: an aged, safe pin can still be unvetted.
  if (r.approved === false && r.direct === "direct") return true;
  if (r.status === "OK") return false;
  if (BLOCKING_ALWAYS.has(r.status)) return true;
  if (ADVISORY_ONLY.has(r.status)) return STRICT;
  return r.direct === "direct" || STRICT;
}

// Hashes are the only control that survives a compromised registry account: a
// name+version approval cannot tell you the bytes changed.
function requiresIntegrity(file, text) {
  if (VERIFY_INTEGRITY) return true;
  return file.endsWith("requirements.txt") && /^--require-hashes/m.test(text);
}
function applyIntegrity(row, dep) {
  if ((dep.hashes || []).length || BLOCKING_ALWAYS.has(row.status)) return row;
  return { ...row, status: "NO_HASH", note: "no hash/integrity recorded for this pin — the bytes are unverifiable" };
}

// --fix: rewrite exact `pkg==x` pins in requirements.txt to the cooldown-safe
// target. Never touches a file holding a COMPROMISED/WITHDRAWN/YANKED pin, and
// safeTarget() already excludes known-bad releases.
async function applyFixes(rows) {
  const byFile = new Map();
  for (const r of rows) {
    if (r.status !== "OUTDATED" || !r.safeTarget || !r.file.endsWith("requirements.txt")) continue;
    if (!byFile.has(r.file)) byFile.set(r.file, new Map());
    byFile.get(r.file).set(normName(r.name), { from: String(r.current), to: String(r.safeTarget) });
  }
  let changed = 0;
  for (const [file, targets] of byFile) {
    const blocked = rows.some((r) => r.file === file && BLOCKING_ALWAYS.has(r.status));
    if (blocked) { stderr.write(`fix: refusing ${file} — resolve the COMPROMISED/WITHDRAWN/YANKED rows first\n`); continue; }
    const text = await readFile(file, "utf8");
    let touched = false;
    const out = text.split("\n").map((line) => {
      const m = line.match(/^(\s*[A-Za-z0-9_.\-]+(?:\[[^\]]*\])?\s*==\s*)([^;#\s]+)(.*)$/);
      if (!m) return line;
      const name = normName(m[1].replace(/\[[^\]]*\]/g, "").replace(/==.*$/, "").trim());
      const t = targets.get(name);
      if (!t || m[2] !== t.from || t.from === t.to) return line;
      touched = true;
      stderr.write(`fix: ${name} ${t.from} -> ${t.to}  (${file})\n`);
      return `${m[1]}${t.to}${m[3]}`;
    });
    if (touched) { await writeFile(file, out.join("\n")); changed++; }
  }
  return changed;
}

// ── main ──
async function scan() {
  const manifests = await findManifests();
  const pkgVersion = (await loadJSON(join(TOOL_ROOT, "package.json"), {}))?.version || "0.0.0";

  const parsed = new Map();
  const texts = new Map();
  const skipped = [];
  for (const f of manifests) {
    const text = await readFile(f, "utf8");
    texts.set(f, text);
    const { deps, skipped: sk } = parseText(f, text);
    parsed.set(f, deps);
    for (const s of sk) skipped.push({ file: relative(cwd(), f), dep: s });
  }

  // Names declared as direct deps, used to scope lockfile rows.
  const directNames = new Set();
  for (const [f, deps] of parsed) {
    if (!DIRECT_MANIFESTS.has(f.split("/").pop())) continue;
    for (const d of deps) directNames.add(`${normEco(d.ecosystem)}:${normName(d.name)}`);
  }

  // scope=new: a direct dep needs approval only if its *name* is new relative to
  // the direct manifests at the baseline revision. Deriving the set from
  // declaration files (not lockfiles) means a package that was already present
  // transitively does not count as "already approved" when it is first declared.
  // No usable baseline is not proof of legacy, so it fails closed (everything is
  // treated as new) rather than silently grandfathering a whole tree.
  let baselineKeys = null;
  if (APPROVAL_ON && APPROVAL_SCOPE === "new" && !NO_BASELINE) {
    const keys = new Set();
    let available = false;
    for (const f of manifests) {
      const base = f.split("/").pop();
      if (!DIRECT_MANIFESTS.has(base)) continue;
      const map = await baselineFor(f);
      if (!map) continue;
      available = true;
      const eco = base === "package.json" ? "npm" : "pypi";
      for (const n of map.keys()) keys.add(`${eco}:${normName(n)}`);
    }
    baselineKeys = available ? keys : null;
  }

  const rows = [];
  for (const [f, deps] of parsed) {
    const base = f.split("/").pop();
    if (NAME_ONLY_MANIFESTS.has(base)) continue;
    const isLock = LOCK_MANIFESTS.has(base);
    const integrity = requiresIntegrity(f, texts.get(f) || "");
    for (const d of deps) {
      const reg = await registryFor(d);
      const direct = isLock ? (directNames.has(`${normEco(d.ecosystem)}:${normName(d.name)}`) ? "direct" : "transitive") : "direct";
      const eco = normEco(d.ecosystem);
      const nameKey = `${eco}:${normName(d.name)}`;
      const legacy = baselineKeys !== null && baselineKeys.has(nameKey);
      // A version-pinned entry is an explicit "come back on a bump", so a
      // mismatch stays in scope even once the name is legacy; otherwise pinning
      // would silently stop working after the first merge.
      const named = approvalNameHit(d);
      const pinnedMismatch = Boolean(named && (named.version || (named.versions || []).length) && !findApproval(d));
      const required = direct === "direct" && APPROVAL_ON && (
        APPROVAL_SCOPE === "all" || baselineKeys === null || !legacy || pinnedMismatch
      );
      const approval = required ? approvalRecordFor(d) : undefined;
      let finalRow = await applyAdoptionRule(d, f, classify(d, reg));
      if (integrity) finalRow = applyIntegrity(finalRow, d);
      rows.push({
        file: relative(cwd(), f),
        ecosystem: d.dev ? `${eco}(dev)` : eco,
        name: d.name,
        op: d.op || null,
        current: d.current || "—",
        latest: reg?.latest || "—",
        direct,
        ...finalRow,
        approved: approval?.approved,
        approvalIssue: approval && !approval.approved ? approval.issue : undefined,
        approvalMissing: approval?.missing?.length ? approval.missing : undefined,
        approvalWeak: approval?.weak?.length ? approval.weak : undefined,
        approvalBasis: !APPROVAL_ON || direct !== "direct" ? undefined
          : APPROVAL_SCOPE === "all" ? "all"
          : baselineKeys === null ? "no-baseline"
          : pinnedMismatch && legacy ? "pinned"
          : required ? "new" : "legacy",
      });
    }
  }

  // A package listed in both a declaration and a lockfile is one decision: keep
  // the direct row, drop the duplicate transitive view.
  const seen = new Map();
  const deduped = [];
  for (const r of rows) {
    const key = `${normEco(r.ecosystem)}:${normName(r.name)}:${r.current}`;
    const prev = seen.get(key);
    if (!prev) { seen.set(key, r); deduped.push(r); continue; }
    if (prev.direct !== "direct" && r.direct === "direct") { seen.set(key, r); deduped[deduped.indexOf(prev)] = r; }
  }
  const out = deduped.sort((a, b) => (STATUS_ORDER[a.status] ?? 99) - (STATUS_ORDER[b.status] ?? 99) || a.name.localeCompare(b.name));
  return { rows: out, skipped, pkgVersion };
}

// --seed-approved: bootstrap the list from the current direct deps, so the gate
// does not start life as a wall of red (which gets rubber-stamped). Seeded
// entries are marked `grandfathered` so an auditor can find the ones that were
// never actually reviewed.
async function seedApprovals(rows) {
  if (!APPROVED_PATH) {
    stderr.write("depcheck: --seed-approved needs --approved=<path>\n");
    exit(2);
  }
  const today = new Date().toISOString().slice(0, 10);
  const reviewBy = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
  const entries = rows
    .filter((r) => r.direct === "direct" && !BLOCKING_ALWAYS.has(r.status) && r.status !== "UNRESOLVING")
    .map((r) => ({
      ecosystem: normEco(r.ecosystem),
      name: r.name,
      grandfathered: true,
      rationale: "Grandfathered when the approval gate was adopted; security must review and replace this text.",
      approvedBy: env.USER || "unset",
      date: today,
      reviewBy,
    }));
  const body = {
    $comment: "Approved DIRECT dependencies. A scope=new run only gates names that are new relative to the git baseline. Blank approvedBy/date is a request, not an approval: it stays blocking. Name-level by default; add \"version\" (or \"versions\") to require a fresh approval on bump.",
    updated: today,
    entries,
  };
  await writeFile(APPROVED_PATH, JSON.stringify(body, null, 2) + "\n");
  stderr.write(`seed-approved: wrote ${entries.length} grandfathered entries to ${APPROVED_PATH} — have security replace each rationale/reviewBy\n`);
  exit(0);
}

// Paste-ready request for the unapproved direct deps. The registry evidence sits
// in the same record the reviewer signs, so the audit trail says *what was
// checked*, not just who clicked approve. Blank approvedBy/date keeps the gate
// red until a reviewer fills them in.
async function buildApprovalRequest(rows) {
  const pending = rows.filter((r) => r.direct === "direct" && r.approved === false);
  const entries = [];
  for (const r of pending) {
    const cached = REGISTRY_CACHE.get(`${normEco(r.ecosystem)}:${normName(r.name)}`);
    const registry = cached ? await cached : null;
    const rel = registry?.rels.find((x) => x.v === String(r.current)) || null;
    entries.push({
      ecosystem: normEco(r.ecosystem),
      name: r.name,
      rationale: "",
      approvedBy: "",
      date: "",
      reviewBy: "",
      checks: {
        requestedVersion: r.current === "—" ? null : r.current,
        status: r.status,
        versionAgeDays: rel ? Number(ageDays(rel.lastUpload).toFixed(1)) : null,
        firstPublished: registry?.firstPublished || null,
        releases: registry?.releaseCount ?? null,
        license: registry?.license || null,
        knownBad: BLOCKING_ALWAYS.has(r.status),
      },
    });
  }
  return entries;
}

async function main() {
  let { rows: out, skipped, pkgVersion } = await scan();

  // --fix rewrites pins, so re-scan afterwards: the exit code must describe the
  // tree as it is now, not as it was before the rewrite.
  if (FIX) {
    const n = await applyFixes(out);
    if (n) {
      ({ rows: out, skipped } = await scan());
      if (!JSON_OUT) stdout.write(`fix: rewrote ${n} file(s); re-scanned\n`);
    }
  }

  if (SEED_APPROVED) await seedApprovals(out);

  const today = new Date().toISOString().slice(0, 10);
  const directKeys = new Set(out.filter((r) => r.direct === "direct").map((r) => `${normEco(r.ecosystem)}:${normName(r.name)}`));
  const staleApprovals = APPROVAL_ON ? APPROVALS.filter((e) => !directKeys.has(`${e.ecosystem}:${normName(e.name)}`)) : [];
  const overdueApprovals = APPROVAL_ON ? APPROVALS.filter((e) => e.reviewBy && e.reviewBy < today) : [];
  const weakApprovals = APPROVAL_ON
    ? APPROVALS.filter((e) => REVIEW_APPROVAL_FIELDS.some((f) => !String(e[f] ?? "").trim()))
    : [];
  const unapproved = out.filter((r) => r.approved === false);
  const noBaseline = out.some((r) => r.approvalBasis === "no-baseline");

  // Fail closed before any output mode can return 0 on an empty scan (wrong
  // working directory, missing build context). Applies to --json too.
  if (FROZEN && !out.length) {
    stderr.write("depcheck: --frozen found no supported manifests — refusing to pass a deploy gate on nothing\n");
    exit(2);
  }

  // The request is a developer-facing artifact, not an approval: it writes only
  // to stdout and keeps the gate's exit code so CI still fails.
  if (PRINT_APPROVAL_REQUEST && !JSON_OUT) {
    if (!APPROVAL_ON) {
      stderr.write("depcheck: --print-approval-request needs the approval gate on (--approved=<path> or .deps-policy.json → approved)\n");
      exit(2);
    }
    const entries = await buildApprovalRequest(out);
    stdout.write(JSON.stringify({
      $comment: "Paste into approved.json → entries. If an entry for this name already exists (e.g. a version-pinned approval being bumped), update it instead of adding a duplicate. Blank approvedBy/date means the request is still PENDING: a security reviewer must check the evidence, fill the record, and commit that change (CODEOWNERS makes the diff the sign-off).",
      entries,
    }, null, 2) + "\n");
    if (!entries.length) stderr.write("depcheck: nothing to request — every in-scope direct dep has an approval record\n");
    exit(out.filter(isBlocking).length ? 1 : 0);
  }

  if (JSON_OUT) {
    const failing = out.filter(isBlocking);
    stdout.write(JSON.stringify({
      version: pkgVersion,
      cooldownDays: COOLDOWN_DAYS,
      strict: STRICT,
      frozen: FROZEN,
      compromisedEntries: COMPROMISED.length,
      approvalGate: {
        active: APPROVAL_ON,
        scope: APPROVAL_SCOPE,
        entries: APPROVALS.length,
        unapproved: unapproved.map((r) => r.name),
        incomplete: unapproved.filter((r) => r.approvalMissing?.length).map((r) => r.name),
        stale: staleApprovals.map((e) => e.name),
        overdue: overdueApprovals.map((e) => e.name),
        weak: weakApprovals.map((e) => e.name),
      },
      approvalRequest: APPROVAL_ON ? await buildApprovalRequest(out) : [],
      skipped,
      rows: out,
    }, null, 2) + "\n");
    exit(failing.length ? 1 : 0);
  }

  if (!out.length) {
    stdout.write("depcheck: no supported manifests found.\n");
    exit(0);
  }

  stdout.write(`\ndepcheck v${pkgVersion}  (cooldown=${COOLDOWN_DAYS}d, ${COMPROMISED.length} compromised entr${COMPROMISED.length === 1 ? "y" : "ies"}, approvals ${APPROVAL_ON ? `${APPROVALS.length}, scope=${APPROVAL_SCOPE}` : "off"}${FROZEN ? ", frozen" : ""}, scanned ${new Set(out.map((r) => r.file)).size} file(s), ${STRICT ? "strict (transitive + fresh pins fail)" : "direct-only (transitive/fresh = advisory)"})\n`);
  if (NO_BASELINE) stdout.write("baseline: disabled (--no-baseline) — new adoptions will report as TOO_NEW, not UNAGED_NEW_DEP\n");
  if (APPROVAL_ON && APPROVAL_SCOPE === "new") {
    stdout.write(`approvals: scope=new — only direct dep names added since ${BASELINE_REV} need sign-off${noBaseline ? "; no usable baseline, so every direct dep is treated as new" : ""}\n`);
  }
  if (FROZEN) stdout.write("frozen: deploy gate — scope=all, strict, approved list required\n");
  if (skipped.length) stdout.write(`pyproject: ${skipped.length} non-exact specifier(s) not evaluated (see --json)\n`);
  stdout.write("\n");

  const headers = ["ECO", "PACKAGE", "CURRENT", "STATUS", "APPROVED", "LATEST", "SCOPE", "NOTE"];
  const keys = ["ecosystem", "name", "current", "status", "approved", "latest", "direct", "note"];
  const cell = (r, k) => {
    if (k === "note") return r.note || "";
    if (k === "approved") return r.approved === undefined ? "—" : r.approved ? "yes" : "no";
    return String(r[k] ?? "—");
  };
  const NOTE_W = 100;
  const truncate = (s, max) => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
  const w = headers.map((h, i) => {
    const max = Math.max(h.length, ...out.map((r) => cell(r, keys[i]).length));
    return keys[i] === "note" ? Math.min(max, NOTE_W) : keys[i] === "approved" ? Math.max(max, 8) : max;
  });
  stdout.write(headers.map((h, i) => h.padEnd(w[i])).join("  ") + "\n");
  for (const r of out) {
    const note = r.revisitAfter ? `${r.note} · eligible ${r.revisitAfter}` : r.note;
    const line = ["ecosystem", "name", "current", "status", "approved", "latest", "direct"].map((k, i) => cell(r, k).padEnd(w[i])).join("  ") + "  " + truncate(note || "", NOTE_W);
    const color = isBlocking(r) ? "\x1b[31m" : r.status === "OK" ? "\x1b[32m" : "\x1b[33m";
    stdout.write(color + line + "\x1b[0m\n");
  }

  const summary = {};
  for (const r of out) summary[r.status] = (summary[r.status] || 0) + 1;
  stdout.write("\nSummary: " + Object.entries(summary).map(([s, c]) => `${c} ${s}`).join(", "));
  const advisory = out.filter((r) => r.status !== "OK" && r.approved !== false && !isBlocking(r));
  if (advisory.length) stdout.write(`  | ${advisory.length} advisory (transitive/fresh pins; --strict to escalate)`);
  stdout.write("\n");

  if (APPROVAL_ON) {
    const incomplete = unapproved.filter((r) => r.approvalMissing?.length);
    const unlisted = unapproved.length - incomplete.length;
    stdout.write(`Approvals: ${unapproved.length} unapproved direct dep(s) (${unlisted} no matching entry, ${incomplete.length} incomplete record)`);
    if (staleApprovals.length) stdout.write(`, ${staleApprovals.length} stale (approved but not in any manifest: ${staleApprovals.slice(0, 5).map((e) => e.name).join(", ")}${staleApprovals.length > 5 ? ", …" : ""})`);
    if (overdueApprovals.length) stdout.write(`, ${overdueApprovals.length} review overdue (${overdueApprovals.slice(0, 5).map((e) => e.name).join(", ")})`);
    if (weakApprovals.length) stdout.write(`, ${weakApprovals.length} missing rationale/reviewBy (required under --strict)`);
    stdout.write("\n");
    for (const r of unapproved.slice(0, 5)) stdout.write(`  unapproved ${r.name}: ${r.approvalIssue}\n`);
    if (unapproved.length > 5) stdout.write(`  … ${unapproved.length - 5} more (see --json)\n`);
    if (unapproved.length) {
      stdout.write("UNAPPROVED: add each unapproved direct dep to the list with a rationale, or remove it. Transitive deps are not name-gated.\n");
      stdout.write("Request the entries with review evidence: --print-approval-request\n");
    }
  }

  const fail = out.filter(isBlocking);
  if (fail.length) {
    const compromised = fail.filter((r) => BLOCKING_ALWAYS.has(r.status));
    if (compromised.length) {
      stdout.write(`\nSECURITY: ${compromised.length} known-bad/withdrawn release(s) pinned. Treat as an incident (see references/runbook.md), not a version bump.\n`);
    }
  }
  exit(fail.length ? 1 : 0);
}

const invokedDirectly = (() => {
  const arg = argv[1];
  if (!arg) return false;
  try { return realpathSync(arg) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (invokedDirectly) await main();
