#!/usr/bin/env node
// depcheck.mjs — dependency freshness, 14-day age gate, known-compromised denylist.
// Python requirements.txt / pyproject.toml / Pipfile.lock / poetry.lock / uv.lock
// + Node package-lock.json / package.json. Stdlib Node 20+ only (no installs).
//
//   node scripts/depcheck.mjs [paths...] [--cooldown=14] [--json] [--strict] [--fix]
//        [--policy=path] [--compromised=path] [--baseline=rev] [--no-baseline]
//
//   - COMPROMISED / WITHDRAWN / YANKED always block: any ecosystem, any scope.
//   - UNAGED_NEW_DEP blocks a *newly introduced* pin younger than the cooldown
//     (a new dependency, or a bump landing on a fresh release). Existing pins
//     that are merely young are TOO_NEW (advisory).
//   - TOO_NEW is advisory unless --strict; it carries a revisitAfter date.
//   - Transitive deps are advisory by default -> --strict escalates scope+status.
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
const VALUE_FLAGS = new Set(["policy", "cooldown", "compromised", "baseline"]);
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
const STRICT = hasFlag("strict");
const NO_BASELINE = hasFlag("no-baseline");
const BASELINE_REV = flagValue("baseline") || "HEAD";

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

async function pypiReleases(name) {
  const d = await getJSON(`${PYPI_INDEX}/${encodeURIComponent(name)}/json`);
  if (!d) return null;
  const rels = [];
  for (const [v, files] of Object.entries(d.releases || {})) {
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
  return { latest: d.info?.version || rels[0]?.v || null, rels };
}

async function npmReleases(name) {
  const d = await getJSON(`${NPM_REGISTRY}/${encodeURIComponent(name)}`);
  if (!d) return null;
  const rels = [];
  const time = d.time || {};
  for (const [v, t] of Object.entries(time)) { if (["created", "modified"].includes(v) || isPrerelease(v)) continue; rels.push({ v, lastUpload: t }); }
  rels.sort((a, b) => new Date(b.lastUpload) - new Date(a.lastUpload));
  return { latest: d["dist-tags"]?.latest || rels[0]?.v || null, rels };
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
export function parseRequirements(text) {
  const deps = [];
  for (const line of text.split("\n")) {
    const raw = line.trim();
    if (!raw || raw.startsWith("#") || raw.startsWith("-e ") || raw.startsWith("--")) continue;
    const m = raw.match(/^([A-Za-z0-9_.\-]+(?:\[[^\]]*\])?)\s*(==|~=|>=|<=|!=|>|<|===)?\s*([^;\s]*)/);
    if (!m) continue;
    deps.push({ ecosystem: "pypi", name: m[1].replace(/\[.*\]$/, ""), op: m[2] || null, current: m[3] || null });
  }
  return deps;
}

export function parseLock(text) {
  const lock = JSON.parse(text);
  const deps = [];
  for (const [key, meta] of Object.entries(lock.packages || {})) {
    if (key === "" || !meta || !meta.version) continue;
    deps.push({ ecosystem: "npm", name: key.replace(/^node_modules\//, ""), op: "locked", current: meta.version, dev: !!meta.dev });
  }
  return deps;
}

export function parsePipfileLock(text) {
  const lock = JSON.parse(text);
  const deps = [];
  for (const section of ["default", "develop"]) {
    for (const [name, meta] of Object.entries(lock[section] || {})) {
      const v = String(meta?.version || "").replace(/^==/, "");
      deps.push({ ecosystem: "pypi", name, op: v ? "==" : null, current: v || null, dev: section === "develop" });
    }
  }
  return deps;
}

// poetry.lock and uv.lock both use `[[package]]` stanzas with name/version.
export function parseTomlPackages(text) {
  const deps = [];
  let cur = null;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t === "[[package]]") { cur = {}; continue; }
    if (!cur) continue;
    if (t.startsWith("[")) { cur = null; continue; } // next table, e.g. [package.dependencies]
    const m = t.match(/^(name|version)\s*=\s*"([^"]+)"/);
    if (!m) continue;
    cur[m[1]] = m[2];
    if (cur.name && cur.version) {
      deps.push({ ecosystem: "pypi", name: cur.name, op: "locked", current: cur.version });
      cur = null;
    }
  }
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
  COMPROMISED: 0, WITHDRAWN: 1, YANKED: 2, UNAGED_NEW_DEP: 3,
  OUTDATED: 4, UNPINNED: 5, PRERELEASE: 6, UNRESOLVING: 7, TOO_NEW: 8, OK: 9,
};
function isBlocking(r) {
  if (r.status === "OK") return false;
  if (BLOCKING_ALWAYS.has(r.status)) return true;
  if (ADVISORY_ONLY.has(r.status)) return STRICT;
  return r.direct === "direct" || STRICT;
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
  const skipped = [];
  for (const f of manifests) {
    const { deps, skipped: sk } = parseText(f, await readFile(f, "utf8"));
    parsed.set(f, deps);
    for (const s of sk) skipped.push({ file: relative(cwd(), f), dep: s });
  }

  // Names declared as direct deps, used to scope lockfile rows.
  const directNames = new Set();
  for (const [f, deps] of parsed) {
    if (!DIRECT_MANIFESTS.has(f.split("/").pop())) continue;
    for (const d of deps) directNames.add(`${normEco(d.ecosystem)}:${normName(d.name)}`);
  }

  const rows = [];
  for (const [f, deps] of parsed) {
    const base = f.split("/").pop();
    if (NAME_ONLY_MANIFESTS.has(base)) continue;
    const isLock = LOCK_MANIFESTS.has(base);
    for (const d of deps) {
      const reg = await registryFor(d);
      const row = classify(d, reg);
      const direct = isLock ? (directNames.has(`${normEco(d.ecosystem)}:${normName(d.name)}`) ? "direct" : "transitive") : "direct";
      const finalRow = await applyAdoptionRule(d, f, row);
      const eco = normEco(d.ecosystem);
      rows.push({
        file: relative(cwd(), f),
        ecosystem: d.dev ? `${eco}(dev)` : eco,
        name: d.name,
        op: d.op || null,
        current: d.current || "—",
        latest: reg?.latest || "—",
        direct,
        ...finalRow,
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

  if (JSON_OUT) {
    const failing = out.filter(isBlocking);
    stdout.write(JSON.stringify({ version: pkgVersion, cooldownDays: COOLDOWN_DAYS, strict: STRICT, compromisedEntries: COMPROMISED.length, skipped, rows: out }, null, 2) + "\n");
    exit(failing.length ? 1 : 0);
  }

  if (!out.length) { stdout.write("depcheck: no supported manifests found.\n"); exit(0); }

  stdout.write(`\ndepcheck v${pkgVersion}  (cooldown=${COOLDOWN_DAYS}d, ${COMPROMISED.length} compromised entr${COMPROMISED.length === 1 ? "y" : "ies"}, scanned ${new Set(out.map((r) => r.file)).size} file(s), ${STRICT ? "strict (transitive + fresh pins fail)" : "direct-only (transitive/fresh = advisory)"})\n`);
  if (NO_BASELINE) stdout.write("baseline: disabled (--no-baseline) — new adoptions will report as TOO_NEW, not UNAGED_NEW_DEP\n");
  if (skipped.length) stdout.write(`pyproject: ${skipped.length} non-exact specifier(s) not evaluated (see --json)\n`);
  stdout.write("\n");

  const headers = ["ECO", "PACKAGE", "CURRENT", "STATUS", "LATEST", "SCOPE", "NOTE"];
  const keys = ["ecosystem", "name", "current", "status", "latest", "direct", "note"];
  const cell = (r, k) => {
    if (k === "note") return r.note || "";
    return String(r[k] ?? "—");
  };
  const NOTE_W = 100;
  const truncate = (s, max) => (s.length <= max ? s : `${s.slice(0, max - 1)}…`);
  const w = headers.map((h, i) => {
    const max = Math.max(h.length, ...out.map((r) => cell(r, keys[i]).length));
    return keys[i] === "note" ? Math.min(max, NOTE_W) : max;
  });
  stdout.write(headers.map((h, i) => h.padEnd(w[i])).join("  ") + "\n");
  for (const r of out) {
    const note = r.revisitAfter ? `${r.note} · eligible ${r.revisitAfter}` : r.note;
    const line = ["ecosystem", "name", "current", "status", "latest", "direct"].map((k, i) => cell(r, k).padEnd(w[i])).join("  ") + "  " + truncate(note || "", NOTE_W);
    const color = r.status === "OK" ? "\x1b[32m" : isBlocking(r) ? "\x1b[31m" : "\x1b[33m";
    stdout.write(color + line + "\x1b[0m\n");
  }

  const summary = {};
  for (const r of out) summary[r.status] = (summary[r.status] || 0) + 1;
  stdout.write("\nSummary: " + Object.entries(summary).map(([s, c]) => `${c} ${s}`).join(", "));
  const advisory = out.filter((r) => r.status !== "OK" && !isBlocking(r));
  if (advisory.length) stdout.write(`  | ${advisory.length} advisory (transitive/fresh pins; --strict to escalate)`);
  stdout.write("\n");

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
