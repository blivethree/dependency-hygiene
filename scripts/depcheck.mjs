#!/usr/bin/env node
// depcheck.mjs — dependency freshness + 14-day age gate.
// Python requirements.txt + Node package-lock.json. Stdlib Node 20+ only (no installs).
//
//   node scripts/depcheck.mjs [paths...] [--cooldown=14] [--json]
//   exit 0 = clean, 1 = violations, 2 = could not run.
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { argv, cwd, exit, stdout } from "node:process";
import { setTimeout } from "node:timers/promises";

const COOLDOWN_DAYS = Number(argv.find((a) => a.startsWith("--cooldown="))?.split("=")[1]) || 14;
const JSON_OUT = argv.includes("--json");
const FIX = argv.includes("--fix");
const SCAN_DIRS = argv.slice(2).filter((a) => !a.startsWith("--"));
if (!SCAN_DIRS.length) SCAN_DIRS.push(cwd());

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".cache", ".backups", "retire_app_backup_20260628_160831", ".nvm", ".local", ".npm", ".vscode-server", ".docker"]);
const sleep = (ms) => setTimeout(ms).then(() => {});

const isPrerelease = (v) => /(\.|^)(a|b|rc|alpha|beta|dev)(\.|\d|$)/i.test(v) || v.includes("-");
const ageDays = (iso) => (Date.now() - new Date(iso).getTime()) / 86400000;
const gte = (a, b) => {
  const pa = String(a).split(".").map((n) => Number(n) || 0), pb = String(b).split(".").map((n) => Number(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const da = pa[i] || 0, db = pb[i] || 0; if (da !== db) return da - db; } return 0;
};
async function getJSON(url) {
  for (let i = 0; i < 3; i++) {
    try { const r = await fetch(url); if (r.ok) return await r.json(); } catch { if (i < 2) await sleep(500 * (i + 1)); }
  }
  return null;
}

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
  return all.filter((f) => { const n = f.split("/").pop(); return n === "requirements.txt" || n === "package-lock.json" || n === "package.json"; }).filter((f) => !/\.(bak|orig|old)$/.test(f));
}

function parseRequirements(text) {
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
function parseLock(text) {
  const lock = JSON.parse(text);
  const deps = [];
  for (const [key, meta] of Object.entries(lock.packages || {})) {
    if (key === "" || !meta || !meta.version) continue;
    deps.push({ ecosystem: "npm", name: key.replace(/^node_modules\//, ""), op: "locked", current: meta.version, dev: !!meta.dev });
  }
  return deps;
}

async function pypiReleases(name) {
  const d = await getJSON(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!d) return null;
  const rels = [];
  for (const [v, files] of Object.entries(d.releases || {})) {
    if (!files || !files.length || isPrerelease(v)) continue;
    const t = files.map((f) => new Date(f.upload_time).getTime()).filter(Boolean);
    if (t.length) rels.push({ v, lastUpload: new Date(Math.max(...t)).toISOString() });
  }
  rels.sort((a, b) => new Date(b.lastUpload) - new Date(a.lastUpload));
  return { latest: d.info?.version || rels[0]?.v || null, rels };
}
async function npmReleases(name) {
  const d = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (!d) return null;
  const rels = [];
  const time = d.time || {};
  for (const [v, t] of Object.entries(time)) { if (["created", "modified"].includes(v) || isPrerelease(v)) continue; rels.push({ v, lastUpload: t }); }
  rels.sort((a, b) => new Date(b.lastUpload) - new Date(a.lastUpload));
  return { latest: d["dist-tags"]?.latest || rels[0]?.v || null, rels };
}

function classify(dep, reg) {
  if (!reg) return { status: "UNRESOLVING", note: "registry lookup failed" };
  if (!dep.current) return reg.latest ? { status: "UNPINNED", note: `latest is ${reg.latest}` } : { status: "UNRESOLVING", note: "no registry info" };
  if (isPrerelease(dep.current)) return { status: "PRERELEASE", note: `current ${dep.current} is a pre-release` };
  const cur = reg.rels.find((r) => r.v === dep.current);
  const curAge = cur ? ageDays(cur.lastUpload) : null;
  const newest = reg.rels[0];
  if (!newest) return { status: "UNRESOLVING", note: "no stable releases" };
  const safeTarget = reg.rels.find((r) => ageDays(r.lastUpload) >= COOLDOWN_DAYS) || null;

  if (dep.current === newest.v) {
    if (curAge !== null && curAge >= COOLDOWN_DAYS) return { status: "OK", note: `latest (${curAge.toFixed(0)}d old)` };
    return { status: "TOO_NEW", note: `latest ${newest.v} < ${COOLDOWN_DAYS}d old (age=${curAge?.toFixed(0) ?? "?"}d)` };
  }
  if (!safeTarget) return { status: "TOO_NEW", note: `no cooldown-safe version; latest ${newest.v} is fresh` };
  if (curAge !== null && curAge >= COOLDOWN_DAYS && gte(dep.current, safeTarget.v)) {
    return { status: "OK", note: `current aged; latest ${newest.v} is fresh` };
  }
  return { status: "OUTDATED", note: `bump to ${safeTarget.v} (cooldown-safe) | latest: ${newest.v}` };
}

// ── main ──
const manifests = await findManifests();
const directSources = manifests.map((f) => ({ path: f, name: f.split("/").pop() }));
const pyFiles = directSources.filter((f) => f.name === "requirements.txt").map((f) => f.path);
const lockFiles = directSources.filter((f) => f.name === "package-lock.json").map((f) => f.path);
// also scan standalone package.json (no lockfile) as source of truth for names
const pkgFiles = directSources.filter((f) => f.name === "package.json").map((f) => f.path);

const rows = [];
for (const f of pyFiles) {
  const text = await readFile(f, "utf8");
  for (const d of parseRequirements(text)) {
    const reg = await pypiReleases(d.name);
    const r = classify(d, reg);
    rows.push({ file: relative(cwd(), f), ecosystem: "pypi", name: d.name, current: d.current || "—", latest: reg?.latest || "—", ...r });
  }
}
for (const f of lockFiles) {
  const lock = JSON.parse(await readFile(f, "utf8"));
  // resolve sibling package.json for dev flag
  const pkgPath = join(f, "..", "package.json");
  let pkg = {};
  try { pkg = JSON.parse(await readFile(pkgPath, "utf8")); } catch {}
  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const pkgText = await readFile(f, "utf8");
  for (const d of parseLock(pkgText)) {
    const isDirect = allDeps[d.name] !== undefined;
    const reg = await npmReleases(d.name);
    const r = classify(d, reg);
    rows.push({ file: relative(cwd(), f), ecosystem: d.dev ? "npm(dev)" : "npm", name: d.name, current: d.current || "—", latest: reg?.latest || "—", direct: isDirect ? "direct" : "transitive", ...r });
  }
}

if (JSON_OUT) { stdout.write(JSON.stringify(rows, null, 2) + "\n"); exit(rows.some((r) => ["OUTDATED", "PRERELEASE", "UNPINNED", "UNRESOLVING"].includes(r.status)) ? 1 : 0); }

if (!rows.length) { console.log("depcheck: no requirements.txt or package-lock.json found."); exit(0); }

console.log(`\ndepcheck  (cooldown=${COOLDOWN_DAYS}d, scanned ${new Set(rows.map((r) => r.file)).size} file(s))\n`);
const headers = ["ECO", "PACKAGE", "CURRENT", "STATUS", "LATEST", "SCOPE", "NOTE"];
const w = headers.map((h) => Math.max(h.length, ...rows.map((r) => String(r[h.toLowerCase()] || r[h.replace(/([A-Z])/g, "_$1").toLowerCase()] || "").length)));
const fmt = (r) => headers.map((h, i) => String(r[h.toLowerCase()] || r[h.replace(/([A-Z])/g, "_$1").toLowerCase()] || "").padEnd(w[i])).join("  ");
stdout.write(headers.join("  ".repeat(1)) + "\n");
for (const r of rows) {
  const line = [
    r.ecosystem.padEnd(w[0]),
    r.name.padEnd(w[1]),
    r.current.toString().padEnd(w[2]),
    r.status.padEnd(w[3]),
    r.latest.padEnd(w[4]),
    (r.direct || "—").padEnd(w[5]),
    r.note,
  ].join("  ");
  // color-code
  let color = ""; const reset = "\x1b[0m";
  if (r.status === "OK") color = "\x1b[32m";
  else if (r.status === "TOO_NEW") color = "\x1b[33m";
  else color = "\x1b[31m";
  stdout.write(color + line + reset + "\n");
}
const summary = {};
for (const r of rows) summary[r.status] = (summary[r.status] || 0) + 1;
stdout.write("\nSummary: " + Object.entries(summary).map(([s, c]) => `${c} ${s}`).join(", ") + "\n");

const fail = rows.filter((r) => ["OUTDATED", "PRERELEASE", "UNPINNED", "UNRESOLVING"].includes(r.status));
exit(fail.length ? 1 : 0);
