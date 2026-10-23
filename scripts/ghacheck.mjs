#!/usr/bin/env node
// ghacheck.mjs — GitHub Actions pin freshness + supply-chain drift detection.
// Stdlib Node 20+ only (no installs).
//
//   node scripts/ghacheck.mjs [paths...] [--resolve] [--cooldown=14] [--json] [--fail]
//
// Why this exists: depcheck audits package manifests and imgcheck audits
// Dockerfiles, but `uses:` pins in .github/workflows/*.yml were invisible to
// both. A SHA-pinned action (e.g. `actions/checkout@11d5960... # v4.4.0`) does
// NOT receive security hardening backported to floating major tags, so an old
// pin silently misses fixes that `@v4` users got automatically. That is exactly
// how a v4-era pin survives in a repo whose whole purpose is freshness.
//
// Policy:
//   - Every `uses:` must be a full 40-char commit SHA with a `# vX.Y.Z` comment.
//     Floating tags (@v4, @main) are UNSAFE_REF and block: a tag can be
//     re-pointed at malicious code after review (the tj-actions/changed-files
//     class of attack).
//   - A pin behind the newest release by >= 1 MAJOR version is OUTDATED_MAJOR
//     and blocks. Major bumps are where breaking security changes land, so a
//     major gap is a real risk, not cosmetics.
//   - Minor/patch drift is OUTDATED_MINOR (advisory).
//   - A pin whose resolved release is younger than the cooldown is TOO_NEW:
//     advisory, so a fresh action release can be observed before adoption.
//
// Resolution needs the network (GitHub REST API). Without it the checker still
// validates ref *shape* offline, and says so rather than passing silently.
// Set GITHUB_TOKEN to lift the 60 req/hr anonymous rate limit in CI.
//
// Exit codes: 0 = clean, 1 = violation, 2 = could not run.
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { argv, cwd, env, exit } from "node:process";

const VALUE_FLAGS = new Set(["cooldown", "policy", "api"]);
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
const FAIL = hasFlag("fail");
// --resolve forces the network pass; it is also implied whenever --fail is set,
// since an offline run cannot prove a pin is current and must not gate on a guess.
const RESOLVE = hasFlag("resolve") || FAIL;
const COOLDOWN_DAYS = Number(flagValue("cooldown")) || 14;
const API = (flagValue("api") || env.GHACHECK_API || "https://api.github.com").replace(/\/+$/, "");
const TOKEN = env.GITHUB_TOKEN || env.GH_TOKEN || null;

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".cache", ".backups", ".nvm", ".local", ".npm", ".vscode-server", ".docker", ".venv", "venv", "site-packages"]);

// ── parsing ───
// Match `uses: owner/repo[/path]@ref` and capture a trailing `# comment`.
// Local actions (`uses: ./path`) and docker refs (`uses: docker://...`) are not
// versioned GitHub Actions and are skipped.
const USES_RE = /^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)["']?\s*(?:#\s*(.*))?$/;
const SHA_RE = /^[0-9a-f]{40}$/i;
// A SHA pin is only reviewable next to a human-readable version comment.
const VERSION_COMMENT_RE = /^v?(\d+)\.(\d+)\.(\d+)/;

function parseUses(raw) {
  if (!raw || raw.startsWith("./") || raw.startsWith("docker://") || raw.startsWith("${{")) return null;
  const at = raw.lastIndexOf("@");
  if (at <= 0) return null;
  const slug = raw.slice(0, at);
  const ref = raw.slice(at + 1);
  // owner/repo[/subdir] — keep owner/repo as the action identity.
  const parts = slug.split("/");
  if (parts.length < 2) return null;
  return { repo: `${parts[0]}/${parts[1]}`, subdir: parts.slice(2).join("/") || null, ref };
}

const semverOf = (comment) => {
  if (!comment) return null;
  const m = comment.trim().match(VERSION_COMMENT_RE);
  return m ? { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), text: `v${m[1]}.${m[2]}.${m[3]}` } : null;
};

// A floating ref like `v4` / `v4.1` still names a version, so we can report how
// far behind it is even though it is already failing the UNSAFE_REF shape check.
// Reporting both together avoids the "fix the pin, then discover it's ancient"
// two-step: a floating @v4 is *also* three majors behind.
const versionFromRef = (ref) => {
  const m = String(ref).match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = m[2] === undefined ? null : Number(m[2]);
  const patch = m[3] === undefined ? null : Number(m[3]);
  return { major, minor, patch, text: minor === null ? `v${major}` : patch === null ? `v${major}.${minor}` : `v${major}.${minor}.${patch}`, floating: true };
};

// ── filesystem walk ───
async function walk(dir, out) {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    try { (await stat(full)).isDirectory() ? await walk(full, out) : out.push(full); } catch {}
  }
}

const isWorkflowFile = (f) => /\.ya?ml$/i.test(f) && /(^|[\\/])\.github[\\/]workflows[\\/]/i.test(f);

async function findWorkflows() {
  const all = [];
  for (const d of SCAN_DIRS) await walk(d, all);
  return all.filter(isWorkflowFile);
}

// ── GitHub API ───
const cache = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function gh(path) {
  if (cache.has(path)) return cache.get(path);
  const headers = { accept: "application/vnd.github+json", "user-agent": "ghacheck" };
  if (TOKEN) headers.authorization = `Bearer ${TOKEN}`;
  let attempt = 0;
  for (;;) {
    let res;
    try {
      res = await fetch(`${API}${path}`, { headers });
    } catch (e) {
      cache.set(path, { error: `network: ${e.message}` });
      return cache.get(path);
    }
    // Secondary rate limits and abuse detection answer 403 with a retry hint.
    if ((res.status === 403 || res.status === 429) && attempt < 2) {
      const retry = Number(res.headers.get("retry-after")) || 2 ** attempt;
      await sleep(Math.min(retry, 10) * 1000);
      attempt++;
      continue;
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      cache.set(path, { error: `HTTP ${res.status}${body ? `: ${body.slice(0, 120)}` : ""}` });
      return cache.get(path);
    }
    const body = await res.json();
    cache.set(path, { body });
    return cache.get(path);
  }
}

// Newest non-prerelease release for an action, using the release *date* for the
// cooldown (unlike PyPI, GitHub gives us tag + publish time directly).
async function latestRelease(repo) {
  const r = await gh(`/repos/${repo}/releases/latest`);
  if (r.error || !r.body) return { error: r.error || "no release" };
  const tag = String(r.body.tag_name || "");
  const m = tag.match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return { error: `unparseable tag ${tag}` };
  return {
    tag: `v${m[1]}.${m[2]}.${m[3]}`,
    major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]),
    publishedAt: r.body.published_at || r.body.created_at || null,
  };
}

// ── main ───
const workflows = await findWorkflows();
const rows = [];
const violations = [];
const warnings = [];

for (const file of workflows) {
  const text = await readFile(file, "utf8");
  text.split("\n").forEach((line, i) => {
    const m = line.match(USES_RE);
    if (!m) return;
    const parsed = parseUses(m[1]);
    if (!parsed) return;
    const comment = m[2] ? m[2].trim() : null;
    rows.push({ file, line: i + 1, ...parsed, comment, declared: semverOf(comment) });
  });
}

if (!rows.length) {
  const msg = { check: "ghacheck", workflows: workflows.length, pins: 0 };
  if (JSON_OUT) console.log(JSON.stringify({ ...msg, status: "clean", violations: [], warnings: [] }, null, 2));
  else console.log("ghacheck: no workflow `uses:` pins found.");
  exit(0);
}

// Shape checks are offline and always run.
for (const r of rows) {
  if (!SHA_RE.test(r.ref)) {
    // Best-effort version from the ref so drift can still be reported: a
    // floating @v4 is unsafe *and* often years behind.
    r.declared = r.declared || versionFromRef(r.ref);
    violations.push({
      ...r, reason: "UNSAFE_REF",
      detail: `ref "${r.ref}" is not a full commit SHA; a tag/branch can be re-pointed at malicious code after review — pin the 40-char SHA`,
    });
    continue;
  }
  if (!r.declared) {
    warnings.push({
      ...r, reason: "UNCOMMENTED_PIN",
      detail: `SHA pin has no "# vX.Y.Z" comment; add one so reviewers can tell what version ${r.ref.slice(0, 12)}… is`,
    });
  }
}

// Resolve freshness only when asked (or when gating).
if (RESOLVE) {
  // Floating refs are compared too, so an unsafe ref surfaces its staleness at
  // the same time instead of after it is converted to a SHA.
  const repos = [...new Set(rows.map((r) => r.repo))];
  const latestByRepo = new Map();
  for (const repo of repos) latestByRepo.set(repo, await latestRelease(repo));

  for (const r of rows) {
    const isSha = SHA_RE.test(r.ref);
    const latest = latestByRepo.get(r.repo);
    if (!latest || latest.error) {
      if (isSha) warnings.push({ ...r, reason: "UNRESOLVED", detail: `could not resolve ${r.repo}: ${latest?.error || "unknown error"}` });
      continue;
    }
    r.latest = latest;
    const cur = r.declared;
    if (!cur) continue; // no declared version → already warned as UNCOMMENTED_PIN
    const majGap = latest.major - cur.major;
    const minorGap = majGap === 0 ? latest.minor - cur.minor : 0;
    const patchGap = majGap === 0 && minorGap === 0 ? latest.patch - cur.patch : 0;

    // A floating ref is already blocking as UNSAFE_REF; enrich that violation
    // with the gap rather than adding a second (confusing) OUTDATED_MAJOR row.
    if (!isSha) {
      if (majGap > 0) {
        const v = violations.find((x) => x.file === r.file && x.line === r.line && x.reason === "UNSAFE_REF");
        if (v) v.detail += ` It is also ${majGap} major version(s) behind ${latest.tag} — pin the current major's SHA, not ${cur.text}.`;
      }
      continue;
    }

    if (majGap > 0) {
      violations.push({
        ...r, reason: "OUTDATED_MAJOR",
        detail: `pinned ${cur.text} is ${majGap} major version(s) behind ${latest.tag}; major releases carry security hardening (and SHA pins are excluded from floating-tag backports)`,
      });
    } else if (minorGap > 0 || patchGap > 0) {
      warnings.push({
        ...r, reason: "OUTDATED_MINOR",
        detail: `pinned ${cur.text} is behind ${latest.tag} (same major)`,
      });
    }

    const age = latest.publishedAt ? (Date.now() - new Date(latest.publishedAt).getTime()) / 86400000 : null;
    if (age !== null && age < COOLDOWN_DAYS) {
      warnings.push({
        ...r, reason: "TOO_NEW",
        detail: `latest ${latest.tag} was published ${age.toFixed(1)}d ago (< ${COOLDOWN_DAYS}d cooldown); confirm before adopting`,
      });
    }
  }
}

// A repo pinned at different majors across workflows is drift worth seeing.
const byRepo = new Map();
for (const r of rows) {
  if (!byRepo.has(r.repo)) byRepo.set(r.repo, []);
  byRepo.get(r.repo).push(r);
}
for (const [repo, rs] of byRepo) {
  const majors = new Set(rs.filter((r) => r.declared).map((r) => r.declared.major));
  if (majors.size > 1) {
    warnings.push({
      file: rs[0].file, line: rs[0].line, repo, ref: rs[0].ref, reason: "PIN_DRIFT",
      detail: `same action pinned at different majors: ${[...majors].sort().map((m) => `v${m}`).join(", ")} → standardize`,
    });
  }
}

// ── output ───
const relPath = (f) => relative(cwd(), f) || basename(f);
if (JSON_OUT) {
  console.log(JSON.stringify({
    check: "ghacheck",
    workflows: workflows.length,
    pins: rows.length,
    resolved: RESOLVE,
    status: violations.length ? "violations" : "clean",
    violations: violations.map((v) => ({ file: relPath(v.file), line: v.line, action: v.repo, ref: v.ref, declared: v.declared?.text || null, latest: v.latest?.tag || null, reason: v.reason, detail: v.detail })),
    warnings: warnings.map((w) => ({ file: relPath(w.file), line: w.line, action: w.repo, ref: w.ref, declared: w.declared?.text || null, latest: w.latest?.tag || null, reason: w.reason, detail: w.detail })),
  }, null, 2));
} else {
  console.log(`\nghacheck  (workflows: ${workflows.length}, pins: ${rows.length}${RESOLVE ? "" : ", offline: shape-only"})\n`);
  for (const v of violations) {
    console.log(`FAIL  ${relPath(v.file)}:${v.line}  ${v.repo}@${v.ref.slice(0, 12)}${v.declared ? ` (${v.declared.text})` : ""}`);
    console.log(`        ${v.reason}: ${v.detail}`);
  }
  for (const w of warnings) {
    console.log(`WARN  ${relPath(w.file)}:${w.line}  ${w.repo}@${w.ref.slice(0, 12)}${w.declared ? ` (${w.declared.text})` : ""}`);
    console.log(`        ${w.reason}: ${w.detail}`);
  }
  if (!violations.length && !warnings.length) console.log("PASS   all workflow action pins comply with policy.");
  if (!RESOLVE) console.log("\nnote: freshness not checked (offline shape-only). Re-run with --resolve to compare against latest releases.");
  console.log("");
}

exit(FAIL && violations.length ? 1 : 0);
