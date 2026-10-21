#!/usr/bin/env node
// imgcheck.mjs — base-image policy + drift detection for Dockerfiles.
// Stdlib Node 20+ only (no installs).
//
//   node scripts/imgcheck.mjs [paths...] [--policy=./deps-policy.json] [--fail]
//
// Policy (deps-policy.json):
//   {
//     "allowedBaseImages": ["python:3.12-slim-trixie", "python:3.12-slim-bookworm", ...],
//     "allowedFamilies": ["debian", "alpine"],   // OS lineage; swap = reject
//     "requirePin": true                        // reject :latest / floating with no digest or codename
//   }
//
// Exit codes: 0 = clean, 1 = policy violation, 2 = could not run.
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, basename } from "node:path";
import { argv, cwd, exit, stdout } from "node:process";

let policyPath = "deps-policy.json";
for (let i = 2; i < argv.length; i++) {
  if (argv[i].startsWith("--policy=")) policyPath = argv[i].slice(9);
  else if (argv[i] === "--policy" && argv[i + 1] && !argv[i + 1].startsWith("--")) policyPath = argv[++i];
}
const FAIL = argv.includes("--fail");
const SCAN_DIRS = argv.slice(2).filter((a) => !a.startsWith("--") && a !== "--policy" && !argv[argv.indexOf(a) - 1]?.startsWith("--policy"));
if (!SCAN_DIRS.length) SCAN_DIRS.push(cwd());

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".cache", ".backups", "retire_app_backup_20260628_160831", ".nvm", ".local", ".npm", ".vscode-server", ".docker"]);

async function walk(dir, out) {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    try { (await stat(full)).isDirectory() ? await walk(full, out) : out.push(full); } catch {}
  }
}

async function findDockerfiles() {
  const all = [];
  for (const d of SCAN_DIRS) await walk(d, all);
  return all.filter((f) => /Dockerfile.*$|^Dockerfile/.test(basename(f))).filter((f) => !/\.(bak|orig|old)$/.test(f));
}

let policy = null;
try { policy = JSON.parse(await readFile(policyPath, "utf8")); } catch { console.error(`imgcheck: could not read ${policyPath} (using built-in defaults)`); }
const ALLOWED = new Set(policy?.allowedBaseImages || []);
const ALLOWED_FAM = new Set(policy?.allowedFamilies || ["debian", "alpine"]);
const REQUIRE_PIN = policy?.requirePin !== false; // default true

// ── FROM parsing ───
const PRERELEASE = /(\-rc\.?\d*|rc\d|\-beta|\-alpha|\-dev|a\d|b\d)/i;
const isPrereleaseTag = (tag) => PRERELEASE.test(tag);

// family detect: debian|bookworm|trixie|bullseye|alpine|slim|ubuntu|jammy|fedora
const FAMILY_OF = (img) => {
  if (/\balpine\b/.test(img)) return "alpine";
  if (/\b(debian|bookworm|trixie|bullseye|slim|buster|stretch)\b/.test(img)) return "debian";
  if (/\b(ubuntu|jammy|noble|focal)\b/.test(img)) return "ubuntu";
  if (/\b(fedora|rhel|centos|rocky|amazonlinux)\b/.test(img)) return "rpm";
  if (/\b(distroless|scratch)\b/.test(img)) return "minimal";
  return "unknown";
};

// floating = no codename/distro and no digest. Note: "slim" is a variant, not a
// codename, so `python:3.12-slim` (no Debian codename) counts as floating/unpinned.
const CODENAMES = /\b(bookworm|trixie|bullseye|alpine|ubuntu|jammy|noble|focal|stretch|buster|bookworm|plucky|resolute|rhel|fedora|rocky|distroless)\b/;
const isFloating = (image) => !/:/.test(image) || (/:/.test(image) && !CODENAMES.test(image.split(":")[1]));
const hasDigest = (image) => image.includes("@sha256:");

const violations = [];
const warnings = [];

function checkLine(file, lineNo, fromLine, stageName) {
  // FROM [--platform=...] image[:tag|@digest] [AS name]
  const cleaned = fromLine.replace(/--platform=[^\s]+/, "").trim();
  const parts = cleaned.replace(/^FROM\s+/, "").split(/\s+/);
  let image = parts[0];
  const asIdx = parts.indexOf("AS");
  if (asIdx !== -1) { image = parts.slice(0, asIdx).join(" "); }
  else image = parts[0];

  const name = (stageName) || (image + (asIdx !== -1 ? `-stage` : ""));

  // parse image:tag@digest
  const [pureImage, digest] = image.split("@");
  const [repo, tag] = pureImage.split(":");
  const display = pureImage;

  // PRERELEASE
  if (tag && isPrereleaseTag(tag)) {
    violations.push({ file, line: lineNo, image: display, reason: "PRERELEASE_TAG", detail: `tag ${tag} is a pre-release; never ship pre-release base images` });
    return;
  }

  // OS-family swap (multi-FROM swap)
  const fam = FAMILY_OF(display);
  if (fam !== "unknown" && !ALLOWED_FAM.has(fam)) {
    violations.push({ file, line: lineNo, image: display, reason: "DISALLOWED_FAMILY", detail: `${fam} base images are disabled for this repo` });
  }

  // floating / unpinned
  if (REQUIRE_PIN && isFloating(display) && !hasDigest(image)) {
    const isLatest = tag === "latest";
    violations.push({ file, line: lineNo, image: display, reason: isLatest ? "FLOATING_LATEST" : "UNPINNED_FAMILY", detail: `${tag ? `tag "${tag}"` : "no tag"} is floating; pin to a Debian codename or use :trixie/:bookworm + a digest` });
    return;
  }

  // allowlist
  if (ALLOWED.size > 0 && !ALLOWED.has(display) && !ALLOWED.has(pureImage)) {
    // maybe it's pinned with digest of an allowed image — also accept repo:tag form
    const matched = [...ALLOWED].some((a) => a === pureImage || a === repo + (tag ? `:${tag}` : ""));
    if (!matched) {
      violations.push({ file, line: lineNo, image: display, reason: "NOT_IN_ALLOWLIST", detail: `base image not in allowlist (${[...ALLOWED].join(", ")})` });
    }
  }

  // drift: warn if same repo uses different OS family across files — checked after parse
  return { image: pureImage, repo, tag, family: fam, file, lineNo, digest: hasDigest(image) };
}

// ── main ──
const targets = await findDockerfiles();
if (!targets.length) { console.log("imgcheck: no Dockerfiles found."); exit(0); }

let results = [];
for (const f of targets) {
  const text = await readFile(f, "utf8");
  let stageName = null;
  text.split("\n").forEach((line, i) => {
    if (!/^\s*FROM\s+/.test(line)) return;
    const m = line.match(/(?:AS|as)\s+(\S+)/i);
    stageName = m ? m[1] : null;
    const res = checkLine(f, i + 1, line, stageName);
    if (res) results.push(res);
  });
}

// drift detection: same image repo, different families or tags-within-family-but-
// different majors
const byRepo = new Map();
for (const r of results) {
  (byRepo.get(r.repo) || []).push(r);
}
for (const [repo, rs] of byRepo) {
  const families = new Set(rs.map((r) => r.family));
  if (families.size > 1) {
    violations.push({ file: rs[0].file, line: rs[0].lineNo, image: repo, reason: "OS_DRIFT", detail: `same image uses different OS families across files: ${[...families].join(", ")} → pin both` });
  }
  const tags = new Set(rs.map((r) => r.tag || "(none)"));
  if (tags.size > 1) {
    warnings.push({ file: rs[0].file, image: repo, reason: "TAG_DRIFT", detail: `inconsistent tags: ${[...tags].join(", ")} → standardize one tag + digest` });
  }
}

// output
console.log(`\nimgcheck  (targets: ${targets.length}, bases: ${results.length})\n`);
if (violations.length === 0 && warnings.length === 0) {
  console.log("PASS   all base images comply with policy.\n");
  exit(0);
}
for (const v of violations) {
  console.log(`FAIL  ${relative(cwd(), v.file)}:${v.line}  ${v.image}`);
  console.log(`        ${v.reason}: ${v.detail}`);
}
for (const w of warnings) {
  console.log(`WARN  ${relative(cwd(), w.file)}  ${w.image}`);
  console.log(`        ${w.reason}: ${w.detail}`);
}
console.log("");
exit((FAIL ? violations.length : 0) ? 1 : 0);
