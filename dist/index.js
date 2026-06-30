const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const VERSION = "2026.06.30";
const MAX_FILES = 5000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FINDINGS = 250;
const MAX_EXTRACTED_BYTES = 100 * 1024 * 1024;
const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "venv", ".venv", "__pycache__", "target", "out", "tmp", ".cache"
]);
const TEXT_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".html", ".htm",
  ".css", ".scss", ".md", ".txt", ".env", ".yml", ".yaml", ".toml", ".ini",
  ".php", ".py", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".sh",
  ".dockerfile", ".conf", ".config", ".properties", ".xml", ".sql"
]);
const NESTED_ARCHIVES = new Set([".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz"]);
const MANIFESTS = new Set([
  "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
  "requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock",
  "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
  "go.mod", "Cargo.toml", "pom.xml"
]);

function input(name, required = false) {
  const normalized = `INPUT_${name.toUpperCase().replace(/-/g, "_")}`;
  const raw = `INPUT_${name.toUpperCase()}`;
  const envName = `DOLLYP_${name.toUpperCase().replace(/-/g, "_")}`;
  const value = process.env[envName] || process.env[normalized] || process.env[raw] || "";
  if (required && !value.trim()) throw new Error(`Missing required input: ${name}`);
  return value.trim();
}

function safeEndpoint(value) {
  const url = new URL(value);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid task endpoint protocol");
  return url.toString().replace(/\/+$/, "");
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text.slice(0, 200) }; }
  if (!response.ok) {
    throw new Error(`DollyP endpoint failed (${response.status}): ${String(data.error || "request failed").slice(0, 180)}`);
  }
  return data;
}

async function githubOidcToken() {
  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) return null;
  const separator = requestUrl.includes("?") ? "&" : "?";
  const response = await fetch(`${requestUrl}${separator}audience=dollyp-source-scan`, {
    headers: { Authorization: `Bearer ${requestToken}` }
  });
  if (!response.ok) throw new Error(`Could not obtain GitHub OIDC token (${response.status})`);
  const body = await response.json();
  return body.value || null;
}

function redact(value) {
  return String(value || "")
    .replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_KEY]")
    .replace(/AIza[0-9A-Za-z_-]{20,}/g, "[REDACTED_GOOGLE_KEY]")
    .replace(/sk_live_[0-9a-zA-Z]{12,}/g, "[REDACTED_STRIPE_SECRET]")
    .replace(/gh[pousr]_[0-9A-Za-z]{20,}/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/FLWSECK_[A-Z]+-[0-9a-zA-Z-]+/g, "[REDACTED_FLUTTERWAVE_SECRET]")
    .replace(/eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/g, "[REDACTED_JWT]")
    .replace(/((?:password|passwd|secret|token|api[_-]?key|client_secret|service_role)\s*[:=]\s*['"])[^'"]{4,}(['"])/gi, "$1[REDACTED]$2");
}

function rel(root, file) {
  return path.relative(root, file).split(path.sep).join("/");
}

function stableId(rule, filePath, line) {
  return `${rule}:${crypto.createHash("sha1").update(`${filePath}:${line}`).digest("hex").slice(0, 12)}`;
}

function snippet(line) {
  return redact(line).trim().slice(0, 220);
}

function finding(rule, opts) {
  return {
    id: stableId(rule, opts.path || "project", opts.line || 0),
    category: opts.category || "security",
    severity: opts.severity || "warning",
    confidence: opts.confidence || "confirmed",
    title: opts.title,
    description: opts.description,
    path: opts.path || null,
    lineStart: opts.line || null,
    lineEnd: opts.lineEnd || opts.line || null,
    snippet: opts.snippet ? snippet(opts.snippet) : null,
    evidenceType: opts.evidenceType || rule,
    fix: opts.fix,
    verification: opts.verification,
    references: opts.references || []
  };
}

const FIX = {
  secret: {
    fix: "Revoke the exposed credential, rotate it in the provider dashboard, move the replacement into server-side secret storage, and remove it from git history where applicable.",
    verification: "Search the repository and deployed client bundles for the old key pattern, then rerun this source scan.",
    references: ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]
  },
  env: {
    fix: "Remove .env files from source control and distribute a .env.example file with placeholder values instead.",
    verification: "Confirm .env is ignored by git and rerun this scan.",
    references: ["https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"]
  },
  injection: {
    fix: "Replace string-based HTML or code execution with safe DOM APIs, framework escaping, or a reviewed sanitizer such as DOMPurify where HTML input is required.",
    verification: "Rerun the scan and review the affected code path with untrusted input test cases.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML", "https://owasp.org/www-community/attacks/xss/"]
  },
  config: {
    fix: "Tighten the configuration to the minimum required access and disable development/debug behavior in production.",
    verification: "Review the deployed configuration and rerun the scan.",
    references: ["https://owasp.org/www-project-top-ten/"]
  },
  deps: {
    fix: "Run the package manager's official audit command in your own trusted environment and update vulnerable dependencies based on verified advisories.",
    verification: "Run an authenticated dependency audit locally or in CI and confirm no critical advisories remain.",
    references: ["https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts"]
  }
};

function isBinary(buffer) {
  if (!buffer.length) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 1024));
  return sample.includes(0);
}

function shouldRead(file) {
  const base = path.basename(file);
  const ext = base.toLowerCase() === "dockerfile" ? ".dockerfile" : path.extname(base).toLowerCase();
  return TEXT_EXTS.has(ext) || MANIFESTS.has(base) || base.startsWith(".env") || base === ".gitignore";
}

function walk(root) {
  const files = [];
  const stack = [root];
  while (stack.length && files.length <= MAX_FILES) {
    const dir = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) files.push(full);
      if (files.length > MAX_FILES) break;
    }
  }
  return files;
}

function scanFile(root, file, findings, counters) {
  const relative = rel(root, file);
  const base = path.basename(file);
  const ext = path.extname(base).toLowerCase();
  let stat;
  try { stat = fs.statSync(file); } catch { return; }
  if (NESTED_ARCHIVES.has(ext)) {
    findings.push(finding("nested-archive", {
      category: "configuration",
      severity: "warning",
      title: "Nested archive present in scanned source",
      description: "Nested archives are not expanded by DollyP because they can hide large or unsafe content.",
      path: relative,
      line: 1,
      fix: "Remove nested archives from the source package and scan the extracted project directly.",
      verification: "Confirm the archive file is gone and rerun the scan.",
      references: ["https://owasp.org/www-community/attacks/Zip_Bomb"]
    }));
    counters.skipped++;
    return;
  }
  if (stat.size > MAX_FILE_BYTES) { counters.skipped++; return; }
  if (!shouldRead(file)) { counters.skipped++; return; }
  const buffer = fs.readFileSync(file);
  if (isBinary(buffer)) { counters.skipped++; return; }
  const text = buffer.toString("utf8");
  counters.scanned++;
  const lines = text.split(/\r?\n/);

  if (base.startsWith(".env")) {
    findings.push(finding("env-file", {
      category: "security",
      severity: "critical",
      title: ".env file included in source",
      description: "Environment files commonly contain production credentials and should not be committed or uploaded for scanning.",
      path: relative,
      line: 1,
      evidenceType: "secret_file",
      ...FIX.env
    }));
  }

  if (base === ".gitignore") {
    const required = [".env", ".env.*", "node_modules", "dist", "build"];
    const missing = required.filter((item) => !text.includes(item));
    if (missing.length) {
      findings.push(finding("weak-gitignore", {
        category: "configuration",
        severity: "warning",
        title: ".gitignore misses common sensitive/generated paths",
        description: `The .gitignore file does not mention: ${missing.join(", ")}.`,
        path: relative,
        line: 1,
        snippet: lines.slice(0, 8).join(" "),
        fix: "Add sensitive and generated paths such as .env, .env.*, node_modules, dist, build, and coverage to .gitignore.",
        verification: "Run git status after creating a local .env file and confirm it is ignored.",
        references: ["https://git-scm.com/docs/gitignore"]
      }));
    }
  }

  if (MANIFESTS.has(base)) {
    findings.push(finding("dependency-manifest", {
      category: "dependencies",
      severity: "info",
      title: "Dependency manifest detected",
      description: "A dependency manifest or lockfile was found. DollyP records this but does not invent vulnerability claims without a verified advisory lookup.",
      path: relative,
      line: 1,
      fix: FIX.deps.fix,
      verification: FIX.deps.verification,
      references: FIX.deps.references
    }));
  }

  const rules = [
    [/AKIA[0-9A-Z]{16}/, "aws-key", "critical", "AWS access key pattern detected", "A value matching the AWS access key format appears in source code."],
    [/sk_live_[0-9a-zA-Z]{12,}/, "stripe-live-secret", "critical", "Stripe live secret key pattern detected", "A Stripe live secret key appears to be hardcoded."],
    [/gh[pousr]_[0-9A-Za-z]{20,}/, "github-token", "critical", "GitHub token pattern detected", "A GitHub token appears to be hardcoded."],
    [/FLWSECK_[A-Z]+-[0-9a-zA-Z-]+/, "flutterwave-secret", "critical", "Flutterwave secret key pattern detected", "A Flutterwave secret key appears to be hardcoded."],
    [/service_role[^A-Za-z0-9_-]{0,20}eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/i, "supabase-service-role", "critical", "Supabase service role key exposure risk", "A Supabase service role key appears to be present in source code."],
    [/(password|passwd|secret|token|api[_-]?key|client_secret)\s*[:=]\s*['"][^'"]{8,}['"]/i, "hardcoded-secret", "critical", "Hardcoded credential-like value", "A credential-like assignment appears in source code."],
    [/\beval\s*\(/, "eval", "warning", "eval usage detected", "eval executes strings as code and is unsafe with untrusted input."],
    [/\bnew\s+Function\s*\(/, "new-function", "warning", "new Function usage detected", "new Function executes strings as code and is unsafe with untrusted input."],
    [/document\.write\s*\(/, "document-write", "warning", "document.write usage detected", "document.write can create XSS risks when content is influenced by users."],
    [/\.innerHTML\s*=/, "inner-html", "warning", "innerHTML assignment detected", "Direct innerHTML assignment can introduce XSS when content is not strictly trusted."],
    [/dangerouslySetInnerHTML\s*=\s*\{/, "dangerously-set-html", "warning", "React dangerouslySetInnerHTML usage detected", "dangerouslySetInnerHTML bypasses React escaping and requires sanitizer review."],
    [/(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*['"][^'"]*(token|password|secret|jwt|auth)/i, "browser-token-storage", "warning", "Sensitive token stored in browser storage", "Long-lived auth secrets in localStorage/sessionStorage are exposed to XSS."],
    [/Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*/i, "cors-wildcard", "warning", "Wildcard CORS configuration detected", "Wildcard CORS can expose APIs more broadly than intended."],
    [/(md5|sha1)\s*\([^)]*(password|passwd)/i, "weak-password-hash", "critical", "Weak password hashing pattern detected", "MD5/SHA1 are not appropriate for password storage."],
    [/(debug|devtools)\s*[:=]\s*true/i, "debug-enabled", "info", "Debug/development flag enabled", "Debug settings can leak implementation details if shipped to production."],
    [/permissions:\s*write-all/i, "github-permissions-write-all", "warning", "GitHub Actions write-all permissions", "Workflow permissions are broader than most scanners need."],
    [/pull_request_target:/i, "github-pr-target", "warning", "pull_request_target workflow trigger detected", "pull_request_target can expose privileged tokens to untrusted pull request code if misused."]
  ];

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    for (const [regex, rule, severity, title, description] of rules) {
      if (regex.test(line)) {
        const kind = String(rule).includes("secret") || String(rule).includes("key") || String(rule).includes("token") || String(rule).includes("role") ? FIX.secret : String(rule).includes("html") || String(rule).includes("eval") || String(rule).includes("function") || String(rule).includes("write") ? FIX.injection : FIX.config;
        findings.push(finding(rule, {
          category: String(rule).includes("manifest") ? "dependencies" : "security",
          severity,
          title,
          description,
          path: relative,
          line: index + 1,
          snippet: line,
          ...kind
        }));
      }
    }
    if (findings.length >= MAX_FINDINGS) return;
  }
}

function scan(root) {
  const findings = [];
  const counters = { scanned: 0, skipped: 0 };
  const files = walk(root);
  if (files.length > MAX_FILES) {
    findings.push(finding("file-count-limit", {
      category: "configuration",
      severity: "warning",
      title: "Project exceeds source scan file limit",
      description: `More than ${MAX_FILES} files were discovered. DollyP scanned the first supported files and skipped the rest.`,
      path: null,
      line: 1,
      fix: "Remove generated dependencies/build outputs from the scan input and rerun.",
      verification: "Confirm ignored directories are excluded and rerun the scan.",
      references: ["https://git-scm.com/docs/gitignore"]
    }));
  }
  const hasGitignore = files.some((file) => path.basename(file) === ".gitignore");
  if (!hasGitignore) {
    findings.push(finding("missing-gitignore", {
      category: "configuration",
      severity: "warning",
      title: ".gitignore file not found",
      description: "No .gitignore was found in the scanned source root, increasing the chance of committing secrets or generated files.",
      path: ".gitignore",
      line: 1,
      fix: "Add a .gitignore containing at least .env, .env.*, node_modules, dist, build, coverage, and local editor files.",
      verification: "Run git check-ignore .env after adding the file.",
      references: ["https://git-scm.com/docs/gitignore"]
    }));
  }
  for (const file of files.slice(0, MAX_FILES)) {
    scanFile(root, file, findings, counters);
    if (findings.length >= MAX_FINDINGS) break;
  }
  return { findings: findings.slice(0, MAX_FINDINGS), scannedFiles: counters.scanned, skippedFiles: counters.skipped };
}

function validateAndExtractZip(zipPath, outDir) {
  const script = `
import os, sys, zipfile, stat
from pathlib import PurePosixPath
zip_path, out_dir = sys.argv[1], sys.argv[2]
max_files = ${MAX_FILES}
max_total = ${MAX_EXTRACTED_BYTES}
max_file = ${MAX_FILE_BYTES}
nested = {'.zip','.tar','.gz','.tgz','.rar','.7z','.bz2','.xz'}
ignored = {'node_modules','.git','dist','build','.next','coverage','vendor','venv','.venv','__pycache__','target','out','tmp','.cache'}
total = 0
count = 0
with zipfile.ZipFile(zip_path) as z:
    infos = z.infolist()
    if len(infos) > max_files:
        raise SystemExit('ZIP contains too many entries')
    for info in infos:
        name = info.filename.replace('\\\\', '/')
        p = PurePosixPath(name)
        parts = [part for part in p.parts if part not in ('', '.')]
        if not parts:
            continue
        if p.is_absolute() or '..' in parts:
            raise SystemExit('ZIP contains unsafe path')
        if any(part in ignored for part in parts):
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise SystemExit('ZIP contains symlink')
        if info.is_dir():
            continue
        ext = os.path.splitext(name.lower())[1]
        if ext in nested:
            raise SystemExit('ZIP contains nested archive')
        if info.file_size > max_file:
            continue
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 100 and info.file_size > 1024 * 1024:
            raise SystemExit('ZIP has unsafe compression ratio')
        total += info.file_size
        count += 1
        if total > max_total:
            raise SystemExit('ZIP extracted content is too large')
        target = os.path.abspath(os.path.join(out_dir, *parts))
        base = os.path.abspath(out_dir) + os.sep
        if not target.startswith(base):
            raise SystemExit('ZIP extraction target escaped workspace')
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with z.open(info) as src, open(target, 'wb') as dst:
            remaining = max_file + 1
            while remaining > 0:
                chunk = src.read(min(65536, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)
            if remaining <= 0:
                raise SystemExit('ZIP file exceeds per-file limit')
print(str(count))
`;
  const result = spawnSync("python3", ["-c", script, zipPath, outDir], { encoding: "utf8", timeout: 120000 });
  if (result.status !== 0) throw new Error((result.stderr || result.stdout || "Invalid ZIP").trim().slice(0, 180));
}

async function main() {
  const mode = input("mode", true);
  const taskToken = input("task-token");
  const scanIdInput = input("scan-id");
  const endpoint = safeEndpoint(input("task-endpoint", true));
  if (!["zip", "repository"].includes(mode)) throw new Error("mode must be zip or repository");

  let claim;
  let resultToken;
  try {
    const oidcToken = taskToken ? null : await githubOidcToken();
    if (!taskToken && (!scanIdInput || !oidcToken)) throw new Error("Missing source scan identity");
    claim = await postJson(`${endpoint}/source-scan-worker-claim`, taskToken ? { taskToken } : { scanId: scanIdInput, oidcToken });
    resultToken = claim.resultToken;
    let root;
    let cleanupRoot;
    if (mode === "zip") {
      if (!claim.signedDownloadUrl) throw new Error("ZIP claim did not include a download URL");
      cleanupRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dollyp-source-"));
      const zipPath = path.join(cleanupRoot, "source.zip");
      const zipRes = await fetch(claim.signedDownloadUrl);
      if (!zipRes.ok) throw new Error(`Could not download ZIP (${zipRes.status})`);
      const zipBuffer = Buffer.from(await zipRes.arrayBuffer());
      if (zipBuffer.length > 25 * 1024 * 1024) throw new Error("ZIP exceeds size limit");
      fs.writeFileSync(zipPath, zipBuffer);
      root = path.join(cleanupRoot, "extract");
      fs.mkdirSync(root, { recursive: true });
      validateAndExtractZip(zipPath, root);
    } else {
      root = path.resolve(input("target-path") || process.cwd());
      if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error("target-path is not a directory");
    }

    const result = scan(root);
    await postJson(`${endpoint}/source-scan-submit-result`, {
      resultToken,
      scanId: claim.scanId,
      findings: result.findings,
      scannedFiles: result.scannedFiles,
      skippedFiles: result.skippedFiles,
      scannerVersion: VERSION
    });

    if (cleanupRoot) fs.rmSync(cleanupRoot, { recursive: true, force: true });
  } catch (error) {
    const message = error && error.message ? error.message : "Source scan failed";
    if (resultToken || taskToken) {
      try {
        await postJson(`${endpoint}/source-scan-fail`, {
          resultToken,
          taskToken: resultToken ? undefined : taskToken,
          scanId: claim && claim.scanId,
          error: message.slice(0, 180)
        });
      } catch {}
    }
    throw error;
  }
}

main().catch((error) => {
  console.error(`DollyP source scan failed: ${error.message}`);
  process.exit(1);
});
