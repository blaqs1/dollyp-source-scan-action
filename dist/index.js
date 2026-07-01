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

function readAssignmentExpression(lines, startIndex) {
  const collected = [];
  for (let i = startIndex; i < Math.min(lines.length, startIndex + 12); i++) {
    collected.push(lines[i]);
    if (/;\s*(?:\/\/.*)?$/.test(lines[i])) break;
  }
  return collected.join("\n");
}

function isStaticInnerHtmlAssignment(lines, startIndex) {
  const expression = readAssignmentExpression(lines, startIndex);
  if (!/\.innerHTML\s*=/.test(expression)) return false;
  if (!/\.innerHTML\s*=\s*`/.test(expression)) return false;
  if (/\$\{/.test(expression)) return false;
  return true;
}

function firstLineMatching(lines, regex) {
  const index = lines.findIndex((line) => regex.test(line));
  return index >= 0 ? index + 1 : 1;
}

const COMMAND_EXISTS_CACHE = new Map();

function commandExists(command) {
  if (COMMAND_EXISTS_CACHE.has(command)) return COMMAND_EXISTS_CACHE.get(command);
  const result = spawnSync("bash", ["-lc", `command -v ${command}`], { encoding: "utf8", timeout: 5000 });
  const exists = result.status === 0;
  COMMAND_EXISTS_CACHE.set(command, exists);
  return exists;
}

function sanitizeToolOutput(output) {
  return redact(String(output || ""))
    .split(/\r?\n/)
    .filter((line) => line.trim() && !/^\s*(at\s|File\s")/.test(line))
    .slice(0, 3)
    .join(" ")
    .trim()
    .slice(0, 220);
}

function lineFromOffset(text, offset) {
  const before = String(text || "").slice(0, Math.max(0, offset));
  return before.split(/\r?\n/).length;
}

function lineFromOutput(output) {
  const text = String(output || "");
  const patterns = [
    /line\s+(\d+)/i,
    /:(\d+):\d+:/,
    /:(\d+):\s/,
    /:(\d+)\s/,
    /\((\d+),\d+\)/
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return Math.max(1, Number(match[1]) || 1);
  }
  return 1;
}

function toolSyntaxError(output, fallback) {
  const message = sanitizeToolOutput(output || fallback);
  return { message: message || fallback, line: lineFromOutput(output) };
}

function runSyntaxCheck(file, base, ext) {
  if ([".js", ".mjs", ".cjs"].includes(ext)) {
    const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "JavaScript syntax check failed.");
  }
  if (ext === ".py") {
    const result = spawnSync("python3", ["-m", "py_compile", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "Python syntax check failed.");
  }
  if (/\.(php|inc)$/i.test(base) && commandExists("php")) {
    const result = spawnSync("php", ["-l", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "PHP syntax check failed.");
  }
  if (ext === ".rb" && commandExists("ruby")) {
    const result = spawnSync("ruby", ["-c", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "Ruby syntax check failed.");
  }
  if (ext === ".sh" && commandExists("bash")) {
    const result = spawnSync("bash", ["-n", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "Shell syntax check failed.");
  }
  if (ext === ".go" && commandExists("gofmt")) {
    const result = spawnSync("gofmt", ["-e", "-d", file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0 || /:\d+:\d+:\s/.test(result.stderr || "")) return toolSyntaxError(result.stderr || result.stdout, "Go syntax check failed.");
  }
  if (ext === ".json") {
    try {
      JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
      const message = error && error.message ? String(error.message) : "JSON syntax check failed.";
      const position = Number((message.match(/position\s+(\d+)/i) || [])[1]);
      return {
        message: sanitizeToolOutput(message),
        line: Number.isFinite(position) ? lineFromOffset(fs.readFileSync(file, "utf8"), position) : 1
      };
    }
  }
  if (ext === ".toml") {
    const script = "import sys,tomllib\ntry:\n  tomllib.load(open(sys.argv[1],'rb'))\nexcept tomllib.TOMLDecodeError as e:\n  print(f'line {getattr(e, \"lineno\", 1)}: {e}', file=sys.stderr)\n  sys.exit(1)\n";
    const result = spawnSync("python3", ["-c", script, file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "TOML syntax check failed.");
  }
  if (ext === ".xml") {
    const script = "import sys,xml.etree.ElementTree as ET\ntry:\n  ET.parse(sys.argv[1])\nexcept ET.ParseError as e:\n  line = getattr(e, 'position', (1,0))[0]\n  print(f'line {line}: {e}', file=sys.stderr)\n  sys.exit(1)\n";
    const result = spawnSync("python3", ["-c", script, file], { encoding: "utf8", timeout: 10000 });
    if (result.status !== 0) return toolSyntaxError(result.stderr || result.stdout, "XML syntax check failed.");
  }
  return null;
}

function hasAny(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function lineMatching(lines, regex) {
  const index = lines.findIndex((line) => typeof regex === "function" ? regex(line) : regex.test(line));
  return { line: index >= 0 ? index + 1 : 1, text: index >= 0 ? lines[index] : "" };
}

function unsafePhpEchoLine(line) {
  const matches = String(line || "").match(/<\?=\s*([\s\S]*?)\s*\?>/g) || [];
  for (const tag of matches) {
    const expr = tag.replace(/^<\?=\s*/, "").replace(/\s*\?>$/, "").trim();
    if (!expr) continue;
    if (/^(htmlspecialchars|htmlentities|number_format|date|count)\s*\(/i.test(expr)) continue;
    if (/^\(?\s*(int|float|bool|string)\s*\)?/i.test(expr)) continue;
    if (/^[0-9\s+\-*/().]+$/.test(expr)) continue;
    if (/(\$_|\[[^\]]+\]|->)/.test(expr)) return true;
  }
  return false;
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
  const syntaxError = runSyntaxCheck(file, base, ext);
  if (syntaxError) {
    findings.push(finding("syntax-error", {
      category: "quality",
      severity: "warning",
      title: "Source file has a syntax error",
      description: "A safe parser/linter check reported that this file is not syntactically valid. This can break the application before security controls run.",
      path: relative,
      line: syntaxError.line || 1,
      snippet: syntaxError.message || "Syntax check failed.",
      fix: "Open the file locally, run the language parser or linter, and fix the syntax error before deployment.",
      verification: "Rerun the language syntax check and then rerun this source scan.",
      references: []
    }));
  }

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

  if (/\.(php|inc)$/i.test(base)) {
    if (/\$DB_USER\s*=\s*['"]root['"]/i.test(text) && /\$DB_PASS\s*=\s*['"]\s*['"]/i.test(text)) {
      findings.push(finding("db-root-blank-password", {
        category: "security",
        severity: "warning",
        title: "Database config uses root with a blank password",
        description: "The database configuration uses the root account with an empty password. If this reaches staging or production, database compromise becomes much easier.",
        path: relative,
        line: firstLineMatching(lines, /\$DB_PASS\s*=/i),
        snippet: lines.filter((line) => /\$DB_(USER|PASS)\s*=/.test(line)).join(" "),
        fix: "Create a dedicated least-privilege database user with a strong password, load credentials from environment variables or server secret storage, and never deploy root/blank database credentials.",
        verification: "Confirm the deployed config no longer contains root or blank database credentials, then rerun the source scan.",
        references: []
      }));
    }

    if (/\$DB_HOST\s*=\s*['"](?:localhost|127\.0\.0\.1)['"]/i.test(text) && /\$DB_(USER|PASS|NAME)\s*=/i.test(text)) {
      findings.push(finding("local-db-config", {
        category: "configuration",
        severity: "info",
        title: "Local database settings are hardcoded",
        description: "The app contains localhost database settings directly in code. That is acceptable for a demo, but production deployments should load database connection settings from server-side environment variables.",
        path: relative,
        line: firstLineMatching(lines, /\$DB_HOST\s*=/i),
        snippet: lines.filter((line) => /\$DB_(HOST|USER|PASS|NAME)\s*=/.test(line)).join(" "),
        fix: "Move database host/name/user/password into environment variables or server secret storage and keep only safe examples in source.",
        verification: "Confirm production database settings are not hardcoded in the repository and rerun the source scan.",
        references: []
      }));
    }

    if (/die\s*\([^;]*(getMessage\s*\(\)|PDOException|mysqli_connect_error)/is.test(text)) {
      findings.push(finding("verbose-db-error", {
        category: "security",
        severity: "warning",
        title: "Database error details may be exposed to users",
        description: "The code can display raw database exception details, which may leak hostnames, table names, SQL errors, or filesystem paths.",
        path: relative,
        line: firstLineMatching(lines, /die\s*\(/i),
        snippet: lines.find((line) => /die\s*\(/i.test(line)) || "",
        fix: "Log detailed exceptions server-side and show users a generic error message such as 'Service temporarily unavailable'.",
        verification: "Force a database connection failure in a safe environment and confirm the browser only sees a generic message.",
        references: []
      }));
    }

    if (!/die\s*\([^;]*(getMessage\s*\(\)|PDOException|mysqli_connect_error)/is.test(text) && /catch\s*\([^)]*(Throwable|Exception|PDOException)[^)]*\)[\s\S]{0,500}(getMessage\s*\(\)|mysqli_error|errorInfo\s*\()/i.test(text)) {
      counters.verboseExceptionFindings = counters.verboseExceptionFindings || 0;
      if (counters.verboseExceptionFindings < 8) {
        counters.verboseExceptionFindings++;
        const match = lineMatching(lines, /getMessage\s*\(\)|mysqli_error|errorInfo\s*\(/i);
        findings.push(finding("verbose-exception-message", {
          category: "security",
          severity: "warning",
          title: "Raw exception message may be shown to users",
          description: "The code catches an exception and appears to place the raw exception message into a user-facing error path. This can leak SQL details, filesystem paths, or stack context.",
          path: relative,
          line: match.line,
          snippet: match.text,
          fix: "Log the raw exception server-side and show users a generic failure message.",
          verification: "Trigger the failure path in a safe environment and confirm the browser does not display internal exception text.",
          references: []
        }));
      }
    }

    if (/<form\b[^>]*method\s*=\s*['"]?post/i.test(text) && !/(csrf|xsrf|_token|csrf_token)/i.test(text)) {
      counters.csrfFindings = counters.csrfFindings || 0;
      if (counters.csrfFindings < 10) {
        counters.csrfFindings++;
        const match = lineMatching(lines, /<form\b[^>]*method\s*=\s*['"]?post/i);
      findings.push(finding("missing-csrf-token", {
        category: "security",
        severity: "warning",
        title: "POST forms appear to lack CSRF protection",
        description: "A state-changing POST form was found without an obvious CSRF token or CSRF validation marker.",
        path: relative,
        line: match.line,
        snippet: match.text,
        fix: "Generate a per-session CSRF token, include it as a hidden field in each POST form, and verify it before processing the request.",
        verification: "Submit the form without the CSRF token in a safe environment and confirm the request is rejected.",
        references: []
      }));
      }
    }

    if (/session_start\s*\(/i.test(text) && !/(session_set_cookie_params|session\.cookie_httponly|session\.cookie_samesite|session\.cookie_secure)/i.test(text)) {
      counters.sessionCookieFindings = counters.sessionCookieFindings || 0;
      if (counters.sessionCookieFindings < 3) {
        counters.sessionCookieFindings++;
        const match = lineMatching(lines, /session_start\s*\(/i);
      findings.push(finding("session-cookie-hardening", {
        category: "security",
        severity: "warning",
        title: "Session cookie security flags are not explicitly configured",
        description: "The application starts a PHP session without clearly setting HttpOnly, Secure, and SameSite cookie attributes.",
        path: relative,
        line: match.line,
        snippet: match.text,
        fix: "Set session cookie parameters before session_start, including httponly=true, secure=true on HTTPS, and samesite=Lax or Strict.",
        verification: "Inspect the Set-Cookie header after login and confirm HttpOnly, Secure on HTTPS, and SameSite are present.",
        references: []
      }));
      }
    }

    if (/(Demo accounts|password:\s*<code>|password123)/i.test(text)) {
      findings.push(finding("demo-credentials-exposed", {
        category: "security",
        severity: "warning",
        title: "Demo credentials are exposed in the login page",
        description: "The login page displays demo usernames and a shared password, which should never be present in a deployed application.",
        path: relative,
        line: firstLineMatching(lines, /(Demo accounts|password123)/i),
        snippet: lines.find((line) => /(Demo accounts|password123)/i.test(line)) || "",
        fix: "Remove demo credentials from the UI and rotate/delete any demo accounts before deployment.",
        verification: "Open the login page and confirm no usernames or passwords are displayed.",
        references: []
      }));
    }

    if (/password_verify\s*\(/i.test(text) && !/\b(rate_limit|rate limit|throttle|attempts?|lockout|captcha|too many)\b/i.test(text)) {
      findings.push(finding("missing-login-rate-limit", {
        category: "security",
        severity: "warning",
        title: "Login flow has no obvious brute-force protection",
        description: "The login handler verifies passwords but does not show evidence of rate limiting, lockout, captcha, or failed-attempt tracking.",
        path: relative,
        line: firstLineMatching(lines, /password_verify\s*\(/i),
        snippet: lines.find((line) => /password_verify\s*\(/i.test(line)) || "",
        fix: "Add IP/account-based throttling, failed-attempt tracking, and alerting for repeated failed login attempts.",
        verification: "Attempt repeated invalid logins in a safe environment and confirm requests are slowed or blocked.",
        references: []
      }));
    }

    if (/\$pdo->query\s*\(\s*(?:["'`][^"'`]*(?:\$\w+|\$_|\{)|[^)]*\.\s*\$_(?:GET|POST|REQUEST)|[^)]*\$_(?:GET|POST|REQUEST))/i.test(text)) {
      findings.push(finding("possible-sql-injection", {
        category: "security",
        severity: "critical",
        title: "User input may reach a raw SQL query",
        description: "A raw query call appears to include variable or request-derived SQL. Use prepared statements for all user-controlled values.",
        path: relative,
        line: firstLineMatching(lines, /\$pdo->query\s*\(/i),
        snippet: lines.find((line) => /\$pdo->query\s*\(/i.test(line)) || "",
        fix: "Replace raw SQL string construction with prepared statements and bound parameters.",
        verification: "Review this path with malicious input and confirm the SQL query structure cannot change.",
        references: []
      }));
    }

    if (lines.some(unsafePhpEchoLine)) {
      counters.phpOutputFindings = counters.phpOutputFindings || 0;
      if (counters.phpOutputFindings < 10) {
        counters.phpOutputFindings++;
        const match = lineMatching(lines, unsafePhpEchoLine);
        findings.push(finding("unescaped-template-output", {
          category: "security",
          severity: "warning",
          title: "Template output may not be HTML-escaped",
          description: "A PHP short echo appears to output variable data without an escaping helper. If the value can contain user input, this can become stored or reflected XSS.",
          path: relative,
          line: match.line,
          snippet: match.text,
          fix: "Wrap untrusted output in htmlspecialchars(..., ENT_QUOTES, 'UTF-8') or an equivalent escaping helper.",
          verification: "Render this template with HTML metacharacters in the underlying data and confirm they are escaped.",
          references: []
        }));
      }
    }
  }

  if (ext === ".sql") {
    if (/(demo|default|sample)\s+(user|account|password|credential)|password123|INSERT\s+INTO\s+users/i.test(text)) {
      findings.push(finding("seeded-demo-accounts", {
        category: "security",
        severity: "warning",
        title: "SQL seed data includes demo/default accounts",
        description: "The SQL file appears to create demo or default user accounts. These accounts often survive into staging or production with known credentials.",
        path: relative,
        line: firstLineMatching(lines, /(demo|default|sample)\s+(user|account|password|credential)|password123|INSERT\s+INTO\s+users/i),
        snippet: lines.find((line) => /(demo|default|sample)\s+(user|account|password|credential)|password123|INSERT\s+INTO\s+users/i.test(line)) || "",
        fix: "Remove demo accounts from production migrations and seed them only in isolated local development fixtures.",
        verification: "Load the production database seed/migration path and confirm no default admin/demo users are created.",
        references: []
      }));
    }
    if (/IDENTIFIED\s+BY\s+['"][^'"]+['"]|PASSWORD\s*=\s*['"][^'"]+['"]/i.test(text)) {
      findings.push(finding("sql-hardcoded-password", {
        category: "security",
        severity: "critical",
        title: "SQL contains a hardcoded password",
        description: "A SQL script contains a literal password. Database credentials should be provisioned through secrets, not committed SQL.",
        path: relative,
        line: firstLineMatching(lines, /IDENTIFIED\s+BY|PASSWORD\s*=/i),
        snippet: lines.find((line) => /IDENTIFIED\s+BY|PASSWORD\s*=/i.test(line)) || "",
        ...FIX.secret
      }));
    }
  }

  if ([".py"].includes(ext)) {
    const pythonRules = [
      [/DEBUG\s*=\s*True/, "django-debug-true", "warning", "Django DEBUG is enabled", "Django DEBUG=True leaks detailed errors and settings if deployed."],
      [/ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]/, "django-allowed-hosts-wildcard", "warning", "Django ALLOWED_HOSTS allows every host", "Wildcard host acceptance can enable host-header attacks."],
      [/SECRET_KEY\s*=\s*['"][^'"]{8,}['"]/, "django-hardcoded-secret-key", "critical", "Django SECRET_KEY is hardcoded", "A committed Django secret key can compromise signing and session security."],
      [/app\.run\s*\([^)]*debug\s*=\s*True/i, "flask-debug-true", "warning", "Flask debug mode is enabled", "Flask debug mode must not be enabled in production."],
      [/CORS\s*\([^)]*origins\s*=\s*['"]\*['"]/i, "flask-cors-wildcard", "warning", "Wildcard CORS configuration detected", "Wildcard CORS can expose APIs more broadly than intended."],
      [/subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True/i, "python-subprocess-shell", "critical", "subprocess uses shell=True", "shell=True can become command injection when arguments contain user input."],
      [/\bos\.system\s*\(/, "python-os-system", "warning", "os.system usage detected", "os.system executes shell commands and is risky with dynamic input."],
      [/pickle\.loads?\s*\(/, "python-pickle-load", "critical", "pickle deserialization detected", "pickle can execute code when loading untrusted data."],
      [/yaml\.load\s*\([^)]*(?!Loader\s*=)/, "python-unsafe-yaml-load", "warning", "yaml.load without explicit safe loader", "yaml.load can construct unsafe objects unless SafeLoader is used."],
      [/requests\.[a-z]+\s*\([^)]*verify\s*=\s*False/i, "python-tls-verify-false", "warning", "TLS verification disabled", "Disabling TLS certificate verification allows man-in-the-middle attacks."]
    ];
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      for (const [regex, rule, severity, title, description] of pythonRules) {
        if (regex.test(line)) {
          findings.push(finding(rule, {
            category: "security",
            severity,
            title,
            description,
            path: relative,
            line: index + 1,
            snippet: line,
            ...(String(rule).includes("secret") ? FIX.secret : FIX.config)
          }));
        }
      }
    }
  }

  if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"].includes(ext)) {
    const jsRules = [
      [/postMessage\s*\([^,]+,\s*['"]\*['"]/, "postmessage-wildcard", "warning", "postMessage uses wildcard target origin", "Wildcard postMessage targets can leak messages to unexpected origins."],
      [/target\s*=\s*['"]_blank['"][^>]*(?<!rel\s*=\s*['"][^'"]*noopener[^'"]*['"])/i, "blank-target-no-noopener", "warning", "External blank link may miss noopener", "target=_blank without rel=noopener can allow reverse tabnabbing."],
      [/(fetch|axios\.[a-z]+)\s*\(\s*['"]http:\/\//i, "insecure-http-request", "warning", "Plain HTTP request detected", "Plain HTTP requests can expose traffic and be modified in transit."],
      [/Math\.random\s*\(\s*\).*?(token|secret|password|otp|code)|(?:token|secret|password|otp|code).*?Math\.random\s*\(/i, "math-random-secret", "warning", "Math.random used for security-sensitive value", "Math.random is not cryptographically secure for tokens, passwords, OTPs, or reset codes."],
      [/child_process\.(exec|execSync)\s*\(/, "node-child-process-exec", "warning", "Node child_process exec usage detected", "exec runs shell commands and can become command injection when input is dynamic."],
      [/res\.send\s*\([^)]*req\.(query|body|params)/i, "express-reflected-input", "warning", "Express response may reflect request input", "Sending request input directly can create reflected XSS or content injection."],
      [/cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/i, "node-cors-wildcard", "warning", "Wildcard CORS configuration detected", "Wildcard CORS can expose APIs more broadly than intended."]
    ];
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      for (const [regex, rule, severity, title, description] of jsRules) {
        if (regex.test(line)) {
          findings.push(finding(rule, {
            category: "security",
            severity,
            title,
            description,
            path: relative,
            line: index + 1,
            snippet: line,
            ...FIX.config
          }));
        }
      }
    }
  }

  if (base.toLowerCase() === "dockerfile" || ext === ".dockerfile") {
    if (!/^USER\s+\S+/im.test(text)) {
      findings.push(finding("dockerfile-no-user", {
        category: "configuration",
        severity: "warning",
        title: "Dockerfile does not set a non-root user",
        description: "Containers run as root by default unless USER is set. A non-root runtime user limits damage after compromise.",
        path: relative,
        line: 1,
        fix: "Create a dedicated low-privilege user in the image and set USER before the final runtime command.",
        verification: "Run the container and confirm id -u does not return 0.",
        references: []
      }));
    }
    if (/ADD\s+https?:\/\//i.test(text)) {
      findings.push(finding("dockerfile-remote-add", {
        category: "configuration",
        severity: "warning",
        title: "Dockerfile downloads remote content with ADD",
        description: "ADD from remote URLs can make builds less reproducible and harder to verify.",
        path: relative,
        line: firstLineMatching(lines, /ADD\s+https?:\/\//i),
        snippet: lines.find((line) => /ADD\s+https?:\/\//i.test(line)) || "",
        fix: "Download verified artifacts with checksum validation in a controlled build step.",
        verification: "Confirm remote artifacts are pinned and checksum-verified.",
        references: []
      }));
    }
  }

  if ([".yml", ".yaml"].includes(ext)) {
    if (/privileged:\s*true/i.test(text)) {
      findings.push(finding("container-privileged-true", {
        category: "configuration",
        severity: "warning",
        title: "Container privileged mode enabled",
        description: "privileged: true gives a container broad host-level capabilities and should be avoided unless absolutely required.",
        path: relative,
        line: firstLineMatching(lines, /privileged:\s*true/i),
        snippet: lines.find((line) => /privileged:\s*true/i.test(line)) || "",
        fix: "Remove privileged mode and grant only the specific Linux capabilities or devices required.",
        verification: "Confirm the service starts without privileged mode.",
        references: []
      }));
    }
    if (/secrets:\s*inherit/i.test(text)) {
      findings.push(finding("github-secrets-inherit", {
        category: "security",
        severity: "warning",
        title: "GitHub Actions workflow inherits all secrets",
        description: "secrets: inherit can expose more repository or organization secrets than the called workflow needs.",
        path: relative,
        line: firstLineMatching(lines, /secrets:\s*inherit/i),
        snippet: lines.find((line) => /secrets:\s*inherit/i.test(line)) || "",
        fix: "Pass only the named secrets required by the reusable workflow.",
        verification: "Inspect the workflow call and confirm only explicitly required secrets are passed.",
        references: []
      }));
    }
  }

  const rules = [
    [/AKIA[0-9A-Z]{16}/, "aws-key", "critical", "AWS access key pattern detected", "A value matching the AWS access key format appears in source code."],
    [/sk_live_[0-9a-zA-Z]{12,}/, "stripe-live-secret", "critical", "Stripe live secret key pattern detected", "A Stripe live secret key appears to be hardcoded."],
    [/gh[pousr]_[0-9A-Za-z]{20,}/, "github-token", "critical", "GitHub token pattern detected", "A GitHub token appears to be hardcoded."],
    [/FLWSECK_[A-Z]+-[0-9a-zA-Z-]+/, "flutterwave-secret", "critical", "Flutterwave secret key pattern detected", "A Flutterwave secret key appears to be hardcoded."],
    [/-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, "private-key-material", "critical", "Private key material detected", "A private key block appears to be committed in source code."],
    [/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, "jwt-token", "critical", "JWT-like token detected", "A JWT-like token appears in source code and may grant access if still valid."],
    [/service_role[^A-Za-z0-9_-]{0,20}eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/i, "supabase-service-role", "critical", "Supabase service role key exposure risk", "A Supabase service role key appears to be present in source code."],
    [/(password|passwd|secret|token|api[_-]?key|client_secret)\s*[:=]\s*['"][^'"]{8,}['"]/i, "hardcoded-secret", "critical", "Hardcoded credential-like value", "A credential-like assignment appears in source code."],
    [/https?:\/\/[^'"\s]+:[^'"\s]+@/i, "url-embedded-credentials", "critical", "URL contains embedded credentials", "A URL appears to include username/password credentials."],
    [/\beval\s*\(/, "eval", "warning", "eval usage detected", "eval executes strings as code and is unsafe with untrusted input."],
    [/\bnew\s+Function\s*\(/, "new-function", "warning", "new Function usage detected", "new Function executes strings as code and is unsafe with untrusted input."],
    [/document\.write\s*\(/, "document-write", "warning", "document.write usage detected", "document.write can create XSS risks when content is influenced by users."],
    [/\.innerHTML\s*=/, "inner-html", "warning", "innerHTML assignment uses dynamic markup", "innerHTML assignment can introduce XSS when the assigned markup includes user-controlled or interpolated content."],
    [/dangerouslySetInnerHTML\s*=\s*\{/, "dangerously-set-html", "warning", "React dangerouslySetInnerHTML usage detected", "dangerouslySetInnerHTML bypasses React escaping and requires sanitizer review."],
    [/(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*['"][^'"]*(token|password|secret|jwt|auth)/i, "browser-token-storage", "warning", "Sensitive token stored in browser storage", "Long-lived auth secrets in localStorage/sessionStorage are exposed to XSS."],
    [/Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*|header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*/i, "cors-wildcard", "warning", "Wildcard CORS configuration detected", "Wildcard CORS can expose APIs more broadly than intended."],
    [/(md5|sha1)\s*\([^)]*(password|passwd)/i, "weak-password-hash", "critical", "Weak password hashing pattern detected", "MD5/SHA1 are not appropriate for password storage."],
    [/(debug|devtools|display_errors)\s*[:=]\s*true|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?1/i, "debug-enabled", "warning", "Debug/development flag enabled", "Debug settings can leak implementation details if shipped to production."],
    [/CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|verify\s*[:=]\s*false/i, "tls-verification-disabled", "warning", "TLS verification disabled", "Disabling certificate verification allows man-in-the-middle attacks."],
    [/chmod\s+777|chmod\s*\([^)]*0777/i, "world-writable-permissions", "warning", "World-writable file permissions detected", "0777 permissions can allow unintended users or processes to modify files."],
    [/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i, "php-untrusted-unserialize", "critical", "PHP unserialize uses request input", "unserialize on untrusted input can lead to object injection and code execution."],
    [/include\s*\(\s*\$_(GET|POST|REQUEST)|require(?:_once)?\s*\(\s*\$_(GET|POST|REQUEST)/i, "php-dynamic-include", "critical", "PHP include/require uses request input", "Including paths from request input can lead to local/remote file inclusion."],
    [/permissions:\s*write-all/i, "github-permissions-write-all", "warning", "GitHub Actions write-all permissions", "Workflow permissions are broader than most scanners need."],
    [/pull_request_target:/i, "github-pr-target", "warning", "pull_request_target workflow trigger detected", "pull_request_target can expose privileged tokens to untrusted pull request code if misused."]
  ];

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    for (const [regex, rule, severity, title, description] of rules) {
      if (regex.test(line)) {
        if (rule === "inner-html" && isStaticInnerHtmlAssignment(lines, index)) continue;
        if (rule === "debug-enabled" && ext === ".py") continue;
        const kind = String(rule).includes("secret") || String(rule).includes("key") || String(rule).includes("token") || String(rule).includes("role") || String(rule).includes("credential") || String(rule).includes("private") || String(rule).includes("jwt") ? FIX.secret : String(rule).includes("html") || String(rule).includes("eval") || String(rule).includes("function") || String(rule).includes("write") ? FIX.injection : FIX.config;
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
      path: null,
      fix: "Add a .gitignore containing at least .env, .env.*, node_modules, dist, build, coverage, and local editor files.",
      verification: "Run git check-ignore .env after adding the file.",
      references: ["https://git-scm.com/docs/gitignore"]
    }));
  }
  const fileNames = new Set(files.map((file) => path.basename(file)));
  const firstRelative = (name) => {
    const matched = files.find((file) => path.basename(file) === name);
    return matched ? rel(root, matched) : name;
  };
  if (fileNames.has("package.json") && !["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"].some((name) => fileNames.has(name))) {
    findings.push(finding("missing-node-lockfile", {
      category: "dependencies",
      severity: "warning",
      title: "Node project has no lockfile",
      description: "package.json exists without a recognized package manager lockfile. Builds may install different dependency versions over time.",
      path: firstRelative("package.json"),
      line: 1,
      fix: "Commit the lockfile generated by the package manager used for this project.",
      verification: "Run the package manager install command locally and confirm the generated lockfile is committed.",
      references: []
    }));
  }
  if (fileNames.has("composer.json") && !fileNames.has("composer.lock")) {
    findings.push(finding("missing-composer-lockfile", {
      category: "dependencies",
      severity: "warning",
      title: "Composer project has no lockfile",
      description: "composer.json exists without composer.lock. Production installs may resolve different dependency versions over time.",
      path: firstRelative("composer.json"),
      line: 1,
      fix: "Commit composer.lock for applications so dependency versions are reproducible.",
      verification: "Run composer install in a trusted environment and confirm composer.lock is present.",
      references: []
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
