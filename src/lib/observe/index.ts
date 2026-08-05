/**
 * Declared versus observed capability.
 *
 * Everything else in this project reads what a server *says about itself* — the
 * tool descriptions it advertises. That is the right input for working out what
 * the model will do with it, and the wrong input for working out what the code
 * can do. A server whose description says "synchronise a Notion page" and whose
 * source opens a socket is the exact shape of an MCP supply-chain attack, and
 * nothing that reads descriptions can see it.
 *
 * So this fetches the package and looks. The finding is not "this code makes
 * network calls" — plenty of things legitimately do. The finding is
 * **undeclared** capability: the code can do something that no tool description
 * mentions. That subtraction is also what keeps it quiet, because a fetch server
 * having network access is silent by construction.
 *
 * Three honest limits, stated here because the output is only worth as much as
 * its caveats:
 *
 *   It is a text search, not a program analysis. Obfuscation, dynamic
 *   `require`, and computed property access all defeat it. A clean result means
 *   "nothing obvious", never "nothing".
 *
 *   It reads the package's own files, not its dependencies. A server that gets
 *   its network access from a library will not be flagged.
 *
 *   Every match is reported with the file, the line, and the source text, so a
 *   reader can dismiss a false positive in a second rather than trusting us.
 *
 * Packages are installed with `--ignore-scripts`. Installing a package to find
 * out whether it is safe would otherwise run its install hooks, which is the
 * thing being checked for.
 */

import spawn from "cross-spawn";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import type { CapabilityId } from "@/lib/engine/capabilities";
import type { Severity } from "@/lib/engine/types";

export interface Observation {
  capability: CapabilityId;
  /** Which signature matched, so a reader knows what we looked for. */
  signature: string;
  /** Whether this alone is worth reporting. See SIGNATURES. */
  confidence: "high" | "low";
  file: string;
  line: number;
  excerpt: string;
}

export interface InstallScript {
  name: string;
  command: string;
}

export interface PackageObservation {
  packageName: string;
  version: string | null;
  filesScanned: number;
  observations: Observation[];
  /** Hooks npm would run on install. Present is itself the finding. */
  installScripts: InstallScript[];
  error: string | null;
}

/**
 * Source signatures, mapped onto the capability vocabulary.
 *
 * `confidence` is what makes this reportable rather than noise, and it took a
 * calibration pass against real servers to get right. The first version flagged
 * `@modelcontextprotocol/server-github` for reading
 * `process.env.GITHUB_PERSONAL_ACCESS_TOKEN` and calling `fetch`. Both true,
 * neither interesting: it was reading the credential its own config declares,
 * and talking to the one API it exists to talk to. Every useful server does
 * both, so reporting them buries the finding that matters under a finding that
 * never matters.
 *
 * So:
 *
 *   `high` — constructs that are genuinely surprising in an MCP server and hard
 *   to arrive at by accident. Spawning processes. Opening raw sockets. Reading
 *   a path that belongs to someone else's credentials. These are reported as
 *   undeclared capability.
 *
 *   `low` — true, common, and uninformative on its own. `fetch` to a fixed API,
 *   reading a file, reading a declared token. Recorded in the observation so
 *   `--json` consumers and future rules can use them, never surfaced as a
 *   finding by themselves.
 */
type Confidence = "high" | "low";

const SIGNATURES: {
  capability: CapabilityId;
  signature: string;
  pattern: RegExp;
  confidence: Confidence;
}[] = [
  {
    capability: "exec.shell",
    signature: "child_process",
    pattern: /(?:require\(|from\s*)['"](?:node:)?child_process['"]/,
    confidence: "high",
  },
  {
    capability: "exec.shell",
    signature: "dynamic-eval",
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,
    confidence: "high",
  },
  {
    // Raw sockets, not HTTP. A server that speaks its own API over `fetch` is
    // ordinary; one that opens a TCP socket is doing something its description
    // had better mention.
    capability: "net.outbound",
    signature: "socket-module",
    pattern: /(?:require\(|from\s*)['"](?:node:)?(?:net|tls|dgram)['"]/,
    confidence: "high",
  },
  {
    capability: "net.outbound",
    signature: "http-client",
    pattern:
      /(?:require\(|from\s*)['"](?:node:)?(?:http|https)['"]|\bfetch\s*\(|\baxios\b|\bnode-fetch\b|\bundici\b|\bXMLHttpRequest\b|\bWebSocket\s*\(/,
    confidence: "low",
  },
  {
    capability: "fs.read",
    signature: "fs-read",
    pattern: /\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream)\s*\(/,
    confidence: "low",
  },
  {
    capability: "fs.write",
    signature: "fs-write",
    pattern: /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|unlinkSync|rmSync)\s*\(/,
    confidence: "low",
  },
  {
    // Kept low even though it looks alarming: a server reading a token-shaped
    // variable is usually reading the one its own config supplies. The check
    // that matters is whether the name was declared, which happens in
    // `undeclared()` where the config is in scope.
    capability: "secrets.read",
    signature: "credential-env",
    pattern: /process\.env(?:\.\w*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|PASSWD)\w*|\[['"][^'"]*(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[^'"]*['"]\])/i,
    confidence: "low",
  },
  {
    // Someone else's credentials. Nothing legitimate reads these by accident.
    capability: "secrets.read",
    signature: "credential-path",
    pattern: /\.aws[/\\]credentials|\.ssh[/\\]id_|id_rsa|\.netrc|\.npmrc|\.docker[/\\]config\.json/,
    confidence: "high",
  },
];

const SCANNABLE = /\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx)$/;

/** Directories whose contents do not run when the server does. */
const SKIP_DIRS = new Set([
  "node_modules",
  "test",
  "tests",
  "__tests__",
  "spec",
  "example",
  "examples",
  "docs",
  "coverage",
  ".git",
]);

const SKIP_FILES = /\.(?:test|spec|min)\.[cm]?[jt]sx?$|\.d\.ts$|\.map$/;

/** Beyond this a line is minified, and quoting it as evidence is useless. */
const MAX_LINE = 400;
const MAX_FILE_BYTES = 2_000_000;

/** npm package names, strictly. Anything else never reaches a subprocess. */
const SAFE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;

function walk(root: string, dir: string, out: string[]) {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      walk(root, full, out);
    } else if (SCANNABLE.test(entry) && !SKIP_FILES.test(entry) && stat.size <= MAX_FILE_BYTES) {
      out.push(full);
    }
  }
}

/** Scans an already-extracted package directory. */
export function observeDirectory(root: string, packageName: string): PackageObservation {
  const files: string[] = [];
  walk(root, root, files);

  const observations: Observation[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relative(root, file).split(sep).join("/");
    const lines = text.split(/\r?\n/);

    for (let i = 0; i < lines.length; i += 1) {
      const raw = lines[i];
      if (raw.length > MAX_LINE) continue;
      const line = raw.trim();
      // Not a parser, but enough to stop a commented-out import counting as a
      // capability. A comment cannot execute.
      if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) continue;

      for (const { capability, signature, pattern, confidence } of SIGNATURES) {
        if (!pattern.test(line)) continue;
        // One example per signature per file. Twelve `readFileSync` hits in one
        // module is the same fact twelve times.
        const key = `${capability}|${signature}|${rel}`;
        if (seen.has(key)) continue;
        seen.add(key);
        observations.push({
          capability,
          signature,
          confidence,
          file: rel,
          line: i + 1,
          excerpt: line.length > 160 ? `${line.slice(0, 160)}…` : line,
        });
      }
    }
  }

  let version: string | null = null;
  const installScripts: InstallScript[] = [];
  const manifestPath = join(root, "package.json");
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      version = typeof manifest.version === "string" ? manifest.version : null;
      for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
        const command = manifest.scripts?.[hook];
        if (typeof command === "string" && command.trim()) {
          installScripts.push({ name: hook, command: command.trim() });
        }
      }
    } catch {
      /* an unreadable manifest is not worth failing the scan over */
    }
  }

  return {
    packageName,
    version,
    filesScanned: files.length,
    observations,
    installScripts,
    error: null,
  };
}

/**
 * Fetches an npm package and scans it.
 *
 * `--ignore-scripts` is the load-bearing flag: installing a package to find out
 * whether it is safe would otherwise run its install hooks first, which is one
 * of the things being checked for.
 *
 * No shell, and the name is validated first. The package name comes out of a
 * config file we do not control, so `shell: true` would turn a config into a
 * command-injection vector — in a tool whose entire subject is untrusted input.
 * cross-spawn is what makes that possible on Windows, where Node refuses to
 * execute `npm.cmd` directly without a shell.
 */
export function observePackage(
  packageName: string,
  opts: { timeoutMs?: number } = {},
): PackageObservation {
  const empty: PackageObservation = {
    packageName,
    version: null,
    filesScanned: 0,
    observations: [],
    installScripts: [],
    error: null,
  };

  if (!SAFE_NAME.test(packageName)) {
    return { ...empty, error: `Refusing to fetch an implausible package name: ${packageName}` };
  }

  let dir: string | null = null;
  try {
    dir = mkdtempSync(join(tmpdir(), "blast-radius-"));
    const install = spawn.sync(
      "npm",
      [
        "install",
        "--prefix",
        dir,
        "--no-save",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--omit=dev",
        "--loglevel=error",
        packageName,
      ],
      { stdio: "pipe", timeout: opts.timeoutMs ?? 120_000, windowsHide: true },
    );

    if (install.status !== 0) {
      const stderr = install.stderr?.toString().trim() ?? "";
      const first = stderr.split(/\r?\n/).find((l) => l.trim()) ?? "npm install failed";
      return { ...empty, error: first.slice(0, 200) };
    }

    const installed = join(dir, "node_modules", ...packageName.split("/"));
    if (!existsSync(installed)) {
      return { ...empty, error: "Package installed but its directory was not found." };
    }
    return observeDirectory(installed, packageName);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ...empty, error: message.split("\n")[0].slice(0, 200) };
  } finally {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
}

export interface UndeclaredFinding {
  serverKey: string;
  packageName: string;
  capability: CapabilityId;
  severity: Severity;
  /** A few examples, not all of them. */
  evidence: Observation[];
}

/**
 * How bad an undeclared capability is.
 *
 * Graded by what the gap enables rather than by the capability alone. A server
 * that quietly can run commands or read credentials is a different kind of
 * problem from one that quietly reads a file — the first two are the primitives
 * an attacker needs, and neither has any business being undisclosed.
 *
 * Note this is severity of the *discrepancy*, not of the capability. `fs.read`
 * is unremarkable in a server that says it reads files; it is only here because
 * nothing said so.
 */
const UNDECLARED_SEVERITY: Partial<Record<CapabilityId, Severity>> = {
  "exec.shell": "critical",
  "secrets.read": "critical",
  "net.outbound": "high",
  "fs.write": "high",
  "fs.read": "medium",
};

/**
 * The subtraction that makes this worth reporting.
 *
 * `declared` is the union of capabilities across everything the server
 * advertises. Anything the code can do that is not in that set is a capability
 * the model was never told about — and therefore one no amount of reading tool
 * descriptions would have found.
 */
export function undeclared(
  serverKey: string,
  observation: PackageObservation,
  declared: Iterable<CapabilityId>,
  opts: { declaredEnv?: Iterable<string>; maxEvidence?: number } = {},
): UndeclaredFinding[] {
  const known = new Set(declared);
  const envNames = new Set([...(opts.declaredEnv ?? [])].map((n) => n.toUpperCase()));
  const maxEvidence = opts.maxEvidence ?? 3;
  const byCapability = new Map<CapabilityId, Observation[]>();

  for (const o of observation.observations) {
    if (known.has(o.capability)) continue;
    // Only constructs that are surprising on their own. See SIGNATURES.
    if (o.confidence !== "high") continue;
    // A server reading a variable its own config supplies is doing the thing it
    // was configured to do, not hiding a capability.
    if (o.signature === "credential-env" && [...envNames].some((n) => o.excerpt.toUpperCase().includes(n))) {
      continue;
    }
    const list = byCapability.get(o.capability) ?? [];
    list.push(o);
    byCapability.set(o.capability, list);
  }

  const order: Severity[] = ["critical", "high", "medium", "low"];
  return [...byCapability.entries()]
    .map(([capability, evidence]) => ({
      serverKey,
      packageName: observation.packageName,
      capability,
      severity: UNDECLARED_SEVERITY[capability] ?? "medium",
      evidence: evidence.slice(0, maxEvidence),
    }))
    .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}
