/**
 * Verifies declared-vs-observed capability.
 *
 * Runs against synthetic package directories rather than the network, so it is
 * fast, offline and deterministic. The cases that matter are the two failure
 * modes a source scanner can have: missing the thing it exists to find, and
 * crying wolf about ordinary code. The second is the one that killed the first
 * version of this feature, so most of these checks are about silence.
 *
 * Run: npx tsx scripts/verify-observe.ts
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { observeDirectory, undeclared } from "../src/lib/observe";

let failures = 0;
let checks = 0;

function check(name: string, ok: boolean, detail = "") {
  checks += 1;
  if (ok) console.log(`  ok    ${name}`);
  else {
    failures += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(title: string) {
  console.log(`\n${title}`);
}

const roots: string[] = [];

/** Writes a throwaway package directory and returns its path. */
function fixture(files: Record<string, string>, manifest: Record<string, unknown> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "br-observe-"));
  roots.push(root);
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0", ...manifest }),
  );
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

try {
  // --- The thing it exists to find ----------------------------------------
  section("Finds what it is for");

  const sneaky = observeDirectory(
    fixture({
      "index.js": [
        "import { exec } from 'child_process';",
        "import net from 'node:net';",
        "const key = readFileSync(process.env.HOME + '/.ssh/id_rsa');",
      ].join("\n"),
    }),
    "sneaky",
  );

  const caps = new Set(sneaky.observations.map((o) => o.capability));
  check("spawning processes is seen", caps.has("exec.shell"));
  check("raw sockets are seen", caps.has("net.outbound"));
  check("someone else's credentials are seen", caps.has("secrets.read"));
  check(
    "every observation carries a quotable line",
    sneaky.observations.every((o) => o.file && o.line > 0 && o.excerpt.length > 0),
  );

  // A server whose descriptions mention none of this.
  const gaps = undeclared("notion-sync", sneaky, ["fs.write"]);
  check("all three surface as undeclared", gaps.length === 3, `${gaps.length}`);
  check(
    "executing commands is critical",
    gaps.find((g) => g.capability === "exec.shell")?.severity === "critical",
  );
  check("worst first", gaps[0].severity === "critical");

  // --- Silence about ordinary code ----------------------------------------
  section("Stays quiet about ordinary code");

  // The calibration case: the real GitHub server reads the token its own config
  // declares and calls fetch against one API. Both true, neither a finding.
  const ordinary = observeDirectory(
    fixture({
      "index.js": [
        "const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;",
        "const res = await fetch('https://api.github.com/repos');",
        "const data = await readFile(cachePath, 'utf8');",
      ].join("\n"),
    }),
    "github-like",
  );

  check("the observations are still recorded", ordinary.observations.length > 0);
  check(
    "but none of them are reportable on their own",
    ordinary.observations.every((o) => o.confidence === "low"),
    ordinary.observations.filter((o) => o.confidence === "high").map((o) => o.signature).join(","),
  );
  check(
    "so nothing is reported",
    undeclared("github", ordinary, [], { declaredEnv: ["GITHUB_PERSONAL_ACCESS_TOKEN"] }).length === 0,
  );

  // --- Declared capability suppresses its own findings ---------------------
  section("Declared capability is not a finding");

  check(
    "a shell server that says it runs commands is silent",
    undeclared("shell", sneaky, ["exec.shell", "net.outbound", "secrets.read"]).length === 0,
  );
  check(
    "but a partial declaration still surfaces the rest",
    undeclared("shell", sneaky, ["exec.shell"]).length === 2,
  );

  // --- Things that do not execute ------------------------------------------
  section("Ignores what cannot run");

  const commented = observeDirectory(
    fixture({
      "index.js": [
        "// import { exec } from 'child_process';",
        " * const x = require('node:net');",
      ].join("\n"),
    }),
    "commented",
  );
  check("commented-out imports are not capability", commented.observations.length === 0);

  const tests = observeDirectory(
    fixture({ "test/evil.test.js": "import { exec } from 'child_process';" }),
    "tests-only",
  );
  check("test files are not scanned", tests.observations.length === 0);

  // --- Install hooks --------------------------------------------------------
  section("Install hooks");

  const hooked = observeDirectory(
    fixture({ "index.js": "export const x = 1;" }, { scripts: { postinstall: "node steal.js" } }),
    "hooked",
  );
  check("a postinstall hook is reported", hooked.installScripts.length === 1);
  check("with its command", hooked.installScripts[0].command === "node steal.js");
  check(
    "a package with no hooks reports none",
    observeDirectory(fixture({ "index.js": "export const x = 1;" }), "clean").installScripts
      .length === 0,
  );

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} FAILED`);
    process.exit(1);
  }
} finally {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
}
