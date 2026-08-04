#!/usr/bin/env node
/**
 * The command-line scanner.
 *
 * The web page is a way to *show* this; it is not the product. The product is a
 * check that runs where the decision is actually made — on a developer's
 * machine before they add a server, and in CI on the config file afterwards.
 * Both of those are this file.
 *
 *   npx tsx scripts/blast-radius.ts                          # auto-detect configs
 *   npx tsx scripts/blast-radius.ts path/to/mcp.json         # a specific one
 *   npx tsx scripts/blast-radius.ts --tools tools.json ...   # supplied definitions
 *   npx tsx scripts/blast-radius.ts --discover ...           # ask the servers
 *   npx tsx scripts/blast-radius.ts --json                   # machine-readable
 *
 * Exits 1 when a critical path is found, so it fails a build.
 *
 * Without tool definitions it still does everything that does not require them:
 * supply-chain posture, credential exposure, registry provenance, pinning.
 *
 * Definitions come from one of two places. `--tools` takes them from a client
 * session, which involves running nothing. `--discover` launches each server and
 * asks it — accurate, but it executes the code under inspection, so it is opt-in,
 * it says so before doing it, and it strips every credential first. See
 * src/lib/discover.
 */

import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseConfig, ConfigError } from "../src/lib/engine/config";
import { scan } from "../src/lib/engine/scan";
import { remediate } from "../src/lib/engine/remediate";
import { classifyTools } from "../src/lib/classify";
import { discoverAll, toolsFrom } from "../src/lib/discover";
import type { DiscoveryResult } from "../src/lib/discover";
import { technique } from "../src/lib/engine/attack";
import type { ServerSpec, ToolSpec, Severity } from "../src/lib/engine/types";

// --- terminal helpers -------------------------------------------------------
// Colour is suppressed when not a TTY or when NO_COLOR is set, so piping into a
// file or a CI log does not produce escape soup.
const COLOUR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (COLOUR ? `[${code}m${s}[0m` : s);
const bold = c("1");
const dim = c("2");
const red = c("31");
const orange = c("33");
const blue = c("34");
const grey = c("90");

const SEV_COLOUR: Record<Severity, (s: string) => string> = {
  critical: red,
  high: orange,
  medium: c("33"),
  low: grey,
};

/**
 * The banner: concentric arcs sweeping out from a single point.
 *
 * The same mark as the site, and the same idea — the product's name drawn
 * literally. Generated rather than pasted as ASCII art so the arcs are actually
 * circular: for each row, solve for the x that lies on the circle, and double it
 * because terminal cells are about twice as tall as they are wide. Hand-drawn
 * arcs at this size always come out as lopsided ellipses.
 *
 * Rings fade outward through the block-shading characters, which are in every
 * monospace font that matters, so this does not turn into tofu on a projector.
 */
function banner(): string {
  const H = 7;
  const cy = (H - 1) / 2;
  const width = 42;
  const rings: { r: number; ch: string; paint: (s: string) => string }[] = [
    { r: 3, ch: "█", paint: c("38;5;209") },
    { r: 6, ch: "▓", paint: c("38;5;173") },
    { r: 9, ch: "▒", paint: c("38;5;67") },
    { r: 12, ch: "░", paint: c("38;5;60") },
    { r: 15, ch: "·", paint: grey },
  ];

  const grid: string[][] = Array.from({ length: H }, () => Array(width).fill(" "));

  for (const { r, ch, paint } of rings) {
    for (let y = 0; y < H; y += 1) {
      const dy = y - cy;
      if (Math.abs(dy) >= r) continue;
      const x = Math.round(Math.sqrt(r * r - dy * dy) * 2);
      if (x >= 0 && x < width) grid[y][x] = COLOUR ? paint(ch) : ch;
    }
  }
  // U+25CF rather than a fancier ringed variant: this one is in the default
  // console fonts on Windows, and a tofu box in the first frame of a demo is
  // not a risk worth taking for a slightly nicer glyph.
  grid[Math.round(cy)][0] = COLOUR ? c("38;5;209")("●") : "●";

  // The wordmark sits in the middle rows, clear of the densest arcs.
  const rows = grid.map((r) => r.join("").replace(/\s+$/, ""));
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - visibleLength(s)));

  rows[cy - 1] = `${pad(rows[cy - 1] ?? "", 44)}${bold("BLAST RADIUS")}`;
  rows[cy] = `${pad(rows[cy] ?? "", 44)}${dim("what your MCP servers can do together")}`;

  return rows.map((r) => `  ${r}`).join("\n");
}

/** Length ignoring ANSI escapes, so padding lines up when colour is on. */
function visibleLength(s: string): number {
  return s.replace(/\[[0-9;]*m/g, "").length;
}

/** Where the common clients keep their configs. */
function defaultConfigPaths(): string[] {
  const home = homedir();
  return [
    join(home, ".cursor", "mcp.json"),
    join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
    join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    join(home, ".config", "Claude", "claude_desktop_config.json"),
    join(home, ".codeium", "windsurf", "mcp_config.json"),
    join(process.cwd(), ".mcp.json"),
    join(process.cwd(), ".cursor", "mcp.json"),
  ];
}

/**
 * Splits argv into boolean flags, `--key value` pairs, and positional paths.
 *
 * Written out rather than done with index arithmetic against `indexOf`, which
 * is where the previous version went wrong: with `--tools` absent, `indexOf`
 * returns -1, `-1 + 1` is 0, and the first positional argument was silently
 * dropped — so passing a config path fell through to auto-detection and scanned
 * a different machine's file than the one you named.
 *
 * `VALUE_FLAGS` is the whole reason this needs to know anything: without it
 * there is no way to tell `--tools file.json` from `--discover file.json`.
 */
const VALUE_FLAGS = new Set(["tools"]);

function parseArgs(argv: string[]): {
  flags: Set<string>;
  values: Map<string, string>;
  positional: string[];
} {
  const flags = new Set<string>();
  const values = new Map<string, string>();
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (VALUE_FLAGS.has(name)) {
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        values.set(name, next);
        i += 1;
      }
      continue;
    }
    flags.add(name);
  }

  return { flags, values, positional };
}

function loadTools(path: string, servers: ServerSpec[]): ToolSpec[] {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const list: unknown[] = Array.isArray(raw) ? raw : (raw.tools ?? []);
  const known = new Set(servers.map((s) => s.key));

  return list
    .filter((t): t is ToolSpec => {
      if (!t || typeof t !== "object") return false;
      const o = t as Record<string, unknown>;
      return (
        typeof o.serverKey === "string" &&
        typeof o.name === "string" &&
        typeof o.description === "string"
      );
    })
    .filter((t) => known.has(t.serverKey));
}

async function main() {
  const { flags, values, positional } = parseArgs(process.argv.slice(2));
  const asJson = flags.has("json");
  const discover = flags.has("discover");
  const toolsPath = values.get("tools") ?? null;

  const targets = positional.length > 0 ? positional : defaultConfigPaths().filter(existsSync);

  if (targets.length === 0) {
    console.error(
      "No MCP configuration found. Pass one explicitly:\n  npx tsx scripts/blast-radius.ts path/to/mcp.json",
    );
    process.exit(2);
  }

  let worstExit = 0;

  for (const target of targets) {
    if (!existsSync(target)) {
      console.error(`${red("✗")} ${target} does not exist`);
      worstExit = Math.max(worstExit, 2);
      continue;
    }

    let servers: ServerSpec[];
    try {
      servers = parseConfig(readFileSync(target, "utf8"));
    } catch (err) {
      const msg = err instanceof ConfigError ? err.message : String(err);
      console.error(`${red("✗")} ${target}: ${msg}`);
      worstExit = Math.max(worstExit, 2);
      continue;
    }

    let tools: ToolSpec[] = toolsPath ? loadTools(toolsPath, servers) : [];
    let discovery: DiscoveryResult[] | null = null;

    if (discover) {
      // Discovery runs the servers. Say so before doing it, every time — the
      // whole argument of this tool is that starting unknown binaries is the
      // risk, and burying that in a man page would be dishonest.
      if (!asJson) {
        console.log();
        console.log(bold("  Discovering tools") + dim("  — launches each server locally"));
        console.log(
          dim("  Credentials are replaced with placeholders and nothing is inherited."),
        );
        console.log();
      }
      discovery = await discoverAll(servers, {
        onResult: (r) => {
          if (asJson) return;
          const mark = r.error ? (r.skipped ? grey("–") : red("✗")) : blue("✓");
          const detail = r.error
            ? dim(r.skipped ? r.error : `failed: ${r.error}`)
            : `${String(r.tools.length).padStart(2)} tools  ${dim(`${(r.durationMs / 1000).toFixed(1)}s`)}`;
          console.log(`    ${mark} ${r.serverKey.padEnd(16)} ${detail}`);
        },
      });
      tools = toolsFrom(discovery);
    }
    // One classification call, reused. Calling it per field would double both
    // the latency and the bill for the same answer.
    const classification = tools.length > 0 ? await classifyTools(tools) : null;
    const result = scan(servers, classification?.tools ?? [], classification?.injections ?? []);
    if (classification && classification.tools.length > 0) {
      result.remediation = remediate(servers, classification.tools, result.paths);
    }

    if (asJson) {
      console.log(JSON.stringify({ config: target, result }, null, 2));
    } else {
      report(target, servers, result);
    }

    const critical = result.paths.filter((p) => p.severity === "critical").length;
    const criticalSupply = result.supply.filter((s) => s.severity === "critical").length;
    if (critical + criticalSupply > 0) worstExit = Math.max(worstExit, 1);
  }

  process.exit(worstExit);
}

function report(
  target: string,
  servers: ServerSpec[],
  result: ReturnType<typeof scan>,
) {
  const line = (s = "") => console.log(s);

  line();
  line(banner());
  line();
  line(dim(`  ${target}`));
  line(dim("  " + "─".repeat(72)));

  // --- Servers -------------------------------------------------------------
  line();
  line(bold(`  ${servers.length} servers configured`));
  for (const s of result.servers) {
    const findings = result.supply.filter((f) => f.serverKey === s.key);
    const worst = findings.some((f) => f.severity === "critical")
      ? red("●")
      : findings.some((f) => f.severity === "high")
        ? orange("●")
        : findings.length > 0
          ? c("33")("●")
          : grey("●");
    line(`    ${worst} ${s.key.padEnd(16)} ${dim(s.invocation.slice(0, 52))}`);
  }

  // --- Attack paths --------------------------------------------------------
  if (result.paths.length > 0) {
    const composed = result.paths.filter((p) => p.requiresComposition).length;
    line();
    line(
      bold(`  ${result.paths.length} attack paths`) +
        dim(`  (${composed} need more than one server)`),
    );
    for (const p of result.paths) {
      const sev = SEV_COLOUR[p.severity](p.severity.toUpperCase().padEnd(8));
      const route = p.legs.map((l) => l.chosen.serverKey).join(" → ");
      const ids = p.techniques.map((t) => technique(t)?.id ?? t).join(" ");
      line(`    ${sev} ${p.name}`);
      line(`             ${dim(route)}  ${grey(ids)}`);
    }
  } else if (result.tools.length === 0) {
    line();
    line(dim("  No tool definitions supplied, so capability analysis was skipped."));
    line(dim("  Pass --tools <file> with definitions captured from a client session."));
  }

  // --- Injections ----------------------------------------------------------
  if (result.injections.length > 0) {
    line();
    line(bold(`  ${result.injections.length} tool descriptions address the model`));
    for (const s of result.injections) {
      line(`    ${red("!")} ${s.serverKey}/${s.toolName}  ${dim(s.pattern)}`);
      line(`      ${dim('"' + s.text.replace(/\s+/g, " ").slice(0, 96) + '…"')}`);
    }
  }

  // --- Supply chain --------------------------------------------------------
  const notable = result.supply.filter(
    (s) => s.severity === "critical" || s.severity === "high",
  );
  if (notable.length > 0) {
    line();
    line(bold(`  ${notable.length} supply-chain findings`));
    for (const f of notable) {
      line(`    ${SEV_COLOUR[f.severity]("●")} ${f.serverKey.padEnd(16)} ${f.summary}`);
    }
  }

  // --- Remediation ---------------------------------------------------------
  const rem = result.remediation;
  if (rem) {
    const inert = rem.perServer.filter((s) => s.pathsClosed === 0);
    line();
    line(bold("  What closes these"));
    line(
      `    ${rem.noSingleFix ? "Removing any single server closes nothing." : `Best single removal closes ${rem.perServer[0].pathsClosed} of ${result.paths.length} paths.`}`,
    );
    if (inert.length > 0) {
      line(
        dim(
          `    ${inert.length} of ${rem.perServer.length} servers close nothing when removed: ${inert.map((s) => s.serverKey).join(", ")}`,
        ),
      );
    }
    const top = rem.byCapabilityClass[0];
    if (top?.closes > 0) {
      line(
        `    Separating ${bold(top.role)}-capable tools into their own session closes ${top.closes}.`,
      );
    }
  }

  // --- Verdict -------------------------------------------------------------
  const critical =
    result.paths.filter((p) => p.severity === "critical").length +
    result.supply.filter((s) => s.severity === "critical").length;

  line();
  line(dim("  " + "─".repeat(72)));
  if (critical > 0) {
    line(`  ${red("✗")} ${bold(`${critical} critical`)} — exit 1`);
  } else {
    line(`  ${blue("✓")} no critical findings — exit 0`);
  }
  line();
}

main().catch((err) => {
  console.error(`\n${red("✗")} ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
