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
 *   npx tsx scripts/blast-radius.ts --tools tools.json ...   # with tool definitions
 *   npx tsx scripts/blast-radius.ts --json                   # machine-readable
 *
 * Exits 1 when a critical path is found, so it fails a build.
 *
 * Without tool definitions it still does everything that does not require them:
 * supply-chain posture, credential exposure, registry provenance, pinning. Tool
 * definitions come from a client session (`--tools`), because enumerating them
 * for real would mean launching every server in the config to ask what it can
 * do — which is the problem this tool exists to warn about, not a way to solve
 * it.
 */

import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseConfig, ConfigError, invocationOf } from "../src/lib/engine/config";
import { scan } from "../src/lib/engine/scan";
import { remediate } from "../src/lib/engine/remediate";
import { assessServer } from "../src/lib/engine/supply";
import { classifyTools } from "../src/lib/classify";
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
  const argv = process.argv.slice(2);
  const asJson = argv.includes("--json");
  const toolsFlag = argv.indexOf("--tools");
  const toolsPath = toolsFlag >= 0 ? argv[toolsFlag + 1] : null;
  const positional = argv.filter(
    (a, i) => !a.startsWith("--") && i !== toolsFlag + 1,
  );

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

    const tools = toolsPath ? loadTools(toolsPath, servers) : [];
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
  line(bold(blue("  BLAST RADIUS")) + dim(`  ${target}`));
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
