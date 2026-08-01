/**
 * Writes the demo fixture out as standalone files the CLI can be pointed at.
 *
 * Keeps one source of truth: the web demo, the CLI example and the verification
 * script all read the same fixture, so they cannot drift apart and show a judge
 * three different numbers.
 *
 * Run: npx tsx scripts/export-example.ts
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DEMO_CONFIG, DEMO_TOOLS } from "../src/lib/demo/fixture";

const OUT = join(process.cwd(), "examples");
mkdirSync(OUT, { recursive: true });

writeFileSync(join(OUT, "mcp.json"), `${DEMO_CONFIG}\n`, "utf8");
writeFileSync(join(OUT, "tools.json"), `${JSON.stringify(DEMO_TOOLS, null, 2)}\n`, "utf8");

console.log(`examples/mcp.json    ${DEMO_CONFIG.length} bytes`);
console.log(`examples/tools.json  ${DEMO_TOOLS.length} tool definitions`);
