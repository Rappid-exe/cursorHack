/**
 * Proves the demo survives a dead key.
 *
 * The live classification is the one part of this system that can fail on the
 * day — a revoked key, a rate limit, or venue wifi. This forces that failure
 * with a deliberately invalid key and checks that the recorded classification
 * takes over and still produces a complete, correct result.
 *
 * It also checks the fallback refuses to apply to anything other than the
 * committed sample, because substituting a recorded answer for a configuration
 * we have never seen would be a fabrication rather than a fallback.
 *
 * Run: npx tsx scripts/verify-fallback.ts
 */

process.env.ANTHROPIC_API_KEY = "sk-ant-deliberately-invalid-key-for-this-test-000000";

import { DEMO_CONFIG, DEMO_TOOLS } from "../src/lib/demo/fixture";
import { parseConfig } from "../src/lib/engine/config";
import { classifyTools, ClassificationError } from "../src/lib/classify";
import { cachedClassification, isDemoSurface } from "../src/lib/demo/cached";
import { scan } from "../src/lib/engine/scan";
import { remediate } from "../src/lib/engine/remediate";

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

async function main() {
  console.log("\nFallback under a rejected key\n");

  const servers = parseConfig(DEMO_CONFIG);

  let threw: ClassificationError | null = null;
  try {
    await classifyTools(DEMO_TOOLS);
  } catch (err) {
    threw = err instanceof ClassificationError ? err : null;
  }

  check("the live call fails with a typed error", threw !== null, String(threw));
  check(
    "and is classified as an auth problem rather than a generic outage",
    threw?.kind === "auth_rejected",
    threw?.kind,
  );

  check("the committed sample is recognised", isDemoSurface(DEMO_TOOLS));
  check(
    "a different surface is not",
    !isDemoSurface([{ serverKey: "x", name: "y", description: "z" }]),
  );

  const fallback = cachedClassification();
  check("the recorded classification covers every sample tool", fallback.tools.length === DEMO_TOOLS.length, `${fallback.tools.length}/${DEMO_TOOLS.length}`);
  check("it carries capabilities", fallback.tools.some((t) => t.capabilities.length > 0));
  check("it carries injection spans", fallback.injections.length > 0);
  check(
    "every recorded span still occurs verbatim in its description",
    fallback.injections.every((s) => {
      const tool = DEMO_TOOLS.find((t) => t.serverKey === s.serverKey && t.name === s.toolName);
      return tool ? tool.description.slice(s.offset, s.offset + s.text.length) === s.text : false;
    }),
  );

  const result = scan(servers, fallback.tools, fallback.injections);
  result.remediation = remediate(servers, fallback.tools, result.paths);

  check("the engine still produces attack paths", result.paths.length > 0, `${result.paths.length}`);
  check("including composed ones", result.summary.compositionPathCount > 0);
  check("supply-chain findings are unaffected", result.supply.length > 0, `${result.supply.length}`);
  check("remediation still computes", (result.remediation?.perServer.length ?? 0) === servers.length);
  check(
    "and still finds servers whose removal changes nothing",
    (result.remediation?.perServer.filter((s) => s.pathsClosed === 0).length ?? 0) > 0,
  );

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} FAILED`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("\nverify-fallback failed:", err);
  process.exit(1);
});
