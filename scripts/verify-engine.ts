/**
 * Verifies the engine against the committed datasets.
 *
 * The product's claim is that a human wrote every rule and a published dataset
 * backs every citation. That claim is only worth anything if something checks
 * it, so this does — including the two traps that would quietly break the
 * product without breaking the build:
 *
 *   a rule citing an ATT&CK technique we never seeded, which renders as a
 *   missing label rather than an error;
 *
 *   the composition test inverting, which would mark single-server paths as
 *   requiring composition and escalate every severity by a band.
 *
 * Run: npx tsx scripts/verify-engine.ts
 */

import { CAPABILITIES, CAPABILITY_IDS, isCapabilityId } from "../src/lib/engine/capabilities";
import { PATH_RULES, severityFor, comparePaths } from "../src/lib/engine/paths";
import { allTechniqueIds, technique, kevEntry } from "../src/lib/engine/data";
import { parseConfig, packageOf, invocationOf } from "../src/lib/engine/config";
import { scan } from "../src/lib/engine/scan";
import { remediate } from "../src/lib/engine/remediate";
import { assessServer } from "../src/lib/engine/supply";
import { DEMO_CONFIG } from "../src/lib/demo/fixture";
import type { ClassifiedTool, Severity } from "../src/lib/engine/types";

let failures = 0;
let checks = 0;

function check(name: string, condition: boolean, detail = "") {
  checks += 1;
  if (condition) {
    console.log(`  ok    ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(title: string) {
  console.log(`\n${title}`);
}

function tool(serverKey: string, name: string, caps: string[]): ClassifiedTool {
  return {
    serverKey,
    name,
    description: "",
    capabilities: caps.filter(isCapabilityId),
    rationale: "",
  };
}

// ---------------------------------------------------------------------------
section("Capability vocabulary");

check(
  "every id has a definition",
  CAPABILITY_IDS.every((id) => CAPABILITIES[id]?.definition?.length > 20),
);
check(
  "every definition names its id",
  CAPABILITY_IDS.every((id) => CAPABILITIES[id].id === id),
);
check(
  "at least one ingress and one egress capability exist",
  CAPABILITY_IDS.some((id) => CAPABILITIES[id].untrustedIngress) &&
    CAPABILITY_IDS.some((id) => CAPABILITIES[id].egress),
);
check("isCapabilityId rejects an invented id", !isCapabilityId("fs.destroy"));
check("isCapabilityId accepts a real one", isCapabilityId("fs.read"));

// ---------------------------------------------------------------------------
section("Rule table ↔ ATT&CK");

const seeded = new Set(allTechniqueIds());
const cited = new Set(PATH_RULES.flatMap((r) => r.techniques));

const uncitedSeeds = [...seeded].filter((t) => !cited.has(t));
const unseededCitations = [...cited].filter((t) => !seeded.has(t));

check(
  "every technique a rule cites was seeded",
  unseededCitations.length === 0,
  unseededCitations.join(", "),
);
check(
  "every seeded technique is cited by a rule",
  uncitedSeeds.length === 0,
  `unused: ${uncitedSeeds.join(", ")}`,
);
check(
  "every cited technique resolves to a MITRE record with a url",
  [...cited].every((id) => technique(id)?.url?.startsWith("https://attack.mitre.org")),
);
check("rule ids are unique", new Set(PATH_RULES.map((r) => r.id)).size === PATH_RULES.length);
check(
  "every rule leg accepts only known capabilities",
  PATH_RULES.every((r) => r.legs.every((l) => l.accepts.every(isCapabilityId))),
);
check(
  "every rule has at least two legs",
  PATH_RULES.every((r) => r.legs.length >= 2),
  "a one-leg rule is a capability, not a path",
);

// ---------------------------------------------------------------------------
section("Severity arithmetic");

const base = PATH_RULES[0];
const plain = severityFor(base, { requiresComposition: false, hasSupplyEvidence: false });
const composed = severityFor(base, { requiresComposition: true, hasSupplyEvidence: false });
const ORDER: Severity[] = ["low", "medium", "high", "critical"];

check("base severity is the rule's own", plain.severity === base.baseSeverity);
check(
  "composition never lowers severity",
  ORDER.indexOf(composed.severity) >= ORDER.indexOf(plain.severity),
);
check(
  "critical is a ceiling",
  severityFor(
    { ...base, baseSeverity: "critical" },
    { requiresComposition: true, hasSupplyEvidence: true },
  ).severity === "critical",
);
check(
  "a medium rule with both escalations reaches critical",
  severityFor(
    { ...base, baseSeverity: "medium" },
    { requiresComposition: true, hasSupplyEvidence: true },
  ).severity === "critical",
);
check("severity always carries a reason", plain.reason.length > 10 && composed.reason.length > 10);
check(
  "comparePaths sorts critical before high",
  comparePaths(
    { severity: "high", serversInvolved: [] },
    { severity: "critical", serversInvolved: [] },
  ) > 0,
);

// ---------------------------------------------------------------------------
section("Composition detection");

// One server holding every capability must NOT be reported as composed.
const omnipotent = CAPABILITY_IDS.map((c, i) => tool("everything", `t${i}`, [c]));
const soloScan = scan([{ key: "everything", command: "node", args: ["s.js"] }], omnipotent);

check("a single all-capable server produces paths", soloScan.paths.length > 0);
check(
  "none of them are marked as requiring composition",
  soloScan.paths.every((p) => !p.requiresComposition),
  `${soloScan.paths.filter((p) => p.requiresComposition).length} wrongly marked`,
);

// The same capabilities split across two servers must be reported as composed.
const splitScan = scan(
  [
    { key: "reader", command: "node", args: ["a.js"] },
    { key: "sender", command: "node", args: ["b.js"] },
  ],
  [
    tool("reader", "fetch", ["browse.untrusted"]),
    tool("reader", "read", ["fs.read"]),
    tool("sender", "post", ["net.outbound"]),
  ],
);
const fileExfil = splitScan.paths.find((p) => p.ruleId === "file-exfil");

check("splitting capabilities across servers still finds the path", Boolean(fileExfil));
check("that path is marked as requiring composition", fileExfil?.requiresComposition === true);
check(
  "and names both servers",
  fileExfil?.serversInvolved.length === 2,
  fileExfil?.serversInvolved.join(", "),
);
check(
  "composition raised its severity above the rule's base",
  fileExfil?.severity === "critical",
  `got ${fileExfil?.severity}, rule base is high`,
);

// An incomplete surface must produce nothing rather than a partial path.
const partialScan = scan(
  [{ key: "readonly", command: "node", args: ["a.js"] }],
  [tool("readonly", "read", ["fs.read"])],
);
check(
  "a surface with no ingress and no egress yields no paths",
  partialScan.paths.length === 0,
  `got ${partialScan.paths.map((p) => p.ruleId).join(", ")}`,
);

// ---------------------------------------------------------------------------
section("Route selection");

check(
  "every leg of every reported path names exactly one provider",
  soloScan.paths.every((p) => p.legs.every((l) => Boolean(l.chosen?.serverKey))),
);
check(
  "the witness route names no more servers than the path has legs",
  splitScan.paths.every((p) => p.serversInvolved.length <= p.legs.length),
);
check(
  "a solo-capable server is reported as such",
  soloScan.paths.every((p) => p.soloCapableServers.includes("everything")),
);
check(
  "a composed path reports no solo-capable server",
  fileExfil?.soloCapableServers.length === 0,
);
check(
  "the chosen provider actually supplies a capability its leg accepts",
  [...soloScan.paths, ...splitScan.paths].every((p) =>
    p.legs.every((l) => l.accepts.includes(l.chosen.capability)),
  ),
);

// Breadth must be counted across all providers, not just the chosen route.
// This is the check that would have caught the original bug, where a path
// reported every capable server as though all were required.
const broadScan = scan(
  [
    { key: "a", command: "node", args: ["a.js"] },
    { key: "b", command: "node", args: ["b.js"] },
    { key: "c", command: "node", args: ["c.js"] },
    { key: "d", command: "node", args: ["d.js"] },
  ],
  [
    tool("a", "browse", ["browse.untrusted"]),
    tool("b", "browse2", ["browse.untrusted"]),
    tool("c", "read", ["fs.read"]),
    tool("d", "post", ["net.outbound"]),
  ],
);
const broad = broadScan.paths.find((p) => p.ruleId === "file-exfil");
// Two servers suffice, not three: fs.read is itself an ingress capability, so
// `c` covers both the ingress and the collection leg and only egress needs `d`.
// The engine is expected to find that shorter cover rather than the obvious
// one-server-per-leg assignment.
check(
  "a four-server surface reports the minimal two-server route",
  broad?.serversInvolved.length === 2,
  `got ${broad?.serversInvolved.join(", ")}`,
);
check(
  "but counts all four as capable of contributing",
  broad?.totalServersCapable === 4,
  `got ${broad?.totalServersCapable}`,
);
check(
  "and counts every alternative provider for the ingress leg",
  broad?.legs[0].alternatives === 3,
  `got ${broad?.legs[0].alternatives}`,
);

// A single server that solo-satisfies must be preferred over a larger cover,
// even when other servers could also contribute legs.
const mixedScan = scan(
  [
    { key: "swiss", command: "node", args: ["a.js"] },
    { key: "extra", command: "node", args: ["b.js"] },
  ],
  [
    tool("swiss", "all", ["browse.untrusted", "fs.read", "net.outbound"]),
    tool("extra", "read", ["fs.read"]),
  ],
);
const mixed = mixedScan.paths.find((p) => p.ruleId === "file-exfil");
check("a solo-capable server is preferred as the route", mixed?.serversInvolved.length === 1);
check("and the path is not marked as composed", mixed?.requiresComposition === false);

// ---------------------------------------------------------------------------
section("Remediation");

// Two servers, each supplying a leg nothing else covers: removing either must
// close the path.
const cutScan = scan(
  [
    { key: "reader", command: "node", args: ["a.js"] },
    { key: "sender", command: "node", args: ["b.js"] },
  ],
  [
    tool("reader", "fetch", ["browse.untrusted"]),
    tool("reader", "read", ["fs.read"]),
    tool("sender", "post", ["net.outbound"]),
  ],
);
const cutFix = remediate(
  [
    { key: "reader", command: "node", args: ["a.js"] },
    { key: "sender", command: "node", args: ["b.js"] },
  ],
  [
    tool("reader", "fetch", ["browse.untrusted"]),
    tool("reader", "read", ["fs.read"]),
    tool("sender", "post", ["net.outbound"]),
  ],
  cutScan.paths,
);

check(
  "removing a server that uniquely supplies a leg closes paths",
  cutFix.perServer.every((s) => s.pathsClosed > 0),
  cutFix.perServer.map((s) => `${s.serverKey}:${s.pathsClosed}`).join(" "),
);
check("a fixable surface is not reported as noSingleFix", cutFix.noSingleFix === false);
check(
  "the minimal cut is a single server when one suffices",
  cutFix.minimalCut?.length === 1,
  JSON.stringify(cutFix.minimalCut),
);

// Redundant egress: two servers can each ship the data, so removing either one
// must close nothing. This is the case the remediation panel exists to surface,
// and the one a naive "count the servers on the path" implementation gets wrong.
const redundantServers = [
  { key: "web", command: "node", args: ["a.js"] },
  { key: "files", command: "node", args: ["b.js"] },
  { key: "out1", command: "node", args: ["c.js"] },
  { key: "out2", command: "node", args: ["d.js"] },
];
const redundantTools = [
  tool("web", "browse", ["browse.untrusted"]),
  tool("files", "read", ["fs.read"]),
  tool("out1", "post", ["net.outbound"]),
  tool("out2", "send", ["msg.send"]),
];
const redundantScan = scan(redundantServers, redundantTools);
const redundantFix = remediate(redundantServers, redundantTools, redundantScan.paths);
const egressImpact = redundantFix.perServer.filter((s) => s.serverKey.startsWith("out"));

check(
  "removing one of two redundant egress servers closes nothing",
  egressImpact.every((s) => s.pathsClosed === 0),
  egressImpact.map((s) => `${s.serverKey}:${s.pathsClosed}`).join(" "),
);
check(
  "but removing the only file reader does close a path",
  (redundantFix.perServer.find((s) => s.serverKey === "files")?.pathsClosed ?? 0) > 0,
);
check(
  "stripping a whole capability role closes at least as much as any one server",
  Math.max(...redundantFix.byCapabilityClass.map((c) => c.closes)) >=
    Math.max(...redundantFix.perServer.map((s) => s.pathsClosed)),
);
check(
  "per-server impact never exceeds the total path count",
  redundantFix.perServer.every((s) => s.pathsClosed <= redundantScan.paths.length),
);

// ---------------------------------------------------------------------------
section("Config parsing");

const parsed = parseConfig(DEMO_CONFIG);
check("the demo config parses", parsed.length === 11, `got ${parsed.length} servers`);
check(
  "npx -y resolves to the package after the flag",
  packageOf(parsed.find((s) => s.key === "filesystem")!)?.name ===
    "@modelcontextprotocol/server-filesystem",
);
check(
  "a pinned uvx spec keeps its version",
  packageOf(parsed.find((s) => s.key === "aws")!)?.version === "1.0.9",
);
check(
  "an unpinned uvx spec has no version",
  packageOf(parsed.find((s) => s.key === "fetch")!)?.version === null,
);
check(
  "a remote server yields no package",
  packageOf(parsed.find((s) => s.key === "sentry")!) === null,
);
check(
  "a remote server's invocation is its url",
  invocationOf(parsed.find((s) => s.key === "sentry")!).startsWith("https://"),
);
check("disabled servers are skipped", parseConfig(
  '{"mcpServers":{"a":{"command":"npx","args":["x"]},"b":{"command":"npx","args":["y"],"disabled":true}}}',
).length === 1);
check(
  "a bare server map is accepted",
  parseConfig('{"a":{"command":"npx","args":["x"]}}').length === 1,
);

let threw = false;
try {
  parseConfig("not json");
} catch {
  threw = true;
}
check("malformed input throws rather than returning empty", threw);

// ---------------------------------------------------------------------------
section("Supply chain");

const fsServer = parsed.find((s) => s.key === "filesystem")!;
const fsFindings = assessServer(fsServer);
check(
  "an unpinned npx launch is flagged",
  fsFindings.some((f) => f.kind === "unpinned-fetch"),
);

const githubFindings = assessServer(parsed.find((s) => s.key === "github")!);
check(
  "a token-shaped env value is flagged",
  githubFindings.some((f) => f.kind === "secret-in-config"),
);
check(
  "the token value itself is never echoed in evidence",
  githubFindings
    .filter((f) => f.kind === "secret-in-config")
    .every((f) => !f.evidence.includes("R2h0aGlzaXNub3RhcmVhbHRva2Vu")),
);

const sentryFindings = assessServer(parsed.find((s) => s.key === "sentry")!);
check(
  "a remote server is flagged as third-party operated",
  sentryFindings.some((f) => f.kind === "remote-operator"),
);
check(
  "a pinned package is not flagged as unpinned",
  !assessServer(parsed.find((s) => s.key === "aws")!).some((f) => f.kind === "unpinned-fetch"),
);
check(
  "every finding carries evidence and a source",
  [...fsFindings, ...githubFindings, ...sentryFindings].every(
    (f) => f.evidence.length > 0 && f.source.length > 0,
  ),
);

// ---------------------------------------------------------------------------
section("Threat data");

check("KEV lookup is case-insensitive", Boolean(kevEntry("cve-2021-44228")) === Boolean(kevEntry("CVE-2021-44228")));
check("an invented CVE is not in KEV", kevEntry("CVE-1999-99999") === null);
check("the seeded ATT&CK table is non-empty", allTechniqueIds().length >= 15);

// ---------------------------------------------------------------------------
console.log(`\n${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}
