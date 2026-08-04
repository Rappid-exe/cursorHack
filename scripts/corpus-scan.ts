/**
 * Measures the published MCP ecosystem.
 *
 * The claim this product makes — that MCP is a supply chain nobody treats as
 * one — is either true of the real registry or it is marketing. So this runs
 * over every server published to the official registry and counts.
 *
 * Two parts, with deliberately different rigour, reported separately because
 * they do not deserve the same confidence:
 *
 *   Census (all 19,513 servers). Delivery mechanism, provenance, package age
 *   and known advisories. Every figure is a join between the committed registry
 *   corpus and the committed npm/PyPI/OSV data — no inference, no model, no
 *   sampling. These numbers are exact.
 *
 *   Capability sample (a random subset). The registry publishes a description
 *   per server but not its tool list, and discovering tools for real would mean
 *   launching nineteen thousand unknown binaries — which is precisely the thing
 *   this product exists to warn against. So capability classification runs over
 *   a random sample of server descriptions, using the same classifier the app
 *   uses, and is reported as a sample with its size stated.
 *
 * Run: npx tsx scripts/corpus-scan.ts [sampleSize]
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { classifyTools } from "../src/lib/classify";
import { CAPABILITIES } from "../src/lib/engine/capabilities";
import type { CapabilityId } from "../src/lib/engine/capabilities";
import { PATH_RULES } from "../src/lib/engine/paths";
import { kevEntry } from "../src/lib/engine/data";
import type { ToolSpec } from "../src/lib/engine/types";

const ROOT = process.cwd();
const OUT = join(ROOT, "src", "data", "corpus");

interface CorpusServer {
  name: string;
  description: string | null;
  version: string | null;
  publishedAt: string | null;
  status: string | null;
  repository: string | null;
  delivery: "local" | "remote" | "both" | "unknown";
  packages: { registryType: string | null; identifier: string | null }[];
  releaseCount: number;
}

interface PackageRecord {
  lastPublished: string | null;
  maintainers: number | null;
  deprecated: string | null;
  advisories: { id: string; cves: string[]; severity: string | null }[];
}

/** Deterministic PRNG so the sample is reproducible across runs. */
function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}

async function main() {
  const sampleSize = Number(process.argv[2] ?? 240);
  await mkdir(OUT, { recursive: true });

  const servers: CorpusServer[] = JSON.parse(
    await readFile(join(ROOT, "src", "data", "registry", "servers.json"), "utf8"),
  );
  const packages: Record<string, PackageRecord> = JSON.parse(
    await readFile(join(ROOT, "src", "data", "supply", "packages.json"), "utf8"),
  );

  console.log(`Corpus scan over ${servers.length.toLocaleString()} published servers\n`);

  // ---- Census -------------------------------------------------------------
  const delivery = { local: 0, remote: 0, both: 0, unknown: 0 };
  let withRepository = 0;
  const ageDays: number[] = [];
  const advisoryServers = new Set<string>();
  const kevServers = new Set<string>();
  const deprecatedServers = new Set<string>();
  let soloMaintainer = 0;
  let maintainerKnown = 0;
  let recentlyPublished = 0;

  for (const s of servers) {
    delivery[s.delivery] += 1;
    if (s.repository) withRepository += 1;

    const age = daysSince(s.publishedAt);
    if (age !== null) {
      ageDays.push(age);
      if (age <= 30) recentlyPublished += 1;
    }

    for (const p of s.packages) {
      if (!p.identifier || !p.registryType) continue;
      const eco = p.registryType.toLowerCase();
      if (eco !== "npm" && eco !== "pypi") continue;

      const rec = packages[`${eco}:${p.identifier.toLowerCase()}`];
      if (!rec) continue;

      if (rec.maintainers !== null) {
        maintainerKnown += 1;
        if (rec.maintainers <= 1) soloMaintainer += 1;
      }
      if (rec.deprecated) deprecatedServers.add(s.name);

      for (const adv of rec.advisories) {
        advisoryServers.add(s.name);
        if (adv.cves.some((c) => kevEntry(c))) kevServers.add(s.name);
      }
    }

  }

  const census = {
    servers: servers.length,
    delivery,
    withRepository,
    withoutRepository: servers.length - withRepository,
    percentWithoutRepository: Math.round(
      ((servers.length - withRepository) / servers.length) * 1000,
    ) / 10,
    percentRemote: Math.round((delivery.remote / servers.length) * 1000) / 10,
    medianDaysSincePublish: median(ageDays),
    publishedLast30Days: recentlyPublished,
    serversWithAdvisories: advisoryServers.size,
    serversWithKevCve: kevServers.size,
    serversDeprecated: deprecatedServers.size,
    soloMaintainerPackages: soloMaintainer,
    maintainerDataAvailable: maintainerKnown,
    percentSoloMaintainer: maintainerKnown
      ? Math.round((soloMaintainer / maintainerKnown) * 1000) / 10
      : 0,
  };

  console.log("Census (exact, all servers):");
  console.log(`  delivery              local ${delivery.local}  remote ${delivery.remote}  both ${delivery.both}`);
  console.log(`  no source repository  ${census.withoutRepository} (${census.percentWithoutRepository}%)`);
  console.log(`  median age            ${census.medianDaysSincePublish} days since last publish`);
  console.log(`  published <30 days    ${census.publishedLast30Days}`);
  console.log(`  with advisories       ${census.serversWithAdvisories}`);
  console.log(`  with a KEV-listed CVE ${census.serversWithKevCve}`);
  console.log(`  single-maintainer     ${census.soloMaintainerPackages} of ${census.maintainerDataAvailable} packages (${census.percentSoloMaintainer}%)`);

  // ---- Capability sample --------------------------------------------------
  let sample: Record<string, unknown> | null = null;

  const hasKey = Boolean(process.env.ANTHROPIC_API_KEY?.trim());
  if (!hasKey) {
    console.log("\nSkipping capability sample: ANTHROPIC_API_KEY not set.");
  } else {
    // Only servers with a description substantial enough to classify. A
    // twelve-character description tells the classifier nothing, and including
    // those would understate capability across the board.
    const eligible = servers.filter((s) => (s.description ?? "").trim().length >= 40);
    const rng = mulberry32(20260801);
    const picked: CorpusServer[] = [];
    const pool = [...eligible];
    for (let i = 0; i < Math.min(sampleSize, pool.length); i += 1) {
      const j = Math.floor(rng() * pool.length);
      picked.push(pool.splice(j, 1)[0]);
    }

    console.log(
      `\nCapability sample: ${picked.length} of ${eligible.length} servers with a usable description`,
    );

    // The registry description is what we have. Treated as one pseudo-tool per
    // server, which is coarser than a real tool list and will under-report —
    // stated in the output rather than glossed.
    const specs: ToolSpec[] = picked.map((s) => ({
      serverKey: s.name,
      name: "server",
      description: `${s.description ?? ""}`.slice(0, 1200),
    }));

    const BATCH = 40;
    const capsByServer = new Map<string, CapabilityId[]>();
    let injectionSpans = 0;

    for (let i = 0; i < specs.length; i += BATCH) {
      const batch = specs.slice(i, i + BATCH);
      process.stdout.write(`  classifying ${i + 1}–${i + batch.length}...`);
      try {
        const res = await classifyTools(batch);
        for (const t of res.tools) capsByServer.set(t.serverKey, t.capabilities);
        injectionSpans += res.injections.length;
        process.stdout.write(" ok\n");
      } catch (err) {
        process.stdout.write(` failed (${err instanceof Error ? err.message : "error"})\n`);
      }
    }

    // Which servers reach a full attack path on their own.
    let soloComplete = 0;
    let anyIngress = 0;
    let anyEgress = 0;
    const capCounts = new Map<CapabilityId, number>();
    const capsPerServer: number[] = [];

    for (const caps of capsByServer.values()) {
      capsPerServer.push(caps.length);
      const set = new Set(caps);
      for (const c of caps) capCounts.set(c, (capCounts.get(c) ?? 0) + 1);
      if (caps.some((c) => CAPABILITIES[c].untrustedIngress)) anyIngress += 1;
      if (caps.some((c) => CAPABILITIES[c].egress)) anyEgress += 1;
      if (PATH_RULES.some((r) => r.legs.every((l) => l.accepts.some((a) => set.has(a))))) {
        soloComplete += 1;
      }
    }

    const classified = capsByServer.size;
    sample = {
      size: classified,
      eligiblePopulation: eligible.length,
      basis: "registry server description, treated as a single tool definition",
      caveat:
        "Coarser than the per-config scan, which reads real tool definitions. Under-reports capability, so the solo-path figure is a floor.",
      withAnyIngress: anyIngress,
      withAnyEgress: anyEgress,
      completePathAlone: soloComplete,
      percentCompletePathAlone: classified
        ? Math.round((soloComplete / classified) * 1000) / 10
        : 0,
      medianCapabilities: median(capsPerServer),
      injectionSpansFound: injectionSpans,
      capabilityFrequency: Object.fromEntries(
        [...capCounts.entries()].sort((a, b) => b[1] - a[1]),
      ),
    };

    console.log(`\nSample results (${classified} servers):`);
    console.log(`  reach a complete path alone   ${soloComplete} (${sample.percentCompletePathAlone}%)`);
    console.log(`  have an ingress capability    ${anyIngress}`);
    console.log(`  have an egress capability     ${anyEgress}`);
    console.log(`  median capabilities each      ${sample.medianCapabilities}`);
    console.log(`  injection spans in listings   ${injectionSpans}`);
  }

  const summary = { scannedAt: new Date().toISOString(), census, sample };
  await writeFile(join(OUT, "summary.json"), JSON.stringify(summary, null, 2), "utf8");
  console.log(`\nWrote ${join("src", "data", "corpus", "summary.json")}`);
}

main().catch((err) => {
  console.error("\nCorpus scan failed:", err);
  process.exit(1);
});
