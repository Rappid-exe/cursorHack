/**
 * Seeds the public MCP server corpus.
 *
 * Pulls every server published to the official Model Context Protocol registry
 * and commits the result to src/data/registry/. Two things depend on this file:
 *
 *   1. The corpus scan (scripts/corpus-scan.ts), which measures how common
 *      dangerous capability combinations actually are across real published
 *      servers rather than asserting it.
 *   2. Provenance lookups at scan time — when a config names a server, we can
 *      say whether it exists in the official registry, who publishes it, and
 *      what package backs it, without a network call.
 *
 * The registry returns every published *version* of every server. We keep the
 * latest version per server name; the earlier ones are noise for our purposes
 * but their count tells us the release cadence, which is a supply-chain signal
 * worth carrying.
 *
 * Run: node scripts/seed-registry.mjs
 */

import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

const API = "https://registry.modelcontextprotocol.io/v0/servers";
const OUT = join(process.cwd(), "src", "data", "registry");
const PAGE = 100;

/** The registry paginates by opaque cursor. Walk until it stops giving us one. */
async function fetchAll() {
  const rows = [];
  let cursor = null;
  let pages = 0;

  for (;;) {
    const url = new URL(API);
    url.searchParams.set("limit", String(PAGE));
    if (cursor) url.searchParams.set("cursor", cursor);

    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`registry -> HTTP ${res.status} ${res.statusText}`);
    const body = await res.json();

    const servers = body.servers ?? [];
    rows.push(...servers);
    pages += 1;
    if (pages % 10 === 0) process.stdout.write(`  ...${rows.length} versions\n`);

    cursor = body.metadata?.nextCursor ?? null;
    if (!cursor || servers.length === 0) break;
  }

  console.log(`  fetched ${rows.length} server versions across ${pages} pages`);
  return rows;
}

/**
 * How a server is delivered decides most of its supply-chain risk, so this is
 * recorded structurally rather than left in prose.
 *
 * `local` means the client downloads and executes code on the user's machine.
 * `remote` means the client speaks HTTP to someone else's server — no local
 * execution, but the operator sees every argument of every call.
 */
function deliveryOf(server) {
  const hasPackages = Array.isArray(server.packages) && server.packages.length > 0;
  const hasRemotes = Array.isArray(server.remotes) && server.remotes.length > 0;
  if (hasPackages && hasRemotes) return "both";
  if (hasPackages) return "local";
  if (hasRemotes) return "remote";
  return "unknown";
}

/**
 * Compares two semver-ish strings numerically, falling back to publish date.
 * Registry versions are free-form, so this stays tolerant rather than strict.
 */
function versionRank(v) {
  return String(v ?? "0")
    .split(/[.\-+]/)
    .map((p) => (/^\d+$/.test(p) ? Number(p) : -1));
}

function isNewer(a, b) {
  const ra = versionRank(a.version);
  const rb = versionRank(b.version);
  for (let i = 0; i < Math.max(ra.length, rb.length); i += 1) {
    const x = ra[i] ?? -1;
    const y = rb[i] ?? -1;
    if (x !== y) return x > y;
  }
  return (a.publishedAt ?? "") > (b.publishedAt ?? "");
}

async function main() {
  await mkdir(OUT, { recursive: true });
  console.log(`Seeding MCP registry -> ${OUT}\n`);

  const raw = await fetchAll();

  // Collapse to one entry per server name, keeping the newest version and
  // counting how many releases we saw.
  const byName = new Map();

  for (const entry of raw) {
    const s = entry.server;
    if (!s?.name) continue;
    const meta = entry._meta?.["io.modelcontextprotocol.registry/official"] ?? {};

    const candidate = {
      name: s.name,
      title: s.title ?? null,
      description: s.description ?? null,
      version: s.version ?? null,
      publishedAt: meta.publishedAt ?? null,
      updatedAt: meta.updatedAt ?? null,
      status: meta.status ?? null,
      repository: s.repository?.url ?? null,
      websiteUrl: s.websiteUrl ?? null,
      delivery: deliveryOf(s),
      // Registry package entries tell us the ecosystem and identifier, which is
      // what the supply-chain layer needs to reach npm/PyPI/OSV.
      packages: (s.packages ?? []).map((p) => ({
        registryType: p.registryType ?? null,
        identifier: p.identifier ?? null,
        version: p.version ?? null,
        transport: p.transport?.type ?? null,
        runtimeHint: p.runtimeHint ?? null,
      })),
      remotes: (s.remotes ?? []).map((r) => ({
        type: r.type ?? null,
        url: r.url ?? null,
      })),
      releaseCount: 1,
    };

    const existing = byName.get(s.name);
    if (!existing) {
      byName.set(s.name, candidate);
      continue;
    }
    existing.releaseCount += 1;
    if (isNewer(candidate, existing)) {
      candidate.releaseCount = existing.releaseCount;
      // Keep the earliest publish we have seen; it dates the project, not the release.
      candidate.firstPublishedAt =
        existing.firstPublishedAt ?? existing.publishedAt ?? candidate.publishedAt;
      byName.set(s.name, candidate);
    } else if (
      (existing.firstPublishedAt ?? existing.publishedAt ?? "") >
      (candidate.publishedAt ?? "")
    ) {
      existing.firstPublishedAt = candidate.publishedAt;
    }
  }

  const servers = [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));

  const counts = {
    servers: servers.length,
    versions: raw.length,
    local: servers.filter((s) => s.delivery === "local").length,
    remote: servers.filter((s) => s.delivery === "remote").length,
    both: servers.filter((s) => s.delivery === "both").length,
    active: servers.filter((s) => s.status === "active").length,
    withRepository: servers.filter((s) => s.repository).length,
  };

  const json = JSON.stringify(servers);
  await writeFile(join(OUT, "servers.json"), json, "utf8");
  await writeFile(
    join(OUT, "meta.json"),
    JSON.stringify(
      {
        source: "Official Model Context Protocol registry",
        api: API,
        homepage: "https://registry.modelcontextprotocol.io",
        seededAt: new Date().toISOString(),
        counts,
      },
      null,
      2,
    ),
    "utf8",
  );

  console.log(`\n  servers.json  ${servers.length} servers  ${Math.round(json.length / 1024)} KB`);
  for (const [k, v] of Object.entries(counts)) {
    console.log(`    ${k.padEnd(16)} ${v}`);
  }
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("\nSeed failed:", err.message);
  process.exit(1);
});
