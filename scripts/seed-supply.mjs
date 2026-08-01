/**
 * Seeds package metadata and vulnerability advisories.
 *
 * Two sources, both public and both authoritative for what they cover:
 *
 *   npm / PyPI registries — when the package was first and last published, how
 *                           many maintainers can publish it, whether it is
 *                           deprecated. Publish recency and maintainer count
 *                           are the signals that matter for a package your
 *                           agent re-downloads and executes on every launch.
 *
 *   OSV.dev              — Google's aggregated vulnerability database, which
 *                          covers npm and PyPI directly. Queried in batches.
 *
 * We enrich every package referenced by the official MCP registry, plus the
 * packages named in the demo config, so the app can answer supply-chain
 * questions offline.
 *
 * Run: node scripts/seed-supply.mjs
 */

import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const OUT = join(process.cwd(), "src", "data", "supply");
const REGISTRY_FILE = join(process.cwd(), "src", "data", "registry", "servers.json");
const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns";
const CONCURRENCY = 24;

/** Packages the demo config names, which must be present whatever the registry holds. */
const DEMO_PACKAGES = [
  ["npm", "@modelcontextprotocol/server-filesystem"],
  ["npm", "@modelcontextprotocol/server-github"],
  ["npm", "@modelcontextprotocol/server-postgres"],
  ["npm", "@modelcontextprotocol/server-slack"],
  ["npm", "@modelcontextprotocol/server-memory"],
  ["npm", "@modelcontextprotocol/server-puppeteer"],
  ["npm", "mcp-shell-server"],
  ["npm", "notion-sync-mcp"],
  ["pypi", "mcp-server-fetch"],
  ["pypi", "awslabs.core-mcp-server"],
];

/** Runs `worker` over `items` with a bounded number in flight. */
async function pool(items, worker, concurrency = CONCURRENCY) {
  const results = [];
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(runners);
  return results;
}

async function npmMeta(name) {
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace(/%40/, "@").replace(/%2F/, "/")}`, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) return null;
  const body = await res.json();

  const latest = body["dist-tags"]?.latest ?? null;
  const times = body.time ?? {};
  const versions = Object.keys(times).filter((k) => k !== "created" && k !== "modified");

  return {
    latestVersion: latest,
    lastPublished: (latest && times[latest]) || times.modified || null,
    firstPublished: times.created ?? null,
    maintainers: Array.isArray(body.maintainers) ? body.maintainers.length : null,
    deprecated:
      latest && body.versions?.[latest]?.deprecated
        ? String(body.versions[latest].deprecated)
        : null,
    repository:
      typeof body.repository?.url === "string"
        ? body.repository.url.replace(/^git\+/, "").replace(/\.git$/, "")
        : null,
    versionCount: versions.length,
  };
}

async function pypiMeta(name) {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) return null;
  const body = await res.json();

  const latest = body.info?.version ?? null;
  const releases = body.releases ?? {};
  // PyPI dates live on individual files rather than the release.
  const dates = Object.values(releases)
    .flat()
    .map((f) => f?.upload_time_iso_8601)
    .filter(Boolean)
    .sort();

  return {
    latestVersion: latest,
    lastPublished: dates.at(-1) ?? null,
    firstPublished: dates[0] ?? null,
    // PyPI does not expose a maintainer list on the JSON API.
    maintainers: null,
    deprecated: body.info?.yanked ? String(body.info.yanked_reason ?? "yanked") : null,
    repository:
      body.info?.project_urls?.Source ??
      body.info?.project_urls?.Repository ??
      body.info?.home_page ??
      null,
    versionCount: Object.keys(releases).length,
  };
}

/** OSV accepts up to 1000 queries per batch and answers with vulnerability ids. */
async function osvBatch(entries) {
  const queries = entries.map(([ecosystem, name]) => ({
    package: { name, ecosystem: ecosystem === "npm" ? "npm" : "PyPI" },
  }));

  const res = await fetch(OSV_BATCH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });
  if (!res.ok) throw new Error(`OSV batch -> HTTP ${res.status}`);
  const body = await res.json();
  return body.results ?? [];
}

/** Full record for one advisory id, for the summary and severity. */
async function osvDetail(id) {
  const res = await fetch(`${OSV_VULN}/${encodeURIComponent(id)}`);
  if (!res.ok) return null;
  const v = await res.json();

  const cves = (v.aliases ?? []).filter((a) => /^CVE-/i.test(a));
  // OSV records severity either as a CVSS vector or in database_specific.
  const sev =
    v.database_specific?.severity ??
    (Array.isArray(v.severity) && v.severity.length ? "UNKNOWN" : null);

  const affected = (v.affected ?? [])
    .map((a) => a.package?.name)
    .filter(Boolean)
    .join(", ");

  return {
    id: v.id,
    summary: (v.summary ?? v.details ?? "").split("\n")[0].slice(0, 220),
    severity: sev,
    cves,
    affected: affected || "the package",
  };
}

async function main() {
  await mkdir(OUT, { recursive: true });
  console.log(`Seeding package supply chain -> ${OUT}\n`);

  // Collect every package the registry references, plus the demo's.
  const wanted = new Map();
  for (const [eco, name] of DEMO_PACKAGES) wanted.set(`${eco}:${name.toLowerCase()}`, [eco, name]);

  try {
    const registry = JSON.parse(await readFile(REGISTRY_FILE, "utf8"));
    for (const server of registry) {
      for (const p of server.packages ?? []) {
        if (!p.identifier || !p.registryType) continue;
        const eco = p.registryType.toLowerCase();
        if (eco !== "npm" && eco !== "pypi") continue;
        wanted.set(`${eco}:${p.identifier.toLowerCase()}`, [eco, p.identifier]);
      }
    }
  } catch {
    console.log("  (registry not seeded yet — enriching demo packages only)");
  }

  const entries = [...wanted.values()];
  console.log(`  ${entries.length} packages to enrich\n`);

  // --- Registry metadata ----------------------------------------------------
  let done = 0;
  const metas = await pool(entries, async ([eco, name]) => {
    let meta = null;
    try {
      meta = eco === "npm" ? await npmMeta(name) : await pypiMeta(name);
    } catch {
      meta = null;
    }
    done += 1;
    if (done % 250 === 0) console.log(`  ...metadata ${done}/${entries.length}`);
    return meta;
  });
  console.log(`  metadata: ${metas.filter(Boolean).length}/${entries.length} resolved`);

  // --- Advisories -----------------------------------------------------------
  const advisoryIds = new Map(); // index -> [ids]
  for (let i = 0; i < entries.length; i += 500) {
    const slice = entries.slice(i, i + 500);
    try {
      const results = await osvBatch(slice);
      results.forEach((r, j) => {
        const ids = (r.vulns ?? []).map((v) => v.id);
        if (ids.length) advisoryIds.set(i + j, ids);
      });
    } catch (err) {
      console.log(`  OSV batch ${i} failed: ${err.message}`);
    }
  }

  const uniqueIds = [...new Set([...advisoryIds.values()].flat())];
  console.log(`  advisories: ${uniqueIds.length} unique across ${advisoryIds.size} packages`);

  const details = new Map();
  const fetched = await pool(uniqueIds, (id) => osvDetail(id).catch(() => null));
  uniqueIds.forEach((id, i) => {
    if (fetched[i]) details.set(id, fetched[i]);
  });

  // --- Assemble -------------------------------------------------------------
  const out = {};
  entries.forEach(([eco, name], i) => {
    const meta = metas[i];
    const ids = advisoryIds.get(i) ?? [];
    const advisories = ids.map((id) => details.get(id)).filter(Boolean);
    // Skip packages we learned nothing about; an empty record would read as
    // "checked and clean", which is exactly the claim we must not make.
    if (!meta && advisories.length === 0) return;

    out[`${eco}:${name.toLowerCase()}`] = {
      ecosystem: eco,
      name,
      latestVersion: meta?.latestVersion ?? null,
      lastPublished: meta?.lastPublished ?? null,
      firstPublished: meta?.firstPublished ?? null,
      maintainers: meta?.maintainers ?? null,
      deprecated: meta?.deprecated ?? null,
      repository: meta?.repository ?? null,
      versionCount: meta?.versionCount ?? null,
      advisories,
    };
  });

  const withAdvisories = Object.values(out).filter((p) => p.advisories.length > 0).length;

  await writeFile(join(OUT, "packages.json"), JSON.stringify(out), "utf8");
  await writeFile(
    join(OUT, "meta.json"),
    JSON.stringify(
      {
        sources: [
          { name: "npm registry", homepage: "https://registry.npmjs.org" },
          { name: "PyPI", homepage: "https://pypi.org" },
          { name: "OSV.dev", homepage: "https://osv.dev" },
        ],
        seededAt: new Date().toISOString(),
        counts: {
          packages: Object.keys(out).length,
          packagesWithAdvisories: withAdvisories,
          advisories: uniqueIds.length,
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  console.log(`\n  packages.json  ${Object.keys(out).length} packages, ${withAdvisories} with advisories`);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("\nSeed failed:", err.message);
  process.exit(1);
});
