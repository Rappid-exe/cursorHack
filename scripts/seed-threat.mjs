/**
 * Seeds the threat-intelligence tables.
 *
 * Two public, authoritative sources, pulled at build time and committed so the
 * app makes no network call at runtime:
 *
 *   CISA KEV  — the US government's catalogue of vulnerabilities observed being
 *               exploited in the wild. Not "a CVE exists", but "this is being
 *               used against people right now". It is the difference between a
 *               scanner that produces 300 alerts and one that produces 3.
 *
 *   MITRE ATT&CK — the technique taxonomy every attack path in this product is
 *               labelled with. We pull the real records rather than typing
 *               technique names from memory, so the id, name, description and
 *               URL on every finding are verbatim MITRE.
 *
 * Only the techniques our composition rules actually cite are committed; the
 * full enterprise bundle is ~40 MB and we need fifteen records from it.
 *
 * Run: node scripts/seed-threat.mjs
 */

import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const ATTACK_URL =
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const OUT = join(process.cwd(), "src", "data", "threat");

/**
 * The techniques our attack-path rules cite.
 *
 * Every entry here must be referenced by a rule in src/lib/engine/paths.ts, and
 * every rule must cite an id from this list — verify-engine.ts enforces both
 * directions, so a rule can never quote a technique we have not pulled.
 */
const TECHNIQUES = [
  "T1059", // Command and Scripting Interpreter
  "T1005", // Data from Local System
  "T1041", // Exfiltration Over C2 Channel
  "T1567", // Exfiltration Over Web Service
  "T1552.001", // Credentials In Files
  "T1195", // Supply Chain Compromise
  "T1195.002", // Compromise Software Supply Chain
  "T1546", // Event Triggered Execution
  "T1119", // Automated Collection
  "T1114", // Email Collection
  "T1213", // Data from Information Repositories
  "T1204", // User Execution
  "T1554", // Compromise Host Software Binary
  "T1078", // Valid Accounts
  "T1074", // Data Staged
];

async function getJson(url, label) {
  process.stdout.write(`  fetching ${label}...`);
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${label} -> HTTP ${res.status} ${res.statusText}`);
  const body = await res.json();
  process.stdout.write(" ok\n");
  return body;
}

async function seedKev() {
  const body = await getJson(KEV_URL, "CISA KEV");

  // Keyed by CVE — every lookup we do is "is this CVE in the catalogue".
  const byCve = {};
  for (const v of body.vulnerabilities ?? []) {
    if (!v.cveID) continue;
    byCve[v.cveID] = {
      vendor: v.vendorProject ?? null,
      product: v.product ?? null,
      name: v.vulnerabilityName ?? null,
      dateAdded: v.dateAdded ?? null,
      dueDate: v.dueDate ?? null,
      // CISA flags whether the vulnerability is known to be used in ransomware
      // campaigns. It is the strongest single severity signal in the feed.
      knownRansomware: /^known$/i.test(v.knownRansomwareCampaignUse ?? ""),
      notes: v.notes ?? null,
    };
  }

  return {
    catalogVersion: body.catalogVersion ?? null,
    dateReleased: body.dateReleased ?? null,
    byCve,
  };
}

async function seedAttack() {
  const bundle = await getJson(ATTACK_URL, "MITRE ATT&CK enterprise");
  const wanted = new Set(TECHNIQUES);
  const found = {};

  for (const obj of bundle.objects ?? []) {
    if (obj.type !== "attack-pattern" || obj.revoked || obj.x_mitre_deprecated) continue;
    const ref = (obj.external_references ?? []).find(
      (r) => r.source_name === "mitre-attack",
    );
    if (!ref?.external_id || !wanted.has(ref.external_id)) continue;

    found[ref.external_id] = {
      id: ref.external_id,
      name: obj.name,
      url: ref.url,
      // First paragraph only. The full ATT&CK description runs to several
      // hundred words and we surface this inline next to a finding.
      description: String(obj.description ?? "")
        .split("\n\n")[0]
        .replace(/\(Citation:[^)]*\)/g, "")
        .trim(),
      tactics: (obj.kill_chain_phases ?? [])
        .filter((p) => p.kill_chain_name === "mitre-attack")
        .map((p) => p.phase_name),
    };
  }

  const missing = TECHNIQUES.filter((t) => !found[t]);
  if (missing.length) {
    throw new Error(
      `ATT&CK techniques not found in the bundle: ${missing.join(", ")}. ` +
        `Either the id is wrong or MITRE has revoked it — fix TECHNIQUES rather than shipping a rule that cites a technique we cannot show.`,
    );
  }

  return found;
}

async function main() {
  await mkdir(OUT, { recursive: true });
  console.log(`Seeding threat intelligence -> ${OUT}\n`);

  const [kev, attack] = await Promise.all([seedKev(), seedAttack()]);

  await writeFile(join(OUT, "kev.json"), JSON.stringify(kev), "utf8");
  await writeFile(join(OUT, "attack.json"), JSON.stringify(attack), "utf8");

  const kevCount = Object.keys(kev.byCve).length;
  const ransomware = Object.values(kev.byCve).filter((v) => v.knownRansomware).length;

  await writeFile(
    join(OUT, "meta.json"),
    JSON.stringify(
      {
        sources: [
          {
            name: "CISA Known Exploited Vulnerabilities Catalog",
            url: KEV_URL,
            homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            catalogVersion: kev.catalogVersion,
            dateReleased: kev.dateReleased,
          },
          {
            name: "MITRE ATT&CK for Enterprise",
            url: ATTACK_URL,
            homepage: "https://attack.mitre.org",
          },
        ],
        seededAt: new Date().toISOString(),
        counts: {
          kevEntries: kevCount,
          kevRansomware: ransomware,
          attackTechniques: Object.keys(attack).length,
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  console.log(`\n  kev.json      ${kevCount} exploited CVEs (${ransomware} ransomware-linked)`);
  console.log(`  attack.json   ${Object.keys(attack).length} techniques`);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("\nSeed failed:", err.message);
  process.exit(1);
});
