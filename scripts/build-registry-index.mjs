/**
 * Derives the app's slim registry index from the full corpus.
 *
 * servers.json is 10 MB — the whole published registry — which is right for the
 * corpus scan and far too heavy to import into a request path. The app only
 * ever asks one question of it ("who publishes this package?"), so this reduces
 * it to exactly that lookup plus the counts the provenance footer prints.
 *
 * Run after seed-registry.mjs:  node scripts/build-registry-index.mjs
 */

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const DIR = join(process.cwd(), "src", "data", "registry");

async function main() {
  const servers = JSON.parse(await readFile(join(DIR, "servers.json"), "utf8"));

  /** `ecosystem:identifier` (lowercased) -> minimal publisher record. */
  const byPackage = {};

  for (const server of servers) {
    for (const p of server.packages ?? []) {
      if (!p.identifier || !p.registryType) continue;
      const key = `${p.registryType.toLowerCase()}:${p.identifier.toLowerCase()}`;
      if (byPackage[key]) continue;
      byPackage[key] = {
        name: server.name,
        version: server.version,
        repository: server.repository,
        status: server.status,
      };
    }
  }

  const json = JSON.stringify(byPackage);
  await writeFile(join(DIR, "index.json"), json, "utf8");
  console.log(
    `index.json  ${Object.keys(byPackage).length} packages  ${Math.round(json.length / 1024)} KB`,
  );
}

main().catch((err) => {
  console.error("Index build failed:", err.message);
  process.exit(1);
});
