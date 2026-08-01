/**
 * Accessors over the committed datasets.
 *
 * Everything under src/data is pulled at build time by the seed scripts and
 * committed, so the running app makes no outbound call to CISA, MITRE, OSV, npm
 * or the MCP registry. The demo is therefore deterministic and works offline,
 * and every claim traces to a file in the repository.
 *
 * The indexes are built once at module load. Next.js keeps this warm across
 * requests; the corpus scan builds them once for tens of thousands of lookups.
 */

import registryIndex from "@/data/registry/index.json";
import kev from "@/data/threat/kev.json";
import packages from "@/data/supply/packages.json";

/**
 * A registry publisher, as held in the slim index.
 *
 * The full corpus record has twenty fields; the app needs four. Everything else
 * lives in servers.json, which only the corpus scan reads.
 */
export interface RegistryPublisher {
  name: string;
  version: string | null;
  repository: string | null;
  status: string | null;
}

export interface KevEntry {
  vendor: string | null;
  product: string | null;
  name: string | null;
  dateAdded: string | null;
  dueDate: string | null;
  knownRansomware: boolean;
  notes: string | null;
}

export interface PackageMeta {
  ecosystem: "npm" | "pypi";
  name: string;
  latestVersion: string | null;
  lastPublished: string | null;
  firstPublished: string | null;
  maintainers: number | null;
  deprecated: string | null;
  repository: string | null;
  advisories: {
    id: string;
    summary: string;
    severity: string | null;
    cves: string[];
    affected: string;
  }[];
}

const KEV = kev as { catalogVersion: string; dateReleased: string; byCve: Record<string, KevEntry> };
const PACKAGES = packages as Record<string, PackageMeta>;
/** Keyed `ecosystem:identifier`, lowercased, built by build-registry-index.mjs. */
const REGISTRY_INDEX = registryIndex as Record<string, RegistryPublisher>;

/** Is this CVE in CISA's actively-exploited catalogue? */
export function kevEntry(cve: string): KevEntry | null {
  return KEV.byCve[cve.toUpperCase()] ?? null;
}

export { technique, allTechniqueIds } from "./attack";
export type { AttackTechnique } from "./attack";

/** Committed npm/PyPI metadata and advisories for a package, if we hold it. */
export function lookupPackage(
  ecosystem: "npm" | "pypi",
  name: string,
): PackageMeta | null {
  return PACKAGES[`${ecosystem}:${name.toLowerCase()}`] ?? null;
}

/** The official-registry server that publishes this package, if any. */
export function lookupRegistryServer(
  ecosystem: "npm" | "pypi",
  name: string,
): RegistryPublisher | null {
  return REGISTRY_INDEX[`${ecosystem}:${name.toLowerCase()}`] ?? null;
}

export { PROVENANCE } from "./provenance";
