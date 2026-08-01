/**
 * Dataset provenance.
 *
 * Split from data.ts so that components can print where the numbers came from
 * without pulling in the lookup tables themselves — the registry index alone is
 * 1.7 MB, and a client component importing it would ship the whole thing to the
 * browser.
 */

import registryMeta from "@/data/registry/meta.json";
import threatMeta from "@/data/threat/meta.json";
import supplyMeta from "@/data/supply/meta.json";

export const PROVENANCE = {
  registry: registryMeta as {
    source: string;
    api: string;
    homepage: string;
    seededAt: string;
    counts: Record<string, number>;
  },
  threat: threatMeta as {
    sources: {
      name: string;
      url: string;
      homepage: string;
      catalogVersion?: string;
      dateReleased?: string;
    }[];
    seededAt: string;
    counts: Record<string, number>;
  },
  supply: supplyMeta as {
    sources: { name: string; homepage: string }[];
    seededAt: string;
    counts: Record<string, number>;
  },
};
