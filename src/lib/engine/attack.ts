/**
 * MITRE ATT&CK technique lookup.
 *
 * Split out of data.ts so client components can label a finding with its
 * technique without importing the registry index or the package table. The
 * technique file is ~8 KB and safe to ship.
 */

import attack from "@/data/threat/attack.json";

export interface AttackTechnique {
  id: string;
  name: string;
  url: string;
  description: string;
  tactics: string[];
}

const ATTACK = attack as Record<string, AttackTechnique>;

/** The MITRE record for a technique id, or null if it was never seeded. */
export function technique(id: string): AttackTechnique | null {
  return ATTACK[id] ?? null;
}

export function allTechniqueIds(): string[] {
  return Object.keys(ATTACK);
}
