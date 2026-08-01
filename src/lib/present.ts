/**
 * Presentation helpers.
 *
 * Severity is decided by the engine; this file only decides how it looks. Kept
 * separate so that no component can quietly invent a band the engine did not
 * assign, and so the mapping from band to colour exists exactly once.
 */

import type { Severity, SupplyFinding, InjectionPattern } from "@/lib/engine/types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Tailwind classes per band. Text, surface and border move together. */
export const SEVERITY_STYLE: Record<Severity, { text: string; chip: string; rail: string }> = {
  critical: {
    text: "text-critical",
    chip: "bg-critical-surface border-critical-border text-critical",
    rail: "bg-critical",
  },
  high: {
    text: "text-high",
    chip: "bg-high-surface border-high-border text-high",
    rail: "bg-high",
  },
  medium: {
    text: "text-medium",
    chip: "bg-medium-surface border-medium-border text-medium",
    rail: "bg-medium",
  },
  low: {
    text: "text-low",
    chip: "bg-low-surface border-low-border text-low",
    rail: "bg-low",
  },
};

export const SUPPLY_LABEL: Record<SupplyFinding["kind"], string> = {
  "unpinned-fetch": "Unpinned",
  "unknown-to-registry": "Unregistered",
  "no-repository": "No source",
  "young-package": "Recently published",
  "known-advisory": "Advisory",
  "kev-listed": "Actively exploited",
  "secret-in-config": "Credential in config",
  "remote-operator": "Third-party operator",
};

export const INJECTION_LABEL: Record<InjectionPattern, string> = {
  "instruction-to-model": "Instructs the model",
  "conceal-from-user": "Hides itself from the user",
  "out-of-scope-file-access": "Reaches outside its purpose",
  "tool-sequencing": "Dictates other tool calls",
  "encoded-content": "Carries encoded content",
};

/** "3 servers" / "1 server" without a separate branch at every call site. */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
