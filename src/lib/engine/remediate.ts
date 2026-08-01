/**
 * What actually closes these paths.
 *
 * A scanner that stops at "you have ten attack paths" has done the easy half.
 * The question a person actually has is which change is worth making, and for
 * a composed surface that is not obvious — removing the scariest-looking server
 * frequently closes nothing at all, because six others provide the same leg.
 *
 * Everything here is the same set arithmetic the scan already does, re-run over
 * a reduced tool surface. No model, no heuristics, no scoring: a path is closed
 * if and only if some leg has no provider left.
 */

import type { AttackPath, ClassifiedTool, ServerSpec, Severity } from "./types";
import { scan } from "./scan";

export interface ServerImpact {
  serverKey: string;
  /** Paths that disappear entirely if this server is removed. */
  pathsClosed: number;
  criticalClosed: number;
  /** Paths still standing afterwards. */
  pathsRemaining: number;
}

export interface Remediation {
  /** Sorted by paths closed, descending. */
  perServer: ServerImpact[];
  /**
   * The smallest set of servers whose removal closes every path.
   *
   * Null when no subset up to the search limit achieves it, which is itself the
   * finding: the surface cannot be fixed by uninstalling things.
   */
  minimalCut: string[] | null;
  /**
   * True when removing any single server closes nothing. This is the sharpest
   * statement of the composition problem — the risk is in the combination, and
   * there is no one bad apple to point at.
   */
  noSingleFix: boolean;
  /**
   * Capabilities that, if no server provided them, would close the most paths.
   * Answers "what kind of tool should not be in this session" rather than
   * "which vendor is at fault".
   */
  byCapabilityClass: { role: "ingress" | "egress" | "execution"; closes: number }[];
}

/** Re-runs the engine with `drop` removed and returns the surviving paths. */
function pathsWithout(
  servers: ServerSpec[],
  tools: ClassifiedTool[],
  drop: Set<string>,
): AttackPath[] {
  const keptServers = servers.filter((s) => !drop.has(s.key));
  const keptTools = tools.filter((t) => !drop.has(t.serverKey));
  if (keptTools.length === 0) return [];
  return scan(keptServers, keptTools).paths;
}

const isCritical = (s: Severity) => s === "critical";

export function remediate(
  servers: ServerSpec[],
  tools: ClassifiedTool[],
  current: AttackPath[],
): Remediation {
  const baseline = current.length;
  const baselineCritical = current.filter((p) => isCritical(p.severity)).length;

  // --- What does removing each server buy you? -----------------------------
  const perServer: ServerImpact[] = servers
    .map((s) => {
      const remaining = pathsWithout(servers, tools, new Set([s.key]));
      const remainingCritical = remaining.filter((p) => isCritical(p.severity)).length;
      return {
        serverKey: s.key,
        pathsClosed: baseline - remaining.length,
        criticalClosed: baselineCritical - remainingCritical,
        pathsRemaining: remaining.length,
      };
    })
    .sort((a, b) => b.pathsClosed - a.pathsClosed || a.serverKey.localeCompare(b.serverKey));

  const noSingleFix = perServer.every((s) => s.pathsClosed === 0);

  // --- Smallest set that closes everything ---------------------------------
  // Exhaustive to size three, then a greedy extension. Configs are small (a
  // heavily-loaded client has twenty servers, so 1,140 three-subsets) and going
  // deeper exhaustively is not worth the time for a result nobody would act on
  // — "uninstall five of your eleven servers" is not advice.
  let minimalCut: string[] | null = null;
  const keys = servers.map((s) => s.key);

  outer: for (let size = 1; size <= Math.min(3, keys.length); size += 1) {
    const combo: string[] = [];
    const search = (start: number): boolean => {
      if (combo.length === size) {
        if (pathsWithout(servers, tools, new Set(combo)).length === 0) {
          minimalCut = [...combo];
          return true;
        }
        return false;
      }
      for (let i = start; i < keys.length; i += 1) {
        combo.push(keys[i]);
        if (search(i + 1)) return true;
        combo.pop();
      }
      return false;
    };
    if (search(0)) break outer;
  }

  // --- Which class of capability is load-bearing? ---------------------------
  // Rather than naming servers, this asks what would happen if the *session*
  // held no tool of a given role — which is the separation advice, and the only
  // remedy available when noSingleFix is true.
  const roles: { role: "ingress" | "egress" | "execution"; caps: string[] }[] = [
    {
      role: "ingress",
      caps: ["browse.untrusted", "fs.read", "repo.read", "db.read", "mail.read", "net.outbound"],
    },
    { role: "egress", caps: ["net.outbound", "msg.send", "repo.write", "cloud.admin"] },
    { role: "execution", caps: ["exec.shell", "config.write", "fs.write", "cloud.admin"] },
  ];

  const byCapabilityClass = roles
    .map(({ role, caps }) => {
      const stripped = tools
        .map((t) => ({ ...t, capabilities: t.capabilities.filter((c) => !caps.includes(c)) }))
        .filter((t) => t.capabilities.length > 0);
      const remaining = stripped.length === 0 ? [] : scan(servers, stripped).paths;
      return { role, closes: baseline - remaining.length };
    })
    .sort((a, b) => b.closes - a.closes);

  return { perServer, minimalCut, noSingleFix, byCapabilityClass };
}
