/**
 * The scanner.
 *
 * Takes a parsed config plus the classified tool surface, and produces every
 * finding deterministically. No model call happens here — by the time control
 * reaches this file, classification is done and validated, and everything from
 * this point is set arithmetic over a fixed rule table.
 *
 * That split is the point of the architecture. The model reads English and says
 * "this tool reads files". The engine decides whether that matters, how badly,
 * and what an attacker would do with it — from rules a human wrote and can
 * audit, citing datasets a human can check.
 */

import type {
  AttackPath,
  ClassifiedTool,
  PathLeg,
  Provider,
  ScanResult,
  ServerReport,
  ServerSpec,
  SupplyFinding,
  InjectionSpan,
} from "./types";
import type { CapabilityId } from "./capabilities";
import { PATH_RULES, severityFor, comparePaths } from "./paths";
import type { PathRule } from "./paths";
import { assessServer, hasConfirmedEvidence } from "./supply";
import { invocationOf, packageOf } from "./config";
import { lookupRegistryServer } from "./data";

/**
 * Chooses the route to report for a rule whose legs are all satisfiable.
 *
 * Prefers a single server that walks the whole path, because that is both the
 * clearest thing to show and the easiest thing to act on. Failing that, finds
 * the smallest set of servers that covers every leg.
 *
 * The cover search is exhaustive over subsets up to size three and greedy
 * beyond it. Exhaustive is affordable at these sizes — a config with twenty
 * servers is 1,540 three-subsets — and three is enough, because no rule in the
 * table has more than three legs and a minimal cover can never need more
 * servers than there are legs.
 */
function chooseRoute(
  rule: PathRule,
  optionsPerLeg: Provider[][],
): { route: Provider[]; solo: string[] } {
  const serversPerLeg = optionsPerLeg.map((opts) => new Set(opts.map((o) => o.serverKey)));
  const allServers = [...new Set(optionsPerLeg.flat().map((o) => o.serverKey))].sort();

  const covers = (chosen: string[]) =>
    serversPerLeg.every((leg) => chosen.some((s) => leg.has(s)));

  /** First provider on `server` for leg `i`, or the leg's first provider. */
  const pick = (i: number, server?: string): Provider =>
    (server ? optionsPerLeg[i].find((o) => o.serverKey === server) : undefined) ??
    optionsPerLeg[i][0];

  // Servers that satisfy every leg alone.
  const solo = allServers.filter((s) => serversPerLeg.every((leg) => leg.has(s)));
  if (solo.length > 0) {
    return { route: optionsPerLeg.map((_, i) => pick(i, solo[0])), solo };
  }

  // Smallest covering set. Sizes 2 and 3 exhaustively.
  for (let size = 2; size <= Math.min(3, allServers.length); size += 1) {
    const combo: string[] = [];
    const search = (start: number): string[] | null => {
      if (combo.length === size) return covers(combo) ? [...combo] : null;
      for (let i = start; i < allServers.length; i += 1) {
        combo.push(allServers[i]);
        const found = search(i + 1);
        combo.pop();
        if (found) return found;
      }
      return null;
    };
    const found = search(0);
    if (found) {
      return {
        route: optionsPerLeg.map((_, i) => pick(i, found.find((s) => serversPerLeg[i].has(s)))),
        solo: [],
      };
    }
  }

  // Greedy fallback. Unreachable for the current rule table, which tops out at
  // three legs, but a rule added later with more legs must still resolve.
  const chosen: string[] = [];
  for (let i = 0; i < serversPerLeg.length; i += 1) {
    if (!chosen.some((s) => serversPerLeg[i].has(s))) {
      chosen.push(optionsPerLeg[i][0].serverKey);
    }
  }
  return {
    route: optionsPerLeg.map((_, i) => pick(i, chosen.find((s) => serversPerLeg[i].has(s)))),
    solo: [],
  };
}

export function scan(
  servers: ServerSpec[],
  tools: ClassifiedTool[],
  injections: InjectionSpan[] = [],
): ScanResult {
  // --- Index the tool surface by capability ---------------------------------
  const providers = new Map<CapabilityId, Provider[]>();
  for (const tool of tools) {
    for (const cap of tool.capabilities) {
      const list = providers.get(cap) ?? [];
      list.push({ capability: cap, serverKey: tool.serverKey, toolName: tool.name });
      providers.set(cap, list);
    }
  }
  const present = [...providers.keys()].sort();

  // --- Supply chain, per server ---------------------------------------------
  const supply: SupplyFinding[] = [];
  const evidenceByServer = new Map<string, boolean>();
  for (const server of servers) {
    const findings = assessServer(server);
    supply.push(...findings);
    evidenceByServer.set(server.key, hasConfirmedEvidence(findings));
  }

  // --- Attack paths ---------------------------------------------------------
  const paths: AttackPath[] = [];

  for (const rule of PATH_RULES) {
    // Every provider that could satisfy each leg, before a route is chosen.
    const optionsPerLeg = rule.legs.map((spec) =>
      spec.accepts.flatMap((cap) => providers.get(cap) ?? []),
    );
    // A rule only fires when every leg has at least one provider. Partial
    // matches would assert an attack the surface cannot actually complete.
    if (optionsPerLeg.some((opts) => opts.length === 0)) continue;

    const { route, solo } = chooseRoute(rule, optionsPerLeg);

    const legs: PathLeg[] = rule.legs.map((spec, i) => ({
      role: spec.role,
      accepts: spec.accepts,
      chosen: route[i],
      alternatives: optionsPerLeg[i].length - 1,
    }));

    const serversInvolved = [...new Set(route.map((p) => p.serverKey))].sort();
    const totalServersCapable = new Set(optionsPerLeg.flat().map((p) => p.serverKey)).size;

    // The composition test: can any single server walk every leg alone? If one
    // can, a per-server audit would have caught this. If none can, the risk
    // exists only because these servers are installed together — which is
    // precisely what nothing else looks at.
    const requiresComposition = solo.length === 0;

    const hasSupplyEvidence = serversInvolved.some((k) => evidenceByServer.get(k) === true);
    const { severity, reason } = severityFor(rule, { requiresComposition, hasSupplyEvidence });

    paths.push({
      ruleId: rule.id,
      name: rule.name,
      narrative: rule.narrative,
      legs,
      techniques: rule.techniques,
      severity,
      severityReason: reason,
      requiresComposition,
      serversInvolved,
      soloCapableServers: solo,
      totalServersCapable,
    });
  }

  paths.sort(comparePaths);

  // --- Per-server summary ---------------------------------------------------
  const toolsByServer = new Map<string, ClassifiedTool[]>();
  for (const tool of tools) {
    const list = toolsByServer.get(tool.serverKey) ?? [];
    list.push(tool);
    toolsByServer.set(tool.serverKey, list);
  }

  const serverReports: ServerReport[] = servers.map((server) => {
    const own = toolsByServer.get(server.key) ?? [];
    const pkg = packageOf(server);
    const registered = pkg ? lookupRegistryServer(pkg.ecosystem, pkg.name) : null;
    return {
      key: server.key,
      delivery: server.url ? "remote" : "local",
      invocation: invocationOf(server),
      toolCount: own.length,
      capabilities: [...new Set(own.flatMap((t) => t.capabilities))].sort(),
      registryName: registered?.name ?? null,
      packageId: pkg ? `${pkg.ecosystem}:${pkg.name}` : null,
    };
  });

  return {
    servers: serverReports,
    tools,
    capabilities: present,
    paths,
    injections,
    supply,
    summary: {
      serverCount: servers.length,
      toolCount: tools.length,
      capabilityCount: present.length,
      pathCount: paths.length,
      compositionPathCount: paths.filter((p) => p.requiresComposition).length,
      criticalCount:
        paths.filter((p) => p.severity === "critical").length +
        supply.filter((s) => s.severity === "critical").length,
      highCount:
        paths.filter((p) => p.severity === "high").length +
        supply.filter((s) => s.severity === "high").length,
    },
  };
}
