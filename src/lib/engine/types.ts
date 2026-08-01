import type { CapabilityId } from "./capabilities";

/**
 * A server as it appears in a client's configuration file.
 *
 * This mirrors the shape Claude Desktop, Cursor and the other MCP clients use:
 * a `mcpServers` object whose keys are local names and whose values describe
 * either a command to run locally or a remote URL to talk to.
 */
export interface ServerSpec {
  /** The key under `mcpServers`. This is the name the model sees. */
  key: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** Set for remote servers rather than locally executed ones. */
  url?: string;
}

/** A tool as advertised by a server: the name and description the model reads. */
export interface ToolSpec {
  serverKey: string;
  name: string;
  description: string;
}

/**
 * A tool after classification.
 *
 * `capabilities` is the model's output, filtered to the known vocabulary.
 * `rationale` is the model explaining itself to a human reviewer — it is never
 * used to derive a finding, and nothing downstream reads it.
 */
export interface ClassifiedTool extends ToolSpec {
  capabilities: CapabilityId[];
  rationale: string;
}

/**
 * A verbatim span of a tool description that instructs the model rather than
 * describing the tool.
 *
 * The model locates these; it does not score them. `text` must appear
 * character-for-character in the description — the scan verifies this and drops
 * any span that does not, so a paraphrase can never be presented as a quote.
 */
export interface InjectionSpan {
  serverKey: string;
  toolName: string;
  /** Exact substring of the description. */
  text: string;
  /** Character offset of `text` within the description, verified at scan time. */
  offset: number;
  /** Which of the fixed pattern classes this span falls into. */
  pattern: InjectionPattern;
}

/**
 * The closed set of injection shapes. As with capabilities, the model may only
 * choose from these, and anything else is dropped.
 */
export const INJECTION_PATTERNS = [
  "instruction-to-model",
  "conceal-from-user",
  "out-of-scope-file-access",
  "tool-sequencing",
  "encoded-content",
] as const;

export type InjectionPattern = (typeof INJECTION_PATTERNS)[number];

export type Severity = "critical" | "high" | "medium" | "low";

/** A concrete way to satisfy one step: this tool, on this server. */
export interface Provider {
  capability: CapabilityId;
  serverKey: string;
  toolName: string;
}

/** One leg of an attack path as walked by the chosen route. */
export interface PathLeg {
  /** What the attacker needs at this step. */
  role: string;
  /** Any one of these capabilities satisfies the leg. */
  accepts: CapabilityId[];
  /** The single provider this route uses. */
  chosen: Provider;
  /**
   * How many other tools could stand in for `chosen` at this step. Reported as
   * a count rather than a list because the point is redundancy — a path with
   * six alternatives at every leg cannot be closed by removing one server.
   */
  alternatives: number;
}

/**
 * An attack path that the installed tool surface makes possible.
 *
 * The path is reported as one concrete route rather than every possible route.
 * Listing all of them is technically complete and practically useless: with
 * eleven servers installed, most legs have six or seven providers and the card
 * becomes a wall of chips that hides the shape of the attack. So the engine
 * picks a *witness* — the smallest set of servers that walks the whole path —
 * and reports the breadth separately as counts.
 *
 * `requiresComposition` is the finding that justifies this product existing: it
 * is true when no single server supplies every leg, which means every server
 * involved is individually defensible and the risk exists only because they are
 * installed together. Nothing that audits one server at a time can see it.
 *
 * `soloCapableServers` is its complement, and is not a lesser finding: a server
 * that walks the whole path by itself is a problem you own regardless of what
 * else you have installed.
 */
export interface AttackPath {
  ruleId: string;
  name: string;
  narrative: string;
  /** The witness route: exactly one provider per leg. */
  legs: PathLeg[];
  techniques: string[];
  severity: Severity;
  severityReason: string;
  requiresComposition: boolean;
  /** Distinct servers in the witness route. */
  serversInvolved: string[];
  /** Servers that satisfy every leg on their own. Empty when composition is required. */
  soloCapableServers: string[];
  /** Distinct servers that could contribute to this path by any route. */
  totalServersCapable: number;
}

/** A supply-chain observation about how a server is delivered. */
export interface SupplyFinding {
  serverKey: string;
  kind:
    | "unpinned-fetch"
    | "unknown-to-registry"
    | "no-repository"
    | "young-package"
    | "known-advisory"
    | "kev-listed"
    | "secret-in-config"
    | "remote-operator";
  severity: Severity;
  summary: string;
  /** Verbatim supporting data, so the claim can be checked. */
  evidence: string;
  /** Where the evidence came from. */
  source: string;
}

export interface ServerReport {
  key: string;
  delivery: "local" | "remote";
  /** Command line as configured, for display. */
  invocation: string;
  toolCount: number;
  capabilities: CapabilityId[];
  registryName: string | null;
  packageId: string | null;
}

/** See src/lib/engine/remediate.ts. Optional so `scan` can skip it when it
 *  is being called recursively to evaluate a hypothetical surface. */
export interface RemediationSummary {
  perServer: {
    serverKey: string;
    pathsClosed: number;
    criticalClosed: number;
    pathsRemaining: number;
  }[];
  minimalCut: string[] | null;
  noSingleFix: boolean;
  byCapabilityClass: { role: "ingress" | "egress" | "execution"; closes: number }[];
}

export interface ScanResult {
  servers: ServerReport[];
  tools: ClassifiedTool[];
  capabilities: CapabilityId[];
  paths: AttackPath[];
  injections: InjectionSpan[];
  supply: SupplyFinding[];
  remediation?: RemediationSummary;
  /** Counts the demo and the brief both read from. */
  summary: {
    serverCount: number;
    toolCount: number;
    capabilityCount: number;
    pathCount: number;
    compositionPathCount: number;
    criticalCount: number;
    highCount: number;
  };
}
