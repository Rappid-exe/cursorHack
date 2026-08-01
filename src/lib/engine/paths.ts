/**
 * Attack-path composition rules.
 *
 * This file is the product's actual claim. Everything else — parsing configs,
 * classifying tools, drawing graphs — exists to feed it.
 *
 * The observation is that MCP security tooling, such as it exists, audits one
 * server at a time. That cannot work, because the model does not experience
 * servers one at a time. It sees a single flat list of tools and will happily
 * use a tool from server A and a tool from server B in the same turn. So the
 * unit of risk is not the server, it is the *union* of everything installed.
 *
 * A rule is a sequence of legs. Each leg lists the capabilities that can
 * satisfy it — any one will do — and all legs must be satisfied for the path to
 * exist. Legs are ordered as the attacker would walk them: get in, collect,
 * get out.
 *
 * Every rule cites MITRE ATT&CK techniques, and every id cited here must exist
 * in the committed ATT&CK table. verify-engine.ts checks both directions.
 *
 * These rules are hand-written and deliberately conservative. They are not
 * generated, not model-authored, and not tuned to make a demo look good. A path
 * is reported only when the capabilities to walk it are genuinely present.
 */

import type { CapabilityId } from "./capabilities";
import { CAPABILITIES } from "./capabilities";
import type { Severity } from "./types";

export interface PathRule {
  id: string;
  name: string;
  /** Plain description of what an attacker does, written for a human. */
  narrative: string;
  legs: { role: string; accepts: CapabilityId[] }[];
  techniques: string[];
  /** Severity before supply-chain evidence is taken into account. */
  baseSeverity: Severity;
}

/** Every capability whose invocation can carry attacker-controlled text. */
const INGRESS: CapabilityId[] = (
  Object.keys(CAPABILITIES) as CapabilityId[]
).filter((id) => CAPABILITIES[id].untrustedIngress);

/** Every capability that can move data to a destination the caller chooses. */
const EGRESS: CapabilityId[] = (
  Object.keys(CAPABILITIES) as CapabilityId[]
).filter((id) => CAPABILITIES[id].egress);

const INGRESS_LEG = {
  role: "Attacker gets text into the model's context",
  accepts: INGRESS,
};

const EGRESS_LEG = {
  role: "Data leaves to a destination the attacker names",
  accepts: EGRESS,
};

export const PATH_RULES: PathRule[] = [
  {
    id: "cred-exfil",
    name: "Injected credential theft",
    narrative:
      "A web page, issue comment or email the agent reads carries instructions. The agent follows them, reads a credential file or environment variable, and sends the contents to an address the instructions supply. The user sees a normal-looking task complete.",
    legs: [
      INGRESS_LEG,
      { role: "Credentials are read", accepts: ["secrets.read"] },
      EGRESS_LEG,
    ],
    techniques: ["T1552.001", "T1041"],
    baseSeverity: "critical",
  },
  {
    id: "injected-rce",
    name: "Injected command execution",
    narrative:
      "Content the agent reads instructs it to run a command. Because a tool that executes shell commands is installed, the instruction succeeds — the attacker is now running code on the developer's machine with their privileges.",
    legs: [INGRESS_LEG, { role: "Commands are executed", accepts: ["exec.shell"] }],
    techniques: ["T1204", "T1059"],
    baseSeverity: "critical",
  },
  {
    id: "file-exfil",
    name: "Local file exfiltration",
    narrative:
      "Injected content directs the agent to read local files — source, configuration, documents — and post them outward. No credential access is needed; the files themselves are the loss.",
    legs: [INGRESS_LEG, { role: "Local files are read", accepts: ["fs.read"] }, EGRESS_LEG],
    techniques: ["T1005", "T1041"],
    baseSeverity: "high",
  },
  {
    id: "config-persistence",
    name: "Agent configuration hijack",
    narrative:
      "Injected content directs the agent to edit its own client configuration and add a server the attacker controls. This survives restart, so a single successful injection becomes permanent access — and the added server is trusted by every future session.",
    legs: [
      INGRESS_LEG,
      { role: "Configuration is modified", accepts: ["config.write", "fs.write"] },
    ],
    techniques: ["T1546", "T1554"],
    baseSeverity: "critical",
  },
  {
    id: "repo-poison",
    name: "Source repository poisoning",
    narrative:
      "The agent reads an attacker-authored issue or pull request comment, then commits or pushes on the user's behalf. What lands in the repository carries the attacker's change, signed with the user's credentials, and flows on to everyone who depends on it.",
    legs: [INGRESS_LEG, { role: "Code is written or pushed", accepts: ["repo.write"] }],
    techniques: ["T1195.002"],
    baseSeverity: "critical",
  },
  {
    id: "code-exfil",
    name: "Private source exfiltration",
    narrative:
      "Injected content directs the agent to read private repositories and forward what it finds. Source, secrets committed by mistake, and unreleased work all leave together.",
    legs: [INGRESS_LEG, { role: "Private code is read", accepts: ["repo.read"] }, EGRESS_LEG],
    techniques: ["T1213", "T1567"],
    baseSeverity: "high",
  },
  {
    id: "db-exfil",
    name: "Database exfiltration",
    narrative:
      "A row of user-supplied data carries instructions. The agent reads it while answering an ordinary question, then queries more broadly and sends the results outward. The injection lives in the data, so it fires again on every scan.",
    legs: [INGRESS_LEG, { role: "The database is queried", accepts: ["db.read"] }, EGRESS_LEG],
    techniques: ["T1213", "T1041"],
    baseSeverity: "high",
  },
  {
    id: "mail-exfil",
    name: "Mailbox exfiltration",
    narrative:
      "An inbound email carries instructions. The agent reads it during a routine triage task, then forwards the mailbox contents onward. Anyone who can email the user can start this.",
    legs: [INGRESS_LEG, { role: "Messages are read", accepts: ["mail.read"] }, EGRESS_LEG],
    techniques: ["T1114", "T1567"],
    baseSeverity: "high",
  },
  {
    id: "cloud-takeover",
    name: "Cloud infrastructure change",
    narrative:
      "Injected content reaches an agent that can administer cloud resources. Changing an IAM policy or opening a security group is a single tool call, and it does not look different from legitimate work.",
    legs: [
      INGRESS_LEG,
      { role: "Infrastructure or IAM is changed", accepts: ["cloud.admin"] },
    ],
    techniques: ["T1078", "T1195"],
    baseSeverity: "critical",
  },
  {
    id: "staged-collection",
    name: "Staged local collection",
    narrative:
      "Data is gathered from several sources and written to one local file. On its own this is not exfiltration, but it assembles the payload — and any later egress, by any tool, ships it in a single call.",
    legs: [
      INGRESS_LEG,
      { role: "Data is collected", accepts: ["fs.read", "db.read", "repo.read", "mail.read"] },
      { role: "Collected data is staged on disk", accepts: ["fs.write"] },
    ],
    techniques: ["T1119", "T1074"],
    baseSeverity: "medium",
  },
];

/**
 * Severity for a matched path.
 *
 * Deliberately a pure function of evidence, in one place, so that no part of
 * the UI can quietly invent a different answer. The base severity comes from
 * the rule; the only things that move it are facts we can point at.
 *
 * Two escalations, both grounded:
 *
 *   Composition across servers escalates by one band. A path assembled from
 *   several servers is strictly harder to notice than one a single server
 *   offers, because no per-server review — and no server's own documentation —
 *   shows it.
 *
 *   Confirmed supply-chain evidence against a server on the path escalates by
 *   one band. If a leg is supplied by a package with a listed advisory or an
 *   unpinned fetch, the path is not hypothetical in the same way.
 *
 * Nothing de-escalates. A rule's base severity is a floor.
 */
const ORDER: Severity[] = ["low", "medium", "high", "critical"];

export function severityFor(
  rule: PathRule,
  opts: { requiresComposition: boolean; hasSupplyEvidence: boolean },
): { severity: Severity; reason: string } {
  let index = ORDER.indexOf(rule.baseSeverity);
  const reasons: string[] = [`${rule.name} is rated ${rule.baseSeverity} by the rule`];

  if (opts.requiresComposition) {
    index = Math.min(index + 1, ORDER.length - 1);
    reasons.push("raised because no single server supplies the whole path");
  }
  if (opts.hasSupplyEvidence) {
    index = Math.min(index + 1, ORDER.length - 1);
    reasons.push("raised because a server on this path has confirmed supply-chain findings");
  }

  return { severity: ORDER[index], reason: reasons.join("; ") };
}

/** Ranks paths for display: worst first, then most servers involved. */
export function comparePaths(
  a: { severity: Severity; serversInvolved: string[] },
  b: { severity: Severity; serversInvolved: string[] },
): number {
  const d = ORDER.indexOf(b.severity) - ORDER.indexOf(a.severity);
  if (d !== 0) return d;
  return b.serversInvolved.length - a.serversInvolved.length;
}
