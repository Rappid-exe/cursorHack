/**
 * The capability vocabulary.
 *
 * This is the fixed, closed set of things an MCP tool can do. It plays the same
 * role a controlled vocabulary plays in any grounded system: the model may
 * classify a tool into these and only these, and anything it invents is dropped
 * before it reaches the engine.
 *
 * The set is deliberately small and orthogonal. Each capability answers a
 * different question about a tool, because the whole product rests on
 * *composition* — on the observation that a tool which reads files is not a
 * vulnerability, a tool which makes HTTP requests is not a vulnerability, and
 * an agent holding both is an exfiltration primitive. Capabilities that overlap
 * would make those combinations ambiguous.
 *
 * Three properties on each capability drive the attack-path rules:
 *
 *   untrustedIngress — invoking this pulls text an attacker may control into
 *                      the model's context. This is the entry condition for
 *                      every prompt-injection chain. Note that it is not only
 *                      web browsing: issue trackers, inboxes and user-generated
 *                      database rows are all attacker-writable.
 *
 *   sensitivity      — how damaging it is for what this returns to escape.
 *
 *   egress           — this can move data to a destination the caller chooses,
 *                      and is therefore the exit leg of an exfiltration chain.
 */

export const CAPABILITY_IDS = [
  "fs.read",
  "fs.write",
  "secrets.read",
  "exec.shell",
  "net.outbound",
  "browse.untrusted",
  "repo.read",
  "repo.write",
  "db.read",
  "db.write",
  "mail.read",
  "msg.send",
  "config.write",
  "cloud.admin",
] as const;

export type CapabilityId = (typeof CAPABILITY_IDS)[number];

export interface Capability {
  id: CapabilityId;
  label: string;
  /** Shown to a human deciding whether the classification is right. */
  definition: string;
  /** Does invoking this bring attacker-influenceable content into context? */
  untrustedIngress: boolean;
  /** Can this move data to a caller-chosen destination? */
  egress: boolean;
  /** How bad is it for what this touches to be read or abused. */
  sensitivity: "low" | "medium" | "high" | "critical";
}

export const CAPABILITIES: Record<CapabilityId, Capability> = {
  "fs.read": {
    id: "fs.read",
    label: "Read local files",
    definition:
      "Reads files from the machine the client runs on. Includes directory listing and search over local paths.",
    untrustedIngress: true,
    egress: false,
    sensitivity: "high",
  },
  "fs.write": {
    id: "fs.write",
    label: "Write local files",
    definition:
      "Creates, modifies, moves or deletes files on the local filesystem.",
    untrustedIngress: false,
    egress: false,
    sensitivity: "high",
  },
  "secrets.read": {
    id: "secrets.read",
    label: "Read credentials",
    definition:
      "Reads API keys, tokens, passwords, environment variables, keychain entries or cloud credential files.",
    untrustedIngress: false,
    egress: false,
    sensitivity: "critical",
  },
  "exec.shell": {
    id: "exec.shell",
    label: "Execute commands",
    definition:
      "Runs shell commands, scripts, or arbitrary code, in any language, on the host or in a container it controls.",
    untrustedIngress: false,
    egress: false,
    sensitivity: "critical",
  },
  "net.outbound": {
    id: "net.outbound",
    label: "Arbitrary outbound requests",
    definition:
      "Makes network requests to a URL supplied by the caller. The destination is not fixed by the server.",
    untrustedIngress: true,
    egress: true,
    sensitivity: "medium",
  },
  "browse.untrusted": {
    id: "browse.untrusted",
    label: "Fetch web content",
    definition:
      "Retrieves and returns content from the public web — pages, search results, scraped text.",
    untrustedIngress: true,
    egress: false,
    sensitivity: "low",
  },
  "repo.read": {
    id: "repo.read",
    label: "Read source repositories",
    definition:
      "Reads private code, issues, pull requests, comments or CI logs from a source-control host.",
    // Issues and PR comments are writable by anyone with an account. This is a
    // routinely underestimated injection vector.
    untrustedIngress: true,
    egress: false,
    sensitivity: "high",
  },
  "repo.write": {
    id: "repo.write",
    label: "Write to repositories",
    definition:
      "Commits, pushes, opens or merges pull requests, edits issues, or triggers CI workflows.",
    untrustedIngress: false,
    egress: true,
    sensitivity: "critical",
  },
  "db.read": {
    id: "db.read",
    label: "Query databases",
    definition:
      "Runs read queries against a database or structured data store.",
    untrustedIngress: true,
    egress: false,
    sensitivity: "high",
  },
  "db.write": {
    id: "db.write",
    label: "Write to databases",
    definition:
      "Inserts, updates, deletes or applies schema changes to a data store.",
    untrustedIngress: false,
    egress: false,
    sensitivity: "high",
  },
  "mail.read": {
    id: "mail.read",
    label: "Read messages",
    definition:
      "Reads email, chat messages, tickets or calendar entries belonging to the user.",
    untrustedIngress: true,
    egress: false,
    sensitivity: "high",
  },
  "msg.send": {
    id: "msg.send",
    label: "Send messages",
    definition:
      "Sends email, chat messages, or posts to a recipient or channel the caller names.",
    untrustedIngress: false,
    egress: true,
    sensitivity: "high",
  },
  "config.write": {
    id: "config.write",
    label: "Change configuration",
    definition:
      "Modifies agent, client, or system configuration — including which servers or tools are installed.",
    untrustedIngress: false,
    egress: false,
    sensitivity: "critical",
  },
  "cloud.admin": {
    id: "cloud.admin",
    label: "Administer cloud infrastructure",
    definition:
      "Creates, modifies or destroys cloud resources, or changes IAM policy, in a hosted environment.",
    untrustedIngress: false,
    egress: true,
    sensitivity: "critical",
  },
};

const VALID = new Set<string>(CAPABILITY_IDS);

/** True when `id` is a capability we hold a definition for. */
export function isCapabilityId(id: string): id is CapabilityId {
  return VALID.has(id);
}

/** The capabilities in `ids` whose invocation admits attacker-controlled text. */
export function ingressCapabilities(ids: Iterable<CapabilityId>): CapabilityId[] {
  return [...ids].filter((id) => CAPABILITIES[id].untrustedIngress);
}

/** The capabilities in `ids` that can move data to a caller-chosen destination. */
export function egressCapabilities(ids: Iterable<CapabilityId>): CapabilityId[] {
  return [...ids].filter((id) => CAPABILITIES[id].egress);
}
