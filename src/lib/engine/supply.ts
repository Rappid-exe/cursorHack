/**
 * Supply-chain assessment for the servers in a config.
 *
 * An MCP server is software you fetch and execute, usually from a public
 * registry, usually at every launch, usually with your credentials in its
 * environment. That is a supply chain, and it is one almost nobody treats as
 * one — there is no lockfile, no review step, and in the common `npx -y` case
 * no pinned version either.
 *
 * Every finding here is backed by a verbatim piece of evidence and names its
 * source, because the whole point is that these are checkable facts rather than
 * our opinion of a package.
 */

import type { ServerSpec, SupplyFinding, Severity } from "./types";
import { invocationOf, packageOf } from "./config";
import { lookupPackage, lookupRegistryServer, kevEntry } from "./data";

/**
 * Environment values that look like live credentials rather than settings.
 *
 * Deliberately narrow: these are prefixes published by the issuing services, so
 * a match is a real token shape and not a guess. We never print the value.
 */
const TOKEN_SHAPES: { pattern: RegExp; label: string }[] = [
  { pattern: /^sk-ant-[A-Za-z0-9_-]{20,}$/, label: "Anthropic API key" },
  { pattern: /^sk-[A-Za-z0-9]{32,}$/, label: "OpenAI API key" },
  { pattern: /^gh[pousr]_[A-Za-z0-9]{20,}$/, label: "GitHub token" },
  { pattern: /^github_pat_[A-Za-z0-9_]{20,}$/, label: "GitHub fine-grained token" },
  { pattern: /^xox[baprs]-[A-Za-z0-9-]{10,}$/, label: "Slack token" },
  { pattern: /^AKIA[0-9A-Z]{16}$/, label: "AWS access key id" },
  { pattern: /^glpat-[A-Za-z0-9_-]{20,}$/, label: "GitLab token" },
  { pattern: /^sk_live_[A-Za-z0-9]{20,}$/, label: "Stripe live key" },
  { pattern: /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, label: "JWT" },
];

/** Names that indicate a secret even when the value is a placeholder. */
const SECRET_NAME = /(_TOKEN|_KEY|_SECRET|_PASSWORD|_CREDENTIAL|_API_KEY|PASSWD)$/i;

/** Days below which a package is too new to have been meaningfully reviewed. */
const YOUNG_DAYS = 30;

function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86_400_000);
}

/**
 * Assesses one server.
 *
 * Returns every finding that the committed data supports. Absence of data
 * produces no finding rather than a reassuring one — we never report a package
 * as clean when we simply have not looked at it.
 */
export function assessServer(server: ServerSpec): SupplyFinding[] {
  const findings: SupplyFinding[] = [];
  const pkg = packageOf(server);
  const invocation = invocationOf(server);

  // --- Credentials sitting in the config ------------------------------------
  for (const [name, value] of Object.entries(server.env ?? {})) {
    const shape = TOKEN_SHAPES.find((s) => s.pattern.test(value));
    if (shape) {
      findings.push({
        serverKey: server.key,
        kind: "secret-in-config",
        severity: "high",
        summary: `A live ${shape.label} is stored in this server's environment block.`,
        // The value is never echoed. Length and prefix are enough to locate it.
        evidence: `${name} = ${value.slice(0, 7)}… (${value.length} chars), matching the published ${shape.label} format`,
        source: "Pattern match against the issuer's documented token format",
      });
    } else if (SECRET_NAME.test(name) && value.trim() && !/^\$\{|^<|^your/i.test(value)) {
      findings.push({
        serverKey: server.key,
        kind: "secret-in-config",
        severity: "medium",
        summary: `${name} holds a value directly in the config rather than a reference.`,
        evidence: `${name} is set to a ${value.length}-character literal`,
        source: "Environment variable naming convention",
      });
    }
  }

  // --- Remote servers -------------------------------------------------------
  if (server.url) {
    let host = server.url;
    try {
      host = new URL(server.url).host;
    } catch {
      /* keep the raw string if it will not parse */
    }
    findings.push({
      serverKey: server.key,
      kind: "remote-operator",
      severity: "medium",
      summary: `Every call to this server, including its arguments, is visible to whoever operates ${host}.`,
      evidence: server.url,
      source: "Server is configured as a remote endpoint rather than a local process",
    });
    return findings;
  }

  // --- Local execution ------------------------------------------------------
  if (!pkg) {
    // A local script or binary. Nothing to look up, and saying nothing is
    // correct — we have no registry to check it against.
    return findings;
  }

  if (!pkg.version) {
    findings.push({
      serverKey: server.key,
      kind: "unpinned-fetch",
      severity: "high",
      summary: `Resolves and executes the latest published ${pkg.name} on every launch — whatever was published most recently, without review.`,
      evidence: invocation,
      source: "No version specifier in the launch command",
    });
  }

  const meta = lookupPackage(pkg.ecosystem, pkg.name);

  if (meta) {
    const age = daysSince(meta.lastPublished);
    if (age !== null && age <= YOUNG_DAYS) {
      findings.push({
        serverKey: server.key,
        kind: "young-package",
        severity: "medium",
        summary: `${pkg.name} published a new version ${age} day${age === 1 ? "" : "s"} ago.`,
        evidence: `version ${meta.latestVersion} published ${meta.lastPublished}`,
        source: `${pkg.ecosystem} registry`,
      });
    }

    for (const adv of meta.advisories) {
      const kev = adv.cves.map((c) => ({ cve: c, entry: kevEntry(c) })).find((x) => x.entry);

      if (kev?.entry) {
        findings.push({
          serverKey: server.key,
          kind: "kev-listed",
          severity: "critical",
          summary: `${pkg.name} carries ${kev.cve}, which CISA lists as being actively exploited${kev.entry.knownRansomware ? " in ransomware campaigns" : ""}.`,
          evidence: `${kev.entry.name ?? kev.cve} — added to the KEV catalogue ${kev.entry.dateAdded}`,
          source: "CISA Known Exploited Vulnerabilities Catalog",
        });
      } else {
        findings.push({
          serverKey: server.key,
          kind: "known-advisory",
          severity: severityFromOsv(adv.severity),
          summary: `${pkg.name} has a published advisory: ${adv.summary}`,
          evidence: `${adv.id}${adv.cves.length ? ` (${adv.cves.join(", ")})` : ""} affecting ${adv.affected}`,
          source: "OSV.dev",
        });
      }
    }
  }

  // --- Provenance -----------------------------------------------------------
  const registered = lookupRegistryServer(pkg.ecosystem, pkg.name);
  if (!registered) {
    findings.push({
      serverKey: server.key,
      kind: "unknown-to-registry",
      severity: "medium",
      summary: `${pkg.name} is not published to the official MCP registry, so there is no verified link between this package and any project.`,
      evidence: `no registry entry backed by ${pkg.ecosystem}:${pkg.name}`,
      source: "Official Model Context Protocol registry",
    });
  } else if (!registered.repository) {
    findings.push({
      serverKey: server.key,
      kind: "no-repository",
      severity: "low",
      summary: `${registered.name} is registered but publishes no source repository, so its code cannot be reviewed.`,
      evidence: `registry entry ${registered.name} v${registered.version} has no repository URL`,
      source: "Official Model Context Protocol registry",
    });
  }

  return findings;
}

/** Maps an OSV severity string onto our bands. Unknown stays medium. */
function severityFromOsv(s: string | null): Severity {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

/** Findings that raise a path's severity: confirmed, not merely hygienic. */
const CONFIRMING: SupplyFinding["kind"][] = [
  "kev-listed",
  "known-advisory",
  "unpinned-fetch",
];

export function hasConfirmedEvidence(findings: SupplyFinding[]): boolean {
  return findings.some((f) => CONFIRMING.includes(f.kind));
}
