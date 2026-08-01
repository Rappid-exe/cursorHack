"use client";

import { useMemo, useSyncExternalStore } from "react";
import Link from "next/link";
import type { ScanResult } from "@/lib/engine/types";
import { technique } from "@/lib/engine/attack";
import { PROVENANCE } from "@/lib/engine/provenance";
import { SUPPLY_LABEL, SEVERITY_STYLE, plural } from "@/lib/present";

/**
 * The printable brief.
 *
 * Reads the scan from sessionStorage rather than re-running it: a brief that
 * disagreed with the dashboard it was opened from would be worse than no brief
 * at all, and re-classifying costs another model call that could return
 * something slightly different.
 */
const STORAGE_KEY = "blast-radius:result";

/**
 * sessionStorage as an external store.
 *
 * The value is written once by the scan and never changes while this page is
 * open, so the subscribe function has nothing to listen for. The server
 * snapshot is null, which renders the empty state during SSR and hydrates to
 * the real result on the client.
 */
function readStored(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

const noSubscribe = () => () => {};
const serverSnapshot = () => null;

export function Brief() {
  const raw = useSyncExternalStore(noSubscribe, readStored, serverSnapshot);

  const result = useMemo<ScanResult | null>(() => {
    if (!raw) return null;
    try {
      return JSON.parse(raw) as ScanResult;
    } catch {
      return null;
    }
  }, [raw]);

  if (!result) {
    return (
      <div className="rounded-lg border border-border bg-surface p-6">
        <h1 className="text-[18px] font-semibold tracking-tight">No scan to report</h1>
        <p className="mt-2 text-[13px] leading-relaxed text-muted">
          The brief renders the most recent scan from this browser session. Run one first.
        </p>
        <Link
          href="/"
          className="mt-4 inline-block rounded bg-accent px-3 py-1.5 text-[13px] font-medium text-white transition-colors hover:bg-accent-hover"
        >
          Back to the scanner
        </Link>
      </div>
    );
  }

  const { summary } = result;
  const composed = result.paths.filter((p) => p.requiresComposition);
  const solo = result.paths.filter((p) => !p.requiresComposition);
  const criticalSupply = result.supply.filter(
    (s) => s.severity === "critical" || s.severity === "high",
  );
  const kevSource = PROVENANCE.threat.sources.find((s) => s.catalogVersion);

  return (
    <article className="flex flex-col gap-6">
      {/* --- Masthead ------------------------------------------------------- */}
      <header className="border-b border-border pb-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-[20px] font-semibold tracking-tight">
              MCP attack surface brief
            </h1>
            <p className="notation mt-1 text-[11px] text-faint">
              {summary.serverCount} servers · {summary.toolCount} tools ·{" "}
              {new Date().toISOString().slice(0, 10)}
            </p>
          </div>
          <PrintButton />
        </div>
      </header>

      {/* --- Bottom line ---------------------------------------------------- */}
      <section>
        <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
          Bottom line
        </h2>
        <p className="mt-2 text-[14px] leading-relaxed">
          This configuration exposes{" "}
          <strong>{plural(summary.pathCount, "complete attack path")}</strong>. Of those,{" "}
          <strong>{composed.length}</strong> require more than one server acting together and
          would not be visible to any tool that audits servers individually.{" "}
          {result.injections.length > 0 && (
            <>
              {plural(result.injections.length, "span")} of tool description{" "}
              {result.injections.length === 1 ? "instructs" : "instruct"} the model rather than
              describing the tool, across{" "}
              {plural(new Set(result.injections.map((s) => s.toolName)).size, "tool")}.
            </>
          )}
        </p>
      </section>

      {/* --- Paths ---------------------------------------------------------- */}
      <section>
        <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
          Attack paths
        </h2>
        <table className="mt-2 w-full border-collapse text-left text-[12px]">
          <thead>
            <tr className="border-b border-border">
              {["Severity", "Path", "Route", "ATT&CK"].map((h) => (
                <th key={h} className="notation py-1.5 pr-3 font-medium text-faint">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.paths.map((p) => (
              <tr key={p.ruleId} className="border-b border-border align-top last:border-0">
                <td className={`py-2 pr-3 ${SEVERITY_STYLE[p.severity].text}`}>
                  <span className="notation text-[11px] uppercase">{p.severity}</span>
                </td>
                <td className="py-2 pr-3">
                  <div className="font-medium">{p.name}</div>
                  <div className="mt-0.5 text-[11px] text-muted">
                    {p.requiresComposition
                      ? `Requires ${p.serversInvolved.length} servers together`
                      : `${p.soloCapableServers[0]} completes this alone`}
                  </div>
                </td>
                <td className="notation py-2 pr-3 text-[11px] text-muted">
                  {p.legs.map((l) => l.chosen.serverKey).join(" → ")}
                </td>
                <td className="notation py-2 text-[11px] text-muted">
                  {p.techniques.map((id) => technique(id)?.id ?? id).join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* --- Injections ----------------------------------------------------- */}
      {result.injections.length > 0 && (
        <section>
          <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
            Tool descriptions carrying instructions
          </h2>
          {result.injections.map((span, i) => (
            <div key={i} className="mt-2 border-l-2 border-critical pl-3">
              <p className="notation text-[11px] text-muted">
                {span.serverKey} · {span.toolName}
              </p>
              <p className="notation mt-1 text-[11.5px] leading-relaxed text-critical">
                &ldquo;{span.text}&rdquo;
              </p>
            </div>
          ))}
        </section>
      )}

      {/* --- Supply chain --------------------------------------------------- */}
      {criticalSupply.length > 0 && (
        <section>
          <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
            Supply chain
          </h2>
          <ul className="mt-2 flex flex-col gap-1.5">
            {criticalSupply.map((f, i) => (
              <li key={i} className="text-[12px] leading-snug">
                <span className={`notation text-[11px] ${SEVERITY_STYLE[f.severity].text}`}>
                  [{SUPPLY_LABEL[f.kind]}]
                </span>{" "}
                <span className="notation text-[11px] text-muted">{f.serverKey}</span> —{" "}
                {f.summary}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* --- Recommended action --------------------------------------------- */}
      <section>
        <h2 className="notation text-[11px] uppercase tracking-[0.14em] text-faint">
          What closes these
        </h2>
        <ul className="mt-2 flex list-disc flex-col gap-1.5 pl-4 text-[12.5px] leading-relaxed">
          {result.injections.length > 0 && (
            <li>
              Remove{" "}
              <span className="notation">
                {[...new Set(result.injections.map((s) => s.serverKey))].join(", ")}
              </span>
              . Its tool descriptions instruct the model to read credentials and conceal having
              done so. Nothing about the rest of the configuration makes that safe.
            </li>
          )}
          {solo.length > 0 && (
            <li>
              <span className="notation">
                {[...new Set(solo.flatMap((p) => p.soloCapableServers.slice(0, 1)))].join(", ")}
              </span>{" "}
              each complete an attack path without help. These are decisions you can make one
              server at a time.
            </li>
          )}
          {composed.length > 0 && (
            <li>
              The remaining {composed.length} paths need servers acting together, so they close by
              separating the surface — running ingress-capable servers in a session that has no
              egress-capable server, rather than by removing any one entry.
            </li>
          )}
          <li>
            Pin every version. {result.supply.filter((s) => s.kind === "unpinned-fetch").length} of
            these servers resolve to whatever was published most recently, at every launch, with
            no review step.
          </li>
        </ul>
      </section>

      {/* --- Provenance ------------------------------------------------------ */}
      <footer className="border-t border-border pt-4">
        <p className="text-[11px] leading-relaxed text-faint">
          Severity and attack paths are computed by a fixed rule table, not by a language model.
          The model&rsquo;s only role is classifying tool capability from description text and
          locating quoted spans, both validated against a closed vocabulary before use. Threat
          data: CISA KEV{kevSource?.catalogVersion ? ` catalogue ${kevSource.catalogVersion}` : ""},
          MITRE ATT&amp;CK for Enterprise, OSV.dev, and the official MCP registry
          ({PROVENANCE.registry.counts.servers.toLocaleString()} servers). Blast Radius is a
          demonstration prototype, not a security product.
        </p>
      </footer>
    </article>
  );
}

function PrintButton() {
  return (
    <button
      type="button"
      onClick={() => window.print()}
      className="no-print shrink-0 rounded border border-border-strong px-3 py-1.5 text-[12px] transition-colors hover:border-accent"
    >
      Print
    </button>
  );
}
