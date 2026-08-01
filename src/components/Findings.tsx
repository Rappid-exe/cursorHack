"use client";

import { useState } from "react";
import type { AttackPath, InjectionSpan, ScanResult, SupplyFinding } from "@/lib/engine/types";
import { CAPABILITIES } from "@/lib/engine/capabilities";
import { technique } from "@/lib/engine/attack";
import { SEVERITY_STYLE, SUPPLY_LABEL, INJECTION_LABEL, plural } from "@/lib/present";
import { SectionLabel, SeverityChip } from "./Chrome";

/**
 * One attack path, drawn as the chain an attacker walks.
 *
 * The legs matter more than the summary. Showing which server contributes which
 * step is what turns "you have a problem" into "you have this problem, here,
 * and it exists because these two things are installed together".
 */
function PathCard({ path, index }: { path: AttackPath; index: number }) {
  const [open, setOpen] = useState(false);
  const style = SEVERITY_STYLE[path.severity];

  return (
    <article
      className="reveal overflow-hidden rounded-lg border border-border bg-surface"
      style={{ animationDelay: `${Math.min(index * 70, 500)}ms` }}
    >
      <div className={`h-0.5 ${style.rail}`} />

      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityChip severity={path.severity} />
          <h3 className="text-[15px] font-semibold tracking-tight">{path.name}</h3>
          {path.requiresComposition ? (
            <span className="notation rounded border border-accent-border bg-accent-soft px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-accent">
              needs {path.serversInvolved.length} servers together
            </span>
          ) : (
            <span className="notation rounded border border-critical-border bg-critical-surface px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-critical">
              {path.soloCapableServers[0]} does this alone
            </span>
          )}
        </div>

        <p className="mt-2.5 max-w-3xl text-[13px] leading-relaxed text-muted">{path.narrative}</p>

        {/* The route. One provider per step — the smallest set of servers that
            walks the whole path. Breadth is reported as counts below. */}
        <ol className="mt-4 flex flex-col gap-2 lg:flex-row lg:items-stretch">
          {path.legs.map((leg, i) => (
            <li key={i} className="flex flex-1 items-stretch gap-2">
              <div className="flex-1 rounded border border-border bg-surface-raised p-3">
                <div className="notation text-[10px] uppercase tracking-[0.1em] text-faint">
                  Step {i + 1}
                </div>
                <div className="mt-1 text-[12px] leading-snug text-foreground">{leg.role}</div>
                <div className="mt-2">
                  <span className="notation rounded border border-border-strong bg-surface px-1.5 py-0.5 text-[11px] text-foreground">
                    {leg.chosen.serverKey}
                  </span>
                </div>
                <div className="notation mt-1.5 text-[10px] leading-relaxed text-faint">
                  {leg.chosen.toolName} · {leg.chosen.capability}
                  {leg.alternatives > 0 && (
                    <>
                      <br />
                      {leg.alternatives} other tool{leg.alternatives === 1 ? "" : "s"} could do this
                    </>
                  )}
                </div>
              </div>
              {i < path.legs.length - 1 && (
                <div className="flex items-center justify-center text-border-strong lg:px-0">
                  <span aria-hidden="true" className="notation text-[13px]">
                    →
                  </span>
                </div>
              )}
            </li>
          ))}
        </ol>

        {path.totalServersCapable > path.serversInvolved.length && (
          <p className="mt-2.5 text-[12px] leading-relaxed text-faint">
            This is the shortest route.{" "}
            <span className="text-muted">
              {path.totalServersCapable} of your servers can contribute to it by some route
            </span>
            , so removing any single one does not close it.
          </p>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border pt-3">
          <div className="flex flex-wrap gap-1.5">
            {path.techniques.map((id) => {
              const t = technique(id);
              return t ? (
                <a
                  key={id}
                  href={t.url}
                  target="_blank"
                  rel="noreferrer"
                  title={t.description}
                  className="notation rounded border border-border px-1.5 py-0.5 text-[10px] text-muted transition-colors hover:border-border-strong hover:text-foreground"
                >
                  {t.id} {t.name}
                </a>
              ) : null;
            })}
          </div>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="notation ml-auto text-[11px] text-faint underline decoration-border underline-offset-4 transition-colors hover:text-foreground"
          >
            {open ? "hide" : "why this severity"}
          </button>
        </div>

        {open && (
          <div className="mt-3 rounded border border-border bg-surface-raised p-3">
            <p className="text-[12px] leading-relaxed text-muted">{path.severityReason}.</p>
            <p className="mt-2 text-[12px] leading-relaxed text-muted">
              Every step is satisfied by a capability the classifier found on a tool in this
              config. The rule, the ordering, and the severity arithmetic are in{" "}
              <span className="notation text-foreground">src/lib/engine/paths.ts</span> — no model
              chose any of it.
            </p>
          </div>
        )}
      </div>
    </article>
  );
}

export function AttackPaths({ paths }: { paths: AttackPath[] }) {
  if (paths.length === 0) {
    return (
      <section>
        <SectionLabel>Attack paths</SectionLabel>
        <div className="rounded-lg border border-border bg-surface p-5">
          <p className="text-[13px] text-muted">
            No rule in the table is fully satisfied by this tool surface. That means the
            capabilities to walk a complete path are not all present — not that the servers are
            safe.
          </p>
        </div>
      </section>
    );
  }

  const composed = paths.filter((p) => p.requiresComposition).length;

  return (
    <section>
      <SectionLabel>
        Attack paths · {paths.length} found, {composed} span more than one server
      </SectionLabel>
      <div className="flex flex-col gap-3">
        {paths.map((p, i) => (
          <PathCard key={p.ruleId} path={p} index={i} />
        ))}
      </div>
    </section>
  );
}

/**
 * A poisoned tool description, quoted.
 *
 * The span is highlighted in place inside the surrounding text, because the
 * attack works precisely by not looking out of place. Seeing it embedded is the
 * argument; seeing it extracted is just a claim.
 */
function InjectionCard({ span, description }: { span: InjectionSpan; description: string }) {
  const before = description.slice(0, span.offset);
  const hit = description.slice(span.offset, span.offset + span.text.length);
  const after = description.slice(span.offset + span.text.length);

  const clip = (s: string, from: "start" | "end") =>
    s.length <= 220 ? s : from === "start" ? `…${s.slice(-220)}` : `${s.slice(0, 220)}…`;

  return (
    <article className="reveal overflow-hidden rounded-lg border border-critical-border bg-surface">
      <div className="h-0.5 bg-critical" />
      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityChip severity="critical" />
          <h3 className="text-[15px] font-semibold tracking-tight">
            Tool description carries instructions
          </h3>
          <span className="notation text-[11px] text-faint">
            {span.serverKey} · {span.toolName}
          </span>
        </div>

        <p className="mt-2.5 max-w-3xl text-[13px] leading-relaxed text-muted">
          This text is loaded into the model&rsquo;s context every session, before the user types
          anything. It is not data the model chooses to read — it is part of the tool catalogue,
          so instructions placed here execute by default.
        </p>

        <div className="notation mt-3 overflow-x-auto rounded border border-border bg-surface-raised p-3 text-[11.5px] leading-relaxed whitespace-pre-wrap">
          <span className="text-faint">{clip(before, "start")}</span>
          <mark className="bg-critical-surface px-0.5 text-critical outline outline-critical-border">
            {hit}
          </mark>
          <span className="text-faint">{clip(after, "end")}</span>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <span className="notation rounded border border-critical-border bg-critical-surface px-1.5 py-0.5 text-[10px] uppercase tracking-[0.08em] text-critical">
            {INJECTION_LABEL[span.pattern]}
          </span>
          <span className="notation text-[10px] text-faint">
            verified verbatim at offset {span.offset}
          </span>
        </div>
      </div>
    </article>
  );
}

export function Injections({ result }: { result: ScanResult }) {
  if (result.injections.length === 0) return null;

  const descriptionFor = (span: InjectionSpan) =>
    result.tools.find((t) => t.serverKey === span.serverKey && t.name === span.toolName)
      ?.description ?? "";

  return (
    <section>
      <SectionLabel>Tool poisoning · {plural(result.injections.length, "span")}</SectionLabel>
      <div className="flex flex-col gap-3">
        {result.injections.map((span, i) => (
          <InjectionCard key={i} span={span} description={descriptionFor(span)} />
        ))}
      </div>
      {/* These are shape matches, and shape does not carry intent. Saying so is
          not a hedge — it is the reason a person reviews this list. */}
      <p className="mt-3 max-w-3xl text-[12px] leading-relaxed text-muted">
        These are matches on <em>form</em>, not intent. A description that addresses the model
        directly is doing the thing that makes poisoning work, whether or not its author meant
        harm — several widely-used, entirely legitimate servers write this way. The scanner
        reports the shape and quotes the text; deciding which of these is an attack is the
        judgement a person has to make, and is exactly where this tool stops.
      </p>
    </section>
  );
}

/** Supply-chain findings, grouped by server so a reader can act per install. */
export function SupplyChain({ findings }: { findings: SupplyFinding[] }) {
  if (findings.length === 0) return null;

  const byServer = new Map<string, SupplyFinding[]>();
  for (const f of findings) {
    const list = byServer.get(f.serverKey) ?? [];
    list.push(f);
    byServer.set(f.serverKey, list);
  }

  return (
    <section>
      <SectionLabel>Supply chain · {plural(findings.length, "finding")}</SectionLabel>
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {[...byServer.entries()].map(([server, list], si) => (
          <div key={server} className={si > 0 ? "border-t border-border" : ""}>
            <div className="border-b border-border bg-surface-raised px-4 py-2">
              <span className="notation text-[12px] text-foreground">{server}</span>
            </div>
            {list.map((f, i) => (
              <div
                key={i}
                className="flex flex-col gap-1.5 px-4 py-3 sm:flex-row sm:items-start sm:gap-4"
              >
                <div className="flex shrink-0 items-center gap-2 sm:w-44">
                  <SeverityChip severity={f.severity} />
                  <span className="text-[11px] text-faint">{SUPPLY_LABEL[f.kind]}</span>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] leading-snug text-foreground">{f.summary}</p>
                  <p className="notation mt-1 text-[11px] break-words text-faint">{f.evidence}</p>
                  <p className="mt-0.5 text-[11px] text-faint">Source: {f.source}</p>
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

/** What the classifier did, stated plainly. */
export function ClassificationNote({
  result,
  classification,
}: {
  result: ScanResult;
  classification: {
    toolsClassified: number;
    unclassified: number;
    rejectedSpans: number;
    rejectedCapabilities: string[];
  };
}) {
  const capabilityList = [...new Set(result.tools.flatMap((t) => t.capabilities))].sort();

  return (
    <section>
      <SectionLabel>What the model did</SectionLabel>
      <div className="rounded-lg border border-border bg-surface p-4 sm:p-5">
        <p className="max-w-3xl text-[13px] leading-relaxed text-muted">
          The model read {plural(result.summary.toolCount, "tool description")} and assigned each
          one capabilities from a fixed list of {Object.keys(CAPABILITIES).length}. It found{" "}
          {capabilityList.length} distinct capabilities across this surface and located{" "}
          {plural(result.injections.length, "injection span")}. It did not decide what any of that
          means — every path, severity and recommendation above came from the rule table.
        </p>
        <dl className="mt-4 grid gap-x-8 gap-y-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            ["Tools classified", `${classification.toolsClassified}`],
            ["No capability found", `${classification.unclassified}`],
            ["Spans rejected as unverifiable", `${classification.rejectedSpans}`],
            [
              "Invented capabilities dropped",
              `${classification.rejectedCapabilities.length}`,
            ],
          ].map(([k, v]) => (
            <div key={k}>
              <dt className="text-[11px] text-faint">{k}</dt>
              <dd className="notation text-[15px] text-foreground">{v}</dd>
            </div>
          ))}
        </dl>
        {classification.rejectedSpans > 0 && (
          <p className="mt-3 text-[12px] leading-relaxed text-muted">
            A rejected span is one the model reported but which does not occur character-for-character
            in the description it was attributed to. Those are dropped rather than shown, because
            the UI presents these as quotes.
          </p>
        )}
      </div>
    </section>
  );
}
