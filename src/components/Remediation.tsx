"use client";

import type { ScanResult } from "@/lib/engine/types";
import { SectionLabel } from "./Chrome";
import { plural } from "@/lib/present";

/**
 * What to actually do.
 *
 * This panel is the argument the rest of the page has been building toward. It
 * asks the only question a person really has — *which change is worth making?*
 * — and the answer for a composed surface is usually uncomfortable: removing
 * the scariest-looking server closes nothing, because six others provide the
 * same leg.
 *
 * Every number is the engine re-run over a reduced surface. Nothing is
 * estimated, and where the honest answer is "uninstalling will not fix this",
 * it says so rather than manufacturing an action.
 */
export function Remediation({ result }: { result: ScanResult }) {
  const r = result.remediation;
  if (!r) return null;

  const inert = r.perServer.filter((s) => s.pathsClosed === 0);
  const best = r.perServer[0];
  const topRole = r.byCapabilityClass[0];
  const total = result.paths.length;

  return (
    <section>
      <SectionLabel>What closes these</SectionLabel>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {/* --- The headline answer ------------------------------------------ */}
        <div className="border-b border-border p-5">
          <h3 className="text-[17px] font-semibold tracking-tight text-critical">
            {r.noSingleFix
              ? "Removing any single server closes nothing."
              : `The best single removal closes ${best.pathsClosed} of ${total} paths.`}
          </h3>
          <p className="mt-2 max-w-3xl text-[13.5px] leading-relaxed text-muted">
            {inert.length > 0 && (
              <>
                <span className="text-foreground">
                  {inert.length} of your {r.perServer.length} servers close no paths at all when
                  removed
                </span>{" "}
                — including <span className="notation">{inert.slice(0, 3).map((s) => s.serverKey).join(", ")}</span>
                . Their legs are covered by something else you already have installed.{" "}
              </>
            )}
            This is what a composed attack surface looks like from the inside, and it is why
            per-server review cannot reach it: there is no single bad apple to point at, so
            uninstalling the scariest-sounding entry buys almost nothing.
          </p>
        </div>

        {/* --- Per-server impact -------------------------------------------- */}
        <div className="p-5">
          <p className="notation mb-3 text-[10px] uppercase tracking-[0.12em] text-faint">
            Paths closed by removing one server
          </p>
          <ul className="flex flex-col gap-1.5">
            {r.perServer.map((s) => {
              const pct = result.paths.length
                ? (s.pathsClosed / result.paths.length) * 100
                : 0;
              return (
                <li key={s.serverKey} className="flex items-center gap-3">
                  <span className="notation w-28 shrink-0 truncate text-[12px] text-foreground">
                    {s.serverKey}
                  </span>
                  <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-sunk">
                    <span
                      className={`block h-full rounded-full ${
                        s.pathsClosed > 0 ? "bg-accent" : "bg-transparent"
                      }`}
                      style={{ width: `${Math.max(pct, s.pathsClosed > 0 ? 4 : 0)}%` }}
                    />
                  </span>
                  <span
                    className={`notation w-24 shrink-0 text-right text-[11px] ${
                      s.pathsClosed > 0 ? "text-foreground" : "text-faint"
                    }`}
                  >
                    {s.pathsClosed === 0 ? "no change" : `−${s.pathsClosed} path${s.pathsClosed === 1 ? "" : "s"}`}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>

        {/* --- The remedy that does work ------------------------------------ */}
        <div className="border-t border-border bg-surface-sunk p-5">
          <p className="notation mb-3 text-[10px] uppercase tracking-[0.12em] text-faint">
            What does work
          </p>

          <ul className="flex flex-col gap-3 text-[13.5px] leading-relaxed">
            {r.minimalCut && r.minimalCut.length > 0 ? (
              <li>
                <span className="font-medium">Uninstall together:</span>{" "}
                <span className="notation">{r.minimalCut.join(", ")}</span>. That combination
                closes every path — no smaller set does.
              </li>
            ) : (
              <li>
                <span className="font-medium">No subset of up to three servers closes every path.</span>{" "}
                The surface cannot be fixed by uninstalling; it has to be separated.
              </li>
            )}

            {topRole && topRole.closes > 0 && (
              <li>
                <span className="font-medium">Separate by role.</span> If this session held no{" "}
                <span className="notation">{topRole.role}</span>-capable tool at all,{" "}
                {plural(topRole.closes, "path")} would close. That is the practical remedy for a
                composed surface: run ingress-capable servers in a session that has no egress, and
                vice versa, rather than trying to find one server to blame.
              </li>
            )}

            {result.injections.length > 0 && (
              <li>
                {/* Deliberately "review", not "remove". The detector matches on
                    form, and legitimate servers write descriptions that address
                    the model. Turning a shape match into a removal instruction
                    would contradict what the findings panel says two sections
                    up, and would be wrong advice for at least one of these. */}
                <span className="font-medium">Read these descriptions yourself:</span>{" "}
                <span className="notation">
                  {[...new Set(result.injections.map((s) => s.serverKey))].join(", ")}
                </span>
                . Each contains text aimed at the model rather than at you. That is the shape
                poisoning takes, but it is also how some entirely legitimate servers are written —
                the quotes are above, and which of them is an attack is a judgement this tool does
                not make for you.
              </li>
            )}

            <li className="text-muted">
              <span className="font-medium text-foreground">Pin every version.</span>{" "}
              {result.supply.filter((s) => s.kind === "unpinned-fetch").length} of these servers
              resolve to whatever was published most recently, at every launch, with no review
              step. Pinning does not close a path, but it stops the code underneath one changing
              without you.
            </li>
          </ul>
        </div>
      </div>

      <p className="mt-3 text-[12px] leading-relaxed text-faint">
        Each figure is the engine re-run with that server&rsquo;s tools removed. A path closes when
        some leg has no provider left — nothing here is estimated.
      </p>
    </section>
  );
}
