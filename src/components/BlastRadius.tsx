"use client";

import { useState } from "react";
import { CAPABILITIES, CAPABILITY_IDS } from "@/lib/engine/capabilities";
import type { CapabilityId } from "@/lib/engine/capabilities";
import type { ScanResult } from "@/lib/engine/types";
import { SectionLabel } from "./Chrome";

/**
 * The surface map.
 *
 * Servers down the side, capabilities across the top, a mark where a server
 * provides one. This is the argument the product makes, in one picture: read
 * any single row and the server looks reasonable; read a column and you see how
 * many different servers can reach the same primitive; read the whole grid and
 * you see the surface the model actually holds, which is the union and which
 * nobody installed on purpose.
 *
 * Capabilities are grouped by their role in an attack rather than
 * alphabetically, because the grouping is the point — ingress on the left,
 * egress on the right, and the damage in the middle.
 */

const GROUPS: { label: string; hint: string; ids: CapabilityId[] }[] = [
  {
    label: "Ingress",
    hint: "Brings text an attacker may control into the model's context",
    ids: CAPABILITY_IDS.filter((id) => CAPABILITIES[id].untrustedIngress),
  },
  {
    label: "Reach",
    hint: "Touches something worth taking or changing",
    ids: CAPABILITY_IDS.filter(
      (id) => !CAPABILITIES[id].untrustedIngress && !CAPABILITIES[id].egress,
    ),
  },
  {
    label: "Egress",
    hint: "Moves data to a destination the caller chooses",
    ids: CAPABILITY_IDS.filter((id) => CAPABILITIES[id].egress && !CAPABILITIES[id].untrustedIngress),
  },
];

export function SurfaceMap({ result }: { result: ScanResult }) {
  const [hovered, setHovered] = useState<CapabilityId | null>(null);

  // Only show capabilities somebody actually has. A grid of empty columns
  // makes the surface look sparser than it is by padding it with nothing.
  const present = new Set(result.capabilities);
  const groups = GROUPS.map((g) => ({ ...g, ids: g.ids.filter((id) => present.has(id)) })).filter(
    (g) => g.ids.length > 0,
  );
  const capsByServer = new Map(result.servers.map((s) => [s.key, new Set(s.capabilities)]));

  // How many distinct servers provide each capability — the column count that
  // shows a primitive is reachable by more than one route.
  const providersFor = (id: CapabilityId) =>
    result.servers.filter((s) => capsByServer.get(s.key)?.has(id)).length;

  return (
    <section>
      <SectionLabel>Capability surface · {result.servers.length} servers</SectionLabel>

      <div className="overflow-x-auto rounded-lg border border-border bg-surface">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-border">
              <th className="sticky left-0 z-10 bg-surface px-4 py-2 text-[11px] font-medium text-faint">
                <span className="notation uppercase tracking-[0.12em]">Server</span>
              </th>
              {groups.map((group, gi) => (
                <th
                  key={group.label}
                  colSpan={group.ids.length}
                  className={`px-2 py-2 text-center ${gi > 0 ? "border-l border-border-strong" : ""}`}
                  title={group.hint}
                >
                  <span className="notation text-[10px] uppercase tracking-[0.12em] text-faint">
                    {group.label}
                  </span>
                </th>
              ))}
            </tr>
            <tr className="border-b border-border">
              <th className="sticky left-0 z-10 bg-surface px-4 pb-2" />
              {groups.map((group, gi) =>
                group.ids.map((id, ii) => (
                  <th
                    key={id}
                    className={`px-1 pb-2 align-bottom ${gi > 0 && ii === 0 ? "border-l border-border-strong" : ""}`}
                    onMouseEnter={() => setHovered(id)}
                    onMouseLeave={() => setHovered(null)}
                  >
                    {/* Vertical labels keep fourteen columns readable without
                        a horizontal scroll on a projector. */}
                    <div
                      className="notation mx-auto whitespace-nowrap text-[10px] text-muted"
                      style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}
                    >
                      {id}
                    </div>
                  </th>
                )),
              )}
            </tr>
          </thead>
          <tbody>
            {result.servers.map((server) => {
              const own = capsByServer.get(server.key) ?? new Set();
              return (
                <tr key={server.key} className="border-b border-border last:border-0">
                  <th
                    scope="row"
                    className="sticky left-0 z-10 max-w-[220px] bg-surface px-4 py-2 text-left font-normal"
                  >
                    <span className="notation text-[12px] text-foreground">{server.key}</span>
                    <span className="ml-2 text-[11px] text-faint">
                      {server.toolCount} tool{server.toolCount === 1 ? "" : "s"}
                    </span>
                  </th>
                  {groups.map((group, gi) =>
                    group.ids.map((id, ii) => {
                      const has = own.has(id);
                      return (
                        <td
                          key={id}
                          className={`px-1 py-2 text-center ${gi > 0 && ii === 0 ? "border-l border-border-strong" : ""} ${
                            hovered === id ? "bg-surface-sunk" : ""
                          }`}
                        >
                          {has ? (
                            <span
                              className="mx-auto block h-2 w-2 rounded-full bg-accent"
                              title={`${server.key} — ${CAPABILITIES[id].label}`}
                            />
                          ) : (
                            <span className="mx-auto block h-2 w-2 rounded-full bg-border" />
                          )}
                        </td>
                      );
                    }),
                  )}
                </tr>
              );
            })}
          </tbody>
          <tfoot>
            <tr className="border-t border-border-strong">
              <td className="sticky left-0 z-10 bg-surface px-4 py-2">
                <span className="notation text-[10px] uppercase tracking-[0.12em] text-faint">
                  Servers providing
                </span>
              </td>
              {groups.map((group, gi) =>
                group.ids.map((id, ii) => {
                  const n = providersFor(id);
                  return (
                    <td
                      key={id}
                      className={`px-1 py-2 text-center ${gi > 0 && ii === 0 ? "border-l border-border-strong" : ""}`}
                    >
                      <span
                        className={`notation text-[11px] ${n > 1 ? "text-accent" : "text-faint"}`}
                      >
                        {n}
                      </span>
                    </td>
                  );
                }),
              )}
            </tr>
          </tfoot>
        </table>
      </div>

      <p className="mt-3 text-[12px] leading-relaxed text-muted">
        {hovered ? (
          <>
            <span className="notation text-foreground">{hovered}</span> — {CAPABILITIES[hovered].definition}
          </>
        ) : (
          <>
            The model sees one flat list of {result.summary.toolCount} tools, not{" "}
            {result.servers.length} separate servers. Any tool can follow any other in the same
            turn, so the surface that matters is this whole grid — the union, which nobody
            installed deliberately.
          </>
        )}
      </p>
    </section>
  );
}

/** The headline counts, above the fold. */
export function SummaryBar({ result }: { result: ScanResult }) {
  const { summary } = result;
  const stats = [
    { value: summary.serverCount, label: "servers" },
    { value: summary.toolCount, label: "tools" },
    { value: summary.capabilityCount, label: "capabilities" },
    { value: summary.pathCount, label: "attack paths", accent: summary.pathCount > 0 },
    {
      value: summary.compositionPathCount,
      label: "need >1 server",
      accent: summary.compositionPathCount > 0,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-5">
      {stats.map((s) => (
        <div key={s.label} className="bg-surface px-4 py-3">
          <div
            className={`notation text-[26px] leading-none font-medium ${
              s.accent ? "text-critical" : "text-foreground"
            }`}
          >
            {s.value}
          </div>
          <div className="mt-1.5 text-[11px] text-faint">{s.label}</div>
        </div>
      ))}
    </div>
  );
}
