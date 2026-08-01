"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import type { ScanResult } from "@/lib/engine/types";
import { DEMO_CONFIG } from "@/lib/demo/fixture";
import { SummaryBar, SurfaceMap } from "./BlastRadius";
import { AttackPaths, Injections, SupplyChain, ClassificationNote } from "./Findings";
import { SectionLabel } from "./Chrome";

interface Classification {
  toolsClassified: number;
  unclassified: number;
  rejectedSpans: number;
  rejectedCapabilities: string[];
}

type Phase = "idle" | "scanning" | "done" | "error";

/**
 * The scan animation.
 *
 * Concentric arcs sweeping out from a single origin, with nodes lighting as
 * each stage completes. It is honest about progress — the stage labels are the
 * actual pipeline, and they advance on a timer that matches the real work
 * rather than resolving instantly and then waiting.
 */
function Scanning({ stage }: { stage: number }) {
  const STAGES = [
    "Parsing configuration",
    "Resolving packages against the registry",
    "Classifying tool capabilities",
    "Composing attack paths",
    "Scoring against CISA KEV and ATT&CK",
  ];

  return (
    <div className="flex flex-col items-center py-16">
      <svg viewBox="0 0 240 160" className="h-40 w-60" aria-hidden="true">
        {/* Rings sweeping out from the origin. */}
        {[28, 52, 76, 100, 124].map((r, i) => (
          <circle
            key={r}
            cx="40"
            cy="130"
            r={r}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="1"
            opacity={i <= stage ? 0.55 - i * 0.08 : 0.08}
            className={i === stage ? "pulse" : ""}
            style={{ transition: "opacity 400ms" }}
          />
        ))}
        {/* Nodes on the arc, one per stage. */}
        {[28, 52, 76, 100, 124].map((r, i) => {
          const angle = -Math.PI / 4;
          const x = 40 + r * Math.cos(angle);
          const y = 130 + r * Math.sin(angle);
          return (
            <circle
              key={`n${r}`}
              cx={x}
              cy={y}
              r={i <= stage ? 3.5 : 2}
              fill={i <= stage ? "var(--accent)" : "var(--border-strong)"}
              style={{ transition: "all 400ms" }}
            />
          );
        })}
        <circle cx="40" cy="130" r="4" fill="var(--accent)" />
      </svg>

      <ol className="mt-6 flex flex-col gap-1.5">
        {STAGES.map((s, i) => (
          <li
            key={s}
            className={`notation text-[12px] transition-colors ${
              i < stage ? "text-muted" : i === stage ? "text-accent" : "text-faint opacity-40"
            }`}
          >
            <span className="mr-2">{i < stage ? "✓" : i === stage ? "▸" : "·"}</span>
            {s}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function ScanFlow() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [configText, setConfigText] = useState(DEMO_CONFIG);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [classification, setClassification] = useState<Classification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState(0);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Advance the stage labels while the request is in flight. The last stage
  // holds until the response lands rather than completing on its own. Stage is
  // reset by runScan before the phase changes, so this effect only schedules.
  useEffect(() => {
    if (phase !== "scanning") return;
    const timers = [700, 1500, 3200, 5200].map((ms, i) =>
      setTimeout(() => setStage(i + 1), ms),
    );
    return () => timers.forEach(clearTimeout);
  }, [phase]);

  useEffect(() => {
    if (phase === "done" && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [phase]);

  const runScan = useCallback(async () => {
    setStage(0);
    setPhase("scanning");
    setError(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ configText }),
      });
      const body = await res.json();
      if (!res.ok) {
        setError(body.error ?? "The scan failed.");
        setPhase("error");
        return;
      }
      setResult(body.result);
      setClassification(body.classification);
      // The brief is a separate route so it can be printed and shared on its
      // own. Handing it the result through sessionStorage keeps the scan a
      // single API call — the alternative is re-running classification, which
      // costs another fifteen seconds and could return something different.
      try {
        sessionStorage.setItem("blast-radius:result", JSON.stringify(body.result));
      } catch {
        /* private mode or quota — the dashboard still works, the brief will say so */
      }
      setPhase("done");
    } catch {
      setError("Could not reach the scanner. Check that the dev server is running.");
      setPhase("error");
    }
  }, [configText]);

  return (
    <div className="flex flex-col gap-10">
      {/* --- Input ---------------------------------------------------------- */}
      <section>
        <div className="mb-3 flex items-end justify-between gap-4">
          <SectionLabel>Client configuration</SectionLabel>
          {configText !== DEMO_CONFIG && (
            <button
              type="button"
              onClick={() => setConfigText(DEMO_CONFIG)}
              className="notation mb-3 text-[11px] text-faint underline decoration-border underline-offset-4 transition-colors hover:text-foreground"
            >
              reset to sample
            </button>
          )}
        </div>

        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          spellCheck={false}
          rows={14}
          aria-label="MCP client configuration JSON"
          className="notation w-full resize-y rounded-lg border border-border bg-surface p-4 text-[12px] leading-relaxed text-foreground outline-none transition-colors focus:border-accent-border"
        />

        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={runScan}
            disabled={phase === "scanning"}
            className="rounded bg-accent px-4 py-2 text-[13px] font-medium text-background transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {phase === "scanning" ? "Scanning…" : "Scan this configuration"}
          </button>
          <p className="text-[12px] text-faint">
            Paste your own <span className="notation">claude_desktop_config.json</span> or{" "}
            <span className="notation">.cursor/mcp.json</span>. It is analysed server-side and
            never stored.
          </p>
        </div>
      </section>

      {/* --- Progress ------------------------------------------------------- */}
      {phase === "scanning" && <Scanning stage={stage} />}

      {/* --- Error ---------------------------------------------------------- */}
      {phase === "error" && (
        <div className="rounded-lg border border-critical-border bg-critical-surface p-5">
          <h2 className="text-[14px] font-semibold text-critical">Scan failed</h2>
          <p className="mt-1.5 text-[13px] leading-relaxed text-muted">{error}</p>
          <button
            type="button"
            onClick={runScan}
            className="mt-3 rounded border border-border-strong px-3 py-1.5 text-[12px] transition-colors hover:border-accent"
          >
            Try again
          </button>
        </div>
      )}

      {/* --- Results -------------------------------------------------------- */}
      {phase === "done" && result && classification && (
        <div ref={resultsRef} className="flex flex-col gap-10">
          <section>
            <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
              <SectionLabel>Result</SectionLabel>
              <Link
                href="/brief"
                className="notation mb-3 text-[11px] text-accent underline decoration-accent-border underline-offset-4 transition-colors hover:text-accent-hover"
              >
                open one-page brief →
              </Link>
            </div>
            <SummaryBar result={result} />
          </section>

          <SurfaceMap result={result} />
          <Injections result={result} />
          <AttackPaths paths={result.paths} />
          <SupplyChain findings={result.supply} />
          <ClassificationNote result={result} classification={classification} />
        </div>
      )}
    </div>
  );
}
