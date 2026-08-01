import { NextResponse } from "next/server";
import { classifyTools, ClassificationError } from "@/lib/classify";
import { parseConfig, ConfigError } from "@/lib/engine/config";
import { scan } from "@/lib/engine/scan";
import { remediate } from "@/lib/engine/remediate";
import { DEMO_TOOLS } from "@/lib/demo/fixture";
import { cachedClassification, isDemoSurface } from "@/lib/demo/cached";
import type { ScanResult, ToolSpec } from "@/lib/engine/types";

export const runtime = "nodejs";
// The committed datasets are imported at module scope; keep this off the edge
// runtime and out of static optimisation.
export const dynamic = "force-dynamic";

export interface ScanResponse {
  result: ScanResult;
  classification: {
    toolsClassified: number;
    unclassified: number;
    rejectedSpans: number;
    rejectedCapabilities: string[];
    /** Whether the model actually ran, or a recorded result was substituted. */
    source: "live" | "cached";
    /** When the recorded result was captured. Set only when source is cached. */
    capturedAt?: string;
  };
}

/** Guards against someone pasting a lockfile into the box. */
const MAX_CHARS = 100_000;
const MAX_TOOLS = 400;

export async function POST(request: Request) {
  let body: { configText?: unknown; tools?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be JSON." }, { status: 400 });
  }

  const configText = typeof body.configText === "string" ? body.configText : "";
  if (!configText.trim()) {
    return NextResponse.json(
      { error: "Paste an MCP client configuration to scan." },
      { status: 400 },
    );
  }
  if (configText.length > MAX_CHARS) {
    return NextResponse.json(
      { error: `Configuration is too long (limit ${MAX_CHARS.toLocaleString()} characters).` },
      { status: 413 },
    );
  }

  let servers;
  try {
    servers = parseConfig(configText);
  } catch (err) {
    if (err instanceof ConfigError) {
      return NextResponse.json({ error: err.message, kind: err.kind }, { status: 400 });
    }
    throw err;
  }

  // Tool definitions come from the caller. A static config does not list them —
  // discovering them means starting each server and calling tools/list, which
  // the scanner deliberately does not do: launching eleven unknown binaries to
  // find out whether they are safe has the obvious problem. The demo supplies
  // the fixture's definitions; a real deployment would pass definitions
  // captured from a client session.
  const supplied = Array.isArray(body.tools) ? body.tools : null;
  const configured = new Set(servers.map((s) => s.key));

  const tools: ToolSpec[] = (supplied ?? DEMO_TOOLS)
    .filter((t): t is ToolSpec => {
      if (!t || typeof t !== "object") return false;
      const o = t as Record<string, unknown>;
      return (
        typeof o.serverKey === "string" &&
        typeof o.name === "string" &&
        typeof o.description === "string"
      );
    })
    // Only tools belonging to servers in this config. A tool naming a server
    // that is not installed would put capabilities on the graph that nobody has.
    .filter((t) => configured.has(t.serverKey))
    .slice(0, MAX_TOOLS);

  if (tools.length === 0) {
    return NextResponse.json(
      {
        error:
          "No tool definitions matched the servers in this configuration, so there is no tool surface to analyse.",
      },
      { status: 422 },
    );
  }

  try {
    let classification: {
      tools: Awaited<ReturnType<typeof classifyTools>>["tools"];
      injections: Awaited<ReturnType<typeof classifyTools>>["injections"];
      rejectedSpans: number;
      rejectedCapabilities: string[];
    };
    let source: "live" | "cached" = "live";
    let capturedAt: string | undefined;

    try {
      classification = await classifyTools(tools);
    } catch (err) {
      // A revoked key, a rate limit or a dead network says nothing about
      // whether the engine works — it is deterministic and offline. For the
      // committed sample we have a recorded classification, so fall back to it
      // and tell the caller. Any other configuration re-throws, because there
      // is no recorded answer and pretending otherwise would be a fabrication.
      if (!(err instanceof ClassificationError) || !isDemoSurface(tools)) throw err;
      const fallback = cachedClassification();
      classification = { ...fallback, rejectedSpans: 0, rejectedCapabilities: [] };
      source = "cached";
      capturedAt = fallback.capturedAt;
      console.warn(`scan: classification unavailable (${err.kind}) — using recorded sample`);
    }

    const result = scan(servers, classification.tools, classification.injections);
    // Computed here rather than inside scan(), because remediation works by
    // re-running scan() over reduced surfaces — doing it inline would recurse.
    result.remediation = remediate(servers, classification.tools, result.paths);

    const payload: ScanResponse = {
      result,
      classification: {
        toolsClassified: classification.tools.filter((t) => t.capabilities.length > 0).length,
        unclassified: classification.tools.filter((t) => t.capabilities.length === 0).length,
        rejectedSpans: classification.rejectedSpans,
        rejectedCapabilities: classification.rejectedCapabilities,
        source,
        capturedAt,
      },
    };
    return NextResponse.json(payload);
  } catch (err) {
    if (err instanceof ClassificationError) {
      const status =
        err.kind === "rate_limited"
          ? 429
          : err.kind === "bad_input"
            ? 400
            : err.kind === "refused"
              ? 422
              : 503;
      console.error(`scan: ${err.kind} — ${err.message}`);
      return NextResponse.json({ error: err.message, kind: err.kind }, { status });
    }
    console.error("scan route failed:", err);
    return NextResponse.json(
      { error: "Scan failed unexpectedly." },
      { status: 500 },
    );
  }
}
