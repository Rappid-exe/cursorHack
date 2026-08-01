/**
 * Client configuration parsing.
 *
 * Every MCP client — Claude Desktop, Cursor, Windsurf, Cline, the reference
 * clients — stores installed servers as a JSON object keyed by local name,
 * under either `mcpServers` or `servers`. A value either describes a command to
 * execute locally or a URL to talk to remotely.
 *
 * Parsing is strict about shape and forgiving about extras: unknown fields are
 * ignored rather than rejected, because clients add their own (`disabled`,
 * `autoApprove`, `timeout`) and a config that a client accepts must not be one
 * we refuse to look at.
 */

import type { ServerSpec } from "./types";

export class ConfigError extends Error {
  constructor(
    message: string,
    readonly kind: "malformed" | "empty" | "unrecognised" = "malformed",
  ) {
    super(message);
    this.name = "ConfigError";
  }
}

function asStringRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === "string") out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

/**
 * Reads a client config into server specs.
 *
 * Throws ConfigError with a `kind` the caller can act on, rather than a generic
 * failure — "this is valid JSON but has no servers in it" and "this is not JSON
 * at all" need different messages in the UI.
 */
export function parseConfig(text: string): ServerSpec[] {
  const trimmed = text.trim();
  if (!trimmed) throw new ConfigError("No configuration provided.", "empty");

  let root: unknown;
  try {
    root = JSON.parse(trimmed);
  } catch (err) {
    throw new ConfigError(
      `Configuration is not valid JSON: ${err instanceof Error ? err.message : "parse failed"}`,
      "malformed",
    );
  }

  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new ConfigError("Configuration must be a JSON object.", "malformed");
  }

  const obj = root as Record<string, unknown>;
  // Accept the two spellings in the wild, and a bare map of servers for people
  // who paste only the inner object.
  const block =
    (obj.mcpServers as Record<string, unknown> | undefined) ??
    (obj.servers as Record<string, unknown> | undefined) ??
    (looksLikeServerMap(obj) ? obj : undefined);

  if (!block || typeof block !== "object") {
    throw new ConfigError(
      "No `mcpServers` block found. Paste a client configuration file — the one containing the servers you have installed.",
      "unrecognised",
    );
  }

  const servers: ServerSpec[] = [];

  for (const [key, raw] of Object.entries(block)) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const v = raw as Record<string, unknown>;

    // Clients use `disabled: true` to keep a server configured but inactive.
    // An inactive server contributes no tools, so it contributes no risk.
    if (v.disabled === true) continue;

    const command = typeof v.command === "string" ? v.command : undefined;
    const url =
      typeof v.url === "string"
        ? v.url
        : typeof v.serverUrl === "string"
          ? v.serverUrl
          : undefined;

    if (!command && !url) continue;

    servers.push({
      key,
      command,
      args: Array.isArray(v.args) ? v.args.filter((a): a is string => typeof a === "string") : undefined,
      env: asStringRecord(v.env),
      url,
    });
  }

  if (servers.length === 0) {
    throw new ConfigError(
      "The configuration parsed, but contains no enabled servers.",
      "empty",
    );
  }

  return servers;
}

/** Heuristic for a pasted inner map: every value looks like a server entry. */
function looksLikeServerMap(obj: Record<string, unknown>): boolean {
  const values = Object.values(obj);
  if (values.length === 0) return false;
  return values.every(
    (v) =>
      v !== null &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      ("command" in (v as object) || "url" in (v as object)),
  );
}

/** The command line as configured, for display and for pinning checks. */
export function invocationOf(server: ServerSpec): string {
  if (server.url) return server.url;
  return [server.command, ...(server.args ?? [])].filter(Boolean).join(" ");
}

/**
 * Extracts the package identifier a local server will fetch and execute.
 *
 * Handles the launchers that actually appear in configs: npx and its bunx/pnpm
 * equivalents for npm, uvx and pipx for Python. Returns null for anything else
 * — a path to a local script, a docker image, a compiled binary — because those
 * are not resolved from a public registry and the supply-chain questions we ask
 * of a registry package do not apply.
 */
export function packageOf(
  server: ServerSpec,
): { ecosystem: "npm" | "pypi"; name: string; version: string | null } | null {
  if (server.url || !server.command) return null;

  const cmd = server.command.toLowerCase().replace(/\.(cmd|exe)$/, "");
  const args = (server.args ?? []).filter((a) => a.trim().length > 0);

  const ecosystem =
    cmd === "npx" || cmd === "bunx" || cmd === "pnpx"
      ? "npm"
      : cmd === "uvx" || cmd === "pipx"
        ? "pypi"
        : null;
  if (!ecosystem) return null;

  // Skip launcher flags to find the first positional argument, which is the
  // package. `-y`/`--yes` suppress the install prompt; `-p`/`--package` name it
  // explicitly; `--from` is uv's spelling.
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "-p" || arg === "--package" || arg === "--from") {
      const next = args[i + 1];
      if (next) return splitVersion(ecosystem, next);
      continue;
    }
    if (arg.startsWith("-")) continue;
    return splitVersion(ecosystem, arg);
  }
  return null;
}

function splitVersion(
  ecosystem: "npm" | "pypi",
  spec: string,
): { ecosystem: "npm" | "pypi"; name: string; version: string | null } {
  // Scoped npm names start with @ and carry their own separator, so only split
  // on an @ that appears after the first character.
  const at = spec.indexOf("@", 1);
  if (ecosystem === "npm" && at > 0) {
    return { ecosystem, name: spec.slice(0, at), version: spec.slice(at + 1) || null };
  }
  const m = spec.match(/^([A-Za-z0-9._-]+)(?:[=<>~!]=?|@)(.+)$/);
  if (ecosystem === "pypi" && m) {
    return { ecosystem, name: m[1], version: m[2] };
  }
  return { ecosystem, name: spec, version: null };
}
