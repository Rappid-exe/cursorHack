/**
 * Tool discovery.
 *
 * Until now the scanner had to be handed a tool list, because working out what
 * a server exposes means running it — and starting unknown binaries to find out
 * whether they are safe is the problem this product describes, not a way to
 * solve it. That objection is real, so discovery is built to answer it rather
 * than to ignore it:
 *
 *   It is opt-in. Nothing discovers unless the caller explicitly asks. The
 *   scanner's default path is still "you supply the definitions".
 *
 *   It never passes a real credential. The config's `env` block is replaced
 *   with placeholders — the declared keys are present, so servers that refuse
 *   to boot without them still start and still advertise their tools, but the
 *   values are obvious rubbish. A server that tries to use one fails
 *   immediately instead of succeeding quietly.
 *
 *   It inherits almost nothing. The SDK's `getDefaultEnvironment()` allowlists
 *   a handful of OS variables and drops everything else, so nothing in the
 *   caller's environment reaches the child by accident.
 *
 *   It is bounded. Every server gets one timeout covering launch, handshake and
 *   listing, and the process is killed when that expires.
 *
 * What this layer does not do is isolate the filesystem or the network. The
 * process runs with the user's own permissions. That is a real limitation and
 * the CLI says so at the point of use; containerised launching is the next
 * layer, and it goes behind this same function.
 */

import type { Stream } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ServerSpec, ToolSpec } from "@/lib/engine/types";

export interface DiscoveryResult {
  serverKey: string;
  tools: ToolSpec[];
  /** What the server called itself during the handshake, if it got that far. */
  serverInfo: { name: string; version: string } | null;
  /** Null on success. A human-readable reason otherwise. */
  error: string | null;
  /** Why we did not even try. Set only when `error` is a refusal, not a failure. */
  skipped: "remote" | "no-command" | null;
  durationMs: number;
}

/**
 * Stand-in for any credential the config declares.
 *
 * Deliberately not token-shaped. A value that looks plausible invites a server
 * to attempt a real call and hang on the network; this one fails at the first
 * validation it meets.
 */
const PLACEHOLDER = "blast-radius-placeholder-not-a-real-credential";

/**
 * Generous, because the first run of an `npx -y` server downloads the package
 * before it starts, and that dominates everything else — a server that boots in
 * 200ms can still take half a minute the first time it is ever launched.
 * Subsequent runs hit the npx cache and finish in seconds, so this ceiling is
 * only reached once per package.
 */
const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Low, because the cost being bounded here is not CPU. Each entry may be
 * resolving and downloading a package, and running all eleven at once means
 * they compete for the same connection and all approach the timeout together.
 */
const DEFAULT_CONCURRENCY = 4;

/**
 * OS plumbing the SDK's allowlist omits but Windows process launching needs.
 *
 * Without PATHEXT the loader cannot resolve `npx` to `npx.cmd`, so every
 * npm-delivered server silently fails to start and times out — which looks
 * exactly like a hung server and is not. These are not secrets; the allowlist
 * exists to keep credentials out, not to break spawning.
 */
const WINDOWS_ESSENTIALS = ["PATHEXT", "COMSPEC", "PROGRAMFILES(X86)", "PROGRAMW6432"];

/**
 * The environment a discovered server runs with.
 *
 * Every key the config declares is present so the server boots, and every value
 * is a placeholder so it can do nothing with them.
 */
function sandboxedEnv(server: ServerSpec): Record<string, string> {
  const env = getDefaultEnvironment();

  if (process.platform === "win32") {
    for (const key of WINDOWS_ESSENTIALS) {
      // Windows environment keys are case-insensitive but process.env is not,
      // so match however the parent spelled it.
      const found = Object.keys(process.env).find((k) => k.toUpperCase() === key);
      if (found && process.env[found]) env[found] = process.env[found];
    }
  }

  for (const key of Object.keys(server.env ?? {})) {
    env[key] = PLACEHOLDER;
  }
  return env;
}

/** Longest stderr we keep. Enough for a stack trace's first frames, not a log. */
const STDERR_LIMIT = 4_000;

/**
 * Accumulates a child's stderr so a failure can explain itself.
 *
 * Bounded: a server stuck in a logging loop must not grow this without limit
 * while we wait out the timeout.
 */
function captureStderr(transport: { stderr: Stream | null }) {
  let buffer = "";
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    if (buffer.length >= STDERR_LIMIT) return;
    buffer += chunk.toString();
  });

  return {
    /** The last meaningful line, which is where the reason for exiting lives. */
    tail(): string | null {
      const lines = buffer
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      if (lines.length === 0) return null;

      // Two kinds of line are never the reason a server failed: the banner it
      // printed when it started fine, and the trailer npm and uv add after the
      // actual error pointing at a log file. Dropping both leaves the real
      // last line — "is not in this registry", "directories are accessible".
      const noise = /running on stdio|complete log of this run|^npm (notice|warn)|^warning:/i;
      const meaningful = lines.filter((l) => !noise.test(l));
      const last = (meaningful.length > 0 ? meaningful : lines).at(-1)!;
      return last.length > 200 ? `${last.slice(0, 200)}…` : last;
    },
  };
}

/**
 * Launches one server, asks what tools it has, and shuts it down.
 *
 * Never throws: a server that crashes, hangs or refuses the handshake is a
 * result to report, not an exception to propagate. A scan of eleven servers
 * should not fail because the fourth one is broken.
 */
export async function discoverServer(
  server: ServerSpec,
  opts: { timeoutMs?: number } = {},
): Promise<DiscoveryResult> {
  const started = Date.now();
  const base: Omit<DiscoveryResult, "error" | "skipped" | "durationMs"> = {
    serverKey: server.key,
    tools: [],
    serverInfo: null,
  };
  const done = (error: string | null, skipped: DiscoveryResult["skipped"] = null) => ({
    ...base,
    error,
    skipped,
    durationMs: Date.now() - started,
  });

  if (server.url) {
    // Remote servers are a different transport and a different trust question —
    // no local execution, but the operator sees that we probed them. Handled in
    // its own layer rather than bolted on here.
    return done("Remote server — discovery over HTTP is not supported yet.", "remote");
  }
  if (!server.command) {
    return done("No command to run.", "no-command");
  }

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args ?? [],
    env: sandboxedEnv(server),
    // Piped rather than inherited for two reasons: servers are chatty and none
    // of it is ours to print, and when one dies the protocol only reports
    // "Connection closed" — the actual reason is on stderr.
    stderr: "pipe",
  });

  // Attached before connect(), because a server that fails to launch writes its
  // reason and exits before the handshake ever completes. The SDK returns the
  // stream immediately for exactly this case.
  const stderr = captureStderr(transport);

  const client = new Client(
    { name: "blast-radius", version: "0.1.0" },
    { capabilities: {} },
  );

  let timer: NodeJS.Timeout | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Timed out after ${timeoutMs / 1000}s`)),
        timeoutMs,
      );
    });

    // One deadline covering launch, handshake and listing together — a server
    // that starts promptly and then stalls on tools/list is just as stuck.
    await Promise.race([client.connect(transport), timeout]);

    const info = client.getServerVersion();
    if (info) base.serverInfo = { name: info.name, version: info.version };

    const listed = await Promise.race([client.listTools(), timeout]);

    base.tools = listed.tools.map((t) => ({
      serverKey: server.key,
      name: t.name,
      // Descriptions are optional in the protocol. An empty one is not an
      // error — it classifies to nothing, which is the correct outcome.
      description: t.description ?? "",
    }));

    return done(null);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    // "Connection closed" on its own tells a user nothing actionable. The
    // process almost always said why — a missing launcher, a path that does not
    // exist, a package that was never published — so lead with that and keep
    // the protocol error as context.
    const said = stderr.tail();
    return done(said ? `${said} (${reason})` : reason);
  } finally {
    clearTimeout(timer);
    // close() terminates the child process. Swallowing here is deliberate: the
    // interesting failure already happened above and a teardown error would
    // mask it.
    await client.close().catch(() => {});
  }
}

/**
 * Discovers a whole config, a few servers at a time.
 *
 * Bounded rather than unbounded because each entry is a real process — eleven
 * `npx` invocations at once will each try to resolve a package, and on a cold
 * cache that is enough to make every one of them time out.
 */
export async function discoverAll(
  servers: ServerSpec[],
  opts: { timeoutMs?: number; concurrency?: number; onResult?: (r: DiscoveryResult) => void } = {},
): Promise<DiscoveryResult[]> {
  const concurrency = opts.concurrency ?? DEFAULT_CONCURRENCY;
  const results: DiscoveryResult[] = [];
  let cursor = 0;

  const workers = Array.from({ length: Math.min(concurrency, servers.length) }, async () => {
    for (;;) {
      const i = cursor++;
      if (i >= servers.length) return;
      const result = await discoverServer(servers[i], { timeoutMs: opts.timeoutMs });
      results[i] = result;
      opts.onResult?.(result);
    }
  });

  await Promise.all(workers);
  return results;
}

/** Everything discovered, flattened, ready for the classifier. */
export function toolsFrom(results: DiscoveryResult[]): ToolSpec[] {
  return results.flatMap((r) => r.tools);
}
