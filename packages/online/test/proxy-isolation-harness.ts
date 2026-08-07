/**
 * Shared rig for the ambient-proxy isolation regressions (`LINK-xscdzrji`).
 *
 * `docs/safe-transport.md` publishes "there is no ... proxy" as an
 * unconditional property of the built-in transport, and nothing pinned it. The
 * regressions that use this rig point Node at a **dead loopback proxy
 * sentinel** and then require the production `NodeConnectionPorts` path to
 * reach a real loopback destination anyway. Routing the built-in path through
 * an ambient proxy therefore turns into a deterministic `ECONNREFUSED`, with no
 * external network and no reliance on a timeout winning a race.
 *
 * Node exposes two independent ambient-proxy switches, and they need different
 * treatment:
 *
 *   - `http.setGlobalProxyFromEnv()` reads `process.env` when called and
 *     **replaces** `http.globalAgent` / `https.globalAgent` with proxying
 *     agents. Calling it again after clearing the variables does *not* undo it
 *     — verified on Node 26.3.1 — so `withRuntimeGlobalProxy` restores by
 *     putting the original agent objects back, which does work because the
 *     originals are left untouched.
 *   - `NODE_USE_ENV_PROXY` is consulted once during bootstrap. Setting it from
 *     inside a running test has no effect at all, so `runUnderStartupProxyEnv`
 *     spawns a child process that was launched with it. The parent's own
 *     environment is never mutated for that case.
 */
import { execFile } from "node:child_process";
import nodeHttp, {
  createServer as createHttpServer,
  request as nodeHttpRequest,
} from "node:http";
import nodeHttps from "node:https";
import { createServer as createTcpServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const CHILD = join(HERE, "fixtures", "proxy-isolation-child.ts");

/**
 * Every spelling Node consults, plus the switches themselves. Both cases clear
 * the whole set before installing the sentinel so an ambient `NO_PROXY` on the
 * developer's machine cannot quietly bypass it and make the test vacuous.
 */
const PROXY_ENV_VARS = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
  "NODE_USE_ENV_PROXY",
] as const;

/**
 * `http.setGlobalProxyFromEnv` is newer than the `@types/node` major this repo
 * pins, so it is reached through a narrowed view rather than the typed surface.
 */
const runtimeGlobalProxyInstaller = (
  nodeHttp as unknown as { setGlobalProxyFromEnv?: () => void }
).setGlobalProxyFromEnv;

/** `engines.node` is `>=24`; the runtime switch landed inside that range. */
export const RUNTIME_GLOBAL_PROXY_SUPPORTED = typeof runtimeGlobalProxyInstaller === "function";

/**
 * A loopback port with nothing behind it: bound so the OS picks a free number,
 * then released. Never a hard-coded port number — a fixed one can collide with
 * whatever else the machine is running and turn a refusal into a hang.
 */
export async function deadLoopbackPort(): Promise<number> {
  const probe = createTcpServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
  const address = probe.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const port = address.port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/**
 * The live control for the runtime case: stand up a throwaway plain-HTTP
 * loopback server and ask the *default* global agent for it. Under an installed
 * global proxy the request is tunnelled to the sentinel and dies there, so this
 * returns `true`. If it returns `false` while a proxy is supposed to be
 * installed, the surrounding isolation assertion is proving nothing and must
 * fail. The server is its own — pointing this at a TLS destination would
 * confuse "the proxy ate it" with "that port does not speak HTTP".
 */
export async function globalAgentIsProxied(): Promise<boolean> {
  const server = createHttpServer((_request, response) => response.end("control"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  try {
    return await new Promise<boolean>((resolve) => {
      const request = nodeHttpRequest(
        { host: "127.0.0.1", port: address.port, path: "/" },
        (response) => {
          response.resume();
          response.on("end", () => resolve(false));
        },
      );
      request.on("error", () => resolve(true));
      request.end();
    });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/**
 * Install a hostile process-wide proxy for the duration of `body`, then undo
 * every part of it. Both the environment snapshot and the two global agents are
 * restored in a `finally`, so a failing assertion cannot leak `HTTP_PROXY` — or
 * a proxying `globalAgent` — into a sibling test sharing this worker.
 */
export async function withRuntimeGlobalProxy<T>(
  proxyPort: number,
  body: () => Promise<T>,
): Promise<T> {
  if (runtimeGlobalProxyInstaller === undefined) {
    throw new Error("http.setGlobalProxyFromEnv() is unavailable on this runtime");
  }
  const savedEnv = new Map(PROXY_ENV_VARS.map((name) => [name, process.env[name]]));
  const savedHttpAgent = nodeHttp.globalAgent;
  const savedHttpsAgent = nodeHttps.globalAgent;
  try {
    const sentinel = `http://127.0.0.1:${proxyPort}`;
    for (const name of PROXY_ENV_VARS) delete process.env[name];
    process.env.HTTP_PROXY = sentinel;
    process.env.HTTPS_PROXY = sentinel;
    process.env.ALL_PROXY = sentinel;
    runtimeGlobalProxyInstaller();
    return await body();
  } finally {
    nodeHttp.globalAgent = savedHttpAgent;
    nodeHttps.globalAgent = savedHttpsAgent;
    for (const [name, value] of savedEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

/** What `fixtures/proxy-isolation-child.ts` reports back over stdout. */
export interface StartupProxyReport {
  readonly control: {
    readonly proxied: boolean;
    readonly code?: string;
    readonly address?: string;
    readonly port?: number;
  };
  readonly direct: {
    readonly status: number;
    readonly body: string;
    readonly remoteAddress: string;
    readonly remotePort: number;
  };
}

/**
 * Run the child against `destinationPort` in a process launched with
 * `NODE_USE_ENV_PROXY=1` and the sentinel in every proxy variable. The parent's
 * environment is copied, scrubbed and passed by value — nothing here mutates
 * `process.env`.
 */
export async function runUnderStartupProxyEnv(
  protocol: "http:" | "https:",
  destinationPort: number,
  proxyPort: number,
): Promise<StartupProxyReport> {
  const sentinel = `http://127.0.0.1:${proxyPort}`;
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of PROXY_ENV_VARS) delete env[name];
  env.NODE_USE_ENV_PROXY = "1";
  env.HTTP_PROXY = sentinel;
  env.HTTPS_PROXY = sentinel;
  env.ALL_PROXY = sentinel;

  const { stdout } = await execFileAsync(
    process.execPath,
    ["--import", "tsx", CHILD, protocol, String(destinationPort)],
    { cwd: REPO_ROOT, env },
  );
  return JSON.parse(stdout) as StartupProxyReport;
}
