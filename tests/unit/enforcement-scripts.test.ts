/**
 * LINK-vhpdcdon — contract tests for the two enforcement wrappers,
 * `enforcement/claude-code-hook.sh` and `enforcement/install-aliases.sh`.
 *
 * Both are documented as fail-closed (docs/enforcement.md) and neither had a
 * single tracked caller before this suite. Everything here runs the real
 * scripts as subprocesses.
 *
 * WHY THE INTERPRETER IS PINNED. The hook is a `set -uo pipefail` script that
 * builds an option array. In bash 3.2 — still `/bin/bash` on macOS, and the
 * only bash on the author's machine — expanding an EMPTY array as bare
 * `"${A[@]}"` under `set -u` is an unbound-variable error, so the script died
 * with 127 (non-blocking) instead of reaching its `exit 2`. bash 5 on CI does
 * not reproduce it. The hook cases therefore run under EVERY distinct bash we
 * can find, `/bin/bash` first, and a source-level assertion pins the
 * `${A[@]+"${A[@]}"}` idiom so a Linux-only CI run cannot go green while the
 * macOS guardrail is broken.
 *
 * WHAT THIS SUITE CANNOT EXERCISE (stated explicitly, per the
 * `fp-closing-comment-guard.test.ts` precedent):
 *   - The Claude Code hook host itself. That the runner spawns the script with
 *     PreToolUse JSON on stdin, and that a `2` (and its stderr) actually
 *     denies the tool call, are properties of Claude Code, not of this repo.
 *     Only the script's side of that contract is pinned here.
 *   - WebFetch's redirect following. The hook sees the ORIGINAL URL only
 *     (docs/enforcement.md §"The hook sees only the original URL"); what the
 *     tool does after the hook allows is out of reach. The proxy pinned below
 *     is that the hook makes exactly one CLI call, for exactly that URL.
 *   - A real interactive login shell sourcing a real rc file. The installer is
 *     driven into a temp `HOME`/`ZDOTDIR` and the emitted guard is sourced
 *     explicitly; nothing here touches the developer's own rc files.
 *   - `shellcheck`-class static analysis. No shellcheck is wired into this
 *     repo's hooks or CI and none is added here.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const HOOK = resolve(REPO_ROOT, "enforcement", "claude-code-hook.sh");
const INSTALLER = resolve(REPO_ROOT, "enforcement", "install-aliases.sh");
const CLI_BIN = resolve(REPO_ROOT, "packages", "cli", "dist", "cli.js");

/** Absolute path of an external command, or undefined when it is not on PATH. */
function which(cmd: string): string | undefined {
  const r = spawnSync("/usr/bin/env", ["sh", "-c", `command -v ${cmd}`], { encoding: "utf8" });
  const out = r.stdout.trim();
  return r.status === 0 && out.length > 0 ? out : undefined;
}

const JQ = which("jq");

/**
 * Externals the two scripts and the emitted guard actually invoke. Everything
 * else is a shell builtin, so a PATH containing only these plus our shims is
 * enough to run them — and is what makes "jq is missing" / "linklint is
 * missing" testable rather than hypothetical.
 */
const REQUIRED_EXTERNALS = ["cat", "grep", "basename"] as const;

/** ASCII unit separator: the argv delimiter our shims write to their log. */
const UNIT_SEP = String.fromCharCode(0x1f);

/**
 * Every distinct bash on this machine, `/bin/bash` first. On macOS that is the
 * 3.2 system bash; on CI it is a single bash 5.
 */
const BASHES: readonly string[] = (() => {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const candidate of ["/bin/bash", which("bash"), "/usr/local/bin/bash", "/opt/homebrew/bin/bash"]) {
    if (candidate === undefined) continue;
    let real: string;
    try {
      real = realpathSync(candidate);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    found.push(candidate);
  }
  return found;
})();

function bashMajor(bash: string): number {
  const r = spawnSync(bash, ["-c", "echo $BASH_VERSINFO"], { encoding: "utf8" });
  return Number.parseInt(r.stdout.trim(), 10);
}

// ---------------------------------------------------------------------------
// Sandbox: a per-test temp root holding a PATH directory we fully control.
// ---------------------------------------------------------------------------

const TMP_ROOT = mkdtempSync(join(tmpdir(), "linklint-enforcement-"));
const cleanups: Array<() => void> = [];

afterAll(() => {
  for (const fn of cleanups) {
    try {
      fn();
    } catch {
      /* best effort */
    }
  }
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

interface Sandbox {
  /** Root of this test's temp tree. Doubles as an isolated `HOME`. */
  readonly root: string;
  /** The ONLY directory placed on PATH for scripts run in this sandbox. */
  readonly bin: string;
  /** Where the `linklint` shim appends one line per invocation. */
  readonly argvLog: string;
  /** Where the stubbed `curl`/`wget` append one line per invocation. */
  readonly fetchLog: string;
  /** Recorded `linklint` invocations, one array of argv per call. */
  linklintCalls(): string[][];
  /** Recorded `curl`/`wget` invocations, one array of argv per call. */
  fetchCalls(): string[][];
}

function readLog(path: string): string[][] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  return raw
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => l.split(UNIT_SEP));
}

function link(bin: string, target: string | undefined, name: string): void {
  if (target === undefined) return;
  try {
    symlinkSync(target, join(bin, name));
  } catch {
    /* already linked */
  }
}

interface SandboxOptions {
  /** `real` shells out to the built CLI; `fake` exits with `linklintExit`. */
  readonly linklint?: "real" | "fake" | "absent";
  readonly linklintExit?: number;
  readonly jq?: boolean;
  /** Install stub `curl`/`wget` that log and exit 0. */
  readonly fetchStubs?: boolean;
}

function makeSandbox(name: string, opts: SandboxOptions = {}): Sandbox {
  const root = mkdtempSync(join(TMP_ROOT, `${name}-`));
  const bin = join(root, "bin");
  mkdirSync(bin);
  const argvLog = join(root, "linklint-argv.log");
  const fetchLog = join(root, "fetch.log");

  for (const cmd of REQUIRED_EXTERNALS) link(bin, which(cmd), cmd);
  if (opts.jq !== false) link(bin, JQ, "jq");

  const record = (log: string, extra: string) =>
    `#!/bin/sh\n{ printf '%s' "$0" ; for a in "$@"; do printf '\\037%s' "$a"; done; printf '\\n'; } >> ${JSON.stringify(log)}\n${extra}\n`;

  const mode = opts.linklint ?? "fake";
  if (mode === "real") {
    writeFileSync(join(bin, "linklint"), record(argvLog, `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(CLI_BIN)} "$@"`), { mode: 0o755 });
  } else if (mode === "fake") {
    writeFileSync(join(bin, "linklint"), record(argvLog, `exit ${opts.linklintExit ?? 0}`), { mode: 0o755 });
  }

  if (opts.fetchStubs === true) {
    for (const tool of ["curl", "wget"]) {
      writeFileSync(join(bin, tool), record(fetchLog, "exit 0"), { mode: 0o755 });
    }
  }

  return {
    root,
    bin,
    argvLog,
    fetchLog,
    linklintCalls: () => readLog(argvLog),
    fetchCalls: () => readLog(fetchLog),
  };
}

/** Run a script with PATH restricted to the sandbox bin, and an isolated HOME. */
function runScript(
  bash: string,
  script: string,
  args: readonly string[],
  sandbox: Sandbox,
  extraEnv: Readonly<Record<string, string>> = {},
  input?: string,
) {
  const home = join(sandbox.root, "home");
  mkdirSync(home, { recursive: true });
  return spawnSync(bash, [script, ...args], {
    encoding: "utf8",
    cwd: sandbox.root,
    env: {
      PATH: sandbox.bin,
      HOME: home,
      // `SHELL` steers the installer's rc choice; default it to something inert.
      SHELL: "/usr/bin/false",
      ...extraEnv,
    },
    ...(input === undefined ? {} : { input }),
  });
}

function hookInput(url: unknown): string {
  return JSON.stringify({ tool_name: "WebFetch", tool_input: { url } });
}

// ---------------------------------------------------------------------------
// Interpreter pins
// ---------------------------------------------------------------------------

describe("interpreter coverage", () => {
  it("finds at least one bash to run the guardrails under", () => {
    expect(BASHES.length).toBeGreaterThan(0);
  });

  it.skipIf(process.platform !== "darwin")(
    "exercises the macOS system bash, which is 3.2 and aborts on an empty array under `set -u`",
    () => {
      expect(BASHES[0]).toBe("/bin/bash");
      expect(bashMajor("/bin/bash")).toBe(3);
      // The exact failure the hook used to hit: 127, not a blocking 2.
      const boom = spawnSync("/bin/bash", ["-c", 'set -uo pipefail; A=(); printf "%s\\n" "${A[@]}"'], { encoding: "utf8" });
      expect(boom.status).toBe(127);
      // ...and the idiom the hook now uses, which survives it.
      const ok = spawnSync("/bin/bash", ["-c", 'set -uo pipefail; A=(); printf "%s\\n" ${A[@]+"${A[@]}"}; echo done'], { encoding: "utf8" });
      expect(ok.status).toBe(0);
      expect(ok.stdout).toContain("done");
    },
  );

  it("keeps the bash-3.2-safe array idiom in the hook source, so a bash-5-only CI run cannot mask a regression", () => {
    const code = readFileSync(HOOK, "utf8")
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"));
    expect(code.join("\n")).toContain('${AGENT_FLAG[@]+"${AGENT_FLAG[@]}"}');
    // A bare expansion of the possibly-empty array is the bug; it must be gone
    // from every executable line (the header comment quotes it deliberately).
    expect(code.filter((line) => /[^+]"\$\{AGENT_FLAG\[@\]\}"/.test(line))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// claude-code-hook.sh
// ---------------------------------------------------------------------------

describe.each(BASHES)("claude-code-hook.sh under %s", (bash) => {
  const runHook = (sandbox: Sandbox, input: string | undefined, env: Record<string, string> = {}) =>
    runScript(bash, HOOK, [], sandbox, env, input);

  describe.skipIf(JQ === undefined)("stdin handling", () => {
    it("blocks with 2 when stdin is empty", () => {
      const sb = makeSandbox("hook-empty", { linklint: "fake", linklintExit: 0 });
      const r = runHook(sb, "");
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("no URL in tool input");
      expect(sb.linklintCalls()).toHaveLength(0);
    });

    it("blocks with 2 when stdin is not JSON at all", () => {
      const sb = makeSandbox("hook-malformed", { linklint: "fake", linklintExit: 0 });
      const r = runHook(sb, "{not json");
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("unreadable hook input");
      expect(sb.linklintCalls()).toHaveLength(0);
    });

    it("blocks with 2 when the payload carries no url key", () => {
      const sb = makeSandbox("hook-nourl", { linklint: "fake", linklintExit: 0 });
      const r = runHook(sb, JSON.stringify({ tool_name: "WebFetch", tool_input: {} }));
      expect(r.status).toBe(2);
      expect(sb.linklintCalls()).toHaveLength(0);
    });

    it("blocks with 2 when the url is null or an empty string", () => {
      for (const url of [null, ""]) {
        const sb = makeSandbox("hook-nullurl", { linklint: "fake", linklintExit: 0 });
        const r = runHook(sb, hookInput(url));
        expect(r.status).toBe(2);
        expect(sb.linklintCalls()).toHaveLength(0);
      }
    });

    it("blocks with 2 when stdin is closed with no payload at all", () => {
      const sb = makeSandbox("hook-nostdin", { linklint: "fake", linklintExit: 0 });
      // `input: undefined` leaves stdin inherited-but-empty for the child.
      const r = spawnSync(bash, [HOOK], {
        encoding: "utf8",
        cwd: sb.root,
        env: { PATH: sb.bin, HOME: join(sb.root, "home") },
        stdio: ["ignore", "pipe", "pipe"],
      });
      expect(r.status).toBe(2);
    });
  });

  describe.skipIf(JQ === undefined)("verdict delegation", () => {
    it("allows with 0 only when the CLI exits 0", () => {
      const sb = makeSandbox("hook-allow", { linklint: "fake", linklintExit: 0 });
      const r = runHook(sb, hookInput("https://example.com/"));
      expect(r.status).toBe(0);
      expect(sb.linklintCalls()).toHaveLength(1);
    });

    it.each([1, 2, 3, 127])("blocks with 2 — never a non-blocking 1 — on CLI exit %i", (code) => {
      const sb = makeSandbox(`hook-exit${code}`, { linklint: "fake", linklintExit: code });
      const r = runHook(sb, hookInput("https://example.com/"));
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("linklint blocked");
    });

    it("blocks with 2 when the CLI is killed by a signal rather than exiting", () => {
      const sb = makeSandbox("hook-signal", { linklint: "absent" });
      writeFileSync(join(sb.bin, "linklint"), "#!/bin/sh\nkill -TERM $$\n", { mode: 0o755 });
      const r = runHook(sb, hookInput("https://example.com/"));
      expect(r.status).toBe(2);
    });

    it("blocks with 2 when linklint is not on PATH (127)", () => {
      const sb = makeSandbox("hook-nobinary", { linklint: "absent" });
      const r = runHook(sb, hookInput("https://example.com/"));
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("linklint blocked");
    });
  });

  it("blocks with 2 when jq is not on PATH", () => {
    const sb = makeSandbox("hook-nojq", { linklint: "fake", linklintExit: 0, jq: false });
    const r = runHook(sb, hookInput("https://example.com/"));
    expect(r.status).toBe(2);
    expect(sb.linklintCalls()).toHaveLength(0);
  });

  describe.skipIf(JQ === undefined)("argument construction", () => {
    it("passes --agent and the default --fail-on high", () => {
      const sb = makeSandbox("hook-agentdefault", { linklint: "fake", linklintExit: 0 });
      expect(runHook(sb, hookInput("https://example.com/")).status).toBe(0);
      const [call] = sb.linklintCalls();
      expect(call).toEqual([expect.stringContaining("linklint"), "check", "https://example.com/", "--fail-on", "high", "--agent"]);
    });

    it("honors LINKLINT_FAIL_ON", () => {
      const sb = makeSandbox("hook-failon", { linklint: "fake", linklintExit: 0 });
      expect(runHook(sb, hookInput("https://example.com/"), { LINKLINT_FAIL_ON: "medium" }).status).toBe(0);
      expect(sb.linklintCalls()[0]).toContain("medium");
    });

    /**
     * THE REGRESSION. With LINKLINT_AGENT=0 the hook expands an empty array;
     * under bash 3.2 the pre-fix script died with 127 — a NON-blocking exit —
     * before it could reach `exit 2`. Both halves are asserted: the allow path
     * still allows, and the deny path still denies with 2.
     */
    it("drops --agent when LINKLINT_AGENT=0 without aborting on the empty array", () => {
      const sb = makeSandbox("hook-agent0", { linklint: "fake", linklintExit: 0 });
      const r = runHook(sb, hookInput("https://example.com/"), { LINKLINT_AGENT: "0" });
      expect(r.status).toBe(0);
      expect(r.stderr).not.toContain("unbound variable");
      const [call] = sb.linklintCalls();
      expect(call).toEqual([expect.stringContaining("linklint"), "check", "https://example.com/", "--fail-on", "high"]);
    });

    it("still blocks with 2 when LINKLINT_AGENT=0 and the CLI denies", () => {
      const sb = makeSandbox("hook-agent0-deny", { linklint: "fake", linklintExit: 1 });
      const r = runHook(sb, hookInput("https://example.com/"), { LINKLINT_AGENT: "0" });
      expect(r.status).toBe(2);
      expect(r.status).not.toBe(127);
      expect(r.stderr).toContain("linklint blocked");
    });
  });

  describe.skipIf(JQ === undefined)("against the real CLI", () => {
    it("allows a benign URL", () => {
      const sb = makeSandbox("hook-real-safe", { linklint: "real" });
      expect(runHook(sb, hookInput("https://example.com/")).status).toBe(0);
    });

    it.each([
      ["an invalid scheme", "file:///etc/passwd"],
      ["a deceptive host", "https://paypa1-secure-login.example.net.verify-account.tk/"],
      ["an unparseable string", "http://"],
    ])("blocks %s with 2", (_label, url) => {
      const sb = makeSandbox("hook-real-block", { linklint: "real" });
      const r = runHook(sb, hookInput(url));
      expect(r.status).toBe(2);
    });

    /**
     * Fail-open found while writing this suite: `linklint check --version` and
     * `--help` exit 0, and `--allow-invalid` with no positional exits 0 too, so
     * an option-shaped `tool_input.url` used to be ALLOWED.
     */
    it.each(["--version", "--help", "--allow-invalid", "-o/tmp/x"])("blocks the option-shaped url %s with 2", (url) => {
      const sb = makeSandbox("hook-optionshaped", { linklint: "real" });
      const r = runHook(sb, hookInput(url));
      expect(r.status).toBe(2);
      expect(sb.linklintCalls()).toHaveLength(0);
    });

    /**
     * Documented limitation, pinned rather than papered over: the hook inspects
     * the ORIGINAL url exactly once. It performs no per-hop revalidation, so a
     * redirect chain that WebFetch follows later is outside its reach.
     */
    it("inspects only the original URL, exactly once", () => {
      const sb = makeSandbox("hook-original", { linklint: "fake", linklintExit: 0 });
      const url = "https://example.com/redirector?to=https%3A%2F%2Fevil.example%2F";
      expect(runHook(sb, hookInput(url)).status).toBe(0);
      const calls = sb.linklintCalls();
      expect(calls).toHaveLength(1);
      expect(calls[0]).toContain(url);
    });
  });
});

// ---------------------------------------------------------------------------
// install-aliases.sh
// ---------------------------------------------------------------------------

describe.each(BASHES)("install-aliases.sh under %s", (bash) => {
  const rcFor = (sb: Sandbox, file: string) => join(sb.root, "home", file);

  describe("--print", () => {
    it("prints the guard and exits 0 even with no linklint on PATH", () => {
      const sb = makeSandbox("inst-print", { linklint: "absent" });
      const r = runScript(bash, INSTALLER, ["--print"], sb);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain(">>> linklint guard >>>");
      expect(r.stdout).toContain("<<< linklint guard <<<");
      expect(r.stdout).toContain("_linklint_guard()");
      expect(r.stdout).toContain("curl() { _linklint_guard curl");
      expect(r.stdout).toContain("wget() { _linklint_guard wget");
      expect(r.stdout).toContain("--fail-on high");
      // Printing must not install anything.
      expect(() => readFileSync(rcFor(sb, ".zshrc"), "utf8")).toThrow();
      expect(() => readFileSync(rcFor(sb, ".profile"), "utf8")).toThrow();
    });

    it("bakes LINKLINT_FAIL_ON into the emitted guard", () => {
      const sb = makeSandbox("inst-print-failon", { linklint: "absent" });
      const r = runScript(bash, INSTALLER, ["--print"], sb, { LINKLINT_FAIL_ON: "medium" });
      expect(r.status).toBe(0);
      expect(r.stdout).toContain("--fail-on medium");
      expect(r.stdout).not.toContain("--fail-on high");
    });
  });

  describe("installation", () => {
    it("exits 1 — not the hook's 2 — when linklint is not on PATH, and writes nothing", () => {
      const sb = makeSandbox("inst-nobinary", { linklint: "absent" });
      const r = runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("not found on PATH");
      expect(() => readFileSync(rcFor(sb, ".zshrc"), "utf8")).toThrow();
    });

    it.each([
      ["/bin/zsh", ".zshrc"],
      ["/bin/bash", ".bashrc"],
      ["/usr/bin/fish", ".profile"],
      ["", ".profile"],
    ])("routes SHELL=%s to %s inside an isolated HOME", (shell, file) => {
      const sb = makeSandbox("inst-route", { linklint: "fake", linklintExit: 0 });
      const r = runScript(bash, INSTALLER, [], sb, { SHELL: shell });
      expect(r.status).toBe(0);
      expect(readFileSync(rcFor(sb, file), "utf8")).toContain(">>> linklint guard >>>");
      expect(r.stdout).toContain("appended linklint guard to");
    });

    it("honors ZDOTDIR for zsh rather than HOME", () => {
      const sb = makeSandbox("inst-zdotdir", { linklint: "fake", linklintExit: 0 });
      const zdot = join(sb.root, "zdotdir");
      mkdirSync(zdot, { recursive: true });
      const r = runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh", ZDOTDIR: zdot });
      expect(r.status).toBe(0);
      expect(readFileSync(join(zdot, ".zshrc"), "utf8")).toContain(">>> linklint guard >>>");
      expect(() => readFileSync(rcFor(sb, ".zshrc"), "utf8")).toThrow();
    });

    it("is idempotent: a second run appends nothing and exits 0", () => {
      const sb = makeSandbox("inst-idempotent", { linklint: "fake", linklintExit: 0 });
      const first = runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" });
      expect(first.status).toBe(0);
      const afterFirst = readFileSync(rcFor(sb, ".zshrc"), "utf8");

      const second = runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" });
      expect(second.status).toBe(0);
      expect(second.stdout).toContain("already present");
      const afterSecond = readFileSync(rcFor(sb, ".zshrc"), "utf8");

      expect(afterSecond).toBe(afterFirst);
      expect(afterSecond.split(">>> linklint guard >>>")).toHaveLength(2);
    });

    it("preserves rc content that was already there", () => {
      const sb = makeSandbox("inst-preserve", { linklint: "fake", linklintExit: 0 });
      mkdirSync(join(sb.root, "home"), { recursive: true });
      writeFileSync(rcFor(sb, ".zshrc"), "export EXISTING=1\n");
      expect(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" }).status).toBe(0);
      expect(readFileSync(rcFor(sb, ".zshrc"), "utf8")).toContain("export EXISTING=1");
    });

    /**
     * Fail-open found while writing this suite: the append used to be
     * unchecked, so an unwritable rc printed "appended linklint guard to …"
     * and exited 0 while nothing was installed.
     */
    it("reports failure with exit 1 when the rc cannot be written", () => {
      const sb = makeSandbox("inst-readonly", { linklint: "fake", linklintExit: 0 });
      const home = join(sb.root, "home");
      mkdirSync(home, { recursive: true });
      writeFileSync(join(home, ".zshrc"), "# existing\n", { mode: 0o444 });
      cleanups.push(() => chmodSync(join(home, ".zshrc"), 0o644));
      const r = runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" });
      expect(r.status).toBe(1);
      expect(r.stdout).not.toContain("appended linklint guard");
      expect(readFileSync(join(home, ".zshrc"), "utf8")).not.toContain("linklint guard");
    });
  });

  describe("the emitted guard's behavior", () => {
    /** Install into a temp rc, then source it in a fresh shell and run cmd. */
    function sourceAndRun(sb: Sandbox, cmd: string, env: Record<string, string> = {}) {
      expect(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh", ...env }).status).toBe(0);
      const rc = rcFor(sb, ".zshrc");
      return spawnSync(bash, ["-c", `. ${JSON.stringify(rc)}; ${cmd}`], {
        encoding: "utf8",
        cwd: sb.root,
        env: { PATH: sb.bin, HOME: join(sb.root, "home") },
      });
    }

    it("lets a URL through to the real tool when linklint exits 0", () => {
      const sb = makeSandbox("guard-allow", { linklint: "fake", linklintExit: 0, fetchStubs: true });
      const r = sourceAndRun(sb, "curl -sS https://example.com/ok");
      expect(r.status).toBe(0);
      expect(sb.fetchCalls()).toHaveLength(1);
      expect(sb.fetchCalls()[0]).toContain("https://example.com/ok");
      // The guard inspected the URL argument, not the flags.
      const inspected = sb.linklintCalls().filter((c) => c.includes("check"));
      expect(inspected).toHaveLength(1);
      expect(inspected[0]).toEqual([expect.stringContaining("linklint"), "check", "https://example.com/ok", "--fail-on", "high"]);
    });

    it("aborts the fetch with return 1 when linklint exits non-zero, and never invokes the tool", () => {
      const sb = makeSandbox("guard-block", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      const r = sourceAndRun(sb, "curl -sS https://evil.example/x");
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("linklint blocked curl");
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it("wraps wget on the same terms", () => {
      const sb = makeSandbox("guard-wget", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      const r = sourceAndRun(sb, "wget https://evil.example/x");
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("linklint blocked wget");
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it("inspects non-http schemes such as file:// and ftp://", () => {
      const sb = makeSandbox("guard-schemes", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      for (const url of ["file:///etc/passwd", "ftp://host/x", "gopher://host/x"]) {
        const r = sourceAndRun(sb, `curl ${JSON.stringify(url)}`);
        expect(r.status).toBe(1);
      }
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it("stops at the first blocked URL of a multi-URL invocation", () => {
      const sb = makeSandbox("guard-multi", { linklint: "absent", fetchStubs: true });
      // Deny only the second URL, so the loop has to reach it.
      writeFileSync(
        join(sb.bin, "linklint"),
        `#!/bin/sh\ncase "$*" in *deny*) exit 1;; esac\nexit 0\n`,
        { mode: 0o755 },
      );
      const r = sourceAndRun(sb, "curl https://ok.example/a https://deny.example/b https://ok.example/c");
      expect(r.status).toBe(1);
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it("bakes LINKLINT_FAIL_ON from install time into the guard", () => {
      const sb = makeSandbox("guard-failon", { linklint: "fake", linklintExit: 0, fetchStubs: true });
      const r = sourceAndRun(sb, "curl https://example.com/ok", { LINKLINT_FAIL_ON: "medium" });
      expect(r.status).toBe(0);
      expect(sb.linklintCalls()[0]).toContain("medium");
    });

    /**
     * Documented limitation, pinned rather than implied away: this wraps
     * INTERACTIVE shell use. A process that does not source the rc — a script,
     * another program, a direct `command curl` — is unmediated by design
     * (docs/enforcement.md non-goals: no PATH shims, no LD_PRELOAD).
     */
    it("does not mediate a shell that never sourced the rc", () => {
      const sb = makeSandbox("guard-nosource", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      expect(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" }).status).toBe(0);
      const r = spawnSync(bash, ["-c", "curl https://evil.example/x"], {
        encoding: "utf8",
        cwd: sb.root,
        env: { PATH: sb.bin, HOME: join(sb.root, "home") },
      });
      expect(r.status).toBe(0);
      expect(sb.fetchCalls()).toHaveLength(1);
    });

    it("does not mediate `command curl`, which bypasses the shell function", () => {
      const sb = makeSandbox("guard-bypass", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      const r = sourceAndRun(sb, "command curl https://evil.example/x");
      expect(r.status).toBe(0);
      expect(sb.fetchCalls()).toHaveLength(1);
    });

    /**
     * Also a scope limitation: the guard's `case` only matches arguments that
     * carry a `://`, so a scheme-less argument (`curl example.com`, which curl
     * itself resolves to https://) reaches the tool uninspected.
     */
    it("does not inspect a scheme-less argument", () => {
      const sb = makeSandbox("guard-schemeless", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      const r = sourceAndRun(sb, "curl example.com");
      expect(r.status).toBe(0);
      expect(sb.fetchCalls()).toHaveLength(1);
      expect(sb.linklintCalls().filter((c) => c.includes("check"))).toHaveLength(0);
    });
  });

  /**
   * LINK-kidprtkk — `${FAIL_ON}` must reach the rc file QUOTED.
   *
   * TWO EXPANSION LAYERS, ONLY ONE OF THEM UNSAFE. The installer expands
   * `${FAIL_ON}` inside a `<<EOF` heredoc, and a heredoc body neither
   * word-splits nor globs — that layer was never the bug. The bug is the TEXT
   * the heredoc produces: it lands in a long-lived rc file that the user's own
   * shell parses later, and that shell does split, glob and substitute. So the
   * fix is a quoted *literal in the emitted text*, not a quoted expansion in
   * the installer; quoting the installer-side expansion would emit a useless
   * `${FAIL_ON}` into the rc instead.
   *
   * The value is install-time environment, not attacker-controlled input, and a
   * malformed one fails CLOSED — which is why this was filed low. It is still
   * worth pinning: the rc outlives the install by years, and the failure modes
   * below range from "surprising" to "arbitrary rc code".
   *
   * NOT COVERED, deliberately: whether the guard should inspect scheme-less
   * arguments at all is a separate open decision (LINK-dkfsxrpc). Nothing here
   * touches the `case` matching logic.
   */
  describe("a hostile LINKLINT_FAIL_ON cannot restructure the generated rc", () => {
    /** The generated guard text, via `--print` (installs nothing). */
    function printGuard(failOn: string): string {
      const sb = makeSandbox("failon-print", { linklint: "absent" });
      const r = runScript(bash, INSTALLER, ["--print"], sb, { LINKLINT_FAIL_ON: failOn });
      expect(r.status).toBe(0);
      return r.stdout;
    }

    /**
     * Install the guard with `failOn` baked in, then source it from a cwd
     * stocked with decoy files and run curl — so a glob in the baked value has
     * something to expand against. Returns the argv `linklint` actually saw.
     */
    function argvUnderGuard(failOn: string): string[] {
      const sb = makeSandbox("failon-argv", { linklint: "fake", linklintExit: 0, fetchStubs: true });
      expect(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh", LINKLINT_FAIL_ON: failOn }).status).toBe(0);
      const rc = join(sb.root, "home", ".zshrc");
      const work = join(sb.root, "work");
      mkdirSync(work, { recursive: true });
      for (const decoy of ["decoy-a", "decoy-b"]) writeFileSync(join(work, decoy), "");
      const r = spawnSync(bash, ["-c", `. ${JSON.stringify(rc)}; curl https://example.com/ok`], {
        encoding: "utf8",
        cwd: work,
        env: { PATH: sb.bin, HOME: join(sb.root, "home") },
      });
      expect(r.status).toBe(0);
      const inspected = sb.linklintCalls().filter((c) => c.includes("check"));
      expect(inspected).toHaveLength(1);
      return inspected[0].slice(1);
    }

    /**
     * A value carrying whitespace used to emit `--fail-on high --allow-invalid`
     * — a bare second argument, silently loosening the guard it was meant to
     * configure.
     */
    it("keeps a whitespace-bearing value as ONE argument instead of injecting a second flag", () => {
      const out = printGuard("high --allow-invalid");
      expect(out).toContain("--fail-on 'high --allow-invalid'");
      expect(out).not.toContain("--fail-on high --allow-invalid");
      expect(argvUnderGuard("high --allow-invalid")).toEqual(["check", "https://example.com/ok", "--fail-on", "high --allow-invalid"]);
    });

    /**
     * The sharpest one, because it is decided at RUNTIME, not install time: a
     * bare `--fail-on *` in the rc globs against whatever directory the user
     * happens to be standing in, so the same rc line means something different
     * in every directory.
     */
    it("does not let a glob in the value expand against the user's cwd at runtime", () => {
      expect(printGuard("*")).toContain("--fail-on '*'");
      const argv = argvUnderGuard("*");
      expect(argv).toEqual(["check", "https://example.com/ok", "--fail-on", "*"]);
      expect(argv).not.toContain("decoy-a");
      expect(argv).not.toContain("decoy-b");
    });

    /**
     * `${LINKLINT_FAIL_ON:-high}` already turns a wholly empty value into
     * `high`, so the "nothing at all" case that actually reaches the rc is a
     * value made only of whitespace. Unquoted it vanished during word
     * splitting, leaving `--fail-on` with no argument at all.
     */
    it("keeps a whitespace-only value from leaving --fail-on with no argument", () => {
      expect(printGuard(" ")).toContain("--fail-on ' '");
      expect(argvUnderGuard(" ")).toEqual(["check", "https://example.com/ok", "--fail-on", " "]);
    });

    /** Single quotes, not double: the baked value must stay inert in the rc. */
    it("bakes a substitution-shaped value in literally rather than running it when the rc is sourced", () => {
      expect(printGuard("$(id -un)")).toContain("--fail-on '$(id -un)'");
      expect(argvUnderGuard("$(id -un)")).toEqual(["check", "https://example.com/ok", "--fail-on", "$(id -un)"]);
    });

    /**
     * The worst outcome available here, and the reason quoting alone is not
     * enough: the value is also interpolated into the `#` comment above the
     * function. A newline ENDS that comment, so the remainder of the value
     * became a live rc line — `rm -rf …` executed by every new shell.
     */
    it("cannot break out of the comment line it is also interpolated into", () => {
      const out = printGuard("high\nrm -rf /tmp/linklint-pwned");
      const preamble = out.split("\n").slice(0, out.split("\n").findIndex((l) => l.includes("_linklint_guard()")));
      expect(preamble.length).toBeGreaterThan(0);
      for (const line of preamble) expect(line.startsWith("#")).toBe(true);
      expect(out).not.toMatch(/^rm -rf/m);
    });

    /** The ordinary values must survive all of the above unchanged. */
    it.each(["high", "medium", "critical"])("still bakes the ordinary value %s through to argv", (failOn) => {
      expect(argvUnderGuard(failOn)).toEqual(["check", "https://example.com/ok", "--fail-on", failOn]);
    });
  });
});
