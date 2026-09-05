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
 *   - Redirect following, on EITHER wrapper. The hook sees the ORIGINAL URL
 *     only (docs/enforcement.md §"The hook sees only the original URL"); what
 *     the tool does after the hook allows is out of reach. The shell guard has
 *     the same blindness for `curl -L` — it judges the argument you typed, and
 *     the `3xx` chain is followed inside curl, past the shell function. The
 *     proxy pinned below, for both, is that exactly one CLI call is made, for
 *     exactly the argument given.
 *   - A real interactive login shell sourcing a real rc file. The installer is
 *     driven into a temp `HOME`/`ZDOTDIR` and the emitted guard is sourced
 *     explicitly; nothing here touches the developer's own rc files.
 *   - `shellcheck`-class static analysis. No shellcheck is wired into this
 *     repo's hooks or CI and none is added here.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

/**
 * `jq` gates four of the hook describes below, and its absence is not
 * hypothetical: GitLab's `node:24` image does not ship it, so those blocks are
 * SKIPPED on every remote run and exercised on a workstation only. Measured —
 * forcing `JQ` undefined here skips exactly 25 tests, which with the
 * darwin-only bash-3.2 pin is the whole of the 26 the runner reported on
 * pipeline 2822652495 (LINK-ujbttpph). Coverage that skips precisely where the
 * matrix would otherwise supply it is not matrix coverage; installing `jq` in
 * the CI job is what would make it so.
 */
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

/** Candidate interpreters that exist, de-duplicated by realpath, order kept. */
function distinctShells(candidates: readonly (string | undefined)[]): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
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
}

/**
 * Every distinct bash on this machine, `/bin/bash` first. On macOS that is the
 * 3.2 system bash; on CI it is a single bash 5.
 */
const BASHES: readonly string[] = distinctShells([
  "/bin/bash",
  which("bash"),
  "/usr/local/bin/bash",
  "/opt/homebrew/bin/bash",
]);

/**
 * The NON-bash interpreters the installer can route the guard into. Its `*)`
 * branch sends every shell that is not bash or zsh to `~/.profile`, which ksh
 * and any `/bin/sh` read — so the emitted text has to be POSIX sh, not bash.
 * macOS ships `/bin/ksh` (ksh93u+) and `/bin/dash`; a Linux CI box usually has
 * dash as `/bin/sh` only.
 */
const POSIX_SHELLS: readonly string[] = distinctShells([
  "/bin/ksh",
  which("ksh"),
  which("ksh93"),
  which("mksh"),
  "/bin/dash",
  which("dash"),
  "/bin/sh",
]);

function bashMajor(bash: string): number {
  const r = spawnSync(bash, ["-c", "echo $BASH_VERSINFO"], { encoding: "utf8" });
  return Number.parseInt(r.stdout.trim(), 10);
}

// ---------------------------------------------------------------------------
// Sandbox: a per-test temp root holding a PATH directory we fully control.
// ---------------------------------------------------------------------------

const TMP_ROOT = mkdtempSync(join(tmpdir(), "linklint-enforcement-"));

afterAll(() => {
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
      // Single-quoted in the emitted text — see the LINK-kidprtkk block below.
      expect(r.stdout).toContain("--fail-on 'high'");
      // Printing must not install anything.
      expect(() => readFileSync(rcFor(sb, ".zshrc"), "utf8")).toThrow();
      expect(() => readFileSync(rcFor(sb, ".profile"), "utf8")).toThrow();
    });

    it("bakes LINKLINT_FAIL_ON into the emitted guard", () => {
      const sb = makeSandbox("inst-print-failon", { linklint: "absent" });
      const r = runScript(bash, INSTALLER, ["--print"], sb, { LINKLINT_FAIL_ON: "medium" });
      expect(r.status).toBe(0);
      expect(r.stdout).toContain("--fail-on 'medium'");
      expect(r.stdout).not.toContain("--fail-on 'high'");
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
     *
     * The unwritability has to be built out of something the KERNEL refuses
     * for every uid, not out of permission bits (LINK-ujbttpph). This case
     * used to write the rc at mode `0o444`, which holds on a workstation and
     * collapses on GitLab's `node:24` job, where the job runs as root and root
     * bypasses the DAC check: the append succeeded, the installer correctly
     * exited 0, and the assertion failed on a premise it had not managed to
     * construct rather than on the behaviour it exists to pin.
     *
     * Measured under `docker run --rm node:24 bash` as uid 0, against the same
     * probe run as uid 501 on macOS: an rc file at `0o444` and an rc parent
     * directory at `0o555` both accept the append as root, so neither can
     * carry this test. Appending onto a path that IS a directory (`EISDIR`)
     * and onto one whose parent is absent (`ENOENT`) are refused for root and
     * non-root alike — those are type and lookup failures, not permission
     * checks — so the two cases below are the premise instead.
     */
    /** The installer refused, said so, and installed nothing. */
    function expectRefusal(r: ReturnType<typeof runScript>): void {
      expect(r.status).toBe(1);
      expect(r.stdout).not.toContain("appended linklint guard");
      // Names the append as the thing that failed, so a bail-out somewhere
      // earlier in the script cannot pass as this coverage.
      expect(r.stderr).toContain("guard NOT installed");
    }

    it("reports failure with exit 1 when the rc path is a directory", () => {
      const sb = makeSandbox("inst-rc-isdir", { linklint: "fake", linklintExit: 0 });
      mkdirSync(rcFor(sb, ".zshrc"), { recursive: true });
      expectRefusal(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh" }));
      // Nothing was written anywhere beneath the rc path either.
      expect(readdirSync(rcFor(sb, ".zshrc"))).toEqual([]);
    });

    it("reports failure with exit 1 when the rc's parent directory is absent", () => {
      const sb = makeSandbox("inst-rc-noparent", { linklint: "fake", linklintExit: 0 });
      // ZDOTDIR is the routing the installer already honors, so this points the
      // rc at a real path shape rather than an invented one. Deliberately never
      // created — an rc under it cannot be opened for append by any uid.
      const zdot = join(sb.root, "zdotdir-that-was-removed");
      expectRefusal(runScript(bash, INSTALLER, [], sb, { SHELL: "/bin/zsh", ZDOTDIR: zdot }));
      expect(existsSync(zdot)).toBe(false);
      expect(existsSync(rcFor(sb, ".zshrc"))).toBe(false);
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
     * Also a scope limitation, and the one LINK-dkfsxrpc decided 2-0 to leave
     * alone: the guard only judges arguments that begin with a scheme, so a
     * scheme-less argument reaches the tool uninspected.
     *
     * `curl example.com` fetches **http://**example.com, not https — curl
     * defaults a scheme-less operand to HTTP and guesses another scheme only
     * from a host-name prefix such as `ftp.`. An earlier version of this
     * comment said https, which understates what the uninspected fetch does.
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
      const [call] = inspected;
      if (call === undefined) throw new Error("unreachable: length asserted above");
      // Drop argv[0] (the shim's own path); what matters is the argument structure.
      return call.slice(1);
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

// ---------------------------------------------------------------------------
// LINK-dwapcooy — WHICH arguments the guard inspects, and WHICH shells can run
// the text it emits. Both directions were untested before this block.
// ---------------------------------------------------------------------------

/** The interpreter used to RUN the installer; the guard it emits is sh, not bash. */
const INSTALLER_BASH = BASHES[0] ?? "/bin/bash";

/**
 * Install the guard into a temp rc, then source it under `shell` and run `cmd`.
 * Nothing here touches a real rc file — `runScript` pins HOME into the sandbox.
 */
function underGuard(sb: Sandbox, cmd: string, shell: string = INSTALLER_BASH) {
  expect(runScript(INSTALLER_BASH, INSTALLER, [], sb, { SHELL: "/bin/zsh" }).status).toBe(0);
  const rc = join(sb.root, "home", ".zshrc");
  return spawnSync(shell, ["-c", `. ${JSON.stringify(rc)}; ${cmd}`], {
    encoding: "utf8",
    cwd: sb.root,
    env: { PATH: sb.bin, HOME: join(sb.root, "home") },
  });
}

/** A real-CLI sandbox with stub `curl`/`wget`, so "did it fetch?" is observable. */
function fetchSandbox(name: string): Sandbox {
  return makeSandbox(name, { linklint: "real", fetchStubs: true });
}

/** Greek omicron in place of the Latin `o` — scores critical on its own. */
const HOMOGLYPH_HOST = "https://gοogle.com";
/** A host the real CLI grades at/above `high`. */
const DECEPTIVE_TARGET = "https://paypa1-secure-login.example.net.verify-account.tk/";

describe("the emitted guard's argument selection (LINK-dwapcooy)", () => {
  /**
   * WAS THE DEFECT. The `case` used to carry a `*://*` catch-all — which also
   * made its four leading `http://*|https://*|ftp://*|file://*` alternatives
   * dead — so it matched `://` ANYWHERE in a token rather than tokens that ARE
   * fetch targets. `linklint check` exits 1 on the resulting unparseable
   * strings and the guard is fail-closed, so ordinary API-call idioms died
   * before curl was reached.
   *
   * These run against the REAL CLI, so the verdicts are the ones a user gets.
   * Each command's own destination is benign, so reaching the tool is the
   * correct outcome for all of them.
   */
  it.each([
    ["a header value", `curl -H 'Origin: https://app.example.com' -d '{}' https://api.example.com/v1`],
    ["a urlencoded form field", `curl --data-urlencode 'url=https://target.example' https://api.example.com`],
    ["a form body", `curl -d 'callback=https://app.example/cb' https://api.example.com`],
    ["a referer header", `curl -H 'Referer: https://example.com' https://api.example.com`],
    ["a referer", `curl -e ${JSON.stringify(HOMOGLYPH_HOST)} 'https://example.com/api'`],
    ["a JSON body carrying a URL", `curl --json '{"cb":"https://app.example/cb"}' https://api.example.com`],
    ["a user agent", `curl -A 'bot/1.0 (+https://bot.example)' https://api.example.com`],
  ])("%s no longer aborts the fetch, because it is not a fetch target", (_label, cmd) => {
    const sb = fetchSandbox("optval-allow");
    const r = underGuard(sb, cmd);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain("linklint blocked");
    expect(sb.fetchCalls()).toHaveLength(1);
  });

  /**
   * The sharpest one, stated as its own assertion because it was not merely
   * over-inspection: the verdict was taken from a REFERER and applied to a
   * DESTINATION, and the loop aborted before the destination was inspected at
   * all. Nothing is ever fetched from a referer.
   */
  it("does not let a deceptive referer veto a benign destination", () => {
    const sb = fetchSandbox("optval-referer");
    const r = underGuard(sb, `curl -e ${JSON.stringify(HOMOGLYPH_HOST)} 'https://example.com/api'`);
    expect(r.status).toBe(0);
    expect(sb.fetchCalls()).toHaveLength(1);
    // The destination — and only the destination — was judged.
    const inspected = sb.linklintCalls().filter((c) => c.includes("check"));
    expect(inspected).toHaveLength(1);
    expect(inspected[0]).toContain("https://example.com/api");
    expect(inspected.flat()).not.toContain(HOMOGLYPH_HOST);
  });

  /**
   * The same homoglyph host as a DESTINATION is still refused, so the referer
   * case above is narrowing rather than a hole: the string did not become
   * acceptable, its position stopped being a fetch.
   */
  it("still refuses that same homoglyph host when it IS the destination", () => {
    const sb = fetchSandbox("optval-homoglyph-target");
    const r = underGuard(sb, `curl ${JSON.stringify(HOMOGLYPH_HOST)}`);
    expect(r.status).toBe(1);
    expect(sb.fetchCalls()).toHaveLength(0);
  });

  /**
   * MISATTRIBUTION, asserted separately from the match. `linklint check` exits
   * 1 for "deceptive" and for "does not parse" alike, so a message that names
   * only the argument reads as an accusation against a host that may not have
   * been judged at all. The guard now re-runs with `--allow-invalid` on the
   * failure path to tell the two apart, and says which it is.
   */
  describe("the block message names the real cause", () => {
    it("says 'deceptive' for a host the CLI actually graded", () => {
      const sb = fetchSandbox("why-deceptive");
      const r = underGuard(sb, `curl ${JSON.stringify(DECEPTIVE_TARGET)}`);
      expect(r.stderr).toContain("linklint blocked curl (deceptive at or above high)");
      expect(r.stderr).toContain(DECEPTIVE_TARGET);
      expect(r.stderr).not.toMatch(/parseable/i);
    });

    it("says 'not a parseable URL' for a target the CLI refused to judge", () => {
      const sb = fetchSandbox("why-invalid");
      // Scheme-prefixed, so it IS treated as a target, but it has no authority.
      const r = underGuard(sb, `curl 'http://'`);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("linklint blocked curl (not a parseable URL, so not judged");
      expect(r.stderr).not.toMatch(/deceptive/i);
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it("says so, and still blocks, when the CLI itself could not run", () => {
      const sb = makeSandbox("why-error", { linklint: "fake", linklintExit: 3, fetchStubs: true });
      const r = underGuard(sb, "curl https://example.com/ok");
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("linklint blocked curl (linklint could not check it (exit 3))");
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    /** The extra `--allow-invalid` probe runs only on the failure path. */
    it("costs no second CLI call when the target passes", () => {
      const sb = makeSandbox("why-nocost", { linklint: "fake", linklintExit: 0, fetchStubs: true });
      expect(underGuard(sb, "curl https://example.com/ok").status).toBe(0);
      expect(sb.linklintCalls().filter((c) => c.includes("check"))).toHaveLength(1);
    });
  });

  /**
   * The scheme test is a PREFIX test, not a containment test, and the prefix
   * has to look like a scheme — `[A-Za-z][A-Za-z0-9+.-]*` — or the token is an
   * option value, a query string or a JSON blob rather than a target.
   */
  describe("only a scheme-prefixed token is treated as a target", () => {
    it.each([
      ["a header value", "Origin: https://app.example.com"],
      ["a form field", "url=https://target.example"],
      ["a JSON body", '{"cb":"https://app.example/cb"}'],
      ["an authority-relative reference", "//evil.example/x"],
      ["a bare `://`", "://evil.example"],
    ])("does not judge %s when it reaches the loop unguarded by a flag", (_label, token) => {
      const sb = makeSandbox("prefix", { linklint: "fake", linklintExit: 1, fetchStubs: true });
      // `--fake-flag` is in no skip list, so the token is examined on its own.
      const r = underGuard(sb, `curl --fake-flag ${JSON.stringify(token)} https://example.com/ok`);
      expect(r.status).toBe(1); // the benign-looking destination is still judged
      expect(sb.linklintCalls().filter((c) => c.includes("check")).flat()).not.toContain(token);
    });
  });

  /**
   * THE OTHER HALF — what narrowing may not break. A real fetch target has to
   * stay inspected and stay blocked, whatever position or option carries it.
   */
  describe("targets stay inspected", () => {
    it.each([
      ["a bare deceptive URL", `curl ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a deceptive URL behind an output flag", `curl -o out.txt ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a deceptive URL behind a header", `curl -H 'X-A: b' ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a deceptive URL behind --url", `curl --url ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a deceptive URL behind --url=", `curl --url=${DECEPTIVE_TARGET}`],
      ["a deceptive URL behind a proxy, which stays inspected", `curl -x http://p.example:3128 ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a dangerous scheme", `curl file:///etc/passwd`],
      ["a deceptive URL passed to wget", `wget ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["a deceptive URL wget reaches behind a header", `wget --header 'X-A: b' ${JSON.stringify(DECEPTIVE_TARGET)}`],
    ])("blocks %s", (_label, cmd) => {
      const sb = fetchSandbox("target-block");
      const r = underGuard(sb, cmd);
      expect(r.status).toBe(1);
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    it.each([
      ["a benign URL", `curl https://example.com/ok`],
      ["a benign URL behind an output flag", `curl -o out.txt https://example.com/ok`],
      ["a benign URL with bundled short flags", `curl -sSL https://example.com/ok`],
      ["a benign URL after a value-less flag", `curl -L https://example.com/ok`],
      ["a benign URL passed to wget", `wget -q https://example.com/ok`],
    ])("lets %s through", (_label, cmd) => {
      const sb = fetchSandbox("target-allow");
      const r = underGuard(sb, cmd);
      expect(r.status).toBe(0);
      expect(sb.fetchCalls()).toHaveLength(1);
    });

    /**
     * The skip list is PER TOOL because the same short flag means different
     * things in each: `-d` is curl's request body but wget's `--debug`, `-H`
     * is curl's header but wget's `--span-hosts`. A shared list would have
     * skipped the URL that follows a value-less wget flag.
     */
    it.each([
      ["wget -d", `wget -d ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["wget -H", `wget -H ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["wget -b", `wget -b ${JSON.stringify(DECEPTIVE_TARGET)}`],
      ["wget -F", `wget -F ${JSON.stringify(DECEPTIVE_TARGET)}`],
    ])("still inspects the URL after %s, which takes no value", (_label, cmd) => {
      const sb = fetchSandbox("wget-valueless");
      const r = underGuard(sb, cmd);
      expect(r.status).toBe(1);
      expect(sb.fetchCalls()).toHaveLength(0);
    });

    /** Every remaining argument is examined; the loop does not stop at the first. */
    it("inspects a target that follows several skipped option values", () => {
      const sb = fetchSandbox("target-late");
      const r = underGuard(sb, `curl -H 'A: https://x.example' -e 'https://y.example' -d 'z=https://q.example' ${JSON.stringify(DECEPTIVE_TARGET)}`);
      expect(r.status).toBe(1);
      const inspected = sb.linklintCalls().filter((c) => c.includes("check"));
      expect(inspected[0]).toContain(DECEPTIVE_TARGET);
      expect(sb.fetchCalls()).toHaveLength(0);
    });
  });

  /**
   * The guard's names must not survive into the interactive shell — an rc
   * function that leaks `_linklint_arg` would collide with the user's own.
   */
  it("leaves none of its own variables set in the calling shell", () => {
    const sb = makeSandbox("guard-noleak", { linklint: "fake", linklintExit: 0, fetchStubs: true });
    const r = underGuard(sb, "curl https://example.com/ok; set | grep -c '^_linklint_[a-z]*=' || true");
    expect(r.status).toBe(0);
    expect(r.stdout.trim().split("\n").pop()).toBe("0");
  });
});

describe.skipIf(POSIX_SHELLS.length === 0)("the emitted guard under a non-bash rc shell (LINK-dwapcooy)", () => {
  /**
   * The installer routes fish, ksh, tcsh — every shell that is not bash or zsh
   * — into `~/.profile`, and its own header comment leans on that routing when
   * it argues the baked `--fail-on` literal is safe "in POSIX sh too". The text
   * it emitted declared `local`, which is a bash/zsh/ash extension POSIX does
   * not define and ksh93 does not carry.
   *
   * WHAT THAT COST, measured against /bin/ksh (ksh93u+) rather than assumed:
   * `local _tool` failed, `$_tool` was left unset, and the trailing
   * `command "$_tool" "$@"` tried to execute the empty string — so a BENIGN
   * fetch died with 126 and nothing was fetched. dash and `/bin/sh` carry
   * `local` as an extension and were unaffected, which is why a dash-only
   * check would have called this fine.
   */
  it.each(POSIX_SHELLS)("%s: runs the guard and lets a benign target through", (shell) => {
    const sb = fetchSandbox("posix-benign");
    const r = underGuard(sb, "curl https://example.com/ok", shell);
    // ksh93 reports `local: not found` on stderr yet still exits 0 from the
    // rest of the function, so the exit status alone would not have caught it.
    expect(r.stderr).not.toContain("local: not found");
    expect(r.status).toBe(0);
    expect(sb.fetchCalls()).toHaveLength(1);
  });

  it.each(POSIX_SHELLS)("%s: still refuses a deceptive target", (shell) => {
    const sb = fetchSandbox("posix-deny");
    const r = underGuard(sb, `curl ${JSON.stringify(DECEPTIVE_TARGET)}`, shell);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("linklint blocked curl");
    expect(sb.fetchCalls()).toHaveLength(0);
  });

  it.each(POSIX_SHELLS)("%s: does not judge an option value", (shell) => {
    const sb = fetchSandbox("posix-optval");
    const r = underGuard(sb, `curl -H 'Origin: https://app.example.com' https://example.com/ok`, shell);
    expect(r.status).toBe(0);
    expect(sb.fetchCalls()).toHaveLength(1);
  });

  /**
   * The source-level half, so a machine with no ksh cannot go green on a
   * regression the way a bash-5-only CI run could mask the array bug above.
   * `local` is the one that bit; the others are the bashisms nearest to hand
   * in a rewrite of this function.
   */
  it("keeps bash-only syntax out of the emitted guard", () => {
    const sb = makeSandbox("posix-source", { linklint: "absent" });
    const r = runScript(INSTALLER_BASH, INSTALLER, ["--print"], sb);
    expect(r.status).toBe(0);
    const code = r.stdout.split("\n").filter((line) => !line.trimStart().startsWith("#"));
    for (const bashism of [/^\s*local\s/, /^\s*declare\s/, /\[\[/, /\$\(\(/, /==/, /\+=/, /<<</]) {
      expect(code.filter((line) => bashism.test(line))).toEqual([]);
    }
  });
});
