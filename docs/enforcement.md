# Enforcement & distribution

linklint only **reports** a verdict — enforcement is the consumer's job
([architecture §8](architecture.md)). This guide ships two thin, fail-closed
enforcement wrappers around the offline CLI, plus the rationale for what is
deliberately *not* built.

The through-line is **fail-closed**: deny on a deceptive verdict, on invalid
input, and on *any* error. The verdict is delegated to `linklint check`'s own
exit code rather than re-derived from `severity` — an `invalid` result (e.g.
`file:///etc/passwd`) has `severity: null`, so a severity-only gate would let it
through. `linklint check` exits `0` only when the URL is below `--fail-on` **and**
parseable; `--fail-on` already treats `invalid` as a failure unless
`--allow-invalid` is passed.

Both wrappers honor `LINKLINT_FAIL_ON` (default `high`) to tune the threshold.

## Claude Code PreToolUse hook

`enforcement/claude-code-hook.sh` blocks a `WebFetch`/`WebSearch` call when the
target URL is deceptive, invalid, or unreadable.

Wire it in `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [
          { "type": "command", "command": "/absolute/path/to/enforcement/claude-code-hook.sh" }
        ]
      }
    ]
  }
}
```

Why the script is shaped the way it is (verified against the Claude Code hook
docs — an earlier example hook was broken and failed **open**):

- **Input is JSON on stdin**, not env vars. `$CLAUDE_TOOL_INPUT_URL` does not
  exist; the URL is read with `jq -r '.tool_input.url'`.
- **Blocking requires exit code 2** (its stderr is fed back to Claude). **Exit
  code 1 is non-blocking** — a block verdict that exits 1 lets the fetch proceed.
- `set -uo pipefail`, **not** `-e`: a `jq`/`linklint` crash must hit the explicit
  `exit 2`, not bubble up as a non-blocking exit 1.
- Every failure path — unreadable input, missing/empty URL, an option-shaped
  URL (one starting with `-`, which the CLI would consume as a flag and exit
  `0` on), threshold hit, invalid input, missing binary (`127`) — explicitly
  `exit 2`s. Default-deny.
- It runs under `/bin/bash`, which on macOS is still 3.2. Empty-array
  expansions there use the `${a[@]+"${a[@]}"}` form; the bare form is an
  unbound-variable abort under `set -u` and would exit non-blocking `127`.
- The hook sees only the **original** URL. WebFetch's own redirect-following
  happens later, inside tool execution, out of the hook's reach (per-hop
  revalidation is roadmap, not v1).
- **Agent mode is ON by default** here — this hook *is* the agent context, so it
  passes `--agent` and the agent-gated detectors (prompt-injection, SSRF
  cloud-metadata escalation, API-endpoint impersonation, credential-harvesting,
  data-exfiltration) are evaluated. Set `LINKLINT_AGENT=0` to disable. Note
  `prompt_injection_url` is weight `0.5` (severity `medium`), so it does **not**
  block at the default `LINKLINT_FAIL_ON=high`; pair it with
  `LINKLINT_FAIL_ON=medium` to make URL-borne prompt injection deny the fetch.

## Shell-alias installer (curl / wget)

`enforcement/install-aliases.sh` appends a safe-chain-style guard to your shell
rc that wraps `curl` and `wget`: each **fetch target** among the arguments is
inspected with `linklint check` first, and **any non-zero exit aborts the
fetch** — threshold hit *or* invalid input, so `file:///…` and unparseable
targets are blocked too, not just `high`/`critical`. What counts as a target,
and what is left alone, is spelled out below.

```bash
./enforcement/install-aliases.sh --print   # review the guard first
./enforcement/install-aliases.sh           # append it to ~/.zshrc / ~/.bashrc
```

It detects the current shell's rc file, is idempotent (guarded by a sentinel
comment), and is uninstalled by deleting the `>>> linklint guard >>>` block.
It exits `1` — not the hook's `2` — when `linklint` is absent from `PATH` or
the rc file cannot be written; the exit codes are not shared between the two
wrappers because only the hook's `2` carries a blocking meaning.

The emitted function is POSIX sh, not bash: the installer's fallback branch
routes any shell that is not bash or zsh into `~/.profile`, which ksh reads,
and ksh93 has no `local`.

### What counts as a fetch target

The guard judges an argument when it **begins** with a scheme *and* is not
sitting in a value-taking option's value slot. Both halves matter, and the
second is argv parsing rather than a guess — the argument after `-H`, `-d` or
`-e` is that option's value, so it is not something curl will fetch.

A header, a request body, a referer and a user agent routinely carry `://`
without being URLs, and `linklint check` reports such a string as invalid
rather than deceptive. Before `LINK-dwapcooy` the match was a bare `*://*`
containment test, so `curl -H 'Origin: https://app.example.com' -d '{}'
https://api.example.com/v1` aborted at the header — a fail-closed guard turning
an unparseable *option value* into a veto over a perfectly ordinary call.
`curl -e 'https://gοogle.com' https://example.com/api` was the sharpest shape:
a deceptive **referer** vetoed a benign **destination**, and nothing is fetched
from a referer.

Options whose value **is** a network endpoint are deliberately left out of that
skip list, so they stay inspected: curl's `--url` (both `--url X` and
`--url=X`), `-x`/`--proxy`/`--preproxy`, and wget's `-B`.

When the guard does block, the message names the cause rather than only the
string — `deceptive at or above 'high'`, `not a parseable URL, so not judged`,
or `linklint could not check it (exit N)`. The bare form read as an accusation
against a host that had not been judged at all.

### Scope limits worth stating plainly

The wrapper is a shell function, not an interceptor. It under-mediates in three
directions and over-mediates in one:

- **Scheme-less arguments are not inspected.** `curl example.com` reaches the
  tool unjudged — and curl then fetches **http://**example.com, since it
  defaults a scheme-less operand to HTTP and guesses another scheme only from a
  host-name prefix such as `ftp.`. `command curl …` likewise bypasses the
  function by design. Widening to cover this was decided against in
  `LINK-dkfsxrpc`: measured against real curl argv tokens, the narrowest
  defensible widening still blocks 20–32% of ordinary non-URL arguments, and
  the benefit has no matching measurement.
- **Redirects are not revalidated.** The guard sees the argument you typed, and
  `curl -L` / `wget` following a `3xx` happens inside the tool, past the shell
  function. This is the same blindness the Claude Code hook has, for the same
  reason: per-hop revalidation is roadmap, not v1.
- **This wraps interactive shell use** — it is intentionally not a system-wide
  interception (see non-goals below). A script or program that does not source
  the rc file is unmediated.
- **A URL in an option's value slot is not inspected**, which is the
  over-mediation direction traded away above. `curl -e <deceptive-url>` and
  `curl -H 'Referer: <deceptive-url>'` reach the tool; the destination is still
  judged. The option list the guard skips is curl's and wget's separately —
  `-d` is curl's request body but wget's `--debug`, `-H` is curl's header but
  wget's `--span-hosts` — so a shared list would have skipped the URL that
  follows a value-less wget flag. An option neither list knows about falls
  through to the scheme test.

## MCP

The [`@linklint/mcp`](../packages/mcp/README.md) server is the third enforcement
surface: an agent calls `check_url` / `check_domain` before fetching. Pass
`agentMode: true` (per call) or set `LINKLINT_AGENT_MODE=1` (server default) to
enable the agent-gated detector channel — `prompt_injection_url`,
`credential_harvesting`, `data_exfiltration`, and the `ssrf_cloud_metadata`
escalation.

## Out of scope (deliberate non-goals)

OS-level interception — DNS sinkhole, eBPF socket filters, macOS Network
Extension, `LD_PRELOAD` shims — is **not** built. The distribution friction
(notarization, kernel fragility, per-process setup) is high for marginal reach
over the hook and shell-alias wrappers above, which cover the dominant
agent/interactive caller paths at near-zero install cost.
