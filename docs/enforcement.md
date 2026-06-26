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
- Every failure path — unreadable input, missing/empty URL, threshold hit,
  invalid input, missing binary (`127`) — explicitly `exit 2`s. Default-deny.
- The hook sees only the **original** URL. WebFetch's own redirect-following
  happens later, inside tool execution, out of the hook's reach (per-hop
  revalidation is roadmap, not v1).

## Shell-alias installer (curl / wget)

`enforcement/install-aliases.sh` appends a safe-chain-style guard to your shell
rc that wraps `curl` and `wget`: each URL argument is inspected with
`linklint check` first, and **any non-zero exit aborts the fetch** — threshold
hit *or* invalid input, so `file:///…` and unparseable inputs are blocked too,
not just `high`/`critical`.

```bash
./enforcement/install-aliases.sh --print   # review the guard first
./enforcement/install-aliases.sh           # append it to ~/.zshrc / ~/.bashrc
```

It detects the current shell's rc file, is idempotent (guarded by a sentinel
comment), and is uninstalled by deleting the `>>> linklint guard >>>` block.
This wraps **interactive** shell use — it is intentionally not a system-wide
interception (see non-goals below).

## MCP

The [`@linklint/mcp`](../packages/mcp/README.md) server is the third enforcement
surface: an agent calls `check_url` / `check_domain` before fetching. Pass
`agentMode: true` (per call) or set `LINKLINT_AGENT_MODE=1` (server default) to
enable the agent-gated detector channel — `prompt_injection_url`,
`api_endpoint_impersonation`, `credential_harvesting`, `data_exfiltration`, and
the `ssrf_cloud_metadata` escalation.

## Out of scope (deliberate non-goals)

OS-level interception — DNS sinkhole, eBPF socket filters, macOS Network
Extension, `LD_PRELOAD` shims — is **not** built. The distribution friction
(notarization, kernel fragility, per-process setup) is high for marginal reach
over the hook and shell-alias wrappers above, which cover the dominant
agent/interactive caller paths at near-zero install cost.
