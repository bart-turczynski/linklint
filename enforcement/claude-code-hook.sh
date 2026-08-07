#!/usr/bin/env bash
# linklint — Claude Code PreToolUse hook (fail-closed).
#
# Blocks a WebFetch/WebSearch tool call when linklint judges the target URL
# deceptive (>= --fail-on severity), unparseable/invalid, or unreadable.
#
# Wiring (settings.json):
#   {
#     "hooks": {
#       "PreToolUse": [
#         { "matcher": "WebFetch",
#           "hooks": [ { "type": "command",
#                        "command": "/absolute/path/to/claude-code-hook.sh" } ] }
#       ]
#     }
#   }
#
# Contract (PRD §6.1, review finding H1) — why this is the shape it is:
#   * Hook input is JSON on stdin, NOT env vars: $CLAUDE_TOOL_INPUT_URL does not
#     exist. The URL is read with `jq -r '.tool_input.url'`.
#   * Blocking requires EXIT CODE 2 (its stderr is fed back to Claude). Exit 1 is
#     NON-blocking — a block verdict that exits 1 would let the fetch proceed.
#   * `set -uo pipefail`, NOT `-e`: a jq/linklint crash must land on our explicit
#     `exit 2`, never bubble up as a non-blocking exit 1 (= fail open).
#   * The verdict is delegated to the CLI's own exit code. `linklint check`
#     exits 0 only when the URL is below --fail-on AND not invalid; --fail-on
#     already treats `invalid` (e.g. file:///etc/passwd) as a failure unless
#     --allow-invalid. We never re-derive the verdict from `severity` — an
#     `invalid` result has `severity: null`, so a severity-only gate fails OPEN.
#   * The hook sees only the ORIGINAL URL. WebFetch's own redirect-following
#     happens later, inside tool execution — out of this hook's reach.
set -uo pipefail

# Severity threshold. Override via env when wiring the hook if you want a
# stricter/looser gate; default matches the CLI default.
FAIL_ON="${LINKLINT_FAIL_ON:-high}"

# Agent mode. This hook IS the agent context — the URL is about to be fed to an
# LLM via WebFetch — so the agent-gated detectors (prompt-injection, SSRF
# cloud-metadata escalation, API-endpoint impersonation, credential-harvesting,
# data-exfiltration) are ON by default. Set LINKLINT_AGENT=0 to disable.
# Note: prompt_injection_url is weight 0.5 (severity `medium`); to make it BLOCK,
# pair this with LINKLINT_FAIL_ON=medium.
# NOTE: every expansion of AGENT_FLAG below uses the `${a[@]+"${a[@]}"}` idiom.
# In bash 3.2 — still /bin/bash on macOS — expanding an EMPTY array as bare
# "${AGENT_FLAG[@]}" under `set -u` is an unbound-variable error: the script
# dies with 127 before reaching any `exit 2`, i.e. fails OPEN on exactly the
# LINKLINT_AGENT=0 path. bash 5 does not reproduce it, so CI alone cannot catch
# this.
if [[ "${LINKLINT_AGENT:-1}" == "0" ]]; then
  AGENT_FLAG=()
else
  AGENT_FLAG=(--agent)
fi

input=$(cat)

# Unreadable input or no jq -> fail closed.
url=$(printf '%s' "$input" | jq -r '.tool_input.url // empty') \
  || { echo "linklint: unreadable hook input — blocking" >&2; exit 2; }

# No URL in the tool input -> fail closed.
[[ -z "$url" ]] && { echo "linklint: no URL in tool input — blocking" >&2; exit 2; }

# An option-shaped "URL" -> fail closed. No URL scheme starts with '-', but
# `linklint check --version` / `--help` / `--allow-invalid` all exit 0, so
# handing such a string to the CLI as a positional would ALLOW the fetch.
[[ "$url" == -* ]] && { echo "linklint: option-shaped URL in tool input — blocking" >&2; exit 2; }

# Any non-zero exit — threshold hit, invalid input, missing binary (127),
# internal error — falls into the deny branch.
if ! linklint check "$url" --fail-on "$FAIL_ON" ${AGENT_FLAG[@]+"${AGENT_FLAG[@]}"} >/dev/null 2>&1; then
  echo "linklint blocked: $url (>= $FAIL_ON, invalid, or check failed)" >&2
  exit 2
fi

exit 0
