#!/usr/bin/env bash
# linklint — shell-alias installer (fail-closed).
#
# safe-chain-style guard: wrap URL-fetching CLIs (curl, wget) in a shell
# function that inspects each URL argument with `linklint check` FIRST and
# ABORTS the fetch on any non-zero exit — threshold hit OR invalid input. Same
# fail-closed contract as the Claude Code hook (PRD §6.1/§6.2): file:///… and
# unparseable inputs are blocked, not just high/critical.
#
# Usage:
#   ./install-aliases.sh            # append the guard to your shell rc
#   ./install-aliases.sh --print    # print the guard to stdout (review first)
#
# This wraps INTERACTIVE shell use. It is intentionally NOT a system-wide
# interception (no PATH shims, no LD_PRELOAD) — those are a documented non-goal
# (PRD §6.4). Re-run after upgrading linklint is not needed; the guard calls the
# CLI by name at runtime.
set -uo pipefail

FAIL_ON="${LINKLINT_FAIL_ON:-high}"

# The threshold is baked into a LONG-LIVED rc file, so it is emitted as a
# single-quoted literal rather than bare. Note WHICH expansion this fixes: the
# install-time one below is already safe, because a `<<EOF` heredoc body neither
# word-splits nor globs. The hazard is the TEXT that heredoc produces — the
# user's own shell parses it later, and that shell does both. Bare, a value with
# whitespace injects a second argument (`--fail-on high --allow-invalid`), a
# glob re-resolves against whatever directory the user is standing in, a
# whitespace-only value leaves `--fail-on` with no argument, and `$(…)` runs on
# every new shell.
#
# Single quotes, not double: the value is fixed at install time, which is the
# semantics the guard already documents, and single quotes are inert in POSIX sh
# too — the `*)` branch below can route this into ~/.profile. An embedded quote
# is escaped the standard '\'' way; the substitution must be assigned bare,
# since spelling it inside double quotes changes how the replacement is parsed.
FAIL_ON_ESC=${FAIL_ON//\'/\'\\\'\'}
# Newlines are folded last. Inside the quotes they would still be one argument,
# but the same value is interpolated into a `#` comment below, where a newline
# ends the comment and turns the remainder into an executable rc line.
FAIL_ON_LIT="'${FAIL_ON_ESC//$'\n'/ }'"

read -r -d '' GUARD <<EOF || true
# >>> linklint guard >>>
# Inspect URL arguments with linklint before curl/wget run. Fail-closed: any
# non-zero linklint exit (deceptive >= ${FAIL_ON_LIT}, invalid, or check error)
# aborts the fetch. Remove this block to uninstall.
_linklint_guard() {
  local _tool="\$1"; shift
  local _arg
  for _arg in "\$@"; do
    case "\$_arg" in
      http://*|https://*|ftp://*|file://*|*://*)
        if ! command linklint check "\$_arg" --fail-on ${FAIL_ON_LIT} >/dev/null 2>&1; then
          printf 'linklint blocked %s: %s\\n' "\$_tool" "\$_arg" >&2
          return 1
        fi
        ;;
    esac
  done
  command "\$_tool" "\$@"
}
curl() { _linklint_guard curl "\$@"; }
wget() { _linklint_guard wget "\$@"; }
# <<< linklint guard <<<
EOF

if [[ "${1:-}" == "--print" ]]; then
  printf '%s\n' "$GUARD"
  exit 0
fi

# linklint must be installed for the guard to be meaningful.
if ! command -v linklint >/dev/null 2>&1; then
  echo "install-aliases: 'linklint' not found on PATH — install it first (npm i -g @linklint/cli)." >&2
  exit 1
fi

# Pick the rc file for the current shell.
case "$(basename "${SHELL:-}")" in
  zsh)  rc="${ZDOTDIR:-$HOME}/.zshrc" ;;
  bash) rc="$HOME/.bashrc" ;;
  *)    rc="${HOME}/.profile" ;;
esac

if [[ -f "$rc" ]] && grep -q '>>> linklint guard >>>' "$rc"; then
  echo "install-aliases: guard already present in $rc — nothing to do."
  exit 0
fi

# A failed append must not report success: an unwritable rc would otherwise
# leave the caller believing curl/wget are guarded when nothing was installed.
printf '\n%s\n' "$GUARD" >> "$rc" \
  || { echo "install-aliases: could not write $rc — guard NOT installed." >&2; exit 1; }
echo "install-aliases: appended linklint guard to $rc"
echo "Open a new shell or run: source \"$rc\""
