#!/usr/bin/env bash
# linklint — shell-alias installer (fail-closed).
#
# safe-chain-style guard: wrap URL-fetching CLIs (curl, wget) in a shell
# function that inspects each FETCH TARGET with `linklint check` FIRST and
# ABORTS the fetch on any non-zero exit — threshold hit OR invalid input. Same
# fail-closed contract as the Claude Code hook (PRD §6.1/§6.2): file:///… and
# unparseable inputs are blocked, not just high/critical.
#
# A target is an argument that BEGINS with a scheme and is not sitting in a
# value-taking option's value slot; see the emitted comment below for why an
# option value is excluded and which options are deliberately not excluded.
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
# Inspect the FETCH TARGETS of curl/wget with linklint before the tool runs.
# Fail-closed: any non-zero linklint exit (deceptive >= ${FAIL_ON_LIT}, invalid,
# or check error) aborts the fetch. Remove this block to uninstall.
#
# A target is an argument that BEGINS with a scheme and is not sitting in an
# option's value slot. An option VALUE — a header, a request body, a referer —
# is not a target and is not judged: nothing is fetched from it, so a verdict
# taken from one would be applied to a different network operation entirely.
#
# POSIX sh, deliberately: the installer's \`*)\` branch can route this text into
# ~/.profile, which ksh reads, and ksh93 has no \`local\`. The names are prefixed
# and cleared before the tool runs so nothing leaks into the interactive shell.
_linklint_guard() {
  _linklint_tool=\$1
  shift
  _linklint_skip=0
  for _linklint_arg in "\$@"; do
    if [ "\$_linklint_skip" = 1 ]; then
      _linklint_skip=0
      continue
    fi
    # Options that take a SEPARATE value argument. Skipping that argument is
    # argv parsing rather than a guess: it is the option's value, so it cannot
    # be a fetch target. Absent on purpose, so their values stay inspected:
    # curl's \`--url\`, \`-x\`/\`--proxy\`/\`--preproxy\`, and wget's \`-B\` — each
    # names a network endpoint. The \`--opt=value\` spelling needs no entry; it
    # does not begin with a scheme. An option this list does not know about
    # falls through to the scheme test below, which is the old behavior.
    if [ "\$_linklint_tool" = curl ]; then
      case "\$_linklint_arg" in
        -A|-b|-c|-C|-d|-D|-e|-E|-F|-H|-K|-m|-o|-P|-Q|-r|-t|-T|-u|-U|-w|-X|-y|-Y|-z) _linklint_skip=1; continue ;;
        --data|--data-ascii|--data-binary|--data-raw|--data-urlencode|--json) _linklint_skip=1; continue ;;
        --form|--form-string|--header|--proxy-header|--referer|--user-agent|--write-out) _linklint_skip=1; continue ;;
        --url=*) _linklint_arg=\${_linklint_arg#--url=} ;;
      esac
    elif [ "\$_linklint_tool" = wget ]; then
      case "\$_linklint_arg" in
        -A|-a|-C|-D|-e|-I|-i|-l|-o|-O|-P|-Q|-R|-t|-T|-U|-w|-X) _linklint_skip=1; continue ;;
        --body-data|--body-file|--header|--post-data|--post-file) _linklint_skip=1; continue ;;
        --referer|--user-agent|--warc-header) _linklint_skip=1; continue ;;
      esac
    fi
    # BEGINS with a scheme, not merely carries \`://\` somewhere. A header value
    # ('Origin: https://…'), a form field ('url=https://…') and a JSON body all
    # contain \`://\` and are none of them URLs; \`linklint check\` rightly calls
    # them unparseable, and under a fail-closed guard that killed the fetch.
    case "\$_linklint_arg" in
      *://*) ;;
      *) continue ;;
    esac
    case "\${_linklint_arg%%://*}" in
      "" | [!A-Za-z]* | *[!A-Za-z0-9.+-]*) continue ;;
    esac
    command linklint check "\$_linklint_arg" --fail-on ${FAIL_ON_LIT} >/dev/null 2>&1 && continue
    _linklint_rc=\$?
    # Name the REAL cause. \`check\` exits 1 for "deceptive" and for "does not
    # parse" alike, so re-run with --allow-invalid to tell them apart; a bare
    # "linklint blocked curl: <string>" reads as an accusation against a host
    # that may not have been judged at all.
    if [ "\$_linklint_rc" -ne 1 ]; then
      _linklint_why="linklint could not check it (exit \$_linklint_rc)"
    elif command linklint check "\$_linklint_arg" --fail-on ${FAIL_ON_LIT} --allow-invalid >/dev/null 2>&1; then
      _linklint_why="not a parseable URL, so not judged — do not assume safe"
    else
      _linklint_why='deceptive at or above '${FAIL_ON_LIT}
    fi
    # Emitting this line is not a free choice: the third field is the user's own
    # argument, the hostile string this guard exists to show ACCURATELY, so the
    # emitter must render arbitrary bytes verbatim. \`printf\` does. \`echo\` does
    # not — dash's and mksh's expand backslash escapes and swallow a leading
    # \`-n\`, which would let a crafted URL rewrite the message that exposes it.
    #
    # So the fallback is \`print -r --\`, which is byte-faithful, and the shells
    # that carry no \`printf\` BUILTIN are exactly the ones that have it: mksh
    # (pdksh), ksh93 and zsh. bash and dash always resolve printf internally, so
    # the else branch is unreachable there. A shell with neither loses the
    # explanation and still refuses the fetch, which is this guard's own failure
    # direction (LINK-jtirhajv).
    if command -v printf >/dev/null 2>&1; then
      printf 'linklint blocked %s (%s): %s\\n' "\$_linklint_tool" "\$_linklint_why" "\$_linklint_arg" >&2
    else
      print -r -- "linklint blocked \$_linklint_tool (\$_linklint_why): \$_linklint_arg" >&2
    fi
    unset _linklint_tool _linklint_arg _linklint_skip _linklint_rc _linklint_why
    return 1
  done
  set -- "\$_linklint_tool" "\$@"
  unset _linklint_tool _linklint_arg _linklint_skip _linklint_rc _linklint_why
  command "\$@"
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
