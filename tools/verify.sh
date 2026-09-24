#!/usr/bin/env bash
#
# The verify gate, run locally across the supported Node matrix.
#
# This is the local half of the CI split (LINK-yrbwwyrj). GitLab's shared
# runners are metered, so remote pipelines are reserved for the changes that
# genuinely need an independent machine (see .gitlab-ci.yml) and every ordinary
# push is gated here instead, for free.
#
# It runs the same three things the remote job runs, in the same order:
#
#   1. `pnpm install --frozen-lockfile` — a warm node_modules hides lockfile
#      drift. This is the only step here that a bare `pnpm check` does not do,
#      and it is the reason this script exists rather than the hook calling
#      `pnpm check` directly.
#   2. `pnpm check` on the default Node.
#   3. `pnpm check` on every OTHER Node in the matrix that is installed.
#
# Usage:
#   tools/verify.sh              # full local gate (what pre-push runs)
#   tools/verify.sh --no-install # skip the frozen-lockfile install
#
set -euo pipefail

cd "$(dirname "$0")/.."

# The matrix, as major versions. 24 is the floor declared by `engines.node` in
# every package and pinned in `.node-version`; 26 is the current release line,
# and `engines` has no upper bound, so users install on it. Keep in sync with
# the `NODE_MAJOR` matrix in .gitlab-ci.yml.
MATRIX=(24 26)

run_install=1
for arg in "$@"; do
  case "$arg" in
    --no-install) run_install=0 ;;
    *) echo "verify: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Resolve a `node` binary for major version $1, or print nothing if unavailable.
#
# Checked in order: the running node, then Homebrew's keg-only `node@<major>`
# prefix (the packaging that does NOT put itself on PATH, so it has to be found
# by path), then a `node<major>` on PATH. Deliberately does not shell out to a
# version manager: none is installed here, and a shim that silently resolves to
# the wrong major would defeat the point of the matrix.
node_for_major() {
  local major="$1" candidate

  if [ "$(node -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')" = "$major" ]; then
    command -v node
    return
  fi

  for candidate in \
    "$(brew --prefix 2>/dev/null || echo /opt/homebrew)/opt/node@${major}/bin/node" \
    "/usr/local/opt/node@${major}/bin/node"
  do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done

  if command -v "node${major}" >/dev/null 2>&1; then
    command -v "node${major}"
  fi
}

if [ "$run_install" -eq 1 ]; then
  echo "verify: pnpm install --frozen-lockfile"
  pnpm install --frozen-lockfile
fi

# Majors that ran, and majors we could not find a runtime for. Reported
# together at the end: a matrix leg that did not run is a gap in the gate, and
# a gap that prints nothing is how a fail-open path starts.
ran=()
missing=()

for major in "${MATRIX[@]}"; do
  node_bin="$(node_for_major "$major")"
  if [ -z "$node_bin" ]; then
    missing+=("$major")
    continue
  fi

  actual="$("$node_bin" -v)"
  echo
  echo "verify: pnpm check on node ${actual} (${node_bin})"
  # Put the chosen runtime first on PATH so pnpm, vitest and cucumber all spawn
  # under it. `pnpm` itself is a node script, so prepending the directory is
  # what actually switches the version the suite runs on.
  PATH="$(dirname "$node_bin"):$PATH" pnpm check
  ran+=("$major")
done

echo
if [ ${#ran[@]} -gt 0 ]; then
  echo "verify: PASSED on node ${ran[*]}"
fi

if [ ${#missing[@]} -gt 0 ]; then
  if [ ${#ran[@]} -eq 0 ]; then
    echo "verify: FAILED — no Node runtime found for any of: ${MATRIX[*]}" >&2
    exit 1
  fi
  echo
  echo "verify: NOT RUN on node ${missing[*]} — no runtime installed for it." >&2
  for major in "${missing[@]}"; do
    echo "verify:   install it with: brew install node@${major}" >&2
  done
  echo "verify: this leg is covered remotely instead — .gitlab-ci.yml runs the" >&2
  echo "verify:   full matrix on dependency and toolchain changes, which is the" >&2
  echo "verify:   change class that can break cross-version parity. Ordinary" >&2
  echo "verify:   pushes are NOT covered on the missing major until you install it." >&2
fi
