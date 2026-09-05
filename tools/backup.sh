#!/usr/bin/env bash
# linklint — offline backup: git history + the fp tracker, verified.
#
# WHY THIS EXISTS
#
# `main` is pushed to GitLab, so git history has an off-machine copy. The
# tracker does not: two things have to survive, and only one of them is in git
# — and only one of them is on any remote:
#
#   1. Git history — captured by `git bundle --all`. Also on GitLab, so this
#      half is belt-and-braces: it protects against a bad local git operation
#      or a bad merge, not against losing the remote.
#   2. `.fp/` — the issue tracker. It is GITIGNORED, so no bundle has ever
#      contained it. It holds every issue, decision record and closing comment
#      the repo's process depends on (LINK-wgsbhovi and LINK-nwqrqjdc were both
#      found by reading it). Losing it loses the reasoning behind the code
#      while leaving the code intact.
#
# It also verifies the bundle after writing it. An unverified backup is a
# guess — the same fail-closed doctrine the codebase applies to inspection
# results (docs/architecture.md 1.1).
#
# SCOPE, DECIDED: same-volume only. `~/Projects/linklint-backups` sits on the
# same filesystem as the working copy, so these archives protect against a bad
# git operation, a bad merge, or a deleted `.fp/` — NOT against losing the
# disk. That residual is accepted deliberately; do not re-propose an
# off-volume or remote destination. The `<dir>` argument stays for writing an
# extra copy elsewhere on this volume, not as a hint to leave it.
#
# Usage:
#   ./tools/backup.sh            # write to the default directory
#   ./tools/backup.sh <dir>      # write to another directory on this volume
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest_dir="${1:-$HOME/Projects/linklint-backups}"
stamp="$(date +%Y%m%d-%H%M)"

mkdir -p "$dest_dir"
cd "$repo_root"

bundle="$dest_dir/linklint-$stamp.bundle"
git bundle create "$bundle" --all >/dev/null 2>&1
git bundle verify "$bundle" >/dev/null 2>&1 || {
  echo "backup: FAILED — bundle does not verify, removing $bundle" >&2
  rm -f "$bundle"
  exit 1
}
echo "backup: git    $bundle ($(du -h "$bundle" | cut -f1), verified)"

if [[ -d "$repo_root/.fp" ]]; then
  tracker="$dest_dir/linklint-fp-$stamp.tar.gz"
  tar -czf "$tracker" -C "$repo_root" .fp
  tar -tzf "$tracker" >/dev/null || {
    echo "backup: FAILED — tracker archive does not read back" >&2
    rm -f "$tracker"
    exit 1
  }
  echo "backup: fp     $tracker ($(du -h "$tracker" | cut -f1), verified)"
else
  echo "backup: WARNING — no .fp/ directory; tracker state was NOT backed up" >&2
fi

echo "backup: done   $(ls -1 "$dest_dir"/*.bundle 2>/dev/null | wc -l | tr -d ' ') bundle(s) in $dest_dir"
