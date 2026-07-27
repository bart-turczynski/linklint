#!/usr/bin/env bash
# linklint — offline backup: git history + the fp tracker, verified.
#
# WHY THIS EXISTS
#
# GitHub push is blocked (403, account suspended), so `main` lives on this
# machine and nowhere else. Two things have to survive, and only one of them is
# in git:
#
#   1. Git history — captured by `git bundle --all`.
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
# Usage:
#   ./tools/backup.sh            # write to the default directory
#   ./tools/backup.sh <dir>      # write somewhere else (e.g. an external volume)
#
# A copy on the SAME filesystem protects against a bad git operation, not
# against losing the disk. Pass an off-volume directory periodically.
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

# Report where this lives relative to the working copy, since a same-volume
# copy is not protection against losing the disk.
repo_vol="$(df -P "$repo_root" | awk 'NR==2{print $1}')"
dest_vol="$(df -P "$dest_dir" | awk 'NR==2{print $1}')"
if [[ "$repo_vol" == "$dest_vol" ]]; then
  echo "backup: NOTE — $dest_dir is on the same volume ($repo_vol) as the repo."
  echo "backup:        Run './tools/backup.sh /Volumes/<external>/linklint' as well."
fi
