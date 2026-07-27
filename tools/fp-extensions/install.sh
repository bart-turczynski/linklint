#!/usr/bin/env bash
# linklint — install this repo's fp extensions into .fp/extensions/.
#
# `.fp/` is gitignored (it holds local tracker state), so an extension authored
# in place would be lost on every fresh clone — and the guards here are exactly
# the kind of thing that must survive a re-clone. Source of truth therefore
# lives in tracked `tools/fp-extensions/`, symlinked into `.fp/extensions/` so
# edits take effect with no copy step and no drift.
#
# Usage:
#   ./tools/fp-extensions/install.sh
#
# Verify with `fp guide`, which prints the loaded extension list.
set -euo pipefail

src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$src_dir/../.." && pwd)"
dest_dir="$repo_root/.fp/extensions"

if [[ ! -d "$repo_root/.fp" ]]; then
  echo "install: no .fp/ directory — run 'fp init' in this repo first." >&2
  exit 1
fi

mkdir -p "$dest_dir"

for ext in "$src_dir"/*/; do
  name="$(basename "$ext")"
  # Relative link, so the symlink survives the repo being moved or re-cloned
  # to a different path.
  ln -sfn "../../tools/fp-extensions/$name" "$dest_dir/$name"
  echo "install: linked $name"
done

echo "install: done — run 'fp guide' to confirm the extensions loaded."
