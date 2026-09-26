#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 TOOLCHAIN_DIR" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "$0")/.." && pwd)
toolchain=$(cd "$1" && pwd)
out_dir=$(mktemp -d /tmp/atlas-pli80-corpus-XXXXXX)
trap 'rm -rf "$out_dir"' EXIT

for source in "$repo_root"/examples/pli80/*.PLI; do
  module=$(basename "$source" .PLI)
  dune exec --root "$repo_root" pli80-analyze -- \
    --toolchain "$toolchain" \
    --source "$source" \
    --output-dir "$out_dir/$module" \
    --analysis run \
    --report summary
done
