#!/usr/bin/env bash
set -euo pipefail

# Isolated replacement for intelmdssim/isisii43-hd. The upstream wrapper
# hard-links its library images to drivea/i/j; this helper makes independent
# working files before launching the same simulator binary.
sim_dir=${RUNES_INTELMDSSIM_DIR:-/home/john/pli/cpm/z80pack/intelmdssim}
cd "$sim_dir"

declare -A expected=(
  [disks/library/isis-ii-43.dsk]=a335f169dd44de5d860911b1c3ae5b1f2804a686d78074139b1838840def27db
  [disks/library/hd-isis-sys.dsk]=c3ee6937b302ccfc9fa9a66a928d9365dab0cf66fc4178b71dc482acf876492a
  [disks/library/hd-isis-usr.dsk]=da1d122e65cd1a6701668b51dd8941bca762eb33a8828c82b408157242dcaa88
)

for image in "${!expected[@]}"; do
  [[ -f "$image" ]] || { printf 'Missing canonical image: %s\n' "$image" >&2; exit 1; }
  actual=$(sha256sum -- "$image" | cut -d ' ' -f 1)
  [[ "$actual" == "${expected[$image]}" ]] || {
    printf 'Canonical image hash mismatch: %s\nexpected %s\nactual   %s\n' \
      "$image" "${expected[$image]}" "$actual" >&2
    exit 1
  }
done

make_working_copy() {
  local source=$1 destination=$2
  if ! cp --reflink=auto -- "$source" "$destination"; then
    # Some cp/filesystem combinations may reject reflink=auto. Retry as an
    # ordinary byte copy after removing only the failed destination.
    if [[ -e "$destination" ]]; then unlink "$destination"; fi
    cp -- "$source" "$destination"
  fi
  chmod u+w -- "$destination"
  [[ ! "$source" -ef "$destination" ]] || {
    printf 'Working image is not independent of source: %s\n' "$destination" >&2
    exit 1
  }
  local source_hash destination_hash
  source_hash=$(sha256sum -- "$source" | cut -d ' ' -f 1)
  destination_hash=$(sha256sum -- "$destination" | cut -d ' ' -f 1)
  [[ "$source_hash" == "$destination_hash" ]] || {
    printf 'Working copy hash mismatch: %s\n' "$destination" >&2
    exit 1
  }
}

# These are the only pre-launch removals. They remove prior disposable drive
# images, never anything under disks/library/.
for drive in disks/drivea.dsk disks/drivei.dsk disks/drivej.dsk; do
  if [[ -e "$drive" ]]; then unlink "$drive"; fi
done

make_working_copy disks/library/isis-ii-43.dsk disks/drivea.dsk
make_working_copy disks/library/hd-isis-sys.dsk disks/drivei.dsk
make_working_copy disks/library/hd-isis-usr.dsk disks/drivej.dsk

exec ./intelmdssim "$@"
