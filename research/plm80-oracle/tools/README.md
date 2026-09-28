# Non-destructive ISIS-II oracle disks

`run-isisii43-isolated.sh` is the safe launcher for the local ISIS-II V4.3
oracle. Do **not** use `isisii43-hd`: the upstream wrapper removes
`drivea/i/j.dsk` and then hard-links them to `disks/library/`, so any guest
write modifies the canonical library images.

The launcher verifies all three canonical SHA-256 hashes before changing
working drives, removes only old `disks/drivea.dsk`, `drivei.dsk`, and
`drivej.dsk`, creates independent copies (reflink when available, ordinary
copy otherwise), makes the copies writable, then runs `./intelmdssim` with
the caller's arguments. The canonical source images are read-only. The
default simulator directory is `/home/john/pli/cpm/z80pack/intelmdssim`; set
`RUNES_INTELMDSSIM_DIR` only if using another compatible checkout.

## Canonical baseline

These are the earliest reliable hashes recorded in the PL/M fixture manifests
and independently match the corresponding blobs in the z80pack repository's
committed `HEAD`:

| Canonical source image | Bytes | SHA-256 |
| --- | ---: | --- |
| `disks/library/isis-ii-43.dsk` | 512512 | `a335f169dd44de5d860911b1c3ae5b1f2804a686d78074139b1838840def27db` |
| `disks/library/hd-isis-sys.dsk` | 3686400 | `c3ee6937b302ccfc9fa9a66a928d9365dab0cf66fc4178b71dc482acf876492a` |
| `disks/library/hd-isis-usr.dsk` | 3686400 | `da1d122e65cd1a6701668b51dd8941bca762eb33a8828c82b408157242dcaa88` |

Before restoring the baseline in this task, the three then-current images were
archived outside the repository at
`/var/tmp/plm80-post-experiments-20260928-duSXna/`. Its `SHA256SUMS` records
the post-experiment hashes. The two changed hard-disk images were restored
from the documented z80pack Git baseline; the ISIS system image already
matched. No disk image is stored in this repository.

## Launch and console handshake

From the simulator directory, launch:

```sh
/home/john/pli/lab/research/plm80-oracle/tools/run-isisii43-isolated.sh -F
```

In another terminal use the established Telnet console:

```sh
/usr/bin/telnet 127.0.0.1 4010
```

The initial connection is silent. Send exactly one ASCII SPACE (`0x20`), with
no CR or LF, and wait for:

```text
ISIS-II, V4.3
-
```

Then enter ISIS-II commands. Keep the Telnet connection open while the
simulator is running; disconnecting it can cause the MDS monitor to fail.

## Cleanup and relaunch

Stop the simulator before cleaning up. The three `drive*.dsk` files are
disposable and may contain guest changes; inspect or hash them first if those
changes are useful. To discard them, remove only those three working files.
The next helper launch also replaces them with fresh copies after verifying
the canonical hashes. Never copy a working drive back into `disks/library/`.
The helper deliberately leaves working images after simulator exit so a run
can be inspected; cleanup is explicit rather than automatic.

## Verification record

The baseline was checked before launch and again after a guest-side file write
using `COPY :CI: TO :F0:ISOTST.TXT` followed by the text
`DISPOSABLE IMAGE WRITE CHECK` and Ctrl-Z. ISIS-II reported the copy
successful. After simulator exit, all three canonical hashes remained equal
to the table above and all canonical images remained mode `0444`, link count
1. The disposable `drivei.dsk` changed to
`dd778f3d97789a0ed2f38fe24daeab10ebecc2a631c7430bb873ba97d0434fff`; the
disposable `drivea.dsk` and `drivej.dsk` retained their source hashes. All
working images had distinct inodes from their sources. Thus this guest file
write was directed to the disposable `drivei.dsk`, not a canonical image.

The snapshot archive was verified with `sha256sum -c`. Its pre-restore hashes
were:

| Archived post-experiment image | SHA-256 |
| --- | --- |
| `isis-ii-43.dsk` | `a335f169dd44de5d860911b1c3ae5b1f2804a686d78074139b1838840def27db` |
| `hd-isis-sys.dsk` | `252ad184c153430dba961d864545ebbbb0b34eba0e6b2842918fe6e04ee6d98c` |
| `hd-isis-usr.dsk` | `bd38985e97b29a1edf2011b83f777c210135fd095c4cba751921993ac167f158` |
