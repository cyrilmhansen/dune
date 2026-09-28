# Headless ISIS-II PL/M-80 oracle procedure

Use the established z80pack Intellec MDS-800 setup; do not create or relink
the disk images manually.

Terminal 1:

```sh
cd /home/john/pli/cpm/z80pack/intelmdssim
./isisii43-hd -F
```

The script selects the prepared ISIS-II V4.3 disk set and starts the simulator
headlessly. Keep it running in the foreground.

Terminal 2:

```sh
/usr/bin/telnet 127.0.0.1 4010
```

The Telnet connection itself, and a carriage return by itself, may produce no
ISIS-II prompt. Send exactly one ASCII space byte (`0x20`) with no CR or LF.
The verified response is:

```text
ISIS-II, V4.3
-
```

Only after this prompt appears should ISIS-II commands be submitted. Keep the
console connection open while the simulator is in use; disconnecting it can
cause the MDS monitor to stop with a fatal I/O error. This procedure was
verified with the local simulator's Telnet console; do not substitute a raw
TCP client without separately validating its Telnet behavior.
