# Provenance Explorer frontend

This directory is the pinned browser application for the offline static report
bundle. It uses Perspective for grouped/virtualized metadata tables, G6 for the
bounded provenance graph, and a small custom canvas for execution/image-space
heatmaps.

```sh
npm ci
npm run build
npm run bundle -- /path/to/provenance-report.json /path/to/output-bundle
# or, for path-control reports:
npm run bundle -- /path/to/provenance-report.json /path/to/provenance-control-report.json /path/to/output-bundle
# add routine/block structure reports to enable the primary Structure view:
npm run bundle -- /path/to/provenance-report.json /path/to/provenance-control-report.json /path/to/output-bundle \
  --structure /path/to/dynamic-structure.json --blocks /path/to/dynamic-blocks.json
npm run smoke -- /path/to/output-bundle
```

The output directory must be empty (use a fresh directory for each build).
The Structure view consumes the existing `RUNES_DYNAMIC_STRUCTURE 1` and
`RUNES_DYNAMIC_BLOCKS 1` artifacts; omit both options for a low-level-only
bundle. It presents the routine first-discovery list and unique narrative
transitions in Perspective, then expands the selected routine into its
observed blocks and formatted instructions. Repeated edges point to existing
routine IDs, and recursion remains a badge rather than expanded calls.

Serve the output directory locally (e.g. `python3 -m http.server -d
/path/to/output-bundle`). The report and WASM/runtime assets are local; no CDN
or external connection is used. `npm run smoke` exercises the generated report
in local Chrome after a compatible `provenance-report.json` is present in
`dist/`.
