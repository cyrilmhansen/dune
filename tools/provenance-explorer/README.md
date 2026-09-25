# Provenance Explorer frontend

This directory is the pinned browser application for the offline static report
bundle. It uses Perspective for grouped/virtualized metadata tables, G6 for the
bounded provenance graph, and a small custom canvas for execution/image-space
heatmaps.

```sh
npm ci
npm run build
npm run bundle -- /path/to/provenance-report.json /path/to/output-bundle
```

The output directory must be empty (use a fresh directory for each build).

Serve the output directory locally (e.g. `python3 -m http.server -d
/path/to/output-bundle`). The report and WASM/runtime assets are local; no CDN
or external connection is used. `npm run smoke` exercises the generated report
in local Chrome after a compatible `provenance-report.json` is present in
`dist/`.
