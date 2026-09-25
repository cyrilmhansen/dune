import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const port = 4179;
const server = spawn("npm", ["run", "preview", "--", "--host", "127.0.0.1", "--port", String(port), "--strictPort"], {stdio:"ignore"});
let browser;
try {
  let ready=false;
  for(let i=0;i<80;i++){try{const r=await fetch(`http://127.0.0.1:${port}/provenance-explorer.html`);if(r.ok){ready=true;break}}catch{} await delay(100)}
  if(!ready)throw new Error("Vite preview did not start");
  browser=await chromium.launch({headless:true,executablePath:"/usr/bin/google-chrome-stable",args:["--no-sandbox"]});
  const page=await browser.newPage();const errors=[],requests=[];page.on("pageerror",e=>errors.push(e.message));page.on("console",m=>{if(m.type()==="error")errors.push(m.text())});page.on("request",r=>requests.push(r.url()));
  page.on("response",r=>{if(r.status()>=400)errors.push(`${r.status()} ${r.url()}`)});
  await page.goto(`http://127.0.0.1:${port}/provenance-explorer.html`);
  try{await page.waitForFunction(()=>window.__explorerReady===true,{timeout:20000})}catch(e){throw new Error(`explorer init timeout; errors=${errors.join(" | ")}; ${e.message}`)}
  const before=await page.evaluate(()=>({rows:window.__perspectiveRows,g6:window.__g6Counts,sink:window.__selectedSink,images:window.__reportLoaded.images}));
  const outputBytes=await page.evaluate(()=>window.__reportLoaded.outputBytes);
  if(before.sink!==0||before.images<1||before.g6.nodes>250||before.g6.combos<2||before.rows["#output-table"]!==outputBytes)throw new Error(`unexpected initial view ${JSON.stringify(before)}`);
  if(!before.rows["#producers"]||!before.rows["#sources"]||!before.rows["#source-ranges"]||!before.rows["#operations"])throw new Error("Perspective views were not populated");
  const second=await page.evaluate(()=>window.__producerRows?.[0]);if(second){await page.evaluate(row=>document.querySelector("#producers").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),second);await page.waitForFunction(()=>document.querySelector("#producer-highlight").textContent.length>0);await page.evaluate(id=>window.__emitG6Producer(id),second.producer_id);}
  const interactions=[];
  for(const p of await page.locator("#sink option").evaluateAll(xs=>xs.map(x=>Number(x.value)))){await page.selectOption("#sink",String(p));await page.waitForFunction(offset=>window.__explorerReady&&window.__selectedSink===offset,p);const view=await page.evaluate(()=>({g6:window.__g6Counts,rows:window.__perspectiveRows}));if(view.g6.nodes>250)throw new Error("G6 received an oversized graph");interactions.push(`sink ${p}: ${view.g6.nodes} graph nodes/${view.g6.combos} combos; Perspective rows=${JSON.stringify(view.rows)}`);}
  const unprojected=await page.locator("#output-bytes .out-byte").nth(1);await unprojected.click();await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===1&&document.querySelector("#sink-meta").textContent.includes("projection not embedded"));if(await page.evaluate(()=>window.__perspectiveRows["#producers"])!==0)throw new Error("unprojected sink retained stale producer rows");interactions.push("unprojected output-byte metadata-only selection");
  await page.selectOption("#sink",String(before.sink));await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===0);
  const heatHashes={};for(const mode of ["execution","participation","producer","value","address","flag","source"]){await page.selectOption("#mode",mode);heatHashes[mode]=await page.locator("canvas.heatmap").evaluateAll(xs=>xs.map(x=>x.toDataURL()).join(""));interactions.push(`heatmap ${mode}`)}
  const roles=await page.evaluate(()=>window.__roleOverlayCounts);if(roles.value&&roles.address&&roles.flag&&new Set([heatHashes.value,heatHashes.address,heatHashes.flag]).size<3)throw new Error("role-specific heatmaps did not differ");
  if(await page.locator("#source-summary img").count())throw new Error("source label was interpreted as HTML");
  const config=await page.evaluate(()=>window.__tableGroups);if(JSON.stringify(config["#producers"])!==JSON.stringify(["image","operation_kind"]))throw new Error("producer grouping configuration missing");
  if(requests.some(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`)))throw new Error(`non-local asset request: ${requests.find(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`))}`);
  if(errors.length)throw new Error(errors.join("; "));
  console.log(JSON.stringify({loaded:before,tableGroups:config,roles,interactions}));
} finally { if(browser)await browser.close();server.kill("SIGTERM"); }
