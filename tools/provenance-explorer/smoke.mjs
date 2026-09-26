import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import path from "node:path";

const port = 4179;
const bundleDir=path.resolve(process.argv[2]??"dist"), expectedInput=process.argv[3]??"";
const server = spawn("python3", ["-m","http.server",String(port),"--bind","127.0.0.1"], {cwd:bundleDir,stdio:"ignore"});
let browser;
try {
  let ready=false;
  for(let i=0;i<80;i++){try{const r=await fetch(`http://127.0.0.1:${port}/provenance-explorer.html`);if(r.ok){ready=true;break}}catch{} await delay(100)}
  if(!ready)throw new Error(`Static explorer bundle did not start from ${bundleDir}`);
  browser=await chromium.launch({headless:true,executablePath:"/usr/bin/google-chrome-stable",args:["--no-sandbox"]});
  const page=await browser.newPage();const errors=[],requests=[];page.on("pageerror",e=>errors.push(e.message));page.on("console",m=>{if(m.type()==="error")errors.push(m.text())});page.on("request",r=>requests.push(r.url()));
  page.on("response",r=>{if(r.status()>=400)errors.push(`${r.status()} ${r.url()}`)});
  await page.goto(`http://127.0.0.1:${port}/provenance-explorer.html`);
  try{await page.waitForFunction(()=>window.__explorerReady===true,{timeout:20000})}catch(e){throw new Error(`explorer init timeout; errors=${errors.join(" | ")}; ${e.message}`)}
  const before=await page.evaluate(()=>({rows:window.__perspectiveRows,g6:window.__g6Counts,sink:window.__selectedSink,images:window.__reportLoaded.images}));
  const outputBytes=await page.evaluate(()=>window.__reportLoaded.outputBytes);
  const interactions=[];
  if(before.sink!==0||before.images<1||before.g6.nodes>250||before.g6.combos<2||before.rows["#output-table"]!==outputBytes)throw new Error(`unexpected initial view ${JSON.stringify(before)}`);
  const structureReady=await page.evaluate(()=>window.__structureReady&&window.__activeView==="structure");
  if(structureReady){
    const structure=await page.evaluate(()=>({summary:window.__structureSummary,rows:window.__structureRows,routines:window.__structureRoutineRows,narrative:window.__structureNarrativeRows,firstBlocks:window.__selectedRoutineBlocks}));
    if(!structure.rows.routines||!structure.rows.narrative||!structure.routines.some(r=>r.id===0)||!structure.routines.some(r=>r.recursive))throw new Error(`structural report not populated: ${JSON.stringify(structure.summary)}`);
    if(!structure.routines[0].display.includes("PLI.COM"))throw new Error(`R000 is not the resident PLI.COM entry: ${structure.routines[0].display}`);
    const pairs=new Set(structure.narrative.map(x=>`${x.from_id}:${x.to_id}`));if(pairs.size!==structure.narrative.length)throw new Error("routine narrative duplicated a directed pair");
    const first=structure.routines[0];await page.evaluate(row=>document.querySelector("#structure-routines").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),first);
    await page.waitForFunction(()=>window.__selectedRoutine===0&&window.__selectedRoutineBlocks>0);
    const block=page.locator("#routine-blocks > details").first();await block.locator(":scope > summary").click();
    const code=page.locator("#routine-blocks > details details").first();await code.locator(":scope > summary").click();
    await page.waitForFunction(()=>document.querySelectorAll("#routine-blocks .instruction-list li").length>0);
    const narrativeRow=structure.narrative[0];await page.evaluate(row=>document.querySelector("#structure-narrative").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),narrativeRow);
    await page.waitForFunction(id=>window.__selectedRoutine===id,narrativeRow.to_id);
    await page.click("#tab-low-level");await page.waitForFunction(()=>window.__activeView==="low-level");
    interactions.push(`structure ${expectedInput||"report"}: ${structure.rows.routines} unique candidates, ${structure.rows.narrative} first-observation edges; selected R000, expanded ${structure.firstBlocks} blocks/instructions, navigated narrative to R${String(narrativeRow.to_id).padStart(3,"0")}; recursion badge present`);
  } else if(expectedInput) throw new Error("structural reports are required for this browser smoke test");
  if(!before.rows["#producers"]||!before.rows["#sources"]||!before.rows["#source-ranges"]||!before.rows["#operations"]||!before.rows["#control-decisions"])throw new Error("Perspective views were not populated");
  const second=await page.evaluate(()=>window.__producerRows?.[0]);if(second){await page.evaluate(row=>document.querySelector("#producers").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),second);await page.waitForFunction(()=>document.querySelector("#producer-highlight").textContent.length>0);await page.evaluate(id=>window.__emitG6Producer(id),second.producer_id);}
  async function verifyPathControl(){
    await page.selectOption("#analysis-mode","path");try{await page.waitForFunction(()=>window.__explorerReady&&window.__analysisMode==="path",{timeout:10000})}catch(e){throw new Error(`path view did not finish; errors=${errors.join(" | ")}; state=${JSON.stringify(await page.evaluate(()=>({ready:window.__explorerReady,mode:window.__analysisMode,graphs:window.__g6Counts,rows:window.__perspectiveRows})))}`)}await page.selectOption("#mode","control");
    const pathView=await page.evaluate(()=>({g6:window.__g6Counts,control:window.__roleOverlayCounts.control,rows:window.__perspectiveRows,groups:window.__tableGroups["#control-decisions"]}));
    if(pathView.g6.nodes>120||!pathView.control||!pathView.rows["#control-decisions"]||JSON.stringify(pathView.groups)!==JSON.stringify(["image","condition","taken"]))throw new Error(`path-control view missing: ${JSON.stringify(pathView)}`);
    const branch=await page.evaluate(()=>window.__controlRows.find(r=>window.__controlPreviewOrigins.some(n=>n.image===r.image&&n.offset===r.image_offset&&n.runtime_pc===r.runtime_pc)));
    if(!branch)throw new Error("no bounded branch location available for Perspective/G6 cross-selection");
    await page.evaluate(row=>document.querySelector("#control-decisions").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),branch);await page.waitForFunction(()=>document.querySelector("#producer-highlight").textContent.includes("Selected path decision"));
    const id=`producer:${branch.image}:${branch.image_offset}:${branch.runtime_pc}`;await page.evaluate(id=>window.__emitG6Producer(id),id);await page.waitForFunction(()=>document.querySelector("#producer-highlight").textContent.includes("Selected producer location"));
    interactions.push(`path-control mode: ${pathView.g6.nodes} bounded G6 nodes, ${pathView.control} decisions, grouped Perspective table with branch cross-selection`);
    await page.selectOption("#analysis-mode","combined");await page.waitForFunction(()=>window.__explorerReady&&window.__analysisMode==="combined");const combined=await page.evaluate(()=>window.__g6Counts);if(combined.nodes>250)throw new Error("combined mode rendered oversized G6 graph");interactions.push("combined data/path view");
    await page.selectOption("#analysis-mode","data");await page.waitForFunction(()=>window.__explorerReady&&window.__analysisMode==="data");
  }
  for(const p of await page.locator("#sink option").evaluateAll(xs=>xs.map(x=>Number(x.value)))){await page.selectOption("#sink",String(p));await page.waitForFunction(offset=>window.__explorerReady&&window.__selectedSink===offset,p);const view=await page.evaluate(()=>({g6:window.__g6Counts,rows:window.__perspectiveRows,pathRows:window.__pathRows}));if(view.g6.nodes>250||!view.pathRows)throw new Error("bounded data/path projection missing");interactions.push(`sink ${p}: ${view.g6.nodes} data graph nodes/${view.g6.combos} combos; path Perspective rows=${view.pathRows}; tables=${JSON.stringify(view.rows)}`);if(p===704)await verifyPathControl();}
  const unprojected=await page.locator("#output-bytes .out-byte").nth(1);await unprojected.click();await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===1&&document.querySelector("#sink-meta").textContent.includes("projection not embedded"));if(await page.evaluate(()=>window.__perspectiveRows["#producers"])!==0)throw new Error("unprojected sink retained stale producer rows");interactions.push("unprojected output-byte metadata-only selection");
  await page.selectOption("#sink",String(before.sink));await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===0);
  const heatHashes={};for(const mode of ["execution","participation","producer","value","address","flag","control","source"]){await page.selectOption("#mode",mode);heatHashes[mode]=await page.locator("canvas.heatmap").evaluateAll(xs=>xs.map(x=>x.toDataURL()).join(""));interactions.push(`heatmap ${mode}`)}
  const roles=await page.evaluate(()=>window.__roleOverlayCounts);if(roles.value&&roles.address&&roles.flag&&new Set([heatHashes.value,heatHashes.address,heatHashes.flag]).size<3)throw new Error("role-specific heatmaps did not differ");if(roles.control&&heatHashes.control===heatHashes.execution)throw new Error("control heatmap did not differ from execution heat");
  if(await page.locator("#source-summary img").count())throw new Error("source label was interpreted as HTML");
  const config=await page.evaluate(()=>window.__tableGroups);if(JSON.stringify(config["#producers"])!==JSON.stringify(["image","operation_kind"]))throw new Error("producer grouping configuration missing");
  if(requests.some(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`)))throw new Error(`non-local asset request: ${requests.find(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`))}`);
  if(errors.length)throw new Error(errors.join("; "));
  console.log(JSON.stringify({loaded:before,tableGroups:config,roles,interactions}));
} finally { if(browser)await browser.close();server.kill("SIGTERM"); }
