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
  const before=await page.evaluate(()=>({rows:window.__perspectiveRows,g6:window.__g6Counts,sink:window.__selectedSink,images:window.__reportLoaded.images,overview:window.__explanationOverview}));
  const outputBytes=await page.evaluate(()=>window.__reportLoaded.outputBytes);
  const interactions=[];
  if(before.sink!==0||before.images<1||before.g6.nodes>250||before.g6.combos<2||before.rows["#output-table"]!==outputBytes)throw new Error(`unexpected initial view ${JSON.stringify(before)}`);
  const structureReady=await page.evaluate(()=>window.__structureReady&&window.__activeView==="structure");
  if(structureReady){
    try{await page.waitForFunction(()=>window.__routineGraphCounts?.mode==="global",{timeout:20000})}catch(e){throw new Error(`routine graph init timeout; errors=${errors.join(" | ")}; ${e.message}`)}
    const structure=await page.evaluate(()=>({summary:window.__structureSummary,rows:window.__structureRows,routines:window.__structureRoutineRows,narrative:window.__structureNarrativeRows,firstBlocks:window.__selectedRoutineBlocks}));
    if(!structure.rows.routines||!structure.rows.narrative||!structure.routines.some(r=>r.id===0)||!structure.routines.some(r=>r.recursive))throw new Error(`structural report not populated: ${JSON.stringify(structure.summary)}`);
    if(!structure.routines[0].display.includes("PLI.COM"))throw new Error(`R000 is not the resident PLI.COM entry: ${structure.routines[0].display}`);
    const pairs=new Set(structure.narrative.map(x=>`${x.from_id}:${x.to_id}`));if(pairs.size!==structure.narrative.length)throw new Error("routine narrative duplicated a directed pair");
    const topology=await page.evaluate(()=>({counts:window.__routineGraphCounts,labels:window.__routineGraphLabels,pairs:window.__routineGraphPairs}));
    if(topology.counts.nodes!==structure.rows.routines||topology.counts.edges!==structure.rows.narrative||topology.labels.length!==structure.rows.routines||new Set(topology.labels).size!==structure.rows.routines||topology.labels.some((label,i)=>label!==structure.routines[i].display))throw new Error(`routine graph cardinality/identity mismatch: ${JSON.stringify(topology.counts)}`);
    if(structure.routines.some(r=>!r.display.startsWith(r.canonical)))throw new Error("generated routine labels lost their canonical image/offset identity");
    if(!structure.routines.some(r=>r.display.includes(" · program entry"))||!structure.routines.some(r=>r.display.includes(" · recursive"))||!structure.routines.some(r=>r.display.includes(" · cycle participant")))throw new Error("expected factual routine descriptors are absent");
    if(!topology.counts.cycleEdges)throw new Error("no cycle-participating narrative edges were visually classified");
    const simpleReturns=topology.pairs.filter(e=>e.kinds.includes("RETURN")&&!e.kinds.includes("CALL")&&topology.pairs.some(r=>r.from===e.to&&r.to===e.from&&r.kinds.includes("CALL")));
    if(!simpleReturns.length||simpleReturns.some(e=>e.cycle))throw new Error("ordinary CALL/RETURN pairs were not kept distinct from cycle edges");
    if(expectedInput==="OPTIMIST"&&(structure.rows.routines!==599||structure.rows.narrative!==2940))throw new Error(`unexpected OPTIMIST structure metrics ${JSON.stringify(structure.rows)}`);
    if(expectedInput==="FIZZBUZ"&&(structure.rows.routines!==530||structure.rows.narrative!==2362))throw new Error(`unexpected FIZZBUZ structure metrics ${JSON.stringify(structure.rows)}`);
    const timeline=await page.evaluate(()=>({facts:window.__structureTimelineFacts,rows:document.querySelectorAll("#structure-timeline [data-routine-id]").length,firstMarkers:document.querySelectorAll("#structure-timeline .timeline-first-marker").length,lastMarkers:document.querySelectorAll("#structure-timeline .timeline-last-marker").length,explanation:document.querySelector("#structure-timeline-panel > p").textContent,progression:[...document.querySelectorAll("#structure-timeline-progression .timeline-appearance")].map(x=>x.textContent)}));
    if(timeline.rows!==structure.rows.routines||timeline.facts.routineCount!==structure.rows.routines||timeline.facts.axisStart!==0||timeline.facts.axisEnd<Math.max(...structure.routines.map(r=>r.last_step??0))||timeline.firstMarkers!==timeline.rows||timeline.lastMarkers!==timeline.rows||!timeline.explanation.includes("does not mean the routine ran continuously"))throw new Error(`routine observation timeline is incomplete or ambiguously described: ${JSON.stringify(timeline)}`);
    const landmarks=await page.evaluate(()=>({facts:window.__structureLandmarkFacts,labels:[...document.querySelectorAll("#structure-landmark-lane svg text")].map(x=>x.textContent),readMarkers:document.querySelectorAll('#structure-landmark-lane [data-landmark-kind="io"]').length,entryMarkers:document.querySelectorAll('#structure-landmark-lane [data-landmark-kind="entry"]').length,writeMarkers:document.querySelectorAll('#structure-landmark-lane [data-landmark-kind="write"]').length,boundaries:document.querySelectorAll('#structure-landmark-lane [data-landmark-kind="boundary"]').length}));
    if(landmarks.readMarkers!==3||landmarks.entryMarkers!==4||landmarks.writeMarkers!==11||landmarks.boundaries!==2||landmarks.facts.run_start!==0||landmarks.facts.run_end!==2535509||landmarks.facts.axisEnd!==landmarks.facts.run_end)throw new Error(`factual landmark lane is incomplete: ${JSON.stringify(landmarks)}`);
    for(const [image,start,end,entry] of [["PLI0.OVL",644,14084,14310],["PLI1.OVL",644035,670051,670277],["PLI2.OVL",1638236,1663484,1663710]]){
      const read=landmarks.facts.reads.find(x=>x.image===image),first=landmarks.facts.entries.find(x=>x.image===image);
      if(!read||read.start!==start||read.end!==end||!first||first.step!==entry||first.entry_kind!=="IMAGE_ENTRY"||!landmarks.labels.includes(`read ${image}`))throw new Error(`read-to-entry chronology missing for ${image}: ${JSON.stringify({read,first,labels:landmarks.labels})}`);
    }
    if(landmarks.facts.writes.length!==11||landmarks.facts.writes[0].step!==840539||landmarks.facts.writes[0].first!==0||landmarks.facts.writes[0].last!==127||landmarks.facts.writes[1].step!==952112||landmarks.facts.writes.at(-1).step!==2533978||landmarks.facts.writes.at(-1).first!==1280||landmarks.facts.writes.at(-1).last!==1407||!landmarks.labels.includes("write OPTIMIST.REL"))throw new Error(`REL record-write chronology/ranges missing: ${JSON.stringify(landmarks.facts.writes)}`);
    await page.locator('#structure-landmark-lane [data-landmark-kind="io"]').first().hover();
    await page.waitForFunction(()=>document.querySelector("#structure-landmark-detail").textContent.includes("PLI0.OVL")&&document.querySelector("#structure-landmark-detail").textContent.includes("644–14,084"));
    await page.locator('#structure-landmark-lane [data-landmark-kind="write"]').first().click();
    await page.waitForFunction(()=>document.querySelector("#structure-landmark-detail").textContent.includes("OPTIMIST.REL")&&document.querySelector("#structure-landmark-detail").textContent.includes("+0000h–+007Fh")&&document.querySelector("#structure-landmark-detail").textContent.includes("840,539"));
    interactions.push("landmark lane: overlay read intervals and IMAGE_ENTRY steps, 11 REL record-write ranges, start/end boundaries, hover/click details");
    if(expectedInput==="OPTIMIST"){
      const imageOrder=timeline.facts.groups.map(x=>x.image),i0=imageOrder.indexOf("PLI0.OVL"),i1=imageOrder.indexOf("PLI1.OVL"),i2=imageOrder.indexOf("PLI2.OVL");
      if(i0<0||i1<=i0||i2<=i1)throw new Error(`overlay first-observation order is not visible: ${JSON.stringify(timeline.facts.groups)}`);
      if(!timeline.progression[i0].startsWith("PLI0.OVL")||!timeline.progression[i1].startsWith("PLI1.OVL")||!timeline.progression[i2].startsWith("PLI2.OVL"))throw new Error(`overlay first-observation sequence is not displayed: ${JSON.stringify(timeline.progression)}`);
      const p0=timeline.facts.groups[i0],p1=timeline.facts.groups[i1],p2=timeline.facts.groups[i2];
      if(!(p0.first_step<p1.first_step&&p1.first_step<p2.first_step))throw new Error(`overlay appearance steps are not chronological: ${JSON.stringify([p0,p1,p2])}`);
      const p1Routine=structure.routines.find(r=>r.image==="PLI1.OVL");const row=page.locator(`#structure-timeline [data-routine-id="${p1Routine.id}"]`);await row.click();await page.waitForFunction(id=>window.__selectedRoutine===id,p1Routine.id);
      if(await page.locator("#routine-detail h2").textContent()!==p1Routine.display)throw new Error("timeline selection did not reuse the routine detail view");
    }
    const first=structure.routines[0];await page.evaluate(row=>document.querySelector("#structure-routines").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),first);
    await page.waitForFunction(()=>window.__selectedRoutine===0&&window.__selectedRoutineBlocks>0);
    await page.evaluate(()=>window.__selectRoutineFromGraph(0));await page.waitForFunction(()=>window.__selectedRoutine===0);
    if(await page.locator("#routine-detail h2").textContent()!==first.display)throw new Error("routine detail header label differs from table/graph identity");
    const block=page.locator("#routine-blocks > details").first();await block.locator(":scope > summary").click();
    const code=page.locator("#routine-blocks > details details").first();await code.locator(":scope > summary").click();
    await page.waitForFunction(()=>document.querySelectorAll("#routine-blocks .instruction-list li").length>0);
    const narrativeRow=structure.narrative[0];await page.evaluate(row=>document.querySelector("#structure-narrative").dispatchEvent(new CustomEvent("perspective-click",{detail:{row}})),narrativeRow);
    await page.waitForFunction(id=>window.__selectedRoutine===id,narrativeRow.to_id);
    if(!narrativeRow.from.startsWith(structure.routines[narrativeRow.from_id].canonical)||!narrativeRow.to.startsWith(structure.routines[narrativeRow.to_id].canonical))throw new Error("narrative rows do not use canonical-preserving generated routine labels");
    const focus=await page.evaluate(()=>window.__routineFocus);if(focus.ordinal!==narrativeRow.ordinal||focus.from!==narrativeRow.from_id||focus.to!==narrativeRow.to_id)throw new Error(`narrative row did not highlight the corresponding edge/nodes: ${JSON.stringify(focus)}`);
    if(expectedInput==="OPTIMIST"){
      const checks=await page.evaluate(()=>({summary:window.__canonicalCodeSummary,blocks:window.__canonicalBlocksForImage("PLI2.OVL")}));
      if(checks.summary.canonical_instructions!==18137||checks.summary.canonical_blocks!==4281)throw new Error(`unexpected canonical code totals ${JSON.stringify(checks.summary)}`);
      const shared=checks.blocks.filter(x=>x.start_offset<=0x11e6&&x.end_offset>0x11e6).map(x=>({id:x.id,start:x.start_offset,end:x.end_offset,owners:[]}));
      for(const block of shared)block.owners=await page.evaluate(id=>window.__canonicalBlockOwners(id),block.id);
      if(shared.length!==1||shared[0].start!==0x11e6||shared[0].end!==0x11ed||JSON.stringify(shared[0].owners)!==JSON.stringify([403,420,422,455,456,458]))throw new Error(`PLI2+11E6 is not one canonical block with six contexts: ${JSON.stringify(shared)}`);
      const split=checks.blocks.filter(x=>x.start_offset<0x143a&&x.end_offset>0x1432).map(x=>[x.start_offset,x.end_offset]);
      if(JSON.stringify(split)!==JSON.stringify([[0x1432,0x1437],[0x1437,0x143a]]))throw new Error(`PLI2 union split mismatch: ${JSON.stringify(split)}`);
      await page.evaluate(()=>window.__selectRoutineFromGraph(403));await page.waitForFunction(()=>window.__selectedRoutine===403);
      let selected=await page.evaluate(()=>({summary:window.__selectedCodeContextSummary,contexts:window.__selectedCodeContexts}));
      if(selected.summary.shared_blocks<1||!selected.contexts.some(x=>x.start===0x11e6&&x.end===0x11ed&&x.owners.length===6))throw new Error(`R403 shared code context missing: ${JSON.stringify(selected.summary)}`);
      const sharedContext=selected.contexts.find(x=>x.start===0x11e6&&x.end===0x11ed);
      const card=page.locator(`#canonical-block-${sharedContext.id}`);await card.locator(":scope > summary").click();
      await card.locator(".context-link").first().click();await page.waitForFunction(()=>window.__selectedRoutine!==403);
      await page.evaluate(()=>window.__selectRoutineFromGraph(458));await page.waitForFunction(()=>window.__selectedRoutine===458);
      selected=await page.evaluate(()=>window.__selectedCodeContextSummary);
      if(selected.shared_blocks<1)throw new Error(`R458 does not expose shared-context counts: ${JSON.stringify(selected)}`);
      await page.evaluate(()=>window.__selectRoutineFromGraph(456));await page.waitForFunction(()=>window.__selectedRoutine===456);
      selected=await page.evaluate(()=>({summary:window.__selectedCodeContextSummary,contexts:window.__selectedCodeContexts}));
      if(selected.summary.split_relations<2||!selected.contexts.some(x=>x.start===0x1432&&x.end===0x1437)||!selected.contexts.some(x=>x.start===0x1437&&x.end===0x143a))throw new Error(`R456 union-split contexts are not discoverable: ${JSON.stringify(selected.summary)}`);
      const splitCards=await page.locator("#routine-blocks .union-split").count();if(splitCards<2)throw new Error(`union split badges missing: ${splitCards}`);
      interactions.push("canonical code: PLI2+11E6 one block/six routine contexts; +1432/+1437 union split; R403/R458 shared counts and cross-context navigation");
    }
    await page.evaluate(ordinal=>window.__focusNarrativeFromGraph(ordinal),narrativeRow.ordinal);await page.waitForFunction(ordinal=>window.__routineFocus?.ordinal===ordinal,narrativeRow.ordinal);
    if(expectedInput&&(narrativeRow.from_id!==0||narrativeRow.to_id!==1))throw new Error(`first narrative transition did not navigate R000 -> R001: ${JSON.stringify(narrativeRow)}`);
    await page.click("#routine-map-local");await page.waitForFunction(()=>window.__routineGraphCounts?.mode==="neighborhood");const local=await page.evaluate(()=>window.__routineGraphCounts);if(local.nodes>40||local.nodes<1)throw new Error(`selected-routine neighborhood is not compact: ${JSON.stringify(local)}`);
    await page.click("#routine-map-global");await page.waitForFunction(()=>window.__routineGraphCounts?.mode==="global"&&window.__routineGraphCounts.nodes===window.__structureRows.routines);
    await page.click("#tab-low-level");await page.waitForFunction(()=>window.__activeView==="low-level");
    interactions.push(`structure ${expectedInput||"report"}: ${structure.rows.routines} nodes/${structure.rows.narrative} unique narrative edges, ${topology.counts.cycleEdges} visibly cycled; selected R000, expanded instructions, navigated R000 → R${String(narrativeRow.to_id).padStart(3,"0")}, local neighborhood ${local.nodes} nodes; recursion badge present`);
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
  for(const p of await page.locator("#sink option").evaluateAll(xs=>xs.map(x=>Number(x.value)))){await page.selectOption("#sink",String(p));await page.waitForFunction(offset=>window.__explorerReady&&window.__selectedSink===offset,p);const view=await page.evaluate(()=>({g6:window.__g6Counts,rows:window.__perspectiveRows,pathRows:window.__pathRows}));if(view.g6.nodes>250||!view.pathRows)throw new Error("bounded data/path projection missing");interactions.push(`sink ${p}: ${view.g6.nodes} data graph nodes/${view.g6.combos} combos; path Perspective rows=${view.pathRows}; tables=${JSON.stringify(view.rows)}`);if(p===704){
    const overview=await page.evaluate(()=>window.__explanationOverview);
    if(overview.offset!==704||overview.value!==0x48||overview.write_step!==1987517||overview.nodes!==241984||overview.source_leaves!==861||!overview.path_context_depth||!overview.sources.length||!overview.operations.length)throw new Error(`selected-sink explanation overview facts mismatch: ${JSON.stringify(overview)}`);
    const what=await page.locator("#overview-what-value").innerText(),when=await page.locator("#overview-when-value").innerText(),how=await page.locator("#overview-how-value").innerText();
    if(!what.includes("OPTIMIST.REL")||!what.includes("+02C0h")||!what.includes("48h")||!when.includes("1,987,517")||!how.includes("241,984 exact data-slice nodes")||!how.includes("861 source leaves"))throw new Error(`visible explanation overview omits selected-byte facts: ${JSON.stringify({what,when,how})}`);
    const sourceRows=await page.locator("#overview-source-rows .overview-source-row").count();if(sourceRows!==overview.sources.length)throw new Error("overview source breakdown does not expose every aggregated source group");
    const sourceText=await page.locator("#overview-source-rows").innerText();if(!sourceText.includes("OPTIMIST.PLI")||!overview.sources.some(x=>["PLI.COM","PLI0.OVL","PLI1.OVL","PLI2.OVL"].some(image=>x.identity.includes(image))))throw new Error(`overview does not show the observed program input and compiler-image source groups: ${sourceText}`);
    if(sourceText.includes("ranges")||sourceText.includes("–"))throw new Error("overview source breakdown includes long range details");
    await page.locator("#overview-source-rows .overview-source-row").first().click();await page.waitForFunction(()=>document.querySelector("#source-influence").getBoundingClientRect().top<250);
    await page.locator("#overview-operation-jump").click();await page.waitForFunction(()=>document.querySelector("#operation-summary").getBoundingClientRect().top<250);
    await page.locator("#overview-path-row button").click();await page.waitForFunction(()=>window.__analysisMode==="path"&&document.querySelector("#path-section").getBoundingClientRect().top<250);
    interactions.push(`explanation overview REL+02C0: 48h at step 1987517, ${overview.nodes} nodes / ${overview.source_leaves} leaves, ${sourceRows} source groups; source/operation/path navigation`);
    await verifyPathControl();
  }}
  const unprojected=await page.locator("#output-bytes .out-byte").nth(1);await unprojected.click();await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===1&&document.querySelector("#sink-meta").textContent.includes("projection not embedded"));if(await page.evaluate(()=>window.__perspectiveRows["#producers"])!==0||await page.evaluate(()=>window.__explanationOverview.projection_embedded!==false||window.__explanationOverview.sources.length!==0))throw new Error("unprojected sink retained stale overview/provenance data");interactions.push("unprojected output-byte metadata-only selection");
  await page.selectOption("#sink",String(before.sink));await page.waitForFunction(()=>window.__explorerReady&&window.__selectedSink===0);
  const heatHashes={};for(const mode of ["execution","participation","producer","value","address","flag","control","source"]){await page.selectOption("#mode",mode);heatHashes[mode]=await page.locator("canvas.heatmap").evaluateAll(xs=>xs.map(x=>x.toDataURL()).join(""));interactions.push(`heatmap ${mode}`)}
  const roles=await page.evaluate(()=>window.__roleOverlayCounts);if(roles.value&&roles.address&&roles.flag&&new Set([heatHashes.value,heatHashes.address,heatHashes.flag]).size<3)throw new Error("role-specific heatmaps did not differ");if(roles.control&&heatHashes.control===heatHashes.execution)throw new Error("control heatmap did not differ from execution heat");
  if(await page.locator("#source-summary img").count())throw new Error("source label was interpreted as HTML");
  const config=await page.evaluate(()=>window.__tableGroups);if(JSON.stringify(config["#producers"])!==JSON.stringify(["image","operation_kind"]))throw new Error("producer grouping configuration missing");
  const codeReady=await page.evaluate(()=>window.__codeEvidenceReady===true);
  if(codeReady){
    await page.click("#tab-code-evidence");await page.waitForFunction(()=>window.__activeView==="code-evidence");
    const jump=async(image,offset)=>{await page.locator("#code-offset").fill(`${image}+${offset.toString(16).toUpperCase()}`);await page.click("#code-jump");await page.waitForFunction(([i,o])=>window.__selectedCodeCoordinate?.image===i&&window.__selectedCodeCoordinate?.offset===o,[image,offset])};
    await jump("PLI.COM",0x0bda);
    let facts=await page.locator("#code-selected-evidence").innerText();
    if(!facts.includes("MINIMAL · OBSERVED")||!facts.includes("FIZZBUZ · OBSERVED")||!facts.includes("0BE2")||!facts.includes("0BDF"))throw new Error(`multi-run block partition example is missing: ${facts.slice(0,900)}`);
    await jump("PLI2.OVL",0x11e6);facts=await page.locator("#code-selected-evidence").innerText();
    if(!facts.includes("PLI2.OVL+11E6")||!facts.includes("R403")||!facts.includes("executions 442"))throw new Error(`multi-context overlay code evidence missing: ${facts.slice(0,1200)}`);
    await jump("PLI0.OVL",0x01dd);facts=await page.locator("#code-selected-evidence").innerText();if(!facts.includes("JMP 038EH"))throw new Error("PLI0 overlay exit evidence missing");
    await jump("PLI1.OVL",0x0138);facts=await page.locator("#code-selected-evidence").innerText();if(!facts.includes("JMP 038EH"))throw new Error("PLI1 overlay exit evidence missing");
    await jump("PLI.COM",0x0d32);facts=await page.locator("#code-listing").innerText();if(!facts.includes("LDA 20A8H")||!facts.includes("STA 201EH")||!facts.includes("JNC 0E3FH"))throw new Error("resident overlay-exit sequence was not listed");
    await jump("PLI.COM",0x19d4);facts=await page.locator("#code-selected-evidence").innerText();if(!facts.includes("JMP 0005H")||!facts.includes("R009"))throw new Error("resident BDOS bridge observation missing");
    const codeTests=await page.evaluate(()=>{
      const byLabel=Object.fromEntries(window.__codeRuns.map(r=>[r.label,r]));
      const all=new Set(window.__codeRuns.flatMap(r=>r.instructions.map(i=>`${i.image}:${i.offset}`)));
      const opt=new Set((byLabel.OPTIMIST?.instructions??[]).map(i=>`${i.image}:${i.offset}`));
      return {runs:window.__codeRuns.map(r=>r.label),coords:all.size,otherOnly:[...all].find(x=>!opt.has(x)),
        selected:window.__selectedCodeCoordinate,listingButtons:document.querySelectorAll("#code-listing .code-instruction").length};
    });
    if(codeTests.runs.length!==4||!codeTests.otherOnly||codeTests.otherOnly.startsWith("undefined:")||codeTests.selected.offset!==0x19d4||!codeTests.listingButtons)throw new Error(`multi-run code view did not retain complete run coverage/navigation: ${JSON.stringify(codeTests)}`);
    const [otherImage,otherOffset]=codeTests.otherOnly.split(":");await jump(otherImage,Number(otherOffset));facts=await page.locator("#code-selected-evidence").innerText();
    if(!facts.includes("OPTIMIST · NOT OBSERVED")||facts.includes("OPTIMIST · OBSERVED"))throw new Error(`coordinate absent from OPTIMIST was not kept as a per-run absence: ${facts.slice(0,800)}`);
    await page.click("#code-next");await page.waitForFunction(()=>window.__selectedCodeCoordinate.offset!==0x19d4);
    await jump("PLI.COM",0x19d4);
    await page.waitForFunction(()=>document.querySelector("#event-witness-status .event-witness-sample"));
    const witnessStatus=await page.locator("#event-witness-status").innerText();
    if(!witnessStatus.includes("OBSERVED executions at PLI.COM+19D4"))throw new Error(`instruction-time witnesses were not shown: ${witnessStatus.slice(0,500)}`);
    const relWrite=page.locator("#event-file-operations .witness-event-link").filter({hasText:"840,539"}).first();
    await relWrite.click();
    const eventContext=page.locator("#event-file-operations .witness-context").filter({hasText:"DEDUCED CALL frames"}).first();
    await page.waitForFunction(()=>[...document.querySelectorAll("#event-file-operations .witness-context")].some(x=>x.textContent.includes("DEDUCED CALL frames")&&x.textContent.includes("PLI1.OVL")));
    await page.waitForFunction(()=>[...document.querySelectorAll("#event-file-operations .witness-transfer-context")].some(x=>x.open&&x.textContent.includes("JMP 0005H")));
    await page.waitForFunction(()=>window.__selectedCodeCoordinate?.image==="PLI.COM"&&window.__selectedCodeCoordinate?.offset===0x19d4);
    const finalRelWrite=page.locator("#event-file-operations .witness-event-link").filter({hasText:"2,533,978"}).first();await finalRelWrite.click();
    await page.waitForFunction(()=>[...document.querySelectorAll("#event-file-operations .witness-context")].some(x=>x.textContent.includes("uncertain")&&x.textContent.includes("1681339")));
    interactions.push(`event witnesses: exact PLI.COM+19D4 instruction executions and REL write 840539 caller context includes PLI1.OVL; file-event selection navigates to bridge`);
    interactions.push(`code evidence: four runs, ${codeTests.coords} coordinates, direct coordinate jump, per-run partitions/contexts/transfers, absent-from-OPTIMIST coordinate ${codeTests.otherOnly}`);
  }
  if(requests.some(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`)))throw new Error(`non-local asset request: ${requests.find(url=>!url.startsWith(`http://127.0.0.1:${port}/`)&&!url.startsWith(`blob:http://127.0.0.1:${port}/`))}`);
  if(errors.length)throw new Error(errors.join("; "));
  console.log(JSON.stringify({loaded:before,tableGroups:config,roles,interactions}));
} finally { if(browser)await browser.close();server.kill("SIGTERM"); }
