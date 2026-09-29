import perspective from "@perspective-dev/client";
import perspectiveViewer from "@perspective-dev/viewer";
import "@perspective-dev/viewer-datagrid";
import "@perspective-dev/viewer/themes";
import serverWasm from "@perspective-dev/server/dist/wasm/perspective-server.wasm?url";
import viewerWasm from "@perspective-dev/viewer/dist/wasm/perspective-viewer.wasm?url";
import { Graph } from "@antv/g6";
import { adjacentInstructions, coordinateEvidence, parseCodeCoordinate } from "./code_evidence.js";
import "./style.css";
import "./code_evidence.css";

const reportUrl = new URL("./provenance-report.json", window.location.href);
const report = await fetch(reportUrl).then(async r => { if (!r.ok) throw new Error(`Report fetch failed: ${r.status}`); const text=await r.text(); const newline=text.indexOf("\n"); if(newline<0||text.slice(0,newline)!=="RUNES_PROVENANCE_REPORT 1")throw new Error("Unsupported provenance report version"); return JSON.parse(text.slice(newline+1)); });
const controlText = await fetch(new URL("./provenance-control-report.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Control report fetch failed: ${r.status}`); return r.text(); });
if (!controlText.startsWith("RUNES_PROVENANCE_CONTROL_REPORT 1\n")) throw new Error("Unsupported path-control report version");
const controlReport = JSON.parse(controlText.slice(controlText.indexOf("\n")+1));
const hasPathControl = controlReport.selections.length > 0;
const manifest = await fetch(new URL("./explorer-manifest.json", window.location.href)).then(async r => {
  if (!r.ok) throw new Error(`Explorer manifest fetch failed: ${r.status}`);
  return r.json();
});
let structureReport = null, blocksReport = null, canonicalCodeReport = null;
if (manifest.structure) {
  const [structureText, blocksText, canonicalCodeText] = await Promise.all([
    fetch(new URL("./dynamic-structure.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Structure report fetch failed: ${r.status}`); return r.text(); }),
    fetch(new URL("./dynamic-blocks.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Block report fetch failed: ${r.status}`); return r.text(); }),
    fetch(new URL("./canonical-code-blocks.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Canonical code report fetch failed: ${r.status}`); return r.text(); })
  ]);
  if (!structureText.startsWith("RUNES_DYNAMIC_STRUCTURE 1\n")) throw new Error("Unsupported dynamic structure report version");
  if (!blocksText.startsWith("RUNES_DYNAMIC_BLOCKS 1\n")) throw new Error("Unsupported dynamic blocks report version");
  if (!canonicalCodeText.startsWith("RUNES_CANONICAL_CODE_BLOCKS 1\n")) throw new Error("Unsupported canonical code report version");
  structureReport = JSON.parse(structureText.slice(structureText.indexOf("\n") + 1));
  blocksReport = JSON.parse(blocksText.slice(blocksText.indexOf("\n") + 1));
  canonicalCodeReport = JSON.parse(canonicalCodeText.slice(canonicalCodeText.indexOf("\n") + 1));
}
const hasStructure = Boolean(structureReport && blocksReport && canonicalCodeReport);
let codeEvidence = null;
if (manifest.codeEvidence) {
  const payload = await fetch(new URL("./code-evidence.json", window.location.href)).then(async r => {
    if (!r.ok) throw new Error(`Code evidence index fetch failed: ${r.status}`);
    return r.json();
  });
  if (payload.schema !== "RUNES_CODE_EVIDENCE 1") throw new Error("Unsupported code evidence index version");
  codeEvidence = payload.runs ?? [];
}
document.querySelector("#structure-view").hidden = !hasStructure;
document.querySelector("#structure-missing").hidden = true;
document.querySelector("#tab-structure").hidden = !hasStructure;
document.querySelector("#tab-code-evidence").hidden = !codeEvidence;
document.querySelector("#code-evidence-view").hidden = !codeEvidence;
if (!hasStructure) document.querySelector("#tab-low-level").classList.add("active");
else document.querySelector("#tab-structure").classList.add("active");
if (!hasPathControl) {
  document.querySelector('#analysis-mode option[value="path"]').hidden = true;
  document.querySelector("#path-section").hidden = true;
}
const selection = new Map(report.selections.map(p => [`${p.sink.file.identity}:${p.sink.offset}`, p]));
const controlSelection = new Map(controlReport.selections.map(p => [`${p.file.identity}:${p.offset}`, p]));
const embedded = new Set([...selection.values()].map(p => `${p.sink.file.identity}:${p.sink.offset}`));
const outputIdentity = report.output_file.identity;
const outputGrid = document.querySelector("#output-bytes");
for (const b of report.output_bytes) {
  const button = document.createElement("button"); button.className = `out-byte ${b.projection_embedded ? "" : "no-projection"}`;
  button.dataset.offset = b.offset; button.title = `offset ${b.offset.toString(16).toUpperCase().padStart(4,"0")} · value ${b.value.toString(16).padStart(2,"0")} · step ${b.write_step ?? "?"} · rewrites ${b.rewrite_count} · projection ${b.projection_embedded ? "embedded" : "not embedded"}`;
  button.textContent = `${b.offset.toString(16).padStart(3,"0")} ${b.value.toString(16).padStart(2,"0")}`;
  button.addEventListener("click", () => selectOffset(b.offset)); outputGrid.append(button);
}

await Promise.all([perspective.init_server(fetch(serverWasm)), perspectiveViewer.init_client(fetch(viewerWasm))]);
const worker = await perspective.worker();
const viewers = {};
async function loadViewer(id, rows, group_by, sort) {
  const viewer=document.querySelector(id), table=await worker.table(rows.length ? rows : [{empty:"no rows"}]);
  await viewer.load(table); await viewer.restore({plugin:"Datagrid",group_by:rows.length?group_by:[],sort:rows.length?sort:[]}); viewers[id]=viewer;
  viewer.addEventListener("perspective-click", event => {
    const row=event.detail?.row ?? {};
    if(id==="#producers"){
      const found=current?.producers.find(p=>p.image.identity===row.image&&p.image_offset===row.image_offset&&p.runtime_pc===row.runtime_pc);
      if(found)highlightProducer(found.id);
    }else if(id==="#control-decisions")highlightControl(row);
    else if(id==="#structure-routines")selectRoutine(Number(row.id));
    else if(id==="#structure-narrative")highlightNarrative(Number(row.ordinal));
  });
  return {viewer,table,rows:rows.length};
}
const initRows = await Promise.all([
  loadViewer("#producers", [], ["image","operation_kind"], [["producer_steps","desc"]]),
  loadViewer("#sources", [], ["classification","identity"], [["offset","asc"]]),
  loadViewer("#operations", [], ["kind"], [["node_count","desc"]]),
  loadViewer("#source-ranges", [], ["classification","identity"], [["first","asc"]]),
  loadViewer("#output-table", report.output_bytes.map(x=>({...x})), [], [["offset","asc"]]),
  loadViewer("#control-decisions", [], ["image","condition","taken"], [["decision_count","desc"]]),
  loadViewer("#structure-routines", [], [], [["id","asc"]]),
  loadViewer("#structure-narrative", [], [], [["ordinal","asc"]])
]);
const viewerTables = {};
for (const [i,id] of ["#producers","#sources","#operations","#source-ranges","#output-table","#control-decisions","#structure-routines","#structure-narrative"].entries()) viewerTables[id]=initRows[i];

const roleColor={value:"#2878b5",address:"#d18a16",flag:"#bc3b82",control:"#555"};
let graph=null, routineGraph=null, routineGraphMode="global", activeNarrativeOrdinal=null;
let current=null, currentPath=null, currentProducer=null, analysisMode="data";
function safeText(el,text){el.textContent=text;}
const formatCount=value=>Number(value??0).toLocaleString("en-US");
const hexValue=(value,width)=>value==null?"unknown":`${Number(value).toString(16).toUpperCase().padStart(width,"0")}h`;
function overviewJump(selector){document.querySelector(selector)?.scrollIntoView({behavior:"smooth",block:"start"});}
function renderUnprojectedOverview(byte){
  const offset=byte?.offset??window.__selectedSink??0;
  safeText(document.querySelector("#overview-what-value"),`${report.output_file.name} +${hexValue(offset,4)} = ${hexValue(byte?.value,2)}`);
  safeText(document.querySelector("#overview-when-value"),`write step ${byte?.write_step==null?"unknown":formatCount(byte.write_step)}`);
  safeText(document.querySelector("#overview-how-value"),"Detailed provenance projection not embedded");
  document.querySelector("#overview-source-rows").replaceChildren();
  const sourceNote=document.createElement("p");sourceNote.className="overview-empty";sourceNote.textContent="Source projection not embedded for this output byte.";document.querySelector("#overview-source-rows").append(sourceNote);
  document.querySelector("#overview-operation-rows").replaceChildren();
  document.querySelector("#overview-path-row").replaceChildren();
  window.__explanationOverview={offset,value:byte?.value??null,write_step:byte?.write_step??null,projection_embedded:false,sources:[],operations:[]};
}
function renderExplanationOverview(projection,path){
  const {sink,value:sink_value,write_step,full_node_count,source_leaf_count,sources,operations}=projection;
  safeText(document.querySelector("#overview-what-value"),`${sink.file.name} +${hexValue(sink.offset,4)} = ${hexValue(sink_value,2)}`);
  safeText(document.querySelector("#overview-when-value"),`write step ${write_step==null?"unknown":formatCount(write_step)}`);
  const pathCount=path?`${formatCount(path.context_depth)} path-context decisions · ${formatCount(path.distinct_branch_locations)} branch locations`:"path-control projection not embedded";
  safeText(document.querySelector("#overview-how-value"),`${formatCount(full_node_count)} exact data-slice nodes · ${formatCount(source_leaf_count)} source leaves · ${pathCount}`);

  const sourceRoot=document.querySelector("#overview-source-rows");sourceRoot.replaceChildren();
  for(const source of sources){
    const row=document.createElement("button");row.type="button";row.className="overview-source-row";row.title=`Open detailed source influence for ${source.identity}`;
    const category=document.createElement("span");category.className="overview-source-kind";category.textContent=source.classification??source.kind;
    const identity=document.createElement("span");identity.className="overview-source-identity";identity.textContent=source.identity;
    const offsets=document.createElement("span");offsets.textContent=`${formatCount(source.distinct_source_bytes)} distinct offsets`;
    const leaves=document.createElement("span");leaves.textContent=`${formatCount(source.leaf_occurrences)} leaf occurrences`;
    row.append(category,identity,offsets,leaves);row.addEventListener("click",()=>overviewJump("#source-influence"));sourceRoot.append(row);
  }
  if(!sources.length){const note=document.createElement("p");note.className="overview-empty";note.textContent="No source leaves in this slice.";sourceRoot.append(note)}

  const operationRoot=document.querySelector("#overview-operation-rows");operationRoot.replaceChildren();
  const topOperations=operations.slice().sort((a,b)=>b.node_count-a.node_count||a.kind.localeCompare(b.kind)).slice(0,4);
  for(const operation of topOperations){
    const row=document.createElement("button");row.type="button";row.className="overview-operation-row";row.title="Open the complete operation summary";
    const name=document.createElement("span");name.textContent=operation.kind;
    const count=document.createElement("span");count.textContent=`${formatCount(operation.node_count)} nodes`;
    row.append(name,count);row.addEventListener("click",()=>overviewJump("#operation-summary"));operationRoot.append(row);
  }
  const pathRoot=document.querySelector("#overview-path-row");pathRoot.replaceChildren();
  if(path){
    const button=document.createElement("button");button.type="button";button.className="overview-path-link";
    button.textContent=`Path context: ${pathCount} · steps ${path.earliest_decision_step==null?"unknown":formatCount(path.earliest_decision_step)}–${path.latest_decision_step==null?"unknown":formatCount(path.latest_decision_step)}`;
    button.addEventListener("click",()=>{
      const selector=document.querySelector("#analysis-mode");
      if(selector.value!=="path"){selector.value="path";selector.dispatchEvent(new Event("change",{bubbles:true}))}
      overviewJump("#path-section");
    });pathRoot.append(button);
  }
  window.__explanationOverview={offset:sink.offset,value:sink_value,write_step,nodes:full_node_count,source_leaves:source_leaf_count,
    path_context_depth:path?.context_depth??null,path_branch_locations:path?.distinct_branch_locations??null,
    sources:sources.map(source=>({kind:source.kind,classification:source.classification??null,identity:source.identity,distinct_source_bytes:source.distinct_source_bytes,leaf_occurrences:source.leaf_occurrences})),
    operations:topOperations.map(operation=>({kind:operation.kind,node_count:operation.node_count}))};
}
for(const button of document.querySelectorAll("#overview-what,#overview-when,#overview-operation-jump"))button.addEventListener("click",()=>overviewJump(button.dataset.target));
document.querySelector("#overview-source-jump").addEventListener("click",()=>overviewJump("#source-influence"));
function roleSummary(p){const roles=p.roles;document.querySelector("#roles").innerHTML="";for(const role of ["value","address","flag","control"]){const d=document.createElement("span");d.className=`role-${role}`;d.textContent=`${role}: ${roles[role]}  `;document.querySelector("#roles").append(d);}}
function groupedRows(p){
  const producers=p.producers.map(x=>({producer_id:x.id,image:x.image.identity,image_offset:x.image_offset,virtual_offset:x.virtual_offset,runtime_pc:x.runtime_pc,operation_kind:x.operation_kind,operation_nodes:x.operation_nodes,producer_steps:x.producer_steps,first_step:x.first_step,last_step:x.last_step,value_edges:x.value_edges,address_edges:x.address_edges,flag_edges:x.flag_edges,control_edges:x.control_edges}));
  const sources=p.source_leaves.map(x=>({node_id:x.node_id,classification:x.classification??"system/initial",identity:x.identity,source_kind:x.kind,offset:x.offset,virtual_offset:x.virtual_offset,value:x.value}));
  const sourceRanges=p.sources.flatMap(x=>x.ranges.map(r=>({classification:x.classification??x.kind,identity:x.identity,source_kind:x.kind,first:r.first,last:r.last,distinct_source_bytes:x.distinct_source_bytes,leaf_occurrences:x.leaf_occurrences})));
  const operations=p.operations.map(x=>({...x}));
  return {producers,sources,sourceRanges,operations};
}
function producerLocationId(origin){return current?.producers.find(p=>p.image.identity===origin.image.identity&&p.image_offset===origin.offset&&p.runtime_pc===origin.runtime_pc)?.id??`producer:${origin.image.identity}:${origin.offset}:${origin.runtime_pc}`;}
function graphData(p,preview=p.preview,rootValue=p.root,rootLabel="selected sink"){
  const nodes=[],edges=[],combos=[],seen=new Set(); const add=(id,data)=>{if(!seen.has(id)){nodes.push({id,...data});seen.add(id)}};
  combos.push({id:"group:root",data:{label:rootLabel}},{id:"group:operations",parentId:"group:root",data:{label:"operations"}},{id:"group:sources",parentId:"group:root",data:{label:"sources"}});
  add("root",{data:{label:`root #${rootValue}`,kind:"root"}});
  for(const n of preview.nodes){
    if(n.origin){const pid=producerLocationId(n.origin), pc=`pc:${pid}`, ic=`image:${n.origin.image.identity}`, kc=`kind:${n.label.split("/")[1]??"operation"}`;
      if(!combos.some(c=>c.id===ic))combos.push({id:ic,parentId:"group:operations",data:{label:n.origin.image.name}});
      if(!combos.some(c=>c.id===kc))combos.push({id:kc,parentId:ic,data:{label:n.label.split("/")[1]??"operation"}});
      if(!combos.some(c=>c.id===pc))combos.push({id:pc,parentId:kc,data:{label:`${n.origin.offset.toString(16)} @${n.origin.runtime_pc.toString(16)}`,producer_id:pid}});
      const id=`node:${n.id}`;add(id,{combo:pc,data:{label:`${n.id} ${n.label}`,node_id:n.id,producer_id:pid,depth:n.depth}});
    } else {const [sourceKind,...identityParts]=n.label.split("/"),identity=identityParts.join("/")||n.label,kindCombo=`source-kind:${sourceKind}`,g=`source:${sourceKind}:${identity}`;if(!combos.some(c=>c.id===kindCombo))combos.push({id:kindCombo,parentId:"group:sources",data:{label:sourceKind}});if(!combos.some(c=>c.id===g))combos.push({id:g,parentId:kindCombo,data:{label:identity}});add(`node:${n.id}`,{combo:g,data:{label:`${n.id} ${n.label}`,node_id:n.id,depth:n.depth}});}
  }
  for(const e of preview.edges)edges.push({id:`edge:${e.from}:${e.to}:${e.role}:${edges.length}`,source:`node:${e.from}`,target:`node:${e.to}`,data:{role:e.role,label:e.role},style:{stroke:roleColor[e.role],lineWidth:2}});
  if(typeof rootValue==="number"&&preview.nodes.some(n=>n.id===rootValue))edges.push({id:`rootedge:${rootValue}`,source:"root",target:`node:${rootValue}`,data:{role:"context"},style:{stroke:"#a8b2bc"}});
  return {nodes,edges,combos};
}
function producerOverlay(p,path){
  const accum=new Map();for(const x of p.producers){if(x.virtual_offset===null)continue;let v=accum.get(x.virtual_offset);if(!v){v={producer:0,value:0,address:0,flag:0,participation:1};accum.set(x.virtual_offset,v)}v.producer+=x.producer_steps;v.value+=x.value_edges;v.address+=x.address_edges;v.flag+=x.flag_edges;}
  for(const x of path?.locations??[]){if(!x.image||x.image_offset===null)continue;const im=report.execution.images.find(im=>`${String.fromCharCode(65+im.id.drive)}:${im.id.user}:${im.id.name}`===x.image.identity);if(!im)continue;const virtual=im.virtual_base+x.image_offset;let v=accum.get(virtual);if(!v){v={producer:0,value:0,address:0,flag:0,participation:0,control:0};accum.set(virtual,v)}v.control=(v.control??0)+x.decision_count;}
  return accum;
}
function renderHeatmaps(p,path=currentPath){
  const root=document.querySelector("#heatmaps");root.replaceChildren();const mode=document.querySelector("#mode").value,overlay=producerOverlay(p,path);
  const heatKey=mode==="producer"?"producer":mode;
  const overlayMaximum=mode==="participation"?1:[...overlay.values()].reduce((n,x)=>Math.max(n,x[heatKey]??0),1);
  const sourceVirtual=new Set(p.source_leaves.map(s=>s.virtual_offset).filter(x=>x!==null));
  for(const im of report.execution.images){const wrap=document.createElement("div"),label=document.createElement("strong"),canvas=document.createElement("canvas"),tip=document.createElement("div");wrap.className="image-map";label.textContent=`${im.display_name} · virtual ${im.virtual_base.toString(16)}–${(im.virtual_base+im.span-1).toString(16)} · ${im.span} bytes`;tip.className="tip";canvas.className="heatmap";canvas.width=Math.max(1,im.span);canvas.height=28;const ctx=canvas.getContext("2d"),max=Math.max(1,...im.bytes.map(b=>b[1]));
    for(let off=0;off<im.span;off++){const b=im.bytes[off],v=overlay.get(im.virtual_base+off);let intensity=0,color="#e4e8ed";
      if(mode==="execution"){intensity=b[1]?Math.log1p(b[1])/Math.log1p(max):0;color=`rgba(31,111,180,${0.08+0.92*intensity})`;}
      else if(mode==="source"){intensity=sourceVirtual.has(im.virtual_base+off)?1:0;color=intensity?"#2d9d78":"#e4e8ed";}
      else {let count=mode==="participation"?(v?1:0):v?.[heatKey]??0;intensity=count?Math.log1p(count)/Math.log1p(overlayMaximum):0;color=count?(mode==="control"?`rgba(116,73,190,${0.1+0.9*intensity})`:`rgba(196,68,53,${0.1+0.9*intensity})`):"#e4e8ed";}
      ctx.fillStyle=b[0]===null?"#cbd2d9":color;ctx.fillRect(off,0,1,28);
      if(b[2]>0){ctx.fillStyle="#17212b";ctx.fillRect(off,0,1,3);}
    }
    if(currentProducer&&currentProducer.virtual_offset!==null&&currentProducer.virtual_offset>=im.virtual_base&&currentProducer.virtual_offset<im.virtual_base+im.span){const off=currentProducer.virtual_offset-im.virtual_base;ctx.strokeStyle="#111";ctx.lineWidth=1;ctx.strokeRect(off+.5,0,1,27);}
    canvas.addEventListener("mousemove",ev=>{const r=canvas.getBoundingClientRect(),off=Math.max(0,Math.min(im.span-1,Math.floor((ev.clientX-r.left)/r.width*im.span))),b=im.bytes[off],v=overlay.get(im.virtual_base+off);tip.textContent=`${im.display_name} offset ${off.toString(16)} virtual ${(im.virtual_base+off).toString(16)} runtime count ${b[1]} starts ${b[2]} slice producer steps ${v?.producer??0} Value ${v?.value??0} Address ${v?.address??0} Flag ${v?.flag??0} Path decisions ${v?.control??0}`;});
    wrap.append(label,canvas,tip);root.append(wrap);
  }
  const imageIdentity=im=>`${String.fromCharCode(65+im.id.drive)}:${im.id.user}:${im.id.name}`;
  const external= p.sources.filter(s=>s.kind==="file_byte"&&!report.execution.images.some(im=>imageIdentity(im)===s.identity));
  const sourceRoot=document.querySelector("#source-data");sourceRoot.replaceChildren();
  for(const source of external){const offsets=source.offsets??[],max=Math.max(1,...offsets)+1,canvas=document.createElement("canvas"),label=document.createElement("div");label.textContent=`${source.classification??source.kind} · ${source.identity} · ${source.distinct_source_bytes} distinct source bytes / ${source.leaf_occurrences} leaf occurrences`;canvas.width=Math.min(max,65536);canvas.height=16;canvas.style.height="24px";const ctx=canvas.getContext("2d");ctx.fillStyle="#e4e8ed";ctx.fillRect(0,0,canvas.width,16);for(const offset of offsets){const x=Math.floor(offset*canvas.width/max);ctx.fillStyle="#2d9d78";ctx.fillRect(x,0,Math.max(1,canvas.width/max),16);}sourceRoot.append(label,canvas);}
}
function highlightProducer(id){let found=current?.producers.find(p=>p.id===id)??null;if(!found){const branch=currentPath?.locations.find(x=>x.image&&`producer:${x.image.identity}:${x.image_offset}:${x.runtime_pc}`===id),image=branch&&report.execution.images.find(im=>`${String.fromCharCode(65+im.id.drive)}:${im.id.user}:${im.id.name}`===branch.image.identity);if(branch&&image)found={id,virtual_offset:image.virtual_base+branch.image_offset};}currentProducer=found;document.querySelector("#producer-highlight").textContent=`Selected producer location: ${id}`;if(graph){const preview=analysisMode==="path"?currentPath?.preview:current?.preview,nodeId=preview?.nodes.find(n=>n.origin&&producerLocationId(n.origin)===id);if(nodeId)graph.setElementState(`node:${nodeId.id}`,"selected");}if(current)renderHeatmaps(current,currentPath);}
function highlightControl(row){const im=report.execution.images.find(im=>`${String.fromCharCode(65+im.id.drive)}:${im.id.user}:${im.id.name}`===row.image);if(!im)return;currentProducer={id:`control:${row.image}:${row.image_offset}:${row.runtime_pc}`,virtual_offset:im.virtual_base+row.image_offset};document.querySelector("#producer-highlight").textContent=`Selected path decision: ${row.image} +${Number(row.image_offset).toString(16)} @${Number(row.runtime_pc).toString(16)} · ${row.condition} ${row.taken?"taken":"not taken"}`;if(graph){const n=currentPath?.preview.nodes.find(n=>n.origin&&n.origin.image.identity===row.image&&n.origin.offset===row.image_offset&&n.origin.runtime_pc===row.runtime_pc);if(n)graph.setElementState(`node:${n.id}`,"selected");}if(current)renderHeatmaps(current,currentPath);}
async function setTableData(p,path){const rows=groupedRows(p);const controlRows=(path?.locations??[]).map(x=>({image:x.image?.identity??"unknown",image_offset:x.image_offset,runtime_pc:x.runtime_pc,condition:x.condition,taken:x.taken,decision_count:x.decision_count,first_step:x.first_step,last_step:x.last_step,distinct_flag_roots:x.distinct_flag_roots}));for(const [id,data] of [["#producers",rows.producers],["#sources",rows.sources],["#operations",rows.operations],["#source-ranges",rows.sourceRanges],["#output-table",report.output_bytes],["#control-decisions",controlRows]]){const old=viewerTables[id];const table=await worker.table(data.length?data:[{empty:"no rows"}]);await old.viewer.load(table);const requestedGroup=id==="#producers"?["image","operation_kind"]:id==="#sources"?["classification","identity"]:id==="#source-ranges"?["classification","identity"]:id==="#operations"?["kind"]:id==="#control-decisions"?["image","condition","taken"]:[];const requestedSort=id==="#producers"?[["producer_steps","desc"]]:id==="#operations"?[["node_count","desc"]]:id==="#source-ranges"?[["first","asc"]]:id==="#control-decisions"?[["decision_count","desc"]]:[["offset","asc"]];const group_by=data.length?requestedGroup:[],sort=data.length?requestedSort:[];await old.viewer.restore({plugin:"Datagrid",group_by,sort});old.table.delete?.();viewerTables[id]={...old,table,rows:data.length};window.__tableGroups??={};window.__tableGroups[id]=group_by;}
  window.__perspectiveRows=Object.fromEntries(Object.entries(viewerTables).map(([k,v])=>[k,v.rows]));window.__producerRows=rows.producers;window.__producerIds=rows.producers.map(x=>x.producer_id);window.__controlRows=controlRows;}
async function renderGraph(p,path){const pathMode=analysisMode==="path",preview=pathMode?path.preview:p.preview,root=pathMode?(preview.nodes[0]?.id??null):p.root,data=graphData(p,preview,root,pathMode?"selected path context":"selected sink");if(graph){graph.destroy();graph=null;}graph=new Graph({container:"graph",width:document.querySelector("#graph").clientWidth,height:540,data,layout:{type:"dagre",rankdir:"LR",nodesep:18,ranksep:40},behaviors:["drag-canvas","zoom-canvas",{type:"collapse-expand",trigger:"click",animation:false}],node:{style:{labelText:d=>d.data?.label??d.id,size:18}},edge:{style:{stroke:d=>roleColor[d.data?.role]??"#a8b2bc",endArrow:true,labelText:d=>d.data?.role??""}},combo:{type:"rect",style:{labelText:d=>d.data?.label??d.id,collapsed:false}}});await graph.render();graph.on("node:click",event=>{const id=event.target?.id??event.data?.id;const d=data.nodes.find(n=>n.id===id)?.data;if(d?.producer_id)highlightProducer(d.producer_id)});graph.on("combo:click",event=>{const id=event.target?.id??event.data?.id;const d=data.combos.find(c=>c.id===id)?.data;if(d?.producer_id)highlightProducer(d.producer_id)});window.__emitG6Producer=id=>{const n=data.nodes.find(x=>x.data?.producer_id===id);if(n)graph.emit("node:click",{target:{id:n.id}});else{const c=data.combos.find(x=>x.data?.producer_id===id);if(c)graph.emit("combo:click",{target:{id:c.id}})}};document.querySelector("#graph-meta").textContent=`G6 bounded ${pathMode?"path-context":"data-DAG"} graph: ${data.nodes.length} nodes, ${data.edges.length} edges, ${data.combos.length} combos (preview max ${preview.max_nodes} nodes, depth ${preview.max_depth}, omitted frontier ${preview.omitted_frontier_count}).`;
  window.__g6Counts={nodes:data.nodes.length,edges:data.edges.length,combos:data.combos.length};}

const hexOffset = value => value == null ? "unknown" : `${Number(value).toString(16).toUpperCase().padStart(4,"0")}h`;
const routineById = new Map((structureReport?.routines ?? []).map(r => [r.id, r]));
const aggregateRoutineEdges = new Map((structureReport?.transitions ?? []).map(e => [`${e.from}:${e.to}`, e]));
const canonicalInstructions = canonicalCodeReport?.instructions ?? [];
const canonicalBlocks = canonicalCodeReport?.blocks ?? [];
const canonicalContexts = canonicalCodeReport?.routine_block_relations ?? [];
const canonicalBlockById = new Map(canonicalBlocks.map(b => [b.id, b]));
const canonicalInstructionByCoordinate = new Map(canonicalInstructions.map(i => [`${i.image.drive}:${i.image.user}:${i.image.name}:${i.offset}`, i]));
const imageCoordinateKey = image => `${image.drive}:${image.user}:${image.name}`;
const instructionContext = (instruction, routineId) => instruction.contexts.find(c => c.routine_id === routineId);
const narrativeByOrdinal = new Map((structureReport?.narrative ?? []).map(e => [e.ordinal, e]));
const routineNodeId = id => `routine:${id}`;
const narrativeEdgeId = ordinal => `narrative:${ordinal}`;
function classifyNarrativeCycles(){
  const narrative=structureReport?.narrative??[];
  // RETURN edges paired with the corresponding first CALL edge are the
  // ordinary dynamic call/return relationship, not evidence of a structural
  // cycle. Exclude that return half for cycle discovery so genuinely cyclic
  // routine topology (including mutual calls and larger cycles) stays visible.
  const ordinaryReturns=new Set(narrative.filter(edge=>{
    const kinds=aggregateRoutineEdges.get(`${edge.from}:${edge.to}`)?.kinds??[edge.kind];
    const reverseKinds=aggregateRoutineEdges.get(`${edge.to}:${edge.from}`)?.kinds??[];
    return kinds.includes("RETURN")&&!kinds.includes("CALL")&&reverseKinds.includes("CALL");
  }).map(edge=>edge.ordinal));
  const adjacency=new Map((structureReport?.routines??[]).map(r=>[r.id,[]]));
  for(const edge of narrative)if(!ordinaryReturns.has(edge.ordinal))adjacency.get(edge.from)?.push(edge.to);
  let next=0;const index=new Map(),low=new Map(),stack=[],onStack=new Set(),component=new Map(),componentSize=new Map(),components=[];
  function visit(v){index.set(v,next);low.set(v,next++);stack.push(v);onStack.add(v);
    for(const w of adjacency.get(v)??[]){if(!index.has(w)){visit(w);low.set(v,Math.min(low.get(v),low.get(w)))}else if(onStack.has(w))low.set(v,Math.min(low.get(v),index.get(w)))}
    if(low.get(v)===index.get(v)){const members=[];let w;do{w=stack.pop();onStack.delete(w);members.push(w)}while(w!==v);const cid=components.length;components.push(members);for(const id of members)component.set(id,cid);componentSize.set(cid,members.length)}}
  for(const id of adjacency.keys())if(!index.has(id))visit(id);
  return narrative.map(edge=>{
    const cid=component.get(edge.from),size=componentSize.get(cid)??1,inCycle=component.get(edge.to)===cid&&size>1;
    const cycle=ordinaryReturns.has(edge.ordinal)||!inCycle?null:size>2?"multi-routine cycle":"mutual cycle";
    return {...edge,cycle,cycle_size:cycle?size:0};
  });
}
const routineNarrative=classifyNarrativeCycles();
const cycleRoutineIds=new Set(routineNarrative.filter(e=>e.cycle).flatMap(e=>[e.from,e.to]));
const routineDisplayLabels=new Map((structureReport?.routines??[]).map(r=>{
  const tags=new Set(r.tags??[]),descriptors=[];
  if(tags.has("entry"))descriptors.push("program entry");
  else if(tags.has("image-entry"))descriptors.push(`${r.image?.name?.replace(/\.OVL$/i,"")??"image"} entry`);
  if(r.recursive||tags.has("recursive"))descriptors.push("recursive");
  if(cycleRoutineIds.has(r.id))descriptors.push("cycle participant");
  return [r.id,[r.display,...descriptors].join(" · ")];
}));
const routineLabel=id=>routineDisplayLabels.get(id)??routineById.get(id)?.display??`R${String(id).padStart(3,"0")}`;
const routineNodes=(structureReport?.routines??[]).map(r=>({id:routineNodeId(r.id),data:{routine_id:r.id,label:routineLabel(r.id),recursive:r.recursive,self_calls:r.self_calls}}));
const routineEdges=routineNarrative.map(edge=>({id:narrativeEdgeId(edge.ordinal),source:routineNodeId(edge.from),target:routineNodeId(edge.to),data:{ordinal:edge.ordinal,kind:edge.kind,kinds:aggregateRoutineEdges.get(`${edge.from}:${edge.to}`)?.kinds??[edge.kind],first_step:edge.first_step,from:edge.from,to:edge.to,cycle:edge.cycle,cycle_size:edge.cycle_size}}));
const routineEdgeById=new Map(routineEdges.map(e=>[e.id,e]));
const routineKindColors={CALL:"#2878b5",RETURN:"#c47c08",RST:"#7851a9",IMAGE_ENTRY:"#27835e",OTHER:"#687785"};
function routineNeighborhood(id){const ids=new Set([id]);for(const edge of routineNarrative)if(edge.from===id||edge.to===id){ids.add(edge.from);ids.add(edge.to)}
  return {ids,edges:routineEdges.filter(e=>ids.has(e.data.from)&&ids.has(e.data.to))};}
function updateRoutineGraphState(focusOrdinal=activeNarrativeOrdinal){
  if(!routineGraph)return;
  const states={};for(const node of routineGraphData.nodes)states[node.id]=[];
  for(const edge of routineGraphData.edges)states[edge.id]=[];
  const incident=new Set();
  for(const edge of routineGraphData.edges)if(edge.data.from===window.__selectedRoutine||edge.data.to===window.__selectedRoutine){states[edge.id]=["incident"];incident.add(edge.data.from);incident.add(edge.data.to)}
  for(const id of incident)states[routineNodeId(id)]=["neighbor"];
  if(window.__selectedRoutine!=null)states[routineNodeId(window.__selectedRoutine)]=["selected"];
  if(focusOrdinal!=null){const edge=routineEdgeById.get(narrativeEdgeId(focusOrdinal));if(edge&&routineGraphData.edges.some(e=>e.id===edge.id)){states[edge.id]=["focus"];states[edge.source]=["endpoint"];states[edge.target]=["endpoint"]}}
  routineGraph.setElementState(states,false);
}
async function renderRoutineGraph(){
  if(!hasStructure)return;
  const allNodes=routineNodes,allEdges=routineEdges;
  const neighborhood=routineGraphMode==="neighborhood"?routineNeighborhood(window.__selectedRoutine??0):null;
  const nodes=neighborhood?allNodes.filter(n=>neighborhood.ids.has(n.data.routine_id)):allNodes;
  const edges=neighborhood?neighborhood.edges:allEdges;
  routineGraphData={nodes,edges};
  if(routineGraph){routineGraph.destroy();routineGraph=null;}
  const local=routineGraphMode==="neighborhood";
  routineGraph=new Graph({container:"routine-graph",width:document.querySelector("#routine-graph").clientWidth,height:650,
    data:routineGraphData,layout:{type:"circular",radius:local?230:280,ordering:null,startAngle:-Math.PI/2},
    behaviors:["drag-canvas","zoom-canvas","click-select"],
    node:{type:"circle",style:{size:local?18:8,fill:d=>d.id===routineNodeId(window.__selectedRoutine)?"#f2b84b":"#91b6d2",
      stroke:d=>d.id===routineNodeId(window.__selectedRoutine)?"#694d00":"#45667e",lineWidth:1,
      labelText:d=>local?d.data.label:"",labelFontSize:11,labelPlacement:"right",labelBackground:true,labelBackgroundFill:"#ffffff",labelBackgroundOpacity:0.9},
      state:{selected:{fill:"#f2b84b",stroke:"#694d00",lineWidth:2,labelText:d=>d.data.label,labelFontSize:12},neighbor:{fill:"#c5e3f5",stroke:"#37708f",lineWidth:2},endpoint:{fill:"#f8d56b",stroke:"#7c5510",lineWidth:2}}},
    edge:{type:"quadratic",style:{stroke:d=>d.data.cycle?"#b42365":(routineKindColors[d.data.kind]??"#687785"),
      strokeOpacity:local?0.72:0.16,lineWidth:d=>d.data.cycle?2.2:1,endArrow:true,endArrowSize:6,
      curveOffset:d=>{const reverse=routineNarrative.some(x=>x.from===d.data.to&&x.to===d.data.from);return reverse?(d.data.from<d.data.to?16:-16):5},
      lineDash:d=>d.data.cycle?[5,3]:undefined,labelText:d=>local?`${d.data.ordinal} ${d.data.kind}`:"",labelFontSize:9},
      state:{incident:{stroke:"#253746",strokeOpacity:0.88,lineWidth:2},focus:{stroke:"#111820",strokeOpacity:1,lineWidth:4},selected:{stroke:"#111820",strokeOpacity:1,lineWidth:4}}}});
  await routineGraph.render();await routineGraph.fitView();
  const onRoutineNodeClick=event=>{const id=event.target?.id??event.data?.id;const routineId=Number(String(id).replace(/^routine:/,""));if(routineById.has(routineId))selectRoutine(routineId)};
  const onRoutineEdgeClick=event=>{const id=event.target?.id??event.data?.id;const edge=routineEdgeById.get(id);if(edge)highlightNarrative(edge.data.ordinal)};
  routineGraph.on("node:click",onRoutineNodeClick);
  routineGraph.on("edge:click",onRoutineEdgeClick);
  updateRoutineGraphState();
  const cycleEdges=edges.filter(e=>e.data.cycle).length;
  document.querySelector("#routine-graph-meta").textContent=`${local?"Selected-routine 1-hop neighborhood":"Global narrative topology"} · ${nodes.length} routine nodes / ${edges.length} unique directed pairs · ${cycleEdges} dashed cycle-participating edges · circular layout preserves cycles; no frequency sizing.`;
  window.__routineGraphCounts={nodes:nodes.length,edges:edges.length,cycleEdges,mode:routineGraphMode};
  window.__routineGraphLabels=nodes.map(n=>n.data.label);window.__routineGraphPairs=edges.map(e=>({ordinal:e.data.ordinal,from:e.data.from,to:e.data.to,kind:e.data.kind,kinds:e.data.kinds,cycle:e.data.cycle}));
  window.__selectRoutineFromGraph=id=>onRoutineNodeClick({target:{id:routineNodeId(id)}});
  window.__focusNarrativeFromGraph=ordinal=>onRoutineEdgeClick({target:{id:narrativeEdgeId(ordinal)}});
}
let routineGraphData={nodes:[],edges:[]};
function highlightNarrative(ordinal){
  const edge=narrativeByOrdinal.get(ordinal);if(!edge)return;
  activeNarrativeOrdinal=ordinal;selectRoutine(edge.to,true);
  const classified=routineNarrative.find(e=>e.ordinal===ordinal);
  const from=routineById.get(edge.from),to=routineById.get(edge.to);
  document.querySelector("#routine-edge-detail").textContent=`#${String(ordinal).padStart(3,"0")} ${routineLabel(edge.from)} → ${routineLabel(edge.to)} · ${edge.kind} · first step ${edge.first_step}${classified?.cycle?` · ${classified.cycle} (${classified.cycle_size} candidates)`:" · not marked as a multi-routine cycle"}`;
  window.__routineFocus={ordinal,from:edge.from,to:edge.to,cycle:classified?.cycle??null};
  if(routineGraphMode==="neighborhood"&&routineGraph&&(!routineGraphData.nodes.some(n=>n.data.routine_id===edge.from)||!routineGraphData.nodes.some(n=>n.data.routine_id===edge.to)))void renderRoutineGraph();
  updateRoutineGraphState(ordinal);
}
function selectBlock(routineId, blockId) {
  if (routineId !== window.__selectedRoutine) { selectRoutine(routineId); setTimeout(() => selectBlock(routineId, blockId), 0); return; }
  const relation=canonicalContexts.find(c=>c.routine_id===routineId&&c.owner_block_id===blockId);
  const canonicalId=relation?.canonical_block_id??blockId;
  const el = document.querySelector(`#canonical-block-${canonicalId}`);
  if (el) { el.open = true; el.scrollIntoView({behavior:"smooth",block:"center"}); }
}
const timelineSvgNamespace="http://www.w3.org/2000/svg";
const timelineImageColors=["#2878b5","#27835e","#a35c9f","#c47c08","#526d82"];
function renderStructureTimeline(routines){
  const groupsByImage=new Map();
  for(const routine of routines){
    const image=routine.image;
    const key=image?`${image.drive}:${image.user}:${image.name}`:"unresolved";
    let group=groupsByImage.get(key);
    if(!group){group={key,imageName:image?.name??"unresolved image origin",routines:[],firstStep:null};groupsByImage.set(key,group)}
    group.routines.push(routine);
    if(routine.first_step!=null&&(group.firstStep==null||routine.first_step<group.firstStep))group.firstStep=routine.first_step;
  }
  const groups=[...groupsByImage.values()].sort((a,b)=>
    (a.firstStep??Number.MAX_SAFE_INTEGER)-(b.firstStep??Number.MAX_SAFE_INTEGER)||a.imageName.localeCompare(b.imageName));
  const runEnd=Number(report.execution.execution_summary?.total);
  const imageLandmarks=(report.execution.images??[]).filter(image=>image.first_execution_step!=null).map(image=>{
    const imageName=image.id?.name??image.display_name;
    const entry=structureReport.narrative.find(edge=>edge.kind==="IMAGE_ENTRY"&&
      structureReport.routines.find(routine=>routine.id===edge.to)?.image?.name===imageName);
    return {image:imageName,step:image.first_execution_step,entry_kind:entry?.kind??(image.first_execution_step===0?"PROGRAM_ENTRY":"FIRST_EXECUTION"),routine_id:entry?.to??null};
  });
  const imageReads=(report.execution.images??[]).filter(image=>image.first_record_read_step!=null&&image.last_record_read_step!=null)
    .map(image=>({image:image.id?.name??image.display_name,start:image.first_record_read_step,end:image.last_record_read_step}));
  const writesByStep=new Map();
  for(const byte of report.output_bytes??[])if(Number.isFinite(byte.write_step)){
    const offsets=writesByStep.get(byte.write_step)??[];offsets.push(byte.offset);writesByStep.set(byte.write_step,offsets);
  }
  const outputWrites=[];
  for(const [step,offsets] of writesByStep){
    offsets.sort((a,b)=>a-b);let first=null,last=null;
    for(const offset of offsets){if(first==null){first=last=offset}else if(offset===last+1)last=offset;else{outputWrites.push({step,first,last});first=last=offset}}
    if(first!=null)outputWrites.push({step,first,last});
  }
  outputWrites.sort((a,b)=>a.step-b.step||a.first-b.first);
  const stepEnds=routines.flatMap(r=>[r.first_step,r.last_step]).filter(Number.isFinite);
  for(const transition of structureReport.transitions??[])for(const step of [transition.first_step,transition.last_step])if(Number.isFinite(step))stepEnds.push(step);
  for(const image of imageLandmarks)stepEnds.push(image.step);
  for(const read of imageReads)stepEnds.push(read.start,read.end);
  for(const write of outputWrites)stepEnds.push(write.step);
  if(Number.isFinite(runEnd))stepEnds.push(runEnd);
  const axisStart=0,axisEnd=Math.max(1,...stepEnds),width=1120,left=280,right=910,plotWidth=right-left;
  const label=(text,attrs={})=>{const node=document.createElementNS(timelineSvgNamespace,"text");node.textContent=text;for(const [name,value] of Object.entries(attrs))node.setAttribute(name,String(value));return node};
  const axis=document.querySelector("#structure-timeline-axis");axis.replaceChildren();
  const axisSvg=document.createElementNS(timelineSvgNamespace,"svg");axisSvg.setAttribute("viewBox",`0 0 ${width} 38`);axisSvg.setAttribute("role","img");axisSvg.setAttribute("aria-label",`Step index axis from ${axisStart} to ${axisEnd}`);
  axisSvg.append(label("routine / image",{x:8,y:28,class:"timeline-axis-label"}));
  axisSvg.append(label("first / last observed step",{x:left,y:10,class:"timeline-axis-label"}));
  axisSvg.append(label("executions",{x:930,y:28,class:"timeline-axis-label"}));
  for(let i=0;i<=4;i++){
    const step=Math.round(axisStart+(axisEnd-axisStart)*i/4),x=left+plotWidth*i/4;
    const line=document.createElementNS(timelineSvgNamespace,"line");line.setAttribute("x1",String(x));line.setAttribute("x2",String(x));line.setAttribute("y1","15");line.setAttribute("y2","35");line.setAttribute("class","timeline-gridline");axisSvg.append(line);
    axisSvg.append(label(step.toLocaleString("en-US"),{x,y:35,class:"timeline-tick","text-anchor":i===0?"start":i===4?"end":"middle"}));
  }
  axis.append(axisSvg);
  const landmarkRoot=document.querySelector("#structure-landmark-lane");landmarkRoot.replaceChildren();
  const landmarkSvg=document.createElementNS(timelineSvgNamespace,"svg");landmarkSvg.setAttribute("viewBox",`0 0 ${width} 132`);landmarkSvg.setAttribute("role","group");landmarkSvg.setAttribute("aria-label","Factual image reads, first executions, output writes, and run boundaries on the execution-step axis");
  const xFor=step=>left+plotWidth*step/axisEnd;
  for(let i=0;i<=4;i++){const x=left+plotWidth*i/4;const line=document.createElementNS(timelineSvgNamespace,"line");line.setAttribute("x1",String(x));line.setAttribute("x2",String(x));line.setAttribute("y1","4");line.setAttribute("y2","126");line.setAttribute("class","landmark-gridline");landmarkSvg.append(line)}
  const detail=document.querySelector("#structure-landmark-detail");
  const addInteractive=(kind,description,draw,metadata={})=>{
    const group=document.createElementNS(timelineSvgNamespace,"g");group.classList.add("timeline-landmark",`landmark-${kind}`);group.dataset.landmarkKind=kind;group.setAttribute("tabindex","0");group.setAttribute("role","button");group.setAttribute("aria-label",description);
    for(const [name,value] of Object.entries(metadata))group.dataset[name]=String(value);
    const title=document.createElementNS(timelineSvgNamespace,"title");title.textContent=description;group.append(title);draw(group);
    const show=()=>{detail.textContent=description};group.addEventListener("mouseenter",show);group.addEventListener("focus",show);group.addEventListener("click",show);group.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();show()}});landmarkSvg.append(group);return group;
  };
  const rowLabel=(text,y)=>landmarkSvg.append(label(text,{x:8,y:y+4,class:"landmark-row-label"}));
  const imageNames=new Set([...imageReads.map(x=>x.image),...imageLandmarks.filter(x=>x.step>0).map(x=>x.image)]);
  const orderedImages=[...imageNames].sort((a,b)=>{
    const ai=imageReads.find(x=>x.image===a)?.start??imageLandmarks.find(x=>x.image===a)?.step??0;
    const bi=imageReads.find(x=>x.image===b)?.start??imageLandmarks.find(x=>x.image===b)?.step??0;return ai-bi||a.localeCompare(b);
  });
  const rowGap=20,firstImageY=13;
  orderedImages.forEach((imageName,index)=>{
    const y=firstImageY+index*rowGap;rowLabel(`read ${imageName}`,y);
    const read=imageReads.find(x=>x.image===imageName);
    if(read){const x1=xFor(read.start),x2=xFor(read.end),intervalDescription=`Image loading · successful record-read interval · ${imageName} · steps ${read.start.toLocaleString("en-US")}–${read.end.toLocaleString("en-US")}`;
      addInteractive("io",intervalDescription,g=>{const bar=document.createElementNS(timelineSvgNamespace,"rect");bar.setAttribute("x",String(x1));bar.setAttribute("y",String(y-3));bar.setAttribute("width",String(Math.max(1,x2-x1)));bar.setAttribute("height","6");bar.setAttribute("rx","2");bar.setAttribute("class","landmark-read-bar");g.append(bar);for(const x of [x1,x2]){const cap=document.createElementNS(timelineSvgNamespace,"line");cap.setAttribute("x1",String(x));cap.setAttribute("x2",String(x));cap.setAttribute("y1",String(y-5));cap.setAttribute("y2",String(y+5));cap.setAttribute("class","landmark-read-cap");g.append(cap)}},{image:imageName,start:read.start,end:read.end});
    }
    const execution=imageLandmarks.find(x=>x.image===imageName);
    if(execution){const routine=execution.routine_id==null?null:structureReport.routines.find(x=>x.id===execution.routine_id);const step=execution.step;
      const description=`Image execution · ${execution.entry_kind=== "IMAGE_ENTRY"?"IMAGE_ENTRY / first observed execution":"first observed execution"} · ${imageName} · step ${step.toLocaleString("en-US")}${routine?` · ${routine.display}`:""}`;
      addInteractive("entry",description,g=>{const x=xFor(step),diamond=document.createElementNS(timelineSvgNamespace,"path");diamond.setAttribute("d",`M ${x} ${y+1} l 5 5 l -5 5 l -5 -5 Z`);diamond.setAttribute("class","landmark-entry-marker");g.append(diamond)},{image:imageName,step,routineId:execution.routine_id??""});
    }
  });
  const writesY=firstImageY+orderedImages.length*rowGap+2;rowLabel(`write ${report.output_file.name}`,writesY);
  for(const write of outputWrites){
    const range=`+${write.first.toString(16).toUpperCase().padStart(4,"0")}h–+${write.last.toString(16).toUpperCase().padStart(4,"0")}h`;
    const description=`Output record write · ${report.output_file.name} · byte range ${range} · step ${write.step.toLocaleString("en-US")}`;
    addInteractive("write",description,g=>{const x=xFor(write.step),line=document.createElementNS(timelineSvgNamespace,"line");line.setAttribute("x1",String(x));line.setAttribute("x2",String(x));line.setAttribute("y1",String(writesY-5));line.setAttribute("y2",String(writesY+5));line.setAttribute("class","landmark-write-marker");g.append(line);const square=document.createElementNS(timelineSvgNamespace,"rect");square.setAttribute("x",String(x-3));square.setAttribute("y",String(writesY-3));square.setAttribute("width","6");square.setAttribute("height","6");square.setAttribute("class","landmark-write-square");g.append(square)},{step:write.step,firstOffset:write.first,lastOffset:write.last});
  }
  const boundaryY=writesY+rowGap;rowLabel("run boundaries",boundaryY);
  const startDescription=`Execution start · step ${axisStart.toLocaleString("en-US")} · PLI.COM first observed execution`;
  addInteractive("boundary",startDescription,g=>{const x=xFor(axisStart),line=document.createElementNS(timelineSvgNamespace,"line");line.setAttribute("x1",String(x));line.setAttribute("x2",String(x));line.setAttribute("y1",String(boundaryY-6));line.setAttribute("y2",String(boundaryY+6));line.setAttribute("class","landmark-start-marker");g.append(line)},{step:axisStart,boundary:"start"});
  const initialImage=imageLandmarks.find(image=>image.step===axisStart);
  if(initialImage){const description=`Image execution · program entry / first observed execution · ${initialImage.image} · step ${axisStart.toLocaleString("en-US")}`;
    addInteractive("entry",description,g=>{const x=xFor(axisStart),circle=document.createElementNS(timelineSvgNamespace,"circle");circle.setAttribute("cx",String(x));circle.setAttribute("cy",String(boundaryY-7));circle.setAttribute("r","4");circle.setAttribute("class","landmark-entry-marker");g.append(circle)},{image:initialImage.image,step:axisStart,routineId:initialImage.routine_id??""});
  }
  if(Number.isFinite(runEnd)){const endDescription=`Run end · execution-summary step boundary ${runEnd.toLocaleString("en-US")} · termination reason is not present in the loaded report`;
    addInteractive("boundary",endDescription,g=>{const x=xFor(runEnd),line=document.createElementNS(timelineSvgNamespace,"line");line.setAttribute("x1",String(x));line.setAttribute("x2",String(x));line.setAttribute("y1",String(boundaryY-6));line.setAttribute("y2",String(boundaryY+6));line.setAttribute("class","landmark-end-marker");g.append(line)},{step:runEnd,boundary:"end"});
  }
  landmarkRoot.append(landmarkSvg);
  const laneHeight=boundaryY+14;landmarkSvg.setAttribute("viewBox",`0 0 ${width} ${laneHeight}`);
  window.__structureLandmarkFacts={axisEnd,reads:imageReads,entries:imageLandmarks,writes:outputWrites,run_start:axisStart,run_end:Number.isFinite(runEnd)?runEnd:null};
  const progression=document.querySelector("#structure-timeline-progression");progression.replaceChildren();
  progression.append(document.createTextNode("First observed image appearances: "));
  const observedGroups=groups.filter(group=>group.firstStep!=null);
  for(const [index,group] of observedGroups.entries()){
    if(index)progression.append(document.createTextNode("  →  "));
    const firstRoutine=[...group.routines].filter(r=>r.first_step===group.firstStep).sort((a,b)=>a.id-b.id)[0];
    const button=document.createElement("button");button.type="button";button.className="timeline-appearance";
    button.textContent=`${group.imageName} · step ${group.firstStep.toLocaleString("en-US")}`;
    button.title=`Select first observed routine ${firstRoutine?routineLabel(firstRoutine.id):""} in ${group.imageName}`;
    if(firstRoutine)button.addEventListener("click",()=>selectRoutine(firstRoutine.id));
    progression.append(button);
  }
  const timeline=document.querySelector("#structure-timeline");timeline.replaceChildren();
  const rowHeight=21,groupHeaderHeight=27,top=8;
  const height=top+groups.reduce((sum,group)=>sum+groupHeaderHeight+group.routines.length*rowHeight,0)+8;
  const svg=document.createElementNS(timelineSvgNamespace,"svg");svg.setAttribute("viewBox",`0 0 ${width} ${height}`);svg.setAttribute("role","list");svg.setAttribute("aria-label",`${routines.length} routine observation envelopes from step ${axisStart} to ${axisEnd}`);
  const rowFacts=[];let y=top;
  for(const [groupIndex,group] of groups.entries()){
    const color=timelineImageColors[groupIndex%timelineImageColors.length];
    const groupTitle=label(`${group.imageName} · first observed ${group.firstStep==null?"unknown":`step ${group.firstStep.toLocaleString("en-US")}`} · ${group.routines.length} routines`,{x:8,y:y+17,class:"timeline-image-heading",fill:color});svg.append(groupTitle);y+=groupHeaderHeight;
    const ordered=group.routines.slice().sort((a,b)=>(a.first_step??Number.MAX_SAFE_INTEGER)-(b.first_step??Number.MAX_SAFE_INTEGER)||a.id-b.id);
    for(const routine of ordered){
      const row=document.createElementNS(timelineSvgNamespace,"g");row.classList.add("timeline-routine");row.setAttribute("data-routine-id",String(routine.id));row.setAttribute("role","listitem");row.setAttribute("tabindex","0");row.setAttribute("aria-label",`${routineLabel(routine.id)} · ${routine.image?.name??"unresolved image"} · first step ${routine.first_step??"unknown"} · last step ${routine.last_step??"unknown"} · ${routine.executions} executions`);
      const start=routine.first_step,end=routine.last_step;
      const details=`${routineLabel(routine.id)}\nImage: ${routine.image?.name??"unresolved image origin"}\nFirst observed step: ${start??"unknown"}\nLast observed step: ${end??"unknown"}\nInstruction execution count: ${routine.executions}`;
      const title=document.createElementNS(timelineSvgNamespace,"title");title.textContent=details;row.append(title);
      const hitArea=document.createElementNS(timelineSvgNamespace,"rect");hitArea.setAttribute("x","0");hitArea.setAttribute("y",String(y-rowHeight/2));hitArea.setAttribute("width",String(width));hitArea.setAttribute("height",String(rowHeight));hitArea.setAttribute("class","timeline-hit-area");row.append(hitArea);
      const rowLabel=label(`R${String(routine.id).padStart(3,"0")} · ${routine.offset==null?"unresolved":Number(routine.offset).toString(16).toUpperCase().padStart(4,"0")}`,{x:8,y:y+4,class:"timeline-routine-label"});row.append(rowLabel);
      if(start!=null&&end!=null){
        const x1=left+plotWidth*start/axisEnd,x2=left+plotWidth*end/axisEnd;
        const envelope=document.createElementNS(timelineSvgNamespace,"line");envelope.setAttribute("x1",String(x1));envelope.setAttribute("x2",String(Math.max(x1+1,x2)));envelope.setAttribute("y1",String(y));envelope.setAttribute("y2",String(y));envelope.setAttribute("class","timeline-envelope");envelope.setAttribute("stroke",color);row.append(envelope);
        const first=document.createElementNS(timelineSvgNamespace,"circle");first.setAttribute("cx",String(x1));first.setAttribute("cy",String(y));first.setAttribute("r","4");first.setAttribute("class","timeline-first-marker");first.setAttribute("fill",color);row.append(first);
        const last=document.createElementNS(timelineSvgNamespace,"path");last.setAttribute("d",`M ${x2} ${y-4} L ${x2+4} ${y} L ${x2} ${y+4} L ${x2-4} ${y} Z`);last.setAttribute("class","timeline-last-marker");last.setAttribute("fill",color);row.append(last);
      }
      row.append(label(`${routine.executions.toLocaleString("en-US")}`,{x:930,y:y+4,class:"timeline-execution-count"}));
      const activate=()=>selectRoutine(routine.id);
      row.addEventListener("click",activate);row.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();activate()}});
      svg.append(row);rowFacts.push({routine_id:routine.id,image:group.imageName,first_step:start,last_step:end,executions:routine.executions});y+=rowHeight;
    }
  }
  timeline.append(svg);
  window.__structureTimelineFacts={routineCount:rowFacts.length,axisStart,axisEnd,groups:groups.map(group=>({image:group.imageName,first_step:group.firstStep,routines:group.routines.length})),rows:rowFacts};
}
function updateTimelineSelection(routineId){
  for(const row of document.querySelectorAll("#structure-timeline [data-routine-id]")){
    const selected=Number(row.getAttribute("data-routine-id"))===routineId;
    row.classList.toggle("selected",selected);row.setAttribute("aria-current",selected?"true":"false");
  }
}
function selectRoutine(id, preserveNarrative=false) {
  if (!hasStructure || !routineById.has(id)) return;
  if(!preserveNarrative)activeNarrativeOrdinal=null;
  const routine = routineById.get(id), detail = document.querySelector("#routine-detail");
  window.__selectedRoutine = id;
  updateTimelineSelection(id);
  detail.replaceChildren();
  const heading = document.createElement("div"); heading.className = "routine-head";
  const title = document.createElement("h2"); title.textContent = routineLabel(routine.id); heading.append(title);
  for (const tag of routine.tags) { const badge=document.createElement("span"); badge.className=`routine-badge ${tag === "recursive" ? "recursive" : ""}`; badge.textContent=tag; heading.append(badge); }
  detail.append(heading);
  const metrics=document.createElement("div");metrics.className="routine-metrics";
  const image=routine.image ? `${String.fromCharCode(65+routine.image.drive)}:${routine.image.user}:${routine.image.name}` : "unresolved image origin";
  const values=[`entry ${image}+${hexOffset(routine.offset)} @${hexOffset(routine.runtime_entry_pc)}`,
    `steps ${routine.first_step ?? "?"}–${routine.last_step ?? "?"}`,`${routine.executions} instruction executions`,
    `${routine.distinct_starts} distinct starts`,`incoming ${routine.incoming} · outgoing ${routine.outgoing}`,
    `calls ${routine.calls} · returns ${routine.returns}`,`self calls ${routine.self_calls}`];
  for(const value of values){const span=document.createElement("span");span.textContent=value;metrics.append(span)}detail.append(metrics);
  const relations=canonicalContexts.filter(c=>c.routine_id===id);
  const byCanonicalBlock=new Map();
  for(const relation of relations){const entries=byCanonicalBlock.get(relation.canonical_block_id)??[];entries.push(relation);byCanonicalBlock.set(relation.canonical_block_id,entries)}
  const contexts=[...byCanonicalBlock.entries()].map(([blockId,entries])=>({block:canonicalBlockById.get(blockId),entries}))
    .filter(x=>x.block).sort((a,b)=>a.block.id-b.block.id);
  const allRelationsByBlock=new Map();for(const relation of canonicalContexts){const entries=allRelationsByBlock.get(relation.canonical_block_id)??[];entries.push(relation);allRelationsByBlock.set(relation.canonical_block_id,entries)}
  const sharedCount=contexts.filter(({block})=>new Set((allRelationsByBlock.get(block.id)??[]).map(x=>x.routine_id)).size>1).length;
  const splitCount=relations.filter(x=>x.split_from_owner_block).length;
  const blockTitle=document.createElement("h3");blockTitle.textContent=`Observed code contexts · ${contexts.length} canonical blocks · shared with other candidates ${sharedCount}${splitCount?` · ${splitCount} union-split relations`:""}`;detail.append(blockTitle);
  const blockRoot=document.createElement("div");blockRoot.id="routine-blocks";
  for(const {block,entries} of contexts){
    const otherRoutines=[...new Set((allRelationsByBlock.get(block.id)??[]).map(x=>x.routine_id).filter(x=>x!==id))].sort((a,b)=>a-b);
    const tags=[...new Set(entries.flatMap(x=>x.tags))];
    const executionCount=entries.reduce((n,x)=>n+x.execution_count,0),entryCount=entries.reduce((n,x)=>n+x.entry_count,0);
    const firstStep=Math.min(...entries.map(x=>x.first_step)),lastStep=Math.max(...entries.map(x=>x.last_step));
    const instructionCount=block.instruction_offsets.length;
    const image=block.image, imageKey=imageCoordinateKey(image);
    const startHex=Number(block.start_offset).toString(16).toUpperCase().padStart(4,"0"),endHex=Number(block.end_offset).toString(16).toUpperCase().padStart(4,"0");
    const card=document.createElement("details");card.className="block-card canonical-context-card";card.id=`canonical-block-${block.id}`;
    const summary=document.createElement("summary");summary.textContent=`${image.name}+${startHex} [${startHex},${endHex}) · ${block.end_offset-block.start_offset} bytes`;card.append(summary);
    if(otherRoutines.length){const shared=document.createElement("span");shared.className="block-tag shared-context";shared.textContent=`shared · ${otherRoutines.length} other candidates`;card.append(shared)}
    if(entries.some(x=>x.split_from_owner_block)){const split=document.createElement("span");split.className="block-tag union-split";split.textContent="union split";card.append(split)}
    const meta=document.createElement("div");meta.className="block-meta";
    meta.textContent=`${instructionCount} canonical instructions · this routine: ${executionCount} executions · entries ${entryCount} · steps ${Number.isFinite(firstStep)?firstStep:"?"}–${Number.isFinite(lastStep)?lastStep:"?"} · contextual tags ${tags.join(", ")||"none"}`;card.append(meta);
    const contextsLine=document.createElement("div");contextsLine.className="block-meta";contextsLine.append(document.createTextNode(`Observed routine contexts: ${routineLabel(id)}${otherRoutines.length?" · shared with ":""}`));
    for(const otherId of otherRoutines){const button=document.createElement("button");button.type="button";button.className="routine-link context-link";button.textContent=routineLabel(otherId);button.title=`Navigate to ${routineLabel(otherId)}`;button.addEventListener("click",event=>{event.preventDefault();event.stopPropagation();selectRoutine(otherId)});contextsLine.append(button)}
    card.append(contextsLine);
    const codeDetails=document.createElement("details");const codeSummary=document.createElement("summary");codeSummary.textContent=`Canonical 8080 instructions (${block.instruction_offsets.length})`;codeDetails.append(codeSummary);
    let rendered=false;codeDetails.addEventListener("toggle",()=>{if(!codeDetails.open||rendered)return;rendered=true;const list=document.createElement("ol");list.className="instruction-list";
      for(const offset of block.instruction_offsets){const ins=canonicalInstructionByCoordinate.get(`${imageKey}:${offset}`);if(!ins)continue;const ctx=instructionContext(ins,id);const line=document.createElement("li");const pcs=ctx?.runtime_pcs?.map(pc=>hexOffset(pc)).join(", ")??"runtime PC unresolved";line.textContent=`${hexOffset(offset)}  ${ins.text}  · ${ctx?.execution_count??0} executions · ${pcs} · steps ${ctx?.first_step??"?"}–${ctx?.last_step??"?"}`;list.append(line)}codeDetails.append(list);});
    card.append(codeDetails);blockRoot.append(card);
  }
  detail.append(blockRoot);
  const localNarrative=(blocksReport.narrative??[]).filter(e=>e.from[0]===id);
  const edgeTitle=document.createElement("h3");edgeTitle.textContent=`Block-level narrative transitions · ${localNarrative.length}`;detail.append(edgeTitle);
  const edgeList=document.createElement("ol");edgeList.className="block-transitions";
  for(const edge of localNarrative){const item=document.createElement("li");const from=document.createElement("button");from.className="routine-link";from.textContent=`R${String(edge.from[0]).padStart(3,"0")}.B${String(edge.from[1]).padStart(3,"0")}`;from.addEventListener("click",()=>selectBlock(edge.from[0],edge.from[1]));const arrow=document.createTextNode(" → ");const to=document.createElement("button");to.className="routine-link";to.textContent=`R${String(edge.to[0]).padStart(3,"0")}.B${String(edge.to[1]).padStart(3,"0")}`;to.addEventListener("click",()=>selectBlock(edge.to[0],edge.to[1]));const kind=document.createTextNode(` · ${edge.kind} · first step ${edge.first_step}`);item.append(from,arrow,to,kind);edgeList.append(item)}
  detail.append(edgeList);detail.scrollIntoView({behavior:"smooth",block:"start"});
  window.__selectedRoutineBlocks=contexts.length;window.__selectedRoutineNarrative=localNarrative.length;
  window.__selectedCodeContextSummary={routine_id:id,canonical_blocks:contexts.length,shared_blocks:sharedCount,split_relations:splitCount};
  window.__selectedCodeContexts=contexts.map(({block})=>({id:block.id,image:block.image.name,start:block.start_offset,end:block.end_offset,owners:[...new Set((allRelationsByBlock.get(block.id)??[]).map(x=>x.routine_id))].sort((a,b)=>a-b)}));
  const cycleEdges=routineNarrative.filter(e=>(e.from===id||e.to===id)&&e.cycle).length;
  document.querySelector("#routine-edge-detail").textContent=`Selected ${routineLabel(id)}: ${routineNarrative.filter(e=>e.from===id||e.to===id).length} incoming/outgoing first-observation edges highlighted · ${cycleEdges} participate in a multi-routine or mutual cycle.`;
  if(routineGraphMode==="neighborhood"&&routineGraph)void renderRoutineGraph();else updateRoutineGraphState();
}
async function initializeStructureView(){
  if(!hasStructure){window.__structureReady=true;return;}
  window.__canonicalCodeSummary={...canonicalCodeReport.summary};
  window.__canonicalBlocksForImage=imageName=>canonicalBlocks.filter(b=>b.image.name===imageName);
  window.__canonicalBlockOwners=blockId=>[...new Set(canonicalContexts.filter(c=>c.canonical_block_id===blockId).map(c=>c.routine_id))].sort((a,b)=>a-b);
  const routineRows=structureReport.routines.map(r=>({id:r.id,display:routineLabel(r.id),canonical:r.display,image:r.image?.name??"unknown",offset:r.offset,
    tags:r.tags.join(", "),recursive:r.recursive,first_step:r.first_step,last_step:r.last_step,executions:r.executions,
    distinct_starts:r.distinct_starts,incoming:r.incoming,outgoing:r.outgoing,calls:r.calls,returns:r.returns,self_calls:r.self_calls}));
  const narrativeRows=structureReport.narrative.map(e=>{const edge=aggregateRoutineEdges.get(`${e.from}:${e.to}`);return {ordinal:e.ordinal,from_id:e.from,
    from:routineLabel(e.from),to_id:e.to,to:routineLabel(e.to),
    first_kind:e.kind,first_step:e.first_step,count:edge?.count??1,kinds:edge?.kinds?.join(", ")??e.kind};});
  window.__structureRoutineRows=routineRows;window.__structureNarrativeRows=narrativeRows;
  renderStructureTimeline(structureReport.routines);
  for(const [selector,data,group_by,sort] of [["#structure-routines",routineRows,[],[["id","asc"]]],
      ["#structure-narrative",narrativeRows,[],[["ordinal","asc"]]]]){
    const old=viewerTables[selector],table=await worker.table(data.length?data:[{empty:"no rows"}]);await old.viewer.load(table);
    await old.viewer.restore({plugin:"Datagrid",group_by,sort});old.table.delete?.();viewerTables[selector]={...old,table,rows:data.length};
  }
  const s=structureReport.summary??{};document.querySelector("#structure-summary").textContent=
    `${s.routine_candidates??routineRows.length} routine candidates · ${s.narrative_transitions??narrativeRows.length} unique first-observation transitions · ${s.aggregate_pairs??structureReport.transitions.length} aggregate directed pairs · ${(structureReport.routines??[]).filter(r=>r.recursive).length} recursive candidates. Narrative rows refer back to one routine candidate each; counts are metadata, not ordering.`;
  window.__structureRows={routines:routineRows.length,narrative:narrativeRows.length};window.__structureSummary={...s};
  window.__tableGroups??={};window.__tableGroups["#structure-routines"]=[];window.__tableGroups["#structure-narrative"]=[];
  if(routineRows.length)selectRoutine(routineRows[0].id);
  window.__structureReady=true;
}
const codeImageNames=[...new Set((codeEvidence??[]).flatMap(run=>run.instructions.map(i=>i.image)))].sort();
function renderCodeEvidence(){
  if(!codeEvidence)return;
  const imageSelect=document.querySelector("#code-image");
  imageSelect.replaceChildren(...codeImageNames.map(name=>{const option=document.createElement("option");option.value=name;option.textContent=name;return option}));
  const coordinateMap=new Map();
  for(const run of codeEvidence)for(const instruction of run.instructions){
    if(!coordinateMap.has(instruction.image))coordinateMap.set(instruction.image,new Set());
    coordinateMap.get(instruction.image).add(instruction.offset);
  }
  const allOffsets=image=>[...(coordinateMap.get(image)??[])].sort((a,b)=>a-b);
  const evidenceFor=(image,offset)=>coordinateEvidence(codeEvidence,image,offset);
  const formatOffset=value=>Number(value).toString(16).toUpperCase().padStart(4,"0");
  function selectCoordinate(image,offset){
    imageSelect.value=image;document.querySelector("#code-offset").dataset.offset=String(offset);
    document.querySelector("#code-offset").value=`${image}+${formatOffset(offset)}`;
    const listing=document.querySelector("#code-listing");listing.replaceChildren();
    const offsets=allOffsets(image),begin=offsets.indexOf(offset),limit=Math.max(1,Math.min(80,Number(document.querySelector("#code-range-count").value)||24));
    let expected=offset,shown=0;
    for(const at of offsets.slice(Math.max(begin,0))){
      if(shown>0&&at!==expected)break;
      const data=evidenceFor(image,at),chosen=data.variants[0]?.members[0]?.instruction;
      const row=document.createElement("li"),button=document.createElement("button");button.type="button";button.className="code-instruction";button.dataset.offset=String(at);
      button.textContent=`${formatOffset(at)}  ${chosen?.bytes??"??"}  ${chosen?.text??"(no decoded observation)"}  · ${data.observations.filter(x=>x.instruction).length}/${codeEvidence.length} runs${data.byte_disagreement?" · BYTE VARIANT":""}`;
      button.addEventListener("click",()=>selectCoordinate(image,at));row.append(button);listing.append(row);shown++;
      const length=chosen?chosen.bytes.length/2:0;expected=at+length;if(shown>=limit||!length)break;
    }
    const status=document.querySelector("#code-coordinate-status");
    const present=offsets.includes(offset);
    status.textContent=present?`${image}+${formatOffset(offset)} · ${dataImageIdentity(image)} · ${shown} contiguous observed instruction starts shown. Code identity is checked against exact bytes.`:`${image}+${formatOffset(offset)} was not observed in these runs.`;
    document.querySelector("#code-summary").textContent=`${codeEvidence.length} runs · ${offsets.length.toLocaleString("en-US")} observed instruction coordinates in ${image}`;
    renderSelected(image,offset);
    window.__codeEvidenceNavigation={image,offset,listed:shown,observed:present};
  }
  function dataImageIdentity(name){
    const found=codeEvidence.find(r=>r.images.some(x=>x[0]===name))?.images.find(x=>x[0]===name);
    return found?`drive ${found[1]}, user ${found[2]}`:"image identity unavailable";
  }
  function renderSelected(image,offset){
    document.querySelector("#code-offset").dataset.offset=String(offset);
    const selectedEvidence=document.querySelector("#code-selected-evidence");selectedEvidence.replaceChildren();
    const coordinate=evidenceFor(image,offset),title=document.createElement("p");
    title.className=coordinate.byte_disagreement?"code-warning":"code-coordinate-title";
    title.textContent=coordinate.byte_disagreement?`${image}+${formatOffset(offset)} · BYTE VARIANT: observations remain separated by bytes.`:`${image}+${formatOffset(offset)} · ${coordinate.variants[0]?.bytes??"no bytes observed"} · ${coordinate.variants[0]?.members[0]?.instruction.text??"unobserved"}`;
    selectedEvidence.append(title);
    for(const observation of coordinate.observations){
      observation.runData=codeEvidence.find(x=>x.label===observation.run);
      const instruction=observation.instruction;
      const panel=document.createElement("article");panel.className="run-evidence";const head=document.createElement("h4");head.textContent=`${observation.run} · ${instruction?"OBSERVED":"NOT OBSERVED"}`;panel.append(head);
      if(!instruction){const absent=document.createElement("p");absent.textContent="Not observed at this image coordinate in this run.";panel.append(absent);selectedEvidence.append(panel);continue}
      const details=document.createElement("p");details.className="evidence-facts";
      details.textContent=`${instruction.image}+${formatOffset(instruction.offset)} · runtime PC ${instruction.runtime_pcs.map(x=>formatOffset(x)).join(", ")||"unknown"} · ${instruction.bytes} ${instruction.text} · executions ${instruction.executions} · steps ${instruction.first_step}–${instruction.last_step}`;panel.append(details);
      const contextsTitle=document.createElement("strong");contextsTitle.textContent="RoutineCandidate contexts · run-local analytical assignments";panel.append(contextsTitle);
      const runRoutines=new Map((observation.runData.routines??[]).map(r=>[r[0],r]));
      const contexts=instruction.contexts??[];
      const contextsNode=document.createElement("p");contextsNode.textContent=contexts.length?contexts.map(c=>{const r=runRoutines.get(c[0]);return `${r?.[1]??`R${String(c[0]).padStart(3,"0")}`} [entry ${r?.[2]??"?"}+${r?.[3]==null?"?":formatOffset(r[3])}] · ${c[1]} executions · ${r?.[4]?.join(",")||"no tags"}`}).join("; "):"none recorded";panel.append(contextsNode);
      const contextIds=new Set(contexts.map(c=>c[0]));
      const candidateTransitions=(observation.runData.routine_transitions??[]).filter(t=>contextIds.has(t.from)||contextIds.has(t.to));
      if(candidateTransitions.length){const relationHeading=document.createElement("strong");relationHeading.textContent="Observed aggregate transitions between these run-local candidates";panel.append(relationHeading);
        const relationList=document.createElement("ul");relationList.className="transfer-list";
        for(const t of candidateTransitions.slice(0,12)){const from=runRoutines.get(t.from),to=runRoutines.get(t.to),li=document.createElement("li");li.textContent=`${from?.[1]??`R${t.from}`} → ${to?.[1]??`R${t.to}`} · ${t.kinds.join(", ")} · ${t.count} observations · steps ${t.first_step}–${t.last_step}`;relationList.append(li)}
        panel.append(relationList);
      }
      const blocksTitle=document.createElement("strong");blocksTitle.textContent="Observed block partition(s)";panel.append(blocksTitle);
      const runBlocks=(observation.runData.blocks??[]).filter(b=>instruction.block_ids?.includes(b.id));
      if(!runBlocks.length){const p=document.createElement("p");p.textContent="No block partition available.";panel.append(p)}
      else for(const block of runBlocks){const p=document.createElement("p");p.textContent=`[${formatOffset(block.start)}, ${formatOffset(block.end)}) · ${block.byte_length} bytes · contexts ${block.contexts.map(c=>`R${String(c[0]).padStart(3,"0")} ${(c[1]??[]).join(",")||"no tags"}`).join("; ")||"none"}`;panel.append(p)}
      for(const kind of ["Incoming observed transfers","Outgoing observed transfers"]){
        const heading=document.createElement("strong");heading.textContent=kind;panel.append(heading);
        const list=document.createElement("ul");list.className="transfer-list";
        const incoming=kind.startsWith("Incoming"), edges=(observation.runData.transitions??[]).filter(t=>incoming?(t.to_image===image&&t.to_offset===offset):(t.from_image===image&&t.from_offset===offset));
        for(const transfer of edges.slice(0,12)){
          const other=incoming?{image:transfer.from_image,offset:transfer.from_offset}:{image:transfer.to_image,offset:transfer.to_offset};
          const counterpart=observation.runData.instructions.find(x=>x.image===other.image&&x.offset===other.offset);
          const li=document.createElement("li");li.textContent=`${other.image}+${formatOffset(other.offset)}${counterpart?` ${counterpart.text}`:""} · ${transfer.kind} · ${transfer.count} observations · steps ${transfer.first_step}–${transfer.last_step}`;list.append(li);
        }
        if(edges.length>12){const more=document.createElement("li");more.textContent=`${edges.length-12} more transfer rows omitted from this compact pane`;list.append(more)}
        if(!edges.length){const none=document.createElement("li");none.textContent="none retained";list.append(none)}panel.append(list);
      }
      selectedEvidence.append(panel);
    }
    window.__selectedCodeCoordinate={image,offset,variants:coordinate.variants.map(x=>x.bytes),observed:coordinate.observations.map(x=>Boolean(x.instruction))};
  }
  const parseCurrent=()=>{
    const parsed=parseCodeCoordinate(document.querySelector("#code-offset").value);
    if(!parsed){document.querySelector("#code-coordinate-status").textContent="Enter IMAGE+hex-offset, for example PLI.COM+0BDA.";return null}
    return parsed;
  };
  document.querySelector("#code-jump").addEventListener("click",()=>{const p=parseCurrent();if(p)selectCoordinate(p.image,p.offset)});
  document.querySelector("#code-offset").addEventListener("keydown",e=>{if(e.key==="Enter"){const p=parseCurrent();if(p)selectCoordinate(p.image,p.offset)}});
  imageSelect.addEventListener("change",()=>{const p=parseCurrent();if(p)selectCoordinate(imageSelect.value,p.offset)});
  document.querySelector("#code-range-count").addEventListener("change",()=>{const p=parseCurrent();if(p)selectCoordinate(p.image,p.offset)});
  const move=delta=>{const p=parseCurrent();if(!p)return;const offsets=allOffsets(p.image),index=offsets.indexOf(p.offset);const next=offsets[index+delta];if(next!=null)selectCoordinate(p.image,next)};
  document.querySelector("#code-previous").addEventListener("click",()=>move(-1));document.querySelector("#code-next").addEventListener("click",()=>move(1));
  const initial=parseCodeCoordinate(document.querySelector("#code-offset").value);
  if(initial&&codeImageNames.includes(initial.image))selectCoordinate(initial.image,initial.offset);else if(codeImageNames.length)selectCoordinate(codeImageNames[0],allOffsets(codeImageNames[0])[0]);
  window.__codeRuns=codeEvidence;
  window.__codeEvidenceReady=true;
}
function showView(view){const structure=view==="structure"&&hasStructure,code=view==="code-evidence"&&Boolean(codeEvidence);document.querySelector("#structure-view").hidden=!structure;document.querySelector("#code-evidence-view").hidden=!code;document.querySelector("#low-level-view").hidden=structure||code;document.querySelector("#tab-structure").classList.toggle("active",structure);document.querySelector("#tab-code-evidence").classList.toggle("active",code);document.querySelector("#tab-low-level").classList.toggle("active",!structure&&!code);window.__activeView=structure?"structure":code?"code-evidence":"low-level";}
async function renderProjection(p){current=p;currentPath=controlSelection.get(`${outputIdentity}:${p.sink.offset}`)??null;window.__explorerReady=false;safeText(document.querySelector("#sink-meta"),"Selected output write · detailed provenance projection embedded");renderExplanationOverview(p,currentPath);
  const pathSummary=document.querySelector("#path-summary");if(currentPath)pathSummary.textContent=`Cumulative concrete path context: ${currentPath.context_depth} decisions at ${currentPath.distinct_branch_locations} static branch locations; steps ${currentPath.earliest_decision_step}–${currentPath.latest_decision_step}. Combined reachable nodes ${currentPath.combined_reachable_nodes} (${currentPath.additional_decision_nodes} decisions, ${currentPath.additional_context_nodes} contexts, ${currentPath.additional_flag_ancestors} additional flag/value ancestors; ${currentPath.control_relations} Control relations). This is not minimal control dependence.`;else pathSummary.textContent="No path-control projection embedded for this output byte.";
  const source=document.querySelector("#source-summary");source.replaceChildren();for(const s of p.sources){const div=document.createElement("div");div.textContent=`${s.classification??s.kind} · ${s.identity}: ${s.distinct_source_bytes} distinct offsets / ${s.leaf_occurrences} leaf occurrences · ${s.ranges.map(r=>r.first===r.last?r.first.toString(16):`${r.first.toString(16)}–${r.last.toString(16)}`).join(", ")}`;source.append(div);}
  roleSummary(p);renderHeatmaps(p,currentPath);await Promise.all([setTableData(p,currentPath),renderGraph(p,currentPath)]);
  const preview=document.querySelector("#preview");preview.replaceChildren();const shownPreview=analysisMode==="path"?currentPath.preview:p.preview;document.querySelector("#preview-meta").textContent=`Bounded ${analysisMode==="path"?"path-context":"data-DAG"} neighborhood: ${shownPreview.visible_nodes??shownPreview.nodes.length} visible nodes / ${shownPreview.max_nodes} maximum; depth ${shownPreview.max_depth}; omitted frontier ${shownPreview.omitted_frontier_count}. Not the complete graph.`;
  for(const n of shownPreview.nodes){const div=document.createElement("div");div.className="preview-node";div.textContent=`#${n.id} ${n.label} value=${n.value.toString(16)} width=${n.width} step=${n.step??"-"} origin=${n.origin?`${n.origin.image.name}+${n.origin.offset.toString(16)} @${n.origin.runtime_pc.toString(16)}`:"-"}`;preview.append(div)}
  for(const button of outputGrid.children)button.classList.toggle("selected",Number(button.dataset.offset)===p.sink.offset);
  window.__selectedSink=p.sink.offset;window.__explorerReady=true;window.__selectProducer=id=>highlightProducer(id);window.__heatMode=document.querySelector("#mode").value;window.__analysisMode=analysisMode;window.__pathRows=currentPath?.locations.length??0;window.__controlPreviewOrigins=currentPath?.preview.nodes.filter(n=>n.origin).map(n=>({image:n.origin.image.identity,offset:n.origin.offset,runtime_pc:n.origin.runtime_pc}))??[];window.__roleOverlayCounts=Object.fromEntries(["value","address","flag","control"].map(k=>[k,k==="control"?(currentPath?.locations.reduce((n,x)=>n+x.decision_count,0)??0):p.producers.reduce((n,x)=>n+x[`${k}_edges`],0)]));}
async function clearProjection(){current=null;currentPath=null;currentProducer=null;document.querySelector("#heatmaps").replaceChildren();document.querySelector("#source-data").replaceChildren();document.querySelector("#source-summary").replaceChildren();document.querySelector("#roles").replaceChildren();document.querySelector("#path-summary").textContent="No detailed projection embedded for this output byte.";document.querySelector("#preview").replaceChildren();document.querySelector("#preview-meta").textContent="No detailed projection embedded for this output byte.";document.querySelector("#graph-meta").textContent="No detailed projection embedded.";document.querySelector("#producer-highlight").textContent="";if(graph){graph.destroy();graph=null;}for(const id of ["#producers","#sources","#operations","#source-ranges","#control-decisions"]){const old=viewerTables[id],table=await worker.table([{status:"No projection embedded"}]);await old.viewer.load(table);await old.viewer.restore({plugin:"Datagrid"});old.table.delete?.();viewerTables[id]={...old,table,rows:0};}window.__perspectiveRows=Object.fromEntries(Object.entries(viewerTables).map(([k,v])=>[k,v.rows]));}
async function selectOffset(offset){const p=selection.get(`${outputIdentity}:${offset}`);document.querySelector("#sink").value=String(offset);for(const button of outputGrid.children)button.classList.toggle("selected",Number(button.dataset.offset)===offset);if(!p){const b=report.output_bytes.find(x=>x.offset===offset);safeText(document.querySelector("#sink-meta"),`Metadata only · detailed projection not embedded · rewrites ${b?.rewrite_count??0}`);await clearProjection();window.__selectedSink=offset;renderUnprojectedOverview(b);window.__explorerReady=true;return;}await renderProjection(p);}
for(const p of report.selections){const opt=document.createElement("option");opt.value=p.sink.offset;opt.textContent=`${p.sink.file.name} +${p.sink.offset.toString(16).toUpperCase().padStart(4,"0")}`;document.querySelector("#sink").append(opt)}
document.querySelector("#sink").addEventListener("change",e=>void selectOffset(Number(e.target.value)));document.querySelector("#mode").addEventListener("change",()=>current&&renderHeatmaps(current,currentPath));document.querySelector("#analysis-mode").addEventListener("change",e=>{analysisMode=e.target.value;if(current)void renderProjection(current)});
document.querySelector("#tab-structure").addEventListener("click",()=>{showView("structure");if(hasStructure&&!routineGraph)void renderRoutineGraph()});document.querySelector("#tab-low-level").addEventListener("click",()=>showView("low-level"));
document.querySelector("#tab-code-evidence").addEventListener("click",()=>showView("code-evidence"));
document.querySelector("#routine-map-global").addEventListener("click",()=>{routineGraphMode="global";activeNarrativeOrdinal=null;document.querySelector("#routine-map-global").classList.add("active");document.querySelector("#routine-map-local").classList.remove("active");void renderRoutineGraph()});
document.querySelector("#routine-map-local").addEventListener("click",()=>{routineGraphMode="neighborhood";activeNarrativeOrdinal=null;document.querySelector("#routine-map-local").classList.add("active");document.querySelector("#routine-map-global").classList.remove("active");void renderRoutineGraph()});
document.querySelector("#image-overview").replaceChildren(...report.execution.images.map(im=>{const d=document.createElement("div");d.className="image-card";d.textContent=`${im.display_name} · virtual ${im.virtual_base.toString(16)}–${(im.virtual_base+im.span-1).toString(16)} · ${im.unique_fetched_byte_count}/${im.known_byte_count} unique bytes fetched · ${im.total_instruction_executions} executions`;return d}));
window.__reportLoaded={images:report.execution.images.length,outputBytes:report.output_bytes.length,selectedProjections:report.selections.length,controlRows:controlReport.decisions.length};
await initializeStructureView();showView("low-level");await selectOffset(report.selections[0]?.sink.offset??-1);showView(hasStructure?"structure":"low-level");if(hasStructure)await renderRoutineGraph();
renderCodeEvidence();
