import perspective from "@perspective-dev/client";
import perspectiveViewer from "@perspective-dev/viewer";
import "@perspective-dev/viewer-datagrid";
import "@perspective-dev/viewer/themes";
import serverWasm from "@perspective-dev/server/dist/wasm/perspective-server.wasm?url";
import viewerWasm from "@perspective-dev/viewer/dist/wasm/perspective-viewer.wasm?url";
import { Graph } from "@antv/g6";
import "./style.css";

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
let structureReport = null, blocksReport = null;
if (manifest.structure) {
  const [structureText, blocksText] = await Promise.all([
    fetch(new URL("./dynamic-structure.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Structure report fetch failed: ${r.status}`); return r.text(); }),
    fetch(new URL("./dynamic-blocks.json", window.location.href)).then(async r => { if (!r.ok) throw new Error(`Block report fetch failed: ${r.status}`); return r.text(); })
  ]);
  if (!structureText.startsWith("RUNES_DYNAMIC_STRUCTURE 1\n")) throw new Error("Unsupported dynamic structure report version");
  if (!blocksText.startsWith("RUNES_DYNAMIC_BLOCKS 1\n")) throw new Error("Unsupported dynamic blocks report version");
  structureReport = JSON.parse(structureText.slice(structureText.indexOf("\n") + 1));
  blocksReport = JSON.parse(blocksText.slice(blocksText.indexOf("\n") + 1));
}
const hasStructure = Boolean(structureReport && blocksReport);
document.querySelector("#structure-view").hidden = !hasStructure;
document.querySelector("#structure-missing").hidden = true;
document.querySelector("#tab-structure").hidden = !hasStructure;
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
  await viewer.load(table); await viewer.restore({plugin:"Datagrid"}); viewers[id]=viewer;
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
async function setTableData(p,path){const rows=groupedRows(p);const controlRows=(path?.locations??[]).map(x=>({image:x.image?.identity??"unknown",image_offset:x.image_offset,runtime_pc:x.runtime_pc,condition:x.condition,taken:x.taken,decision_count:x.decision_count,first_step:x.first_step,last_step:x.last_step,distinct_flag_roots:x.distinct_flag_roots}));for(const [id,data] of [["#producers",rows.producers],["#sources",rows.sources],["#operations",rows.operations],["#source-ranges",rows.sourceRanges],["#output-table",report.output_bytes],["#control-decisions",controlRows]]){const old=viewerTables[id];const table=await worker.table(data.length?data:[{empty:"no rows"}]);await old.viewer.load(table);const group_by=id==="#producers"?["image","operation_kind"]:id==="#sources"?["classification","identity"]:id==="#source-ranges"?["classification","identity"]:id==="#operations"?["kind"]:id==="#control-decisions"?["image","condition","taken"]:[];const sort=id==="#producers"?[["producer_steps","desc"]]:id==="#operations"?[["node_count","desc"]]:id==="#source-ranges"?[["first","asc"]]:id==="#control-decisions"?[["decision_count","desc"]]:[["offset","asc"]];await old.viewer.restore({plugin:"Datagrid",group_by,sort});old.table.delete?.();viewerTables[id]={...old,table,rows:data.length};window.__tableGroups??={};window.__tableGroups[id]=group_by;}
  window.__perspectiveRows=Object.fromEntries(Object.entries(viewerTables).map(([k,v])=>[k,v.rows]));window.__producerRows=rows.producers;window.__producerIds=rows.producers.map(x=>x.producer_id);window.__controlRows=controlRows;}
async function renderGraph(p,path){const pathMode=analysisMode==="path",preview=pathMode?path.preview:p.preview,root=pathMode?(preview.nodes[0]?.id??null):p.root,data=graphData(p,preview,root,pathMode?"selected path context":"selected sink");if(graph){graph.destroy();graph=null;}graph=new Graph({container:"graph",width:document.querySelector("#graph").clientWidth,height:540,data,layout:{type:"dagre",rankdir:"LR",nodesep:18,ranksep:40},behaviors:["drag-canvas","zoom-canvas",{type:"collapse-expand",trigger:"click",animation:false}],node:{style:{labelText:d=>d.data?.label??d.id,size:18}},edge:{style:{stroke:d=>roleColor[d.data?.role]??"#a8b2bc",endArrow:true,labelText:d=>d.data?.role??""}},combo:{type:"rect",style:{labelText:d=>d.data?.label??d.id,collapsed:false}}});await graph.render();graph.on("node:click",event=>{const id=event.target?.id??event.data?.id;const d=data.nodes.find(n=>n.id===id)?.data;if(d?.producer_id)highlightProducer(d.producer_id)});graph.on("combo:click",event=>{const id=event.target?.id??event.data?.id;const d=data.combos.find(c=>c.id===id)?.data;if(d?.producer_id)highlightProducer(d.producer_id)});window.__emitG6Producer=id=>{const n=data.nodes.find(x=>x.data?.producer_id===id);if(n)graph.emit("node:click",{target:{id:n.id}});else{const c=data.combos.find(x=>x.data?.producer_id===id);if(c)graph.emit("combo:click",{target:{id:c.id}})}};document.querySelector("#graph-meta").textContent=`G6 bounded ${pathMode?"path-context":"data-DAG"} graph: ${data.nodes.length} nodes, ${data.edges.length} edges, ${data.combos.length} combos (preview max ${preview.max_nodes} nodes, depth ${preview.max_depth}, omitted frontier ${preview.omitted_frontier_count}).`;
  window.__g6Counts={nodes:data.nodes.length,edges:data.edges.length,combos:data.combos.length};}

const hexOffset = value => value == null ? "unknown" : `${Number(value).toString(16).toUpperCase().padStart(4,"0")}h`;
const routineById = new Map((structureReport?.routines ?? []).map(r => [r.id, r]));
const aggregateRoutineEdges = new Map((structureReport?.transitions ?? []).map(e => [`${e.from}:${e.to}`, e]));
const instructionById = new Map((blocksReport?.instructions ?? []).map(i => [i.id, i]));
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
const routineNodes=(structureReport?.routines??[]).map(r=>({id:routineNodeId(r.id),data:{routine_id:r.id,label:r.display,recursive:r.recursive,self_calls:r.self_calls}}));
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
  document.querySelector("#routine-edge-detail").textContent=`#${String(ordinal).padStart(3,"0")} ${from?.display??`R${edge.from}`} → ${to?.display??`R${edge.to}`} · ${edge.kind} · first step ${edge.first_step}${classified?.cycle?` · ${classified.cycle} (${classified.cycle_size} candidates)`:" · not marked as a multi-routine cycle"}`;
  window.__routineFocus={ordinal,from:edge.from,to:edge.to,cycle:classified?.cycle??null};
  if(routineGraphMode==="neighborhood"&&routineGraph&&(!routineGraphData.nodes.some(n=>n.data.routine_id===edge.from)||!routineGraphData.nodes.some(n=>n.data.routine_id===edge.to)))void renderRoutineGraph();
  updateRoutineGraphState(ordinal);
}
function selectBlock(routineId, blockId) {
  if (routineId !== window.__selectedRoutine) { selectRoutine(routineId); setTimeout(() => selectBlock(routineId, blockId), 0); return; }
  const el = document.querySelector(`#block-${routineId}-${blockId}`);
  if (el) { el.open = true; el.scrollIntoView({behavior:"smooth",block:"center"}); }
}
function selectRoutine(id, preserveNarrative=false) {
  if (!hasStructure || !routineById.has(id)) return;
  if(!preserveNarrative)activeNarrativeOrdinal=null;
  const routine = routineById.get(id), detail = document.querySelector("#routine-detail");
  window.__selectedRoutine = id;
  detail.replaceChildren();
  const heading = document.createElement("div"); heading.className = "routine-head";
  const title = document.createElement("h2"); title.textContent = routine.display; heading.append(title);
  for (const tag of routine.tags) { const badge=document.createElement("span"); badge.className=`routine-badge ${tag === "recursive" ? "recursive" : ""}`; badge.textContent=tag; heading.append(badge); }
  detail.append(heading);
  const metrics=document.createElement("div");metrics.className="routine-metrics";
  const image=routine.image ? `${String.fromCharCode(65+routine.image.drive)}:${routine.image.user}:${routine.image.name}` : "unresolved image origin";
  const values=[`entry ${image}+${hexOffset(routine.offset)} @${hexOffset(routine.runtime_entry_pc)}`,
    `steps ${routine.first_step ?? "?"}–${routine.last_step ?? "?"}`,`${routine.executions} instruction executions`,
    `${routine.distinct_starts} distinct starts`,`incoming ${routine.incoming} · outgoing ${routine.outgoing}`,
    `calls ${routine.calls} · returns ${routine.returns}`,`self calls ${routine.self_calls}`];
  for(const value of values){const span=document.createElement("span");span.textContent=value;metrics.append(span)}detail.append(metrics);
  const blocks=(blocksReport.blocks??[]).filter(b=>b.routine===id).sort((a,b)=>a.id-b.id);
  const blockTitle=document.createElement("h3");blockTitle.textContent=`Observed basic blocks · ${blocks.length}`;detail.append(blockTitle);
  const blockRoot=document.createElement("div");blockRoot.id="routine-blocks";
  for(const block of blocks){
    const card=document.createElement("details");card.className="block-card";card.id=`block-${id}-${block.id}`;
    const summary=document.createElement("summary");summary.textContent=block.display;card.append(summary);
    const meta=document.createElement("div");meta.className="block-meta";
    const blockImage=block.image?.name ?? block.origin?.kind ?? "unresolved";
    const blockOffset=block.start_offset == null ? `runtime ${hexOffset(block.runtime_start)}` : `${blockImage}+${hexOffset(block.start_offset)}`;
    meta.textContent=`${blockOffset} · ${block.byte_length} bytes · ${block.instruction_count} instructions · entries ${block.entries} · steps ${block.first_step}–${block.last_step} · tags ${block.tags.join(", ") || "none"}`;card.append(meta);
    const codeDetails=document.createElement("details");const codeSummary=document.createElement("summary");codeSummary.textContent=`Formatted 8080 instructions (${block.instruction_count})`;codeDetails.append(codeSummary);
    let rendered=false;codeDetails.addEventListener("toggle",()=>{if(!codeDetails.open||rendered)return;rendered=true;const list=document.createElement("ol");list.className="instruction-list";
      for(const instructionId of block.instructions){const ins=instructionById.get(instructionId);if(!ins)continue;const line=document.createElement("li");line.textContent=`${hexOffset(ins.runtime_pc)}  ${ins.text}  · ${ins.executions} executions · steps ${ins.first_step}–${ins.last_step}`;list.append(line)}codeDetails.append(list);});
    card.append(codeDetails);blockRoot.append(card);
  }
  detail.append(blockRoot);
  const localNarrative=(blocksReport.narrative??[]).filter(e=>e.from[0]===id);
  const edgeTitle=document.createElement("h3");edgeTitle.textContent=`Block-level narrative transitions · ${localNarrative.length}`;detail.append(edgeTitle);
  const edgeList=document.createElement("ol");edgeList.className="block-transitions";
  for(const edge of localNarrative){const item=document.createElement("li");const from=document.createElement("button");from.className="routine-link";from.textContent=`R${String(edge.from[0]).padStart(3,"0")}.B${String(edge.from[1]).padStart(3,"0")}`;from.addEventListener("click",()=>selectBlock(edge.from[0],edge.from[1]));const arrow=document.createTextNode(" → ");const to=document.createElement("button");to.className="routine-link";to.textContent=`R${String(edge.to[0]).padStart(3,"0")}.B${String(edge.to[1]).padStart(3,"0")}`;to.addEventListener("click",()=>selectBlock(edge.to[0],edge.to[1]));const kind=document.createTextNode(` · ${edge.kind} · first step ${edge.first_step}`);item.append(from,arrow,to,kind);edgeList.append(item)}
  detail.append(edgeList);detail.scrollIntoView({behavior:"smooth",block:"start"});
  window.__selectedRoutineBlocks=blocks.length;window.__selectedRoutineNarrative=localNarrative.length;
  const cycleEdges=routineNarrative.filter(e=>(e.from===id||e.to===id)&&e.cycle).length;
  document.querySelector("#routine-edge-detail").textContent=`Selected ${routine.display}: ${routineNarrative.filter(e=>e.from===id||e.to===id).length} incoming/outgoing first-observation edges highlighted · ${cycleEdges} participate in a multi-routine or mutual cycle.`;
  if(routineGraphMode==="neighborhood"&&routineGraph)void renderRoutineGraph();else updateRoutineGraphState();
}
async function initializeStructureView(){
  if(!hasStructure){window.__structureReady=true;return;}
  const routineRows=structureReport.routines.map(r=>({id:r.id,display:r.display,image:r.image?.name??"unknown",offset:r.offset,
    tags:r.tags.join(", "),recursive:r.recursive,first_step:r.first_step,last_step:r.last_step,executions:r.executions,
    distinct_starts:r.distinct_starts,incoming:r.incoming,outgoing:r.outgoing,calls:r.calls,returns:r.returns,self_calls:r.self_calls}));
  const narrativeRows=structureReport.narrative.map(e=>{const edge=aggregateRoutineEdges.get(`${e.from}:${e.to}`);return {ordinal:e.ordinal,from_id:e.from,
    from:routineById.get(e.from)?.display??`R${e.from}`,to_id:e.to,to:routineById.get(e.to)?.display??`R${e.to}`,
    first_kind:e.kind,first_step:e.first_step,count:edge?.count??1,kinds:edge?.kinds?.join(", ")??e.kind};});
  window.__structureRoutineRows=routineRows;window.__structureNarrativeRows=narrativeRows;
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
function showView(view){const structure=view==="structure"&&hasStructure;document.querySelector("#structure-view").hidden=!structure;document.querySelector("#low-level-view").hidden=structure;document.querySelector("#tab-structure").classList.toggle("active",structure);document.querySelector("#tab-low-level").classList.toggle("active",!structure);window.__activeView=structure?"structure":"low-level";}
async function renderProjection(p){current=p;currentPath=controlSelection.get(`${outputIdentity}:${p.sink.offset}`)??null;window.__explorerReady=false;safeText(document.querySelector("#sink-meta"),`${p.sink.file.name} +${p.sink.offset.toString(16).toUpperCase().padStart(4,"0")}h = ${p.value?.toString(16).toUpperCase().padStart(2,"0")}h · write step ${p.write_step} · root ${p.root} · ${p.full_node_count} exact data-slice nodes · ${p.source_leaf_count} source leaves`);
  const pathSummary=document.querySelector("#path-summary");if(currentPath)pathSummary.textContent=`Cumulative concrete path context: ${currentPath.context_depth} decisions at ${currentPath.distinct_branch_locations} static branch locations; steps ${currentPath.earliest_decision_step}–${currentPath.latest_decision_step}. Combined reachable nodes ${currentPath.combined_reachable_nodes} (${currentPath.additional_decision_nodes} decisions, ${currentPath.additional_context_nodes} contexts, ${currentPath.additional_flag_ancestors} additional flag/value ancestors; ${currentPath.control_relations} Control relations). This is not minimal control dependence.`;else pathSummary.textContent="No path-control projection embedded for this output byte.";
  const source=document.querySelector("#source-summary");source.replaceChildren();for(const s of p.sources){const div=document.createElement("div");div.textContent=`${s.classification??s.kind} · ${s.identity}: ${s.distinct_source_bytes} distinct offsets / ${s.leaf_occurrences} leaf occurrences · ${s.ranges.map(r=>r.first===r.last?r.first.toString(16):`${r.first.toString(16)}–${r.last.toString(16)}`).join(", ")}`;source.append(div);}
  roleSummary(p);renderHeatmaps(p,currentPath);await Promise.all([setTableData(p,currentPath),renderGraph(p,currentPath)]);
  const preview=document.querySelector("#preview");preview.replaceChildren();const shownPreview=analysisMode==="path"?currentPath.preview:p.preview;document.querySelector("#preview-meta").textContent=`Bounded ${analysisMode==="path"?"path-context":"data-DAG"} neighborhood: ${shownPreview.visible_nodes??shownPreview.nodes.length} visible nodes / ${shownPreview.max_nodes} maximum; depth ${shownPreview.max_depth}; omitted frontier ${shownPreview.omitted_frontier_count}. Not the complete graph.`;
  for(const n of shownPreview.nodes){const div=document.createElement("div");div.className="preview-node";div.textContent=`#${n.id} ${n.label} value=${n.value.toString(16)} width=${n.width} step=${n.step??"-"} origin=${n.origin?`${n.origin.image.name}+${n.origin.offset.toString(16)} @${n.origin.runtime_pc.toString(16)}`:"-"}`;preview.append(div)}
  for(const button of outputGrid.children)button.classList.toggle("selected",Number(button.dataset.offset)===p.sink.offset);
  window.__selectedSink=p.sink.offset;window.__explorerReady=true;window.__selectProducer=id=>highlightProducer(id);window.__heatMode=document.querySelector("#mode").value;window.__analysisMode=analysisMode;window.__pathRows=currentPath?.locations.length??0;window.__controlPreviewOrigins=currentPath?.preview.nodes.filter(n=>n.origin).map(n=>({image:n.origin.image.identity,offset:n.origin.offset,runtime_pc:n.origin.runtime_pc}))??[];window.__roleOverlayCounts=Object.fromEntries(["value","address","flag","control"].map(k=>[k,k==="control"?(currentPath?.locations.reduce((n,x)=>n+x.decision_count,0)??0):p.producers.reduce((n,x)=>n+x[`${k}_edges`],0)]));}
async function clearProjection(){current=null;currentPath=null;currentProducer=null;document.querySelector("#heatmaps").replaceChildren();document.querySelector("#source-data").replaceChildren();document.querySelector("#source-summary").replaceChildren();document.querySelector("#roles").replaceChildren();document.querySelector("#path-summary").textContent="No detailed projection embedded for this output byte.";document.querySelector("#preview").replaceChildren();document.querySelector("#preview-meta").textContent="No detailed projection embedded for this output byte.";document.querySelector("#graph-meta").textContent="No detailed projection embedded.";document.querySelector("#producer-highlight").textContent="";if(graph){graph.destroy();graph=null;}for(const id of ["#producers","#sources","#operations","#source-ranges","#control-decisions"]){const old=viewerTables[id],table=await worker.table([{status:"No projection embedded"}]);await old.viewer.load(table);await old.viewer.restore({plugin:"Datagrid"});old.table.delete?.();viewerTables[id]={...old,table,rows:0};}window.__perspectiveRows=Object.fromEntries(Object.entries(viewerTables).map(([k,v])=>[k,v.rows]));}
async function selectOffset(offset){const p=selection.get(`${outputIdentity}:${offset}`);document.querySelector("#sink").value=String(offset);for(const button of outputGrid.children)button.classList.toggle("selected",Number(button.dataset.offset)===offset);if(!p){const b=report.output_bytes.find(x=>x.offset===offset);safeText(document.querySelector("#sink-meta"),`Metadata only · ${report.output_file.name} +${offset.toString(16).toUpperCase().padStart(4,"0")}h · value ${b?.value.toString(16).toUpperCase().padStart(2,"0")}h · write step ${b?.write_step??"?"} · rewrites ${b?.rewrite_count??0} · detailed projection not embedded.`);await clearProjection();window.__selectedSink=offset;window.__explorerReady=true;return;}await renderProjection(p);}
for(const p of report.selections){const opt=document.createElement("option");opt.value=p.sink.offset;opt.textContent=`${p.sink.file.name} +${p.sink.offset.toString(16).toUpperCase().padStart(4,"0")}`;document.querySelector("#sink").append(opt)}
document.querySelector("#sink").addEventListener("change",e=>void selectOffset(Number(e.target.value)));document.querySelector("#mode").addEventListener("change",()=>current&&renderHeatmaps(current,currentPath));document.querySelector("#analysis-mode").addEventListener("change",e=>{analysisMode=e.target.value;if(current)void renderProjection(current)});
document.querySelector("#tab-structure").addEventListener("click",()=>{showView("structure");if(hasStructure&&!routineGraph)void renderRoutineGraph()});document.querySelector("#tab-low-level").addEventListener("click",()=>showView("low-level"));
document.querySelector("#routine-map-global").addEventListener("click",()=>{routineGraphMode="global";activeNarrativeOrdinal=null;document.querySelector("#routine-map-global").classList.add("active");document.querySelector("#routine-map-local").classList.remove("active");void renderRoutineGraph()});
document.querySelector("#routine-map-local").addEventListener("click",()=>{routineGraphMode="neighborhood";activeNarrativeOrdinal=null;document.querySelector("#routine-map-local").classList.add("active");document.querySelector("#routine-map-global").classList.remove("active");void renderRoutineGraph()});
document.querySelector("#image-overview").replaceChildren(...report.execution.images.map(im=>{const d=document.createElement("div");d.className="image-card";d.textContent=`${im.display_name} · virtual ${im.virtual_base.toString(16)}–${(im.virtual_base+im.span-1).toString(16)} · ${im.unique_fetched_byte_count}/${im.known_byte_count} unique bytes fetched · ${im.total_instruction_executions} executions`;return d}));
window.__reportLoaded={images:report.execution.images.length,outputBytes:report.output_bytes.length,selectedProjections:report.selections.length,controlRows:controlReport.decisions.length};
await initializeStructureView();showView("low-level");await selectOffset(report.selections[0]?.sink.offset??-1);showView(hasStructure?"structure":"low-level");if(hasStructure)await renderRoutineGraph();
