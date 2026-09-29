import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { projectCodeRun } from "./src/code_evidence.js";

const root=path.dirname(fileURLToPath(import.meta.url));
const args=process.argv.slice(2);
const positional=[],named={},codeRunArgs=[],witnessRunArgs=[];
for(let i=0;i<args.length;i++){
  if(args[i]==="--structure"||args[i]==="--blocks"||args[i]==="--canonical-code-blocks"){
    const option=args[i],value=args[++i];if(!value||value.startsWith("--")){console.error(`${option} requires a file path`);process.exit(2)}
    if(named[option]){console.error(`${option} may be specified only once`);process.exit(2)}named[option]=value;
  }else if(args[i]==="--code-run"){
    const label=args[++i],dir=args[++i];
    if(!label||!dir||label.startsWith("--")||dir.startsWith("--")){console.error("--code-run requires LABEL DIRECTORY");process.exit(2)}
    if(codeRunArgs.some(x=>x.label===label)){console.error(`duplicate code-run label: ${label}`);process.exit(2)}
    codeRunArgs.push({label,dir:path.resolve(dir)});
  }else if(args[i]==="--witness-run"){
    const label=args[++i],file=args[++i];
    if(!label||!file||label.startsWith("--")||file.startsWith("--")){console.error("--witness-run requires LABEL EVENT_WITNESSES.json");process.exit(2)}
    if(witnessRunArgs.some(x=>x.label===label)){console.error(`duplicate witness-run label: ${label}`);process.exit(2)}
    witnessRunArgs.push({label,file:path.resolve(file)});
  }else positional.push(args[i]);
}
const [reportArg,controlArg,outputArg]=positional.length===2?[positional[0],null,positional[1]]:positional;
const hasAnyStructure=Boolean(named["--structure"]||named["--blocks"]||named["--canonical-code-blocks"]);
const completeStructure=Boolean(named["--structure"]&&named["--blocks"]&&named["--canonical-code-blocks"]);
if(!reportArg||!outputArg||positional.length<2||positional.length>3||(hasAnyStructure&&!completeStructure)){console.error("usage: npm run bundle -- REPORT.json [CONTROL_REPORT.json] OUTPUT_DIRECTORY [--structure STRUCTURE.json --blocks BLOCKS.json --canonical-code-blocks CANONICAL_CODE.json] [--code-run LABEL DIR] [--witness-run LABEL EVENT_WITNESSES.json]");process.exit(2)}
const report=path.resolve(reportArg),output=path.resolve(outputArg);
for(const entry of witnessRunArgs)if(!codeRunArgs.some(run=>run.label===entry.label))throw new Error(`witness run ${entry.label} must match a --code-run label`);
const text=await readFile(report,"utf8");
if(!text.startsWith("RUNES_PROVENANCE_REPORT 1\n"))throw new Error("unsupported provenance report schema");
const controlText=controlArg?await readFile(path.resolve(controlArg),"utf8"):
  "RUNES_PROVENANCE_CONTROL_REPORT 1\n{\"decisions\":[],\"selections\":[]}\n";
if(!controlText.startsWith("RUNES_PROVENANCE_CONTROL_REPORT 1\n"))throw new Error("unsupported path-control report schema");
let structureText=null,blocksText=null,canonicalCodeText=null;
if(hasAnyStructure){
  structureText=await readFile(path.resolve(named["--structure"]),"utf8");
  blocksText=await readFile(path.resolve(named["--blocks"]),"utf8");
  canonicalCodeText=await readFile(path.resolve(named["--canonical-code-blocks"]),"utf8");
  if(!structureText.startsWith("RUNES_DYNAMIC_STRUCTURE 1\n"))throw new Error("unsupported dynamic structure schema");
  if(!blocksText.startsWith("RUNES_DYNAMIC_BLOCKS 1\n"))throw new Error("unsupported dynamic blocks schema");
  if(!canonicalCodeText.startsWith("RUNES_CANONICAL_CODE_BLOCKS 1\n"))throw new Error("unsupported canonical code blocks schema");
}
await mkdir(output,{recursive:true});
if((await readdir(output)).length!==0)throw new Error("output directory must be empty; choose a fresh directory");
await cp(path.join(root,"dist"),output,{recursive:true,force:true});
await writeFile(path.join(output,"provenance-report.json"),text);
await writeFile(path.join(output,"provenance-control-report.json"),controlText);
if(structureText){await writeFile(path.join(output,"dynamic-structure.json"),structureText);await writeFile(path.join(output,"dynamic-blocks.json"),blocksText);await writeFile(path.join(output,"canonical-code-blocks.json"),canonicalCodeText)}
let codeEvidenceRuns=[];
if(codeRunArgs.length){
  if(codeRunArgs.length<2)throw new Error("multi-run code evidence requires at least two --code-run inputs");
  codeEvidenceRuns=await Promise.all(codeRunArgs.map(async ({label,dir})=>{
    const [structure,blocks,canonical]=await Promise.all([
      readFile(path.join(dir,"dynamic-structure.json"),"utf8"),
      readFile(path.join(dir,"dynamic-blocks.json"),"utf8"),
      readFile(path.join(dir,"canonical-code-blocks.json"),"utf8")]);
    for(const [text,header,file] of [[structure,"RUNES_DYNAMIC_STRUCTURE 1","dynamic-structure.json"],[blocks,"RUNES_DYNAMIC_BLOCKS 1","dynamic-blocks.json"],[canonical,"RUNES_CANONICAL_CODE_BLOCKS 1","canonical-code-blocks.json"]])
      if(!text.startsWith(`${header}\n`))throw new Error(`unsupported ${file} in code run ${label}`);
    const parse=text=>JSON.parse(text.slice(text.indexOf("\n")+1));
    return projectCodeRun(label,parse(structure),parse(blocks),parse(canonical));
  }));
  await writeFile(path.join(output,"code-evidence.json"),JSON.stringify({schema:"RUNES_CODE_EVIDENCE 1",runs:codeEvidenceRuns})+"\n");
}
const eventWitnesses=[];
if(witnessRunArgs.length){
  await mkdir(path.join(output,"event-witnesses"),{recursive:true});
  for(const {label,file} of witnessRunArgs){
    const text=await readFile(file,"utf8");
    if(!text.startsWith("RUNES_EVENT_WITNESSES 1\n"))throw new Error(`unsupported event witness report for ${label}`);
    const safe=label.replace(/[^A-Za-z0-9._-]/g,"_");
    const targetDir=path.join(output,"event-witnesses",safe),sourceChunkDir=path.join(path.dirname(file),"event-witnesses","chunks");
    await mkdir(path.join(targetDir,"chunks"),{recursive:true});
    await cp(sourceChunkDir,path.join(targetDir,"chunks"),{recursive:true,force:true});
    const newline=text.indexOf("\n"),index=JSON.parse(text.slice(newline+1));
    if(index.encoding!=="chronological-chunks")throw new Error(`unsupported event witness encoding for ${label}`);
    index.chunk_prefix="./chunks/";
    const filename=`event-witnesses/${safe}/index.json`;
    await writeFile(path.join(output,filename),`${text.slice(0,newline+1)}${JSON.stringify(index)}\n`);
    eventWitnesses.push({label,file:filename});
  }
}
await writeFile(path.join(output,"explorer-manifest.json"),JSON.stringify({structure:Boolean(structureText),codeEvidence:codeEvidenceRuns.length>1,eventWitnesses})+"\n");
console.log(`offline bundle written to ${output}`);
