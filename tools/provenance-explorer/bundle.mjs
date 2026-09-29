import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { projectCodeRun } from "./src/code_evidence.js";

const root=path.dirname(fileURLToPath(import.meta.url));
const args=process.argv.slice(2);
const positional=[],named={},codeRunArgs=[];
for(let i=0;i<args.length;i++){
  if(args[i]==="--structure"||args[i]==="--blocks"||args[i]==="--canonical-code-blocks"){
    const option=args[i],value=args[++i];if(!value||value.startsWith("--")){console.error(`${option} requires a file path`);process.exit(2)}
    if(named[option]){console.error(`${option} may be specified only once`);process.exit(2)}named[option]=value;
  }else if(args[i]==="--code-run"){
    const label=args[++i],dir=args[++i];
    if(!label||!dir||label.startsWith("--")||dir.startsWith("--")){console.error("--code-run requires LABEL DIRECTORY");process.exit(2)}
    if(codeRunArgs.some(x=>x.label===label)){console.error(`duplicate code-run label: ${label}`);process.exit(2)}
    codeRunArgs.push({label,dir:path.resolve(dir)});
  }else positional.push(args[i]);
}
const [reportArg,controlArg,outputArg]=positional.length===2?[positional[0],null,positional[1]]:positional;
const hasAnyStructure=Boolean(named["--structure"]||named["--blocks"]||named["--canonical-code-blocks"]);
const completeStructure=Boolean(named["--structure"]&&named["--blocks"]&&named["--canonical-code-blocks"]);
if(!reportArg||!outputArg||positional.length<2||positional.length>3||(hasAnyStructure&&!completeStructure)){console.error("usage: npm run bundle -- REPORT.json [CONTROL_REPORT.json] OUTPUT_DIRECTORY [--structure STRUCTURE.json --blocks BLOCKS.json --canonical-code-blocks CANONICAL_CODE.json]");process.exit(2)}
const report=path.resolve(reportArg),output=path.resolve(outputArg);
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
await writeFile(path.join(output,"explorer-manifest.json"),JSON.stringify({structure:Boolean(structureText),codeEvidence:codeEvidenceRuns.length>1})+"\n");
console.log(`offline bundle written to ${output}`);
