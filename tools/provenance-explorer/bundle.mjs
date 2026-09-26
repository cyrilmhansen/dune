import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root=path.dirname(fileURLToPath(import.meta.url));
const args=process.argv.slice(2);
const positional=[],named={};
for(let i=0;i<args.length;i++){
  if(args[i]==="--structure"||args[i]==="--blocks"){
    const option=args[i],value=args[++i];if(!value||value.startsWith("--")){console.error(`${option} requires a file path`);process.exit(2)}
    if(named[option]){console.error(`${option} may be specified only once`);process.exit(2)}named[option]=value;
  }else positional.push(args[i]);
}
const [reportArg,controlArg,outputArg]=positional.length===2?[positional[0],null,positional[1]]:positional;
if(!reportArg||!outputArg||positional.length<2||positional.length>3||Boolean(named["--structure"])!==Boolean(named["--blocks"])){console.error("usage: npm run bundle -- REPORT.json [CONTROL_REPORT.json] OUTPUT_DIRECTORY [--structure STRUCTURE.json --blocks BLOCKS.json]");process.exit(2)}
const report=path.resolve(reportArg),output=path.resolve(outputArg);
const text=await readFile(report,"utf8");
if(!text.startsWith("RUNES_PROVENANCE_REPORT 1\n"))throw new Error("unsupported provenance report schema");
const controlText=controlArg?await readFile(path.resolve(controlArg),"utf8"):
  "RUNES_PROVENANCE_CONTROL_REPORT 1\n{\"decisions\":[],\"selections\":[]}\n";
if(!controlText.startsWith("RUNES_PROVENANCE_CONTROL_REPORT 1\n"))throw new Error("unsupported path-control report schema");
let structureText=null,blocksText=null;
if(named["--structure"]){
  structureText=await readFile(path.resolve(named["--structure"]),"utf8");
  blocksText=await readFile(path.resolve(named["--blocks"]),"utf8");
  if(!structureText.startsWith("RUNES_DYNAMIC_STRUCTURE 1\n"))throw new Error("unsupported dynamic structure schema");
  if(!blocksText.startsWith("RUNES_DYNAMIC_BLOCKS 1\n"))throw new Error("unsupported dynamic blocks schema");
}
await mkdir(output,{recursive:true});
if((await readdir(output)).length!==0)throw new Error("output directory must be empty; choose a fresh directory");
await cp(path.join(root,"dist"),output,{recursive:true,force:true});
await writeFile(path.join(output,"provenance-report.json"),text);
await writeFile(path.join(output,"provenance-control-report.json"),controlText);
if(structureText){await writeFile(path.join(output,"dynamic-structure.json"),structureText);await writeFile(path.join(output,"dynamic-blocks.json"),blocksText)}
await writeFile(path.join(output,"explorer-manifest.json"),JSON.stringify({structure:Boolean(structureText)})+"\n");
console.log(`offline bundle written to ${output}`);
