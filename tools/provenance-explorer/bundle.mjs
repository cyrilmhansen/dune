import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root=path.dirname(fileURLToPath(import.meta.url));
const args=process.argv.slice(2);
const [reportArg,controlArg,outputArg]=args.length===2?[args[0],null,args[1]]:args;
if(!reportArg||!outputArg||args.length<2||args.length>3){console.error("usage: npm run bundle -- REPORT.json [CONTROL_REPORT.json] OUTPUT_DIRECTORY");process.exit(2)}
const report=path.resolve(reportArg),output=path.resolve(outputArg);
const text=await readFile(report,"utf8");
if(!text.startsWith("RUNES_PROVENANCE_REPORT 1\n"))throw new Error("unsupported provenance report schema");
const controlText=controlArg?await readFile(path.resolve(controlArg),"utf8"):
  "RUNES_PROVENANCE_CONTROL_REPORT 1\n{\"decisions\":[],\"selections\":[]}\n";
if(!controlText.startsWith("RUNES_PROVENANCE_CONTROL_REPORT 1\n"))throw new Error("unsupported path-control report schema");
await mkdir(output,{recursive:true});
if((await readdir(output)).length!==0)throw new Error("output directory must be empty; choose a fresh directory");
await cp(path.join(root,"dist"),output,{recursive:true,force:true});
await writeFile(path.join(output,"provenance-report.json"),text);
await writeFile(path.join(output,"provenance-control-report.json"),controlText);
console.log(`offline bundle written to ${output}`);
