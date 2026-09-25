import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root=path.dirname(fileURLToPath(import.meta.url));
const [reportArg,outputArg]=process.argv.slice(2);
if(!reportArg||!outputArg){console.error("usage: npm run bundle -- REPORT.json OUTPUT_DIRECTORY");process.exit(2)}
const report=path.resolve(reportArg),output=path.resolve(outputArg);
const text=await readFile(report,"utf8");
if(!text.startsWith("RUNES_PROVENANCE_REPORT 1\n"))throw new Error("unsupported provenance report schema");
await mkdir(output,{recursive:true});
if((await readdir(output)).length!==0)throw new Error("output directory must be empty; choose a fresh directory");
await cp(path.join(root,"dist"),output,{recursive:true,force:true});
await writeFile(path.join(output,"provenance-report.json"),text);
console.log(`offline bundle written to ${output}`);
