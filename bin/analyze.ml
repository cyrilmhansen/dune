[@@@warning "-4-26-27-33-40-41-42-69"]

type options = Pli80.Analyze_options.t
type source_text = Pli80.Analyze_options.source_text = Cpm | Raw
open Pli80.Experiment
let usage = Pli80.Analyze_options.usage
let parse = Pli80.Analyze_options.parse

let read_file path =
  let channel=open_in_bin path in
  Fun.protect ~finally:(fun()->close_in channel)(fun()->let n=in_channel_length channel in let b=Bytes.create n in really_input channel b 0 n;b)

let json_quote s =
  let b=Buffer.create(String.length s+8) in Buffer.add_char b '"';
  String.iter(fun c->match c with
    |'"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"
    |c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf"\\u%04x"(Char.code c))
    |c->Buffer.add_char b c)s;Buffer.add_char b '"';Buffer.contents b

let write_bytes path bytes =
  let ch=open_out_bin path in Fun.protect ~finally:(fun()->close_out ch)(fun()->output_bytes ch bytes)
let termination_name = function Runner.Warm_boot->"warm_boot"|Bdos_function n->"bdos_"^string_of_int n
let pass_ok console phrase=String.length console>=String.length phrase &&
  let rec find i=i+String.length phrase<=String.length console &&
    (String.sub console i(String.length phrase)=phrase||find(i+1)) in find 0

let mkdir path =
  if not(Sys.file_exists path) then Unix.mkdir path 0o755;
  if (Unix.stat path).Unix.st_kind<>Unix.S_DIR then failwith("output path is not a directory: "^path)

let absolute_path path = if Filename.is_relative path then Filename.concat(Sys.getcwd())path else path

let check_outputs dir names =
  List.iter(fun name->let path=Filename.concat dir name in if Sys.file_exists path then failwith("refusing to overwrite existing output: "^path))names

let json_summary ~module_name ~source ~host_source_bytes ~normalized_source_bytes ~analysis ~run ~rel_name ~rel_bytes ~int_name ~int_bytes ~execution_map ~provenance ~dynamic_structure ~dynamic_blocks ~source_seconds ~experiment ~report_timings ~serialization_seconds ~host_writes ~summary_bytes =
  let b=Buffer.create 2048 and add=Buffer.add_string in
  add b "RUNES_PLI80_EXPERIMENT 1\n{\"module\":";add b(json_quote module_name);
  add b ",\"source\":";add b(json_quote source);
  Printf.bprintf b ",\"source_host_bytes\":%d,\"source_compiler_bytes\":%d,\"analysis\":%s,\"termination\":%s,\"steps\":%d,\"pass1_success\":%b,\"pass2_success\":%b,\"end_compilation\":%b"
    host_source_bytes normalized_source_bytes (json_quote(Pli80.Experiment.analysis_name analysis))
    (json_quote(termination_name run.Runner.termination))run.steps
    (pass_ok experiment.Pli80.Experiment.console "NO ERROR(S) IN PASS 1")
    (pass_ok experiment.console "NO ERROR(S) IN PASS 2") (pass_ok experiment.console "END  COMPILATION");
  let file name bytes=match bytes with None->Printf.bprintf b ",\"%s\":null" name|Some bytes->Printf.bprintf b ",\"%s\":{\"name\":%s,\"size\":%d,\"sha256\":%s}" name(json_quote(if name="rel" then rel_name else int_name))(Bytes.length bytes)(json_quote(Pli80.Experiment.sha256_hex bytes)) in
  file "rel" rel_bytes;file "int" int_bytes;
  (match execution_map with None->add b ",\"execution_map\":null"|Some map->let s=Analysis.Execution_map.summary map in Printf.bprintf b ",\"execution_map\":{\"steps\":%d,\"attributed\":%d,\"unknown\":%d,\"mixed\":%d}" s.total_instruction_executions s.attributed_instruction_executions s.unknown_executions s.mixed_or_unresolved_executions);
  (match provenance with None->add b ",\"provenance\":null"|Some p->Printf.bprintf b ",\"provenance\":{\"nodes\":%d,\"edges\":%d,\"path_decisions\":%d,\"control_relations\":%d}" (Analysis.Provenance.node_count p)(Analysis.Provenance.edge_count p)(Analysis.Provenance.control_decision_count p)(Analysis.Provenance.control_relation_count p));
  (match dynamic_structure with None->add b ",\"dynamic_structure\":null"|Some s->let x=Analysis.Dynamic_structure.summary s in
    Printf.bprintf b ",\"dynamic_structure\":{\"routine_candidates\":%d,\"narrative_transitions\":%d,\"aggregate_pairs\":%d,\"recursive_candidates\":%d,\"anomaly_groups\":%d,\"anomaly_observations\":%d}"
      x.routine_count x.narrative_transition_count x.aggregate_pair_count x.recursive_candidate_count x.anomaly_count x.anomaly_observation_count);
  (match dynamic_blocks with None->add b ",\"dynamic_blocks\":null"|Some report->let x=Analysis.Dynamic_blocks.summary report in
    Printf.bprintf b ",\"dynamic_blocks\":{\"blocks\":%d,\"instructions\":%d,\"transitions\":%d,\"backward_edge_targets\":%d,\"anomalies\":%d}"
      x.block_count x.instruction_count x.transition_count x.backward_edge_target_count x.anomaly_count);
  let sec name value=Printf.bprintf b ",\"%s_seconds\":%.6f" name value in
  sec "input_load_normalization" source_seconds;sec "setup" experiment.Pli80.Experiment.timings.setup_seconds;
  sec "execution_and_live_analysis" experiment.timings.execution_seconds;
  List.iter(fun(name,v)->sec name v)report_timings;sec "serialization" serialization_seconds;
  add b ",\"host_writes\":{";
  List.iteri(fun i(name,n)->if i>0 then add b ",";add b(json_quote name);Printf.bprintf b ":%d" n)host_writes;
  Printf.bprintf b "},\"summary_metadata_bytes\":%d}\n" summary_bytes;
  Buffer.contents b

let error_text = function
  |Pli80.Experiment.Invalid_module_name n->Printf.sprintf"invalid CP/M 8.3 module name %S (expected 1..8 legal base-name characters)"n
  |Filesystem_error(Cpm.Filesystem.Invalid_name n)->"invalid CP/M file name: "^n
  |Filesystem_error e->"CP/M filesystem setup error: "^(match e with File_too_large _->"file too large"|Record_out_of_range _->"record out of range"|Invalid_drive _->"invalid drive"|Invalid_user _->"invalid user"|Invalid_name n->n)
  |Run_error e->"compiler run failed: "^(match e with
    |Runner.Load_error _->"COM load failed"|Cpu_error _->"CPU error"|Bdos_error _->"BDOS error"
    |Step_limit_exceeded{max_steps;steps}->Printf.sprintf"instruction budget exhausted at %d/%d"steps max_steps
    |Invalid_step_limit _->"invalid step limit"|Invalid_command_tail _->"invalid command tail")
  |Structure_requires_execution_map->"--structure requires --analysis execution, data, or path"

let run (options : options) =
  let total_started=Unix.gettimeofday() in
  match options.toolchain,options.source,options.output_dir with
  |None,_,_->failwith"--toolchain DIR is required"
  |_,None,_->failwith"--source FILE is required"
  |_,_,None->failwith"--output-dir DIR is required"
  |Some toolchain,Some source_path,Some output_dir->
    let module_name=match options.module_name with
      |Some name->(match Pli80.Experiment.validate_module_name name with Ok x->x|Error e->failwith(error_text e))
      |None->(match Pli80.Experiment.derive_module_name source_path with Ok x->x|Error e->failwith(error_text e)) in
    let source_started=Unix.gettimeofday() in
    let source_host=read_file source_path in
    let pli_com=read_file(Filename.concat toolchain "PLI.COM") in
    let pli0=read_file(Filename.concat toolchain "PLI0.OVL") in
    let pli1=read_file(Filename.concat toolchain "PLI1.OVL") in
    let pli2=read_file(Filename.concat toolchain "PLI2.OVL") in
    let source_compiler=Pli80.Experiment.prepare_source ~normalize:(options.source_text=Cpm) source_host in
    let source_seconds=Unix.gettimeofday()-.source_started in
    let targets=[module_name^".REL";module_name^".INT"] @
      (if options.report=Summary then["run-summary.json"]else[]) @
      (if options.structure then["dynamic-structure.json";"dynamic-blocks.json"]else[]) @
      (if options.report=Explorer then["provenance-report.json"]@(if options.analysis=Path then["provenance-control-report.json"]else[])else[]) @
      List.map(fun n->Printf.sprintf"slice-%04X.json"n)options.raw_slices in
    if options.report=Explorer && not(List.mem options.analysis [Data;Path]) then failwith"--report explorer requires --analysis data or path";
    if options.structure && options.analysis=Run then failwith"--structure requires --analysis execution, data, or path";
    if options.raw_slices<>[] && not(List.mem options.analysis [Data;Path]) then failwith"--raw-slice requires --analysis data or path";
    mkdir output_dir;check_outputs output_dir targets;
    let command_tail=Bytes.of_string(" "^module_name) in
    let input={Pli80.Experiment.pli_com;pli0_ovl=pli0;pli1_ovl=pli1;pli2_ovl=pli2;
      source_name=module_name^".PLI";source_bytes=source_compiler;module_name;command_tail;max_steps=options.max_steps} in
    let experiment=match Pli80.Experiment.run ~structure:options.structure ~analysis:options.analysis input with Ok x->x|Error e->failwith(error_text e) in
    print_string experiment.console;
    flush stdout;
    if experiment.run.termination<>Runner.Warm_boot
       || not(pass_ok experiment.console "NO ERROR(S) IN PASS 1")
       || not(pass_ok experiment.console "NO ERROR(S) IN PASS 2")
       || not(pass_ok experiment.console "END  COMPILATION")
       || experiment.rel_bytes=None
    then failwith "PL/I compilation did not complete successfully";
    let rel=Option.get experiment.rel_bytes in
    (match Pli80.Experiment.select_rel_offsets ~requested:options.raw_slices (Bytes.length rel) with
     |Ok _->()
     |Error message->failwith("invalid --raw-slice: "^message));
    if options.report=Explorer then
      (match Pli80.Experiment.select_rel_offsets ?requested:(if options.selected_rel=[] then None else Some options.selected_rel)
        (Bytes.length rel) with Ok _->()|Error message->failwith("invalid --select-rel: "^message));
    let host_writes=ref[] in
    let save name bytes=let path=Filename.concat output_dir name in write_bytes path bytes;host_writes:=(name,Bytes.length bytes)::!host_writes in
    Option.iter(save experiment.rel_name) experiment.rel_bytes;
    Option.iter(save experiment.int_name) experiment.int_bytes;
    let report_timings=ref[] in
    let serialization_started=Unix.gettimeofday() in
    if options.report=Explorer then (
      let map=Option.get experiment.execution_map and provenance=Option.get experiment.provenance in
      let images=List.map(fun name->match Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename:name with Ok i->i|Error _->failwith"bad execution image")
        ["PLI.COM";"PLI0.OVL";"PLI1.OVL";"PLI2.OVL"] in
      let map_started=Unix.gettimeofday() in
      let execution=match Analysis.Execution_report.report_of_map map ~images with Ok x->x|Error _->failwith"Execution Map report missing image" in
      report_timings:=("execution_report_projection",Unix.gettimeofday()-.map_started)::!report_timings;
      let rel=match experiment.rel_bytes with Some b->b|None->failwith"compiler produced no REL; explorer requires an output REL" in
      let rel_key=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:experiment.rel_name with Ok k->k|Error _->failwith"invalid REL identity" in
      let classify key=match key.Cpm.Filesystem.name with
        |name when name=module_name^".PLI"->Analysis.Provenance_report.Program_input
        |name when name=module_name^".INT"->Intermediate
        |"PLI.COM"|"PLI0.OVL"|"PLI1.OVL"|"PLI2.OVL"->Program_image
        |name when name=module_name^".REL"->Output|_->Other"other" in
      let selected_offsets=match Pli80.Experiment.select_rel_offsets ?requested:(if options.selected_rel=[] then None else Some options.selected_rel)(Bytes.length rel) with Ok x->x|Error e->failwith e in
      let selected=List.map(fun offset->{Analysis.Provenance_report.file=rel_key;offset;generation=None})selected_offsets in
      let data_started=Unix.gettimeofday() in
      let report=match Analysis.Provenance_report.report_of_provenance ~provenance ~execution ~classify ~output_file:rel_key ~output_bytes:rel ~selected () with Ok x->x|Error _->failwith"provenance report projection failed" in
      report_timings:=("data_report_projection",Unix.gettimeofday()-.data_started)::!report_timings;
      let data_json=Analysis.Provenance_report.to_json_string report in
      save "provenance-report.json" (Bytes.of_string data_json);
      let control_json=if options.analysis=Path then (
        let path_started=Unix.gettimeofday() in
        let control=match Analysis.Provenance_report.path_control_report_of_provenance ~provenance ~selected with Ok x->x|Error _->failwith"path-control projection failed" in
        report_timings:=("path_control_projection",Unix.gettimeofday()-.path_started)::!report_timings;
        let json=Analysis.Provenance_report.control_report_to_json_string control in
        save "provenance-control-report.json" (Bytes.of_string json);Some json) else None in
      ignore control_json);
    List.iter(fun offset->
      let p=Option.get experiment.provenance in
      let rel_name=experiment.rel_name in
      let file=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:rel_name with Ok f->f|Error _->failwith"bad output key" in
      let observation=match Analysis.Provenance.final_output_byte p ~file ~offset with Some o->o|None->failwith(Printf.sprintf"no REL output provenance at offset %d"offset) in
      let name=Printf.sprintf"slice-%04X.json"offset in
      let path=Filename.concat output_dir name and ch=ref None in
      let channel=open_out_bin path in ch:=Some channel;
      Fun.protect ~finally:(fun()->close_out(Option.get !ch))(fun()->Analysis.Provenance.write_slice_json channel p ~roots:[observation.root]);
      let bytes=(Unix.stat path).Unix.st_size in host_writes:=(name,bytes)::!host_writes) options.raw_slices;
    (match experiment.dynamic_structure with
     |None->()
     |Some structure->
       let started=Unix.gettimeofday() in
       let json=Analysis.Dynamic_structure.to_json_string structure in
       save "dynamic-structure.json" (Bytes.of_string json);
       report_timings:=("dynamic_structure_serialization",Unix.gettimeofday()-.started)::!report_timings);
    (match experiment.dynamic_blocks with
     |None->()
     |Some report->
       let started=Unix.gettimeofday() in
       let json=Analysis.Dynamic_blocks.to_json_string report in
       save "dynamic-blocks.json" (Bytes.of_string json);
       report_timings:=("dynamic_blocks_serialization",Unix.gettimeofday()-.started)::!report_timings);
    let summary_file=options.report=Summary in
    if summary_file then (
      let size=ref 0 and json=ref"" in
      for _=0 to 5 do
        let host_writes=List.rev !host_writes @ ["run-summary.json",!size] in
        json:=json_summary ~module_name ~source:source_path ~host_source_bytes:(Bytes.length source_host)
          ~normalized_source_bytes:(Bytes.length source_compiler) ~analysis:options.analysis ~run:experiment.run
          ~rel_name:experiment.rel_name ~rel_bytes:experiment.rel_bytes ~int_name:experiment.int_name ~int_bytes:experiment.int_bytes
          ~execution_map:experiment.execution_map ~provenance:experiment.provenance
          ~dynamic_structure:experiment.dynamic_structure ~dynamic_blocks:experiment.dynamic_blocks ~source_seconds ~experiment
          ~report_timings:(List.rev !report_timings) ~serialization_seconds:(Unix.gettimeofday()-.serialization_started)
          ~host_writes ~summary_bytes:!size;
        let next=String.length !json in if next= !size then () else size:=next
      done;
      save "run-summary.json" (Bytes.of_string !json));
    let serialization_seconds=Unix.gettimeofday()-.serialization_started in
    let total_seconds=Unix.gettimeofday()-.total_started in
    Printf.printf "module: %s\nsource: %s\nnormalized source: %d -> %d bytes\nanalysis: %s\nreport: %s\n\ncompiler:\n  termination: %s\n  steps: %d\n  pass1: %s\n  pass2: %s\n  END COMPILATION: %s\n\n"
      module_name source_path (Bytes.length source_host)(Bytes.length source_compiler)
      (Pli80.Experiment.analysis_name options.analysis)(Pli80.Experiment.report_name options.report)
      (termination_name experiment.run.termination)experiment.run.steps
      (if pass_ok experiment.console"NO ERROR(S) IN PASS 1"then"success"else"not confirmed")
      (if pass_ok experiment.console"NO ERROR(S) IN PASS 2"then"success"else"not confirmed")
      (if pass_ok experiment.console"END  COMPILATION"then"yes"else"no");
    (match experiment.rel_bytes with None->print_endline"output: REL not produced"|Some rel->Printf.printf"output:\n  %s: %d bytes\n  SHA-256: %s\n  %s survives: %s\n\n"
      experiment.rel_name(Bytes.length rel)(Pli80.Experiment.sha256_hex rel)experiment.int_name(if experiment.int_bytes=None then"no"else"yes"));
    (match experiment.execution_map with None->()|Some map->let x=Analysis.Execution_map.summary map in Printf.printf"execution attributed: %d / %d\n"
      x.attributed_instruction_executions x.total_instruction_executions);
    (match experiment.provenance with None->()|Some p->Printf.printf"provenance nodes: %d\nprovenance edges: %d\ncontrol decisions: %d\n"
      (Analysis.Provenance.node_count p)(Analysis.Provenance.edge_count p)(Analysis.Provenance.control_decision_count p));
    Printf.printf"\nwall timings (seconds): input_load_normalization=%.3f setup=%.3f execution+live_analysis=%.3f report_projection=%.3f serialization=%.3f total=%.3f\n"
      source_seconds experiment.timings.setup_seconds experiment.timings.execution_seconds
      (List.fold_left(fun n (name,v)->if name="execution_report_projection"||name="data_report_projection"||name="path_control_projection" then n+.v else n)0. !report_timings) serialization_seconds total_seconds;
    Printf.printf"host bytes written: %d (guest CP/M writes were memory-backed and are excluded)\n"
      (List.fold_left(fun n (_,size)->n+size)0 !host_writes);
    Option.iter(fun structure->
      print_string (Analysis.Dynamic_structure.to_text ~limit:20 structure);
      Printf.printf "structure report: %s (%d bytes)\nstructure serialization: %.3f s (live observation is included in execution+analysis)\n"
        (Filename.concat output_dir "dynamic-structure.json")
        (match List.assoc_opt "dynamic-structure.json" !host_writes with Some n->n|None->0)
        (Option.value(List.assoc_opt "dynamic_structure_serialization" !report_timings)~default:0.)) experiment.dynamic_structure;
    Option.iter(fun report->
      print_string (Analysis.Dynamic_blocks.to_text report);
      let by_image=Hashtbl.create 8 in
      List.iter(fun (block:Analysis.Dynamic_blocks.block)->
        let key=match block.image with Some image->image.Cpm.Filesystem.name|None->"<unresolved>" in
        Hashtbl.replace by_image key (1+Option.value(Hashtbl.find_opt by_image key)~default:0))
        (Analysis.Dynamic_blocks.blocks report);
      let counts=Hashtbl.fold(fun name count acc->(name,count)::acc)by_image []|>List.sort compare in
      Printf.printf "blocks by image: %s\nblock report: %s (%d bytes)\n"
        (String.concat ", "(List.map(fun(name,count)->Printf.sprintf "%s=%d" name count)counts))
        (Filename.concat output_dir "dynamic-blocks.json")
        (match List.assoc_opt "dynamic-blocks.json" !host_writes with Some n->n|None->0)) experiment.dynamic_blocks;
    if options.report=Explorer then (
      let report_path=Filename.concat output_dir"provenance-report.json" in
      let bundle=Filename.concat output_dir"explorer-bundle" in
      if options.analysis=Path then Printf.printf"\nExplorer:\n  cd tools/provenance-explorer\n  npm run build\n  npm run bundle -- %s %s %s\n  python3 -m http.server --directory %s 8000\n"
        (Filename.quote (absolute_path report_path))
        (Filename.quote (absolute_path (Filename.concat output_dir "provenance-control-report.json")))
        (Filename.quote (absolute_path bundle))
        (Filename.quote (absolute_path bundle))
      else Printf.printf"\nExplorer:\n  cd tools/provenance-explorer\n  npm run build\n  npm run bundle -- %s %s\n  python3 -m http.server --directory %s 8000\n"
        (Filename.quote (absolute_path report_path))
        (Filename.quote (absolute_path bundle))
        (Filename.quote (absolute_path bundle));
    );
    (match options.report with Summary->Printf.printf"summary metadata: %s\n"(Filename.concat output_dir"run-summary.json")|_->());
    ignore total_seconds

let () =
  let args=Array.to_list Sys.argv |> List.tl in
  match args with
  |["--help"]->print_endline usage
  |_->
    let finish ()=try match parse args with
      |Error"help"->print_endline usage
      |Error e->failwith(e^"\n"^usage)
      |Ok o->run o
      with Sys_error e|Failure e->prerr_endline("pli80-analyze: "^e);exit 2 in
    finish()
