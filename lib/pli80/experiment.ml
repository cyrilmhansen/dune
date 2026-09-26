[@@@warning "-4-27-40-41-42-69"]

type analysis = Run | Execution | Data | Path
type report = No_report | Summary | Explorer
type input = {
  pli_com:bytes; pli0_ovl:bytes; pli1_ovl:bytes; pli2_ovl:bytes;
  source_name:string; source_bytes:bytes; module_name:string; command_tail:bytes;
  max_steps:int;
}
type timings = {setup_seconds:float;execution_seconds:float}
type result = {
  run:Runner.run_result;console:string;filesystem:Cpm.Filesystem.t;
  rel_name:string;rel_bytes:bytes option;int_name:string;int_bytes:bytes option;
  execution_map:Analysis.Execution_map.t option;
  provenance:Analysis.Provenance.t option;
  dynamic_structure:Analysis.Dynamic_structure.t option;
  dynamic_blocks:Analysis.Dynamic_blocks.report option;
  ownership_audit:Analysis.Ownership_audit.t option;
  timings:timings;
}
type error = Invalid_module_name of string | Filesystem_error of Cpm.Filesystem.error
  | Run_error of Runner.error | Structure_requires_execution_map

let analysis_name = function Run->"run"|Execution->"execution"|Data->"data"|Path->"path"
let parse_analysis = function
  |"run"->Ok Run|"execution"->Ok Execution|"data"->Ok Data|"path"->Ok Path
  |_ ->Error"analysis must be run, execution, data, or path"
let report_name = function No_report->"none"|Summary->"summary"|Explorer->"explorer"
let parse_report = function
  |"none"->Ok No_report|"summary"->Ok Summary|"explorer"->Ok Explorer
  |_ ->Error"report must be none, summary, or explorer"

let parse_offset text =
  try
    let value=if String.starts_with ~prefix:"0x" text || String.starts_with ~prefix:"0X" text
      then int_of_string text
      else if String.ends_with ~suffix:"h" text || String.ends_with ~suffix:"H" text
      then int_of_string ("0x"^String.sub text 0 (String.length text-1))
      else int_of_string text in
    if value<0 then Error"offset must be non-negative" else Ok value
  with _->Error"offset must be decimal or 0x-prefixed hexadecimal"

let select_rel_offsets ?requested size =
  if size<0 then Error"REL size must be non-negative"
  else match requested with
    |Some offsets->
        let rec check seen=function
          |[]->Ok(List.rev seen)
          |x::_ when x<0 || x>=size->Error(Printf.sprintf"REL offset %d is outside the %d-byte file"x size)
          |x::xs->check(if List.mem x seen then seen else x::seen)xs in check[]offsets
    |None when size=0->Ok[]
    |None->Ok(List.fold_left(fun acc x->if List.mem x acc then acc else acc@[x])[][0;size/2;size-1])

let module_char c =
  match c with
  |'A'..'Z'|'0'..'9'|'$'|'#'|'@'|'!'|'%'|'&'|'\''|'('|')'|'-'|'_'|'{'|'}'|'^'|'~' -> true
  |_ -> false

let validate_module_name name =
  let normalized=String.uppercase_ascii name in
  if String.length normalized<1 || String.length normalized>8
     || not(String.for_all module_char normalized)
  then Error(Invalid_module_name name) else Ok normalized

let derive_module_name path =
  let base=Filename.basename path in
  let stem=match String.rindex_opt base '.' with
    |Some dot->String.sub base 0 dot|None->base in
  validate_module_name stem

let output_names module_name =
  match validate_module_name module_name with
  |Error _ as error->error
  |Ok module_name->Ok(module_name^".REL",module_name^".INT")

let normalize_cpm_source source =
  let length=Bytes.length source in
  let logical_end=ref length in
  while !logical_end>0 && Char.code(Bytes.get source (!logical_end-1))=0x1a do decr logical_end done;
  let out=Bytes.create (2* !logical_end+1) in
  let dst=ref 0 and i=ref 0 in
  while !i< !logical_end do
    let c=Bytes.get source !i in
    if c='\r' && !i+1< !logical_end && Bytes.get source (!i+1)='\n' then (
      Bytes.set out !dst '\r';Bytes.set out (!dst+1) '\n';dst:= !dst+2;i:= !i+2)
    else if c='\n' then (
      Bytes.set out !dst '\r';Bytes.set out (!dst+1) '\n';dst:= !dst+2;incr i)
    else (Bytes.set out !dst c;incr dst;incr i)
  done;
  Bytes.set out !dst '\026';Bytes.sub out 0 (!dst+1)

let prepare_source ~normalize source =
  if normalize then normalize_cpm_source source else Bytes.copy source

(* Dependency-free SHA-256, used for reproducible output metadata. *)
let sha256_hex input =
  let k=[|
    0x428a2f98l;0x71374491l;0xb5c0fbcfl;0xe9b5dba5l;0x3956c25bl;0x59f111f1l;0x923f82a4l;0xab1c5ed5l;
    0xd807aa98l;0x12835b01l;0x243185bel;0x550c7dc3l;0x72be5d74l;0x80deb1fel;0x9bdc06a7l;0xc19bf174l;
    0xe49b69c1l;0xefbe4786l;0x0fc19dc6l;0x240ca1ccl;0x2de92c6fl;0x4a7484aal;0x5cb0a9dcl;0x76f988dal;
    0x983e5152l;0xa831c66dl;0xb00327c8l;0xbf597fc7l;0xc6e00bf3l;0xd5a79147l;0x06ca6351l;0x14292967l;
    0x27b70a85l;0x2e1b2138l;0x4d2c6dfcl;0x53380d13l;0x650a7354l;0x766a0abbl;0x81c2c92el;0x92722c85l;
    0xa2bfe8a1l;0xa81a664bl;0xc24b8b70l;0xc76c51a3l;0xd192e819l;0xd6990624l;0xf40e3585l;0x106aa070l;
    0x19a4c116l;0x1e376c08l;0x2748774cl;0x34b0bcb5l;0x391c0cb3l;0x4ed8aa4al;0x5b9cca4fl;0x682e6ff3l;
    0x748f82eel;0x78a5636fl;0x84c87814l;0x8cc70208l;0x90befffal;0xa4506cebl;0xbef9a3f7l;0xc67178f2l|] in
  let rotr x n=Int32.logor(Int32.shift_right_logical x n)(Int32.shift_left x (32-n)) in
  let n=Bytes.length input in
  let padded=((n+9+63)/64)*64 in
  let message=Bytes.make padded '\000' in Bytes.blit input 0 message 0 n;Bytes.set message n '\128';
  let bit_length=Int64.mul(Int64.of_int n)8L in
  for i=0 to 7 do Bytes.set message (padded-1-i)(Char.chr(Int64.to_int(Int64.logand(Int64.shift_right_logical bit_length (8*i))255L))) done;
  let h=[|0x6a09e667l;0xbb67ae85l;0x3c6ef372l;0xa54ff53al;0x510e527fl;0x9b05688cl;0x1f83d9abl;0x5be0cd19l|] in
  let w=Array.make 64 0l in
  for block=0 to padded/64-1 do
    let offset=block*64 in
    for i=0 to 15 do
      let j=offset+4*i in
      let byte j=Int32.of_int(Char.code(Bytes.get message j)) in
      w.(i)<-Int32.logor(Int32.shift_left(byte j)24)(Int32.logor(Int32.shift_left(byte(j+1))16)(Int32.logor(Int32.shift_left(byte(j+2))8)(byte(j+3))))
    done;
    for i=16 to 63 do
      let x=w.(i-15) and y=w.(i-2) in
      let s0=Int32.logxor(rotr x 7)(Int32.logxor(rotr x 18)(Int32.shift_right_logical x 3)) in
      let s1=Int32.logxor(rotr y 17)(Int32.logxor(rotr y 19)(Int32.shift_right_logical y 10)) in
      w.(i)<-Int32.add(Int32.add(Int32.add w.(i-16) s0) w.(i-7)) s1
    done;
    let a=ref h.(0) and b=ref h.(1) and c=ref h.(2) and d=ref h.(3)
    and e=ref h.(4) and f=ref h.(5) and g=ref h.(6) and hh=ref h.(7) in
    for i=0 to 63 do
      let s1=Int32.logxor(rotr !e 6)(Int32.logxor(rotr !e 11)(rotr !e 25)) in
      let ch=Int32.logxor(Int32.logand !e !f)(Int32.logand(Int32.lognot !e)!g) in
      let t1=Int32.add(Int32.add(Int32.add(Int32.add !hh s1)ch)k.(i))w.(i) in
      let s0=Int32.logxor(rotr !a 2)(Int32.logxor(rotr !a 13)(rotr !a 22)) in
      let maj=Int32.logxor(Int32.logand !a !b)(Int32.logxor(Int32.logand !a !c)(Int32.logand !b !c)) in
      let t2=Int32.add s0 maj in
      hh:= !g;g:= !f;f:= !e;e:=Int32.add !d t1;d:= !c;c:= !b;b:= !a;a:=Int32.add t1 t2
    done;
    Array.iteri(fun i value->h.(i)<-Int32.add h.(i) value)[|!a;!b;!c;!d;!e;!f;!g;!hh|]
  done;
  Array.to_list h |> List.map(Printf.sprintf "%08lx") |> String.concat ""

let run ?(structure=false) ~analysis input =
  match validate_module_name input.module_name with
  |Error _ as error->error
  |Ok _ when structure && analysis=Run->Error Structure_requires_execution_map
  |Ok module_name->
    let setup_started=Unix.gettimeofday() in
    let filesystem=Cpm.Filesystem.create() in
    let source_name=if input.source_name="" then module_name^".PLI" else input.source_name in
    let add name bytes=match Cpm.Filesystem.add_file filesystem ~name bytes with
      |Ok()->Ok()|Error e->Error(Filesystem_error e) in
    let rec add_all=function []->Ok()|(name,bytes)::rest->(match add name bytes with Ok()->add_all rest|Error _ as e->e) in
    match add_all ["PLI0.OVL",input.pli0_ovl;"PLI1.OVL",input.pli1_ovl;"PLI2.OVL",input.pli2_ovl;source_name,input.source_bytes] with
    |Error _ as error->error
    |Ok()->
      let execution_map=match analysis with Run->None|Execution|Data|Path->Some(Analysis.Execution_map.create()) in
      let dynamic_structure=if structure then Some(Analysis.Dynamic_structure.create()) else None in
      let dynamic_blocks_builder=if structure then Some(Analysis.Dynamic_blocks.create()) else None in
      let ownership_audit=if structure then Some(Analysis.Ownership_audit.create()) else None in
      let provenance=match analysis with
        |Run|Execution->None
        |Data->Some(Analysis.Provenance.create ~path_control:false ())
        |Path->Some(Analysis.Provenance.create()) in
      let image name=match Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename:name with
        |Ok image->image|Error _->failwith("invalid image identity: "^name) in
      let com_image=image "PLI.COM" in
      Option.iter(fun map->match Analysis.Execution_map.seed_image map ~image:com_image ~runtime_base:0x100 input.pli_com with
        |Ok()->()|Error message->failwith message)execution_map;
      Option.iter(fun p->Analysis.Provenance.seed_image p ~image:com_image ~runtime_base:0x100 input.pli_com)provenance;
      let console=Buffer.create 256 in
      let on_start page=Option.iter(fun p->
        Analysis.Provenance.seed_memory p ~class_:Analysis.Provenance.System ~address:0 page;
        Analysis.Provenance.seed_command_tail p ~address:0x81 input.command_tail;
        if Bytes.length input.command_tail>1 then
          Analysis.Provenance.seed_command_tail_mapping p ~address:0x5d ~tail_offset:1
            (Bytes.sub input.command_tail 1 (Bytes.length input.command_tail-1)))provenance in
      let last_sp=ref None in
      let on_start_state=if provenance=None && dynamic_structure=None then None else Some(fun state->
        Option.iter(fun p->Analysis.Provenance.seed_initial_registers p state) provenance;
        if dynamic_structure<>None then last_sp:=Some state.Runner.sp) in
      let on_step_state=match provenance,dynamic_structure,dynamic_blocks_builder with
        |None,None,None->None
        |provenance,dynamic_structure,dynamic_blocks_builder->Some(fun ~step_index state step->
          let attribution=Option.map(fun structure->
            Analysis.Dynamic_structure.observe_step_detailed ?sp_before:!last_sp ~sp_after:state.Runner.sp
              structure (Option.get execution_map) ~step_index step)dynamic_structure in
          (match ownership_audit,attribution with
           |Some audit,Some attribution->Analysis.Ownership_audit.observe_step audit (Option.get execution_map)
               ~routine_id:attribution.routine_id ~step_index step attribution.audit_events
           |_->());
          (match dynamic_blocks_builder,attribution with
           |Some blocks,Some attribution->Analysis.Dynamic_blocks.observe_step blocks (Option.get execution_map)
               ~routine_id:attribution.routine_id ~routine_entry:attribution.routine_entry ~step_index step
           |_->());
          Option.iter(fun p->
          let resolve ~pc ~fetched=match execution_map with
            |None->None
            |Some map->(match Analysis.Execution_map.origin_at map pc with
              |Analysis.Execution_map.Image_byte {image;offset}->
                  let consistent=ref true in
                  Bytes.iteri(fun i _->if Analysis.Execution_map.origin_at map ((pc+i)land 0xffff)
                    <>Analysis.Execution_map.Image_byte {image;offset=offset+i} then consistent:=false)fetched;
                  if !consistent then Some{Analysis.Provenance.image;offset;runtime_pc=pc}else None
              |Analysis.Execution_map.Unknown->None) in
          Analysis.Provenance.observe_step ~origin_at:resolve p ~step_index state step)provenance;
          if dynamic_structure<>None then last_sp:=Some state.Runner.sp) in
      let on_event=Option.map Analysis.Execution_map.observe_runner_event execution_map in
      let on_bdos_event=match execution_map,provenance with
        |None,None->None
        |_->Some(fun ~step_index event->
          Option.iter(fun map->Analysis.Execution_map.observe_bdos_event ~step_index map event)execution_map;
          Option.iter(fun p->Analysis.Provenance.observe_bdos_event p ~step_index event)provenance) in
      let on_bdos_effect=Option.map Analysis.Provenance.observe_bdos_effect provenance in
      let setup_seconds=Unix.gettimeofday()-.setup_started in
      let execution_started=Unix.gettimeofday() in
      let run_result=Runner.run_bytes ~max_steps:input.max_steps ?on_step_state ?on_event ?on_bdos_event ?on_bdos_effect
        ~on_start ?on_start_state ~filesystem ~command_tail:input.command_tail
        ~output:(Buffer.add_char console) input.pli_com in
      let execution_seconds=Unix.gettimeofday()-.execution_started in
      (match run_result with Error e->Error(Run_error e)|Ok run->
        let rel_name,int_name=match output_names module_name with Ok names->names|Error _->assert false in
        let read name=match Cpm.Filesystem.get_file filesystem ~name () with Ok b->b|Error _->None in
        let dynamic_blocks=match dynamic_structure,dynamic_blocks_builder with
          |Some structure,Some blocks->Some(Analysis.Dynamic_blocks.materialize blocks (Analysis.Dynamic_structure.routines structure))
          |_->None in
        Ok{run;console=Buffer.contents console;filesystem;rel_name;rel_bytes=read rel_name;
          int_name;int_bytes=read int_name;execution_map;provenance;dynamic_structure;dynamic_blocks;ownership_audit;
          timings={setup_seconds;execution_seconds}})
