[@@@warning "-4-40-41-42"]
type previous = { origin : Analysis.Execution_map.origin;
  before : Runner.state_snapshot; after : Runner.state_snapshot; step : I8080.Step.t }
type oracle = { input : Runner.state_snapshot; output : Runner.state_snapshot;
  entry_memory : bytes; post_memory : bytes; logical_digest : string }
type prepared = { state : Runner.state_snapshot; memory : bytes;
  logical_writes : (int * int) list; compatibility_writes : (int * int) list }
type t = { image : string; entry_pc : int; end_pc : int;
  remaining : oracle list ref; records : (string * int * bytes) list ref;
  pending : oracle option ref; count : int ref;
  prepare : previous -> Analysis.Execution_map.origin -> Runner.instruction_boundary -> prepared }
let require b message=if not b then failwith("Native dispatch: "^message)
let write_digest writes=Experiment.sha256_hex(Bytes.of_string(String.concat";"(List.map(fun(a,v)->Printf.sprintf"%04X:%02X"a v)writes)))
let create ~image ~entry_pc ~end_pc ~oracles ~records ~prepare=
  {image;entry_pc;end_pc;remaining=ref oracles;records=ref records;pending=ref None;count=ref 0;prepare}
let run input controllers =
  require(List.length controllers=List.length(List.sort_uniq compare(List.map(fun c->c.entry_pc)controllers)))"overlapping interceptors";
  let previous=ref None and current_origin=ref Analysis.Execution_map.Unknown in
  let on_before_instruction ~origin ~step_index:_ boundary=
    current_origin:=origin;
    List.iter(fun c->match !(c.pending)with None->()|Some expected->
      require(boundary.Runner.state=expected.output)"applied resume registers/flags";
      require(boundary.copy_memory()=expected.post_memory)"applied full64KiB resume memory";
      c.pending:=None)controllers in
  let on_guest_step ~step_index:_ ~before ~after step=
    List.iter(fun c->
      let belongs=match !current_origin with Analysis.Execution_map.Image_byte{image;_}->image.name=c.image|_->false in
      require(not(belongs && I8080.Step.pc_before step>=c.entry_pc && I8080.Step.pc_before step<c.end_pc))"unexpected historical execution of replaced body")controllers;
    previous:=Some{origin= !current_origin;before;after;step}in
  let on_bdos_record ~step_index:_ =function
    |Cpm.Bdos.Write_record{file;logical_record;data;_}->List.iter(fun c->match !(c.records)with
      |(name,r,b)::rest->require(name=file.name && r=logical_record && b=data)"INT/REL record identity";c.records:=rest
      |[]->failwith"Unexpected additional output record")controllers
    |_->()in
  let intercept ~origin ~step_index:_ boundary=
    (* Runtime PCs recur in different overlays; only the selected canonical image
       is a replacement boundary. Unknown origins still fail through its proof. *)
    match List.find_opt(fun c->c.entry_pc=boundary.Runner.state.pc &&
      (match origin with Analysis.Execution_map.Image_byte{image;_}->image.name=c.image|_->true))controllers with
    |None->Runner.Continue_guest_execution
    |Some c->
      let expected=match !(c.remaining)with x::_->x|[]->failwith"Unexpected additional native invocation"in
      require(boundary.state=expected.input && boundary.copy_memory()=expected.entry_memory)"per-invocation entry differs";
      let previous=match !previous with Some p->p|None->failwith"Entry without actual CALL"in
      let result=c.prepare previous origin boundary in
      require(result.state=expected.output && result.memory=expected.post_memory)"prepared full post-state differs";
      require(write_digest result.logical_writes=expected.logical_digest)"logical write chronology";
      c.remaining:=List.tl !(c.remaining);incr c.count;c.pending:=Some expected;
      Runner.Apply_host_transition{next_state=result.state;memory_writes=result.logical_writes@result.compatibility_writes}in
  match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record ~intercept input with
  |Error _ as e->e|Ok result->
    List.iter(fun c->require(!(c.remaining)=[] && !(c.pending)=None && !(c.records)=[])"omitted expected invocation/resume/record")controllers;
    let counts=List.map(fun c-> !(c.count))controllers in
    require(List.fold_left(+)0 counts=result.run.host_transitions)"native transition accounting";
    Ok(counts,result)
