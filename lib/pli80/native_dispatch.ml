[@@@warning "-4-40-41-42"]
type previous = { origin : Analysis.Execution_map.origin;
  before : Runner.state_snapshot; after : Runner.state_snapshot; step : I8080.Step.t }
type oracle = { input : Runner.state_snapshot; output : Runner.state_snapshot;
  entry_memory : bytes; post_memory : bytes; logical_digest : string }
type prepared = { state : Runner.state_snapshot; memory : bytes;
  logical_writes : (int * int) list; compatibility_writes : (int * int) list }
type applicability = Inapplicable | Eligible
type t = { image : string; entry_pc : int; end_pc : int;
  remaining : oracle list ref; records : (string * int * bytes) list ref;
  pending : oracle option ref; count : int ref;
  scope : (previous -> Analysis.Execution_map.origin -> Runner.instruction_boundary -> applicability) option;
  guest_frames : (int * int) list ref; declined : int ref;
  host_program : (Runner.instruction_boundary -> prepared -> Runner.host_program) option;
  prepare : previous -> Analysis.Execution_map.origin -> Runner.instruction_boundary -> prepared }
let require b message=if not b then failwith("Native dispatch: "^message)
let write_digest writes=Experiment.sha256_hex(Bytes.of_string(String.concat";"(List.map(fun(a,v)->Printf.sprintf"%04X:%02X"a v)writes)))
let create ~image ~entry_pc ~end_pc ~oracles ~records ~prepare=
  {image;entry_pc;end_pc;remaining=ref oracles;records=ref records;pending=ref None;count=ref 0;prepare;host_program=None;scope=None;guest_frames=ref[];declined=ref 0}
let with_partial_scope t scope={t with scope=Some scope}
let declined_count t= !(t.declined)
let with_host_program t program = {t with host_program=Some program}
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
      if belongs && I8080.Step.pc_before step>=c.entry_pc && I8080.Step.pc_before step<c.end_pc then
       require(c.scope<>None && (match !(c.guest_frames)with (sp,_)::_->before.Runner.sp<=sp|[]->false))"unexpected historical execution of replaced body";
      (match !(c.guest_frames),I8080.Step.control_flow step with
       |(sp,resume)::rest,I8080.Step.Return{taken=true;target=Some target}when before.sp=sp&&target=resume->
        require(after.Runner.sp=sp+2)"declined hardware RET stack";c.guest_frames:=rest
       |_->()))controllers;
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
      let previous=match !previous with Some p->p|None->failwith"Entry without actual CALL"in
      let applicable=match c.scope with None->Eligible|Some probe->probe previous origin boundary in
      if applicable=Inapplicable then(
       let s=boundary.Runner.state.sp in
       let continuation=boundary.read_memory s lor(boundary.read_memory(s+1)lsl 8)in
       require(previous.after=boundary.state&&previous.before.sp=s+2&&continuation=previous.before.pc+3&&
        I8080.Step.control_flow previous.step=I8080.Step.Call{target=c.entry_pc;taken=true})"declined hardware CALL ancestry";
       c.guest_frames:=(s,continuation)::!(c.guest_frames);incr c.declined;
       Runner.Continue_guest_execution
      )else(
      let expected=match !(c.remaining)with x::_->x|[]->failwith"Unexpected additional native invocation"in
      require(boundary.state=expected.input && boundary.copy_memory()=expected.entry_memory)"per-invocation entry differs";
      let result=c.prepare previous origin boundary in
      require(result.state=expected.output && result.memory=expected.post_memory)"prepared full post-state differs";
      require(write_digest result.logical_writes=expected.logical_digest)"logical write chronology";
      c.remaining:=List.tl !(c.remaining);incr c.count;c.pending:=Some expected;
      (match c.host_program with
       |None->Runner.Apply_host_transition{next_state=result.state;memory_writes=result.logical_writes@result.compatibility_writes}
       |Some program->Runner.Apply_host_program(program boundary result)))in
  match Experiment.run ~analysis:Experiment.Execution ~on_before_instruction ~on_guest_step ~on_bdos_record ~intercept input with
  |Error _ as e->e|Ok result->
    List.iter(fun c->require(!(c.remaining)=[] && !(c.pending)=None && !(c.records)=[] && !(c.guest_frames)=[])"omitted expected invocation/resume/record")controllers;
    let counts=List.map(fun c-> !(c.count))controllers in
    require(List.fold_left(+)0 counts=result.run.host_transitions)"native transition accounting";
    Ok(counts,result)
