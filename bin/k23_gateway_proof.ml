[@@@warning "-4-40-41-42"]
module N=Pli80.Native_resident_output
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let ()=
 let images=ref""and windows=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--windows",Arg.Set_string windows,"windows";"--output",Arg.Set_string output,"output"]ignore"k23 staged whole-gateway law proof, no dispatcher installation";
 let c=open_in !windows in let rec lines acc=match input_line c with s->lines(s::acc)|exception End_of_file->List.rev acc in let rows=Fun.protect ~finally:(fun()->close_in c)(fun()->lines[])in
 let summaries=List.map(fun name->
  let ws=List.filter_map(fun line->match String.split_on_char ' ' line with [n;a;b]when n=name->Some(int_of_string a,int_of_string b)|_->None)rows in
  let image n=read(Filename.concat !images n)in
  let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let p="examples/pli80/"^name^".PLI"in if Sys.file_exists p then p else Filename.concat !images(name^".PLI")));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
  let shadow off=match N.shadow ~pli2:true ~offset:off ~within:ws ~run_negatives:(off=0x1fb5) input with Ok q->q|_->failwith"k23 whole-chain shadow"in
  let bridge=Pli80.Acquisition_family_bridge.create_with_images ~pli_com:input.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
  let previous=ref None and origin=ref Analysis.Execution_map.Unknown and accepted=ref 0 and rejected=ref 0 in
  let on_before_instruction ~origin:o ~step_index:_ (boundary:Runner.instruction_boundary)=
   origin:=o;
   if o=Pli80.Acquisition_family_bridge.origin "PLI2.OVL" 0x1fb5 then(
    let ram=boundary.copy_memory()and files=boundary.copy_filesystem()and dma=boundary.dma in
    (match Pli80.Acquisition_family_bridge.verify_call bridge (Pli2_output 0x1fb5)(Option.get !previous)~entry:boundary.state with
     |call->(match Pli80.Acquisition_family_bridge.prepare bridge (Pli2_output 0x1fb5)~call ~origin:o boundary with
       |_->incr accepted|exception Invalid_argument _->incr rejected)
     |exception Invalid_argument _->failwith"gateway CALL identity failed");
    if boundary.copy_memory()<>ram||boundary.dma<>dma||not(Cpm.Filesystem.equal(boundary.copy_filesystem())files)then failwith"scope audit live mutation")in
  let on_guest_step ~step_index:_ ~before ~after step=previous:=Some{Pli80.Native_dispatch.origin= !origin;before;after;step}in
  ignore(match Pli80.Experiment.run ~analysis:Execution ~on_before_instruction ~on_guest_step input with Ok q->q|_->failwith"scope audit");
  let root=shadow 0x1fb5 in
  if !accepted<>List.length(N.cases root)then failwith"scope differs from natural inventory";
  let components=List.map(fun off->off,shadow off)[0x047d;0x1dff;0x0992;0x04a9;0x3e36]in
  Printf.printf"%s whole k23 shadows %d\n%!"name(List.length(N.cases root));
  Printf.sprintf"{\"source\":%S,\"roots\":%d,\"rejected_other_gateway_roots\":%d,\"components\":[%s],\"full_state_RAM_writes_stack_calls_services\":true}"name(List.length(N.cases root))!rejected(String.concat","(List.map(fun(o,v)->Printf.sprintf"{\"offset\":%d,\"count\":%d}"o(List.length(N.cases v)))components))
 )["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]in
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"sources\":[%s],\"synthetic_cases\":[%s],\"all_passed\":true,\"native_gateway_installed\":false}"(String.concat","summaries)(String.concat","(List.rev !N.carrier_synthetic_proofs)))
