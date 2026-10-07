[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array xs="["^String.concat","xs^"]"
let ()=
 let toolchain=ref""and output=ref""and spine=ref false in
 Arg.parse["--spine",Arg.Set spine,"prove recursive prefix up to first missing resident route";"--toolchain",Arg.Set_string toolchain,"DISK1";"--output",Arg.Set_string output,"development proof JSON"](fun _->failwith"argument")"partial +6223 implementation proof";
 if !toolchain=""|| !output=""then failwith"arguments required";
 let reports=List.concat_map(fun name->
 let image n=read(Filename.concat !toolchain n)in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
 List.map(fun op->let matched,pending,cases=Pli80.Native_acquisition_family.shadow ~entry_steps:[390902;460822;527620] op input in
 let operation=match op with Pli80.Acquisition_family_bridge.Resident->"1376"|_->assert false in
 Printf.printf"%s %s: field15 matched %d; boundary proofs %d\n%!"name operation matched pending;
 Printf.sprintf"{\"source\":%S,\"operation\":%S,\"field15_matched\":%d,\"field80_boundary_matched\":%d,\"cases\":%s}"name operation matched pending(array cases))[Pli80.Acquisition_family_bridge.Resident])["FIZZBUZ"]in
 let ch=open_out !output in Fun.protect ~finally:(fun()->close_out ch)(fun()->output_string ch
 (Printf.sprintf"{\"status\":\"development proof; no hybrid controller\",\"recursive_prefix\":%b,\"sources\":%s}\n"!spine(array reports)))
