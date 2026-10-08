[@@@warning "-4-40-41-42"]
let read path=let c=open_in_bin path in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array xs="["^String.concat","xs^"]"
let ()=
 let toolchain=ref""and output=ref""and spine=ref false and operation=ref""in
 Arg.parse["--operation",Arg.Set_string operation,"2259 or345E bounded proofs";"--spine",Arg.Set spine,"prove recursive prefix up to first missing resident route";"--toolchain",Arg.Set_string toolchain,"DISK1";"--output",Arg.Set_string output,"development proof JSON"](fun _->failwith"argument")"partial +6223 implementation proof";
 if !toolchain=""|| !output=""then failwith"arguments required";
 let reports=List.concat_map(fun name->
 let image n=read(Filename.concat !toolchain n)in
 let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=name^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read("examples/pli80/"^name^".PLI"));module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}in
 List.map(fun op->let matched,pending,cases=Pli80.Native_acquisition_family.shadow ~spine:!spine op input in
 let operation=match op with Pli80.Acquisition_family_bridge.Context->"60E5"|Field->"5E98"|Pair_gate->"2259"|Selected_transform->"345E"|Table_adapter->"25A9"|Wrapper->"6619"|Repeat->"654E"|Copy05->"6708-E05"|Traversal->"46ED"|Construction->"4738"|Record_output->"666E"|Index_one->"28AA-I1"|Parent->"19F0"|_->assert false in
 Printf.printf"%s %s: field15 matched %d; boundary proofs %d\n%!"name operation matched pending;
 Printf.sprintf"{\"source\":%S,\"operation\":%S,\"field15_matched\":%d,\"field80_boundary_matched\":%d,\"cases\":%s}"name operation matched pending(array cases))(match !operation with "19F0"->[Pli80.Acquisition_family_bridge.Parent]|"28AA-I1"->[Pli80.Acquisition_family_bridge.Index_one]|"666E"->[Pli80.Acquisition_family_bridge.Record_output]|"46ED"->[Pli80.Acquisition_family_bridge.Traversal]|"4738"->[Pli80.Acquisition_family_bridge.Construction]|"6708-E05"->[Pli80.Acquisition_family_bridge.Copy05]|"2259"->[Pli80.Acquisition_family_bridge.Pair_gate]|"345E"->[Pli80.Acquisition_family_bridge.Selected_transform]|"25A9"->[Pli80.Acquisition_family_bridge.Table_adapter]|"6619"->[Pli80.Acquisition_family_bridge.Wrapper]|"654E"->[Pli80.Acquisition_family_bridge.Repeat]|""->[Context;Field]|_->failwith"operation"))(if List.mem !operation["25A9";"654E";"6619";"6708-E05";"46ED";"4738";"666E";"28AA-I1";"19F0"]then["MINIMAL";"FIZZBUZ";"PICTURE"]else["FIZZBUZ";"PICTURE"])in
 let ch=open_out !output in Fun.protect ~finally:(fun()->close_out ch)(fun()->output_string ch
 (Printf.sprintf"{\"status\":\"development proof; no hybrid controller\",\"recursive_prefix\":%b,\"sources\":%s}\n"!spine(array reports)))
