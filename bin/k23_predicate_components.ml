[@@@warning "-4-40-41-42"]
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
module N=Pli80.Native_resident_output
let ()=
 let images=ref""and windows=ref""and output=ref""in Arg.parse["--images",Arg.Set_string images,"images";"--windows",Arg.Set_string windows,"source start end rows";"--output",Arg.Set_string output,"JSON"]ignore"independent existing canonical child shadows";
 let c=open_in !windows in let rec lines xs=match input_line c with line->lines(line::xs)|exception End_of_file->List.rev xs in let rows=Fun.protect ~finally:(fun()->close_in c)(fun()->lines[])in
 let summaries=List.concat_map(fun source->let selected=List.filter_map(fun line->match String.split_on_char ' ' line with [name;a;b]when name=source->Some(int_of_string a,int_of_string b)|_->None)rows in
 if selected=[]then []else(
 let image n=read(Filename.concat !images n)in let input:Pli80.Experiment.input={pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";source_name=source^".PLI";source_bytes=Pli80.Experiment.prepare_source ~normalize:true(read(let p="examples/pli80/"^source^".PLI"in if Sys.file_exists p then p else Filename.concat !images(source^".PLI")));module_name=source;command_tail=Bytes.of_string(" "^source);max_steps=10_000_000}in
 List.map(fun offset->let proof=match N.shadow ~pli2:true ~offset ~within:selected ~run_negatives:(offset=0x1dff) input with Ok q->q|Error _->failwith"canonical child mismatch"in
 Printf.printf"%s +%04X component shadows=%d\n%!"source offset(List.length(N.cases proof));
 Printf.sprintf"{\"source\":%S,\"offset\":%d,\"count\":%d,\"full_registers_flags_RAM_ordered_writes_stack_services_compared\":true}"source offset(List.length(N.cases proof)))[0x1dff;0x0992;0x04a9;0x047d]))["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]in
 let c=open_out !output in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"components\":[%s],\"synthetic_cases\":[%s],\"all_passed\":true}"(String.concat","summaries)(String.concat","(List.rev !N.carrier_synthetic_proofs)))
