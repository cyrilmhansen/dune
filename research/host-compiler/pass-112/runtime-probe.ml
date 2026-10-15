(* One bounded feasibility probe using the existing Runner/CPM interfaces. *)
let read p = let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)
 (fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let () =
 let fs=Cpm.Filesystem.create()and console=Buffer.create 256 and steps=ref 0 and calls=ref[]in
 List.iter(fun(name,path)->match Cpm.Filesystem.add_file fs ~name (read path)with
 |Ok()->()|Error _->failwith"probe input")
 ["FIZZBUZ.REL",Sys.argv.(2);"PLILIB.IRL",Filename.concat Sys.argv.(1)"PLILIB.IRL"];
 let result=Runner.run_file ~filesystem:fs ~command_tail:(Bytes.of_string" FIZZBUZ")
  ~max_steps:10_000_000 ~on_before_instruction:(fun ~step_index _->steps:=step_index)
  ~on_bdos_call_state:(fun ~step_index:_ ~state ~dma:_ ~read_memory:_->calls:=state.Runner.c::!calls)
  ~output:(Buffer.add_char console) ~path:(Filename.concat Sys.argv.(1)"LINK.COM")()in
 let status=match result with
 |Error(Runner.Bdos_error(Cpm.Bdos.Unsupported_function n))->"unsupported_bdos_"^string_of_int n
 |Error(Runner.Step_limit_exceeded _)->"bounded_step_limit"
 |Error _->"other_runner_error"
 |Ok _->"linker_returned"in
 let com=match Cpm.Filesystem.get_file fs ~name:"FIZZBUZ.COM"()with Ok(Some b)->Bytes.length b|_->0 in
 Printf.printf"status=%s\nlast_step=%d\nCOM_bytes=%d\nbdos=%s\nconsole=%S\n"status !steps com
  (String.concat","(List.map string_of_int(List.rev !calls)))(Buffer.contents console)
