[@@@warning "-4"]
(* Archaeology validation only: execute exact historical bytes, never a native emitter. *)
let bytes hex = Bytes.init (String.length hex / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub hex (2*i) 2)))
let emitter = bytes "21b020712a0c1e2600018c1d093ab020773a0c1e3c320c1efe80c22c10018c1dcdee03210c1e360001a21ccd2804fe00ca2c10cda00fc9"
let decode raw =
 let rec loop i = if i=Bytes.length raw then [] else
 match I8080.Decode.decode raw ~offset:i with
 | Ok d -> (i,I8080.Instr_format.format d.I8080.Decode.instr)::loop(i+d.I8080.Decode.length)
 | Error _ -> failwith "Exact historical decode failed" in loop 0
let even n = let count=ref 0 in for bit=0 to 7 do if n land (1 lsl bit)<>0 then incr count done; !count mod 2=0
let () =
 (match Sys.getenv_opt "RUNES_HOST_IMAGES" with None -> () | Some directory ->
  let channel=open_in_bin(Filename.concat directory "PLI.COM")in
  let raw=Fun.protect ~finally:(fun()->close_in channel)(fun()->let b=Bytes.create(in_channel_length channel)in really_input channel b 0(Bytes.length b);b)in
  List.iter(fun(off,hex)->assert(Bytes.sub raw off (String.length hex/2)=bytes hex))[0xef6,"21b020712a0c1e2600018c1d093ab020773a0c1e3c320c1efe80c22c10018c1dcdee03210c1e360001a21ccd2804fe00ca2c10cda00fc9";0x328,"216620702b712a6520eb0e15cdbb1ac9";0xea0,"019802cdf205c9";0x4f2,"217520702b713a051d1fd2050601e41ccd050421112036012a7420444dcd7d05c9"]);
 assert(List.assoc 51 (decode emitter)="CALL 0FA0H");
 assert(List.map snd(decode(bytes "217520702b713a051d1fd2050601e41ccd050421112036012a7420444dcd7d05c9"))=["LXI H,2075H";"MOV M,B";"DCX H";"MOV M,C";"LDA 1D05H";"RAR";"JNC 0605H";"LXI B,1CE4H";"CALL 0405H";"LXI H,2011H";"MVI M,01H";"LHLD 2074H";"MOV B,H";"MOV C,L";"CALL 057DH";"RET"]);
 let wrapper=decode(bytes "216620702b712a6520eb0e15cdbb1ac9")in
 assert(List.map snd wrapper=["LXI H,2066H";"MOV M,B";"DCX H";"MOV M,C";"LHLD 2065H";"XCHG";"MVI C,15H";"CALL 1ABBH";"RET"]);
 assert(List.map snd(decode(bytes "019802cdf205c9"))=["LXI B,0298H";"CALL 05F2H";"RET"]);
 for index=0 to 255 do
  (* 127 flushes; 128/129 alias the index pair and are outside this local scope. *)
  if index<>127 && index<>128 && index<>129 then for mask=0 to 31 do
   let m=I8080.Memory.create()and s=I8080.State.create()in
   I8080.Memory.load m ~address:0xff6 emitter;
   I8080.Memory.write m 0x1e0c index;I8080.Memory.write m 0x1e0d 0x73;
   I8080.Memory.write16 m 0xf000 0x4000;
   I8080.State.set_pc s 0xff6;I8080.State.set_sp s 0xf000;
   I8080.State.set_bc s 0x125a;I8080.State.set_de s 0x6789;
   let f=I8080.State.flags s in
   I8080.Flags.set_sign f(mask land 16<>0);I8080.Flags.set_zero f(mask land 8<>0);
   I8080.Flags.set_auxiliary_carry f(mask land 4<>0);I8080.Flags.set_parity f(mask land 2<>0);I8080.Flags.set_carry f(mask land 1<>0);
   let cpu=I8080.Cpu.create ~state:s ~bus:(I8080.Bus.create m)in
   let writes=ref[]in
   for _instruction=1 to 14 do match I8080.Cpu.step cpu with
   |Error _->failwith "Historical nonflush execution failed"
   |Ok step->List.iter(function I8080.Step.Write{address;value}->writes:=(address,value)::!writes|_->())(I8080.Step.memory_accesses step)
   done;
   let q=(index+1)land 255 in let diff=(q-128)land 255 in
   assert(I8080.State.pc s=0x4000&&I8080.State.sp s=0xf002);
   assert(I8080.State.a s=q&&I8080.State.bc s=0x1d8c&&I8080.State.de s=0x6789&&I8080.State.hl s=0x1d8c+index);
   assert(List.rev !writes=[0x20b0,0x5a;0x1d8c+index,0x5a;0x1e0c,q]);
   assert(I8080.Flags.sign f=(diff land 128<>0)&&I8080.Flags.zero f=(diff=0));
   assert(I8080.Flags.auxiliary_carry f&&I8080.Flags.parity f=even diff&&I8080.Flags.carry f=(q<128))
  done
 done;
 Printf.printf "Exact static decodes and 8,096 nonaliasing nonflush index/flag cases passed\n"
