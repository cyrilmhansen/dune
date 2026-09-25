module P = Analysis.Provenance
[@@@warning "-40-41-42-4"]

let file name =
  match Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename:name with
  | Ok x -> x | Error _ -> failwith "invalid test image"

let snapshot (s : I8080.State.t) =
  let f=I8080.State.flags s in
  { Runner.a=I8080.State.a s; b=I8080.State.b s; c=I8080.State.c s;
    d=I8080.State.d s; e=I8080.State.e s; h=I8080.State.h s;
    l=I8080.State.l s; sp=I8080.State.sp s; pc=I8080.State.pc s;
    sign=I8080.Flags.sign f; zero=I8080.Flags.zero f;
    auxiliary_carry=I8080.Flags.auxiliary_carry f; parity=I8080.Flags.parity f;
    carry=I8080.Flags.carry f }

let run_program ?(initial_sp=0xfffe) bytes count =
  let p=P.create () and map=Analysis.Execution_map.create () in
  let id=file "TEST.COM" in
  let memory=I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x100 bytes;
  assert(Analysis.Execution_map.seed_image map ~image:id ~runtime_base:0x100 bytes=Ok());
  P.seed_image p ~image:id ~runtime_base:0x100 bytes;
  let state=I8080.State.create() in
  I8080.State.set_pc state 0x100; I8080.State.set_sp state initial_sp;
  P.seed_initial_registers p (snapshot state);
  let cpu=I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  for i=0 to count-1 do
    match I8080.Cpu.step cpu with
    | Error e -> failwith(Printf.sprintf "CPU test step %d failed: %s" i (match e with
        |I8080.Cpu.Cpu_halted->"halted"|Decode_error _->"decode"|Unsupported_instruction _->"unsupported"
        |Bus_io_error _->"I/O"|Interrupt_acknowledge_length _->"interrupt payload"))
    | Ok step ->
        P.observe_step ~origin_at:(fun ~pc ~fetched -> match Analysis.Execution_map.origin_at map pc with
          | Analysis.Execution_map.Image_byte {image;offset} when
              let good=ref true in Bytes.iteri(fun i _->if Analysis.Execution_map.origin_at map ((pc+i)land 0xffff)<>Analysis.Execution_map.Image_byte {image;offset=offset+i} then good:=false) fetched; !good ->
                Some {P.image;offset;runtime_pc=pc}
          | _->None) p ~step_index:i (snapshot state) step;
        assert(Analysis.Execution_map.observe_step map ~step_index:i step=Ok())
  done;
  p,map,state,memory

let has_edge role node = List.exists(fun (r,_)->r=role)node.P.inputs

let test_copy_alu_and_memory () =
  let program=Bytes.of_string
      "\x3e\x2a\x47\x0e\x03\x81\x21\x00\x30\x36\x5a\x7e\x3c\x3d\x32\x00\x40\x3a\x00\x40\x76" in
  let p,_,state,_=run_program program 12 in
  assert(I8080.State.b state=0x2a);
  assert(I8080.State.a state=0x5a);
  let copy,_,_,_=run_program (Bytes.of_string "\x3e\x42\x47\x76") 3 in
  assert(P.register_root copy ~register:I8080.Instr.B=P.register_root copy ~register:I8080.Instr.A);
  (* MOV B,A aliases the immediate-producing node instead of adding a fake copy node. *)
  let bnode=P.node copy (match P.register_root copy ~register:I8080.Instr.B with Node n->n|_->failwith "B untracked") in
  let copy_slice=P.slice_json copy ~roots:[P.register_root copy ~register:I8080.Instr.B] in
  assert(copy_slice=
    "RUNES_PROVENANCE_SLICE 1\n{\"roots\":[17],\"sinks\":[],\"nodes\":[{\"id\":1,\"value\":66,\"width\":8,\"step\":null,\"kind\":{\"drive\":0,\"user\":0,\"file\":\"TEST.COM\",\"offset\":1,\"value\":66},\"origin\":null,\"inputs\":[]},{\"id\":17,\"value\":66,\"width\":8,\"step\":0,\"kind\":{\"operation\":\"MVI\"},\"origin\":{\"drive\":0,\"user\":0,\"image\":\"TEST.COM\",\"offset\":0,\"runtime_pc\":256},\"inputs\":[{\"role\":\"value\",\"node\":1}]}]}\n");
  assert(bnode.kind=P.Operation "MVI");
  assert(List.exists(function P.File_byte {offset=1;_}->true|_->false)(P.source_leaves(P.slice copy [P.register_root copy ~register:I8080.Instr.B])));
  let root=P.memory_root p ~address:0x4000 in
  let s=P.slice p [root] in
  assert(List.exists(fun n->has_edge P.Address n)s.nodes);
  assert(List.exists(fun n->n.P.kind=P.Operation "Load.M" && has_edge P.Address n)s.nodes);
  assert(List.exists(function P.File_byte {file;offset;_}->file.name="TEST.COM" && offset=10|_->false)(P.source_leaves s));
  assert(P.memory_value p ~address:0x4000=0x5a)

let test_flags_stack_and_special_memory () =
  let program=Bytes.of_string
      "\x3e\xff\x37\xce\x00\x06\x00\x98\xb8\x27\x17\xf5\x3e\x00\xf1\x21\x34\x12\x22\x00\x30\x21\x00\x00\x2a\x00\x30\xe3\x76" in
  let p,_,_,_=run_program program 17 in
  assert(P.node_count p>20);
  let ac_root=P.flag_root p ~flag:`Carry in
  (match ac_root with
   |Node id->assert((P.node p id).width=1)
   |Untracked->failwith "flag width root missing");
  let ac_slice=P.slice p [ac_root;P.register_root p ~register:I8080.Instr.A;
    P.register_root p ~register:I8080.Instr.H;P.register_root p ~register:I8080.Instr.L;
    P.memory_root p ~address:0x3000] in
  assert(List.exists(fun n->n.P.kind=P.Operation "ALU.ADC" && has_edge P.Flag n)ac_slice.nodes);
  assert(List.exists(fun n->n.P.kind=P.Operation "ALU.SBB" && has_edge P.Flag n)ac_slice.nodes);
  assert(List.exists(fun n->n.P.kind=P.Operation "DAA.A")ac_slice.nodes);
  let daa_node=List.find(fun n->n.P.kind=P.Operation "DAA.A")ac_slice.nodes in
  assert(has_edge P.Flag daa_node);
  assert(List.exists(fun n->n.P.kind=P.Operation "ROTATE")ac_slice.nodes);
  assert(List.exists(fun id->match (P.node p id).P.kind with
    |P.Operation "PUSH.SP"->(P.node p id).width=16
    |_ ->false)(List.init(P.node_count p)Fun.id));
  let rotate_node=List.find(fun n->n.P.kind=P.Operation "ROTATE")ac_slice.nodes in
  assert(has_edge P.Flag rotate_node);
  let psw=Bytes.of_string "\x3e\x80\x37\xf5\x3e\x00\xf1\x76" in
  let pp,_,_,_=run_program psw 6 in
  assert((P.node pp (match P.register_root pp ~register:I8080.Instr.A with Node n->n|_->assert false)).kind=P.Operation "POP.PSW.A");
  let xthl=Bytes.of_string "\x21\x34\x12\xe3\x76" in
  let xp,_,_,_=run_program xthl 3 in
  assert((P.node xp (match P.register_root xp ~register:I8080.Instr.L with Node n->n|_->assert false)).kind=P.Operation "XTHL.load");
  let direct=Bytes.of_string "\x21\x34\x12\x22\x00\x30\x21\x00\x00\x2a\x00\x30\x76" in
  let dp,_,_,_=run_program direct 5 in
  assert((P.node dp (match P.register_root dp ~register:I8080.Instr.L with Node n->n|_->assert false)).kind=P.Operation "LHLD.L");
  assert(List.exists(fun n->n.P.kind=P.Operation "SHLD.L")(P.slice dp [P.memory_root dp ~address:0x3000]).nodes);
  let carry_program=Bytes.of_string "\x3e\xff\x37\x3c\x3d\x76" in
  let carry_prov,_,carry_state,_=run_program carry_program 5 in
  assert(I8080.Flags.carry (I8080.State.flags carry_state));
  (match P.node carry_prov (match P.flag_root carry_prov ~flag:`Carry with Node n->n|_->assert false) with
   | {P.kind=P.Operation "STC";_}->()|_->failwith "INR/DCR did not preserve carry provenance")

let test_bdos_read_and_external_sync () =
  let p=P.create() and memory=I8080.Memory.create() in
  let fs=Cpm.Filesystem.create() in
  let data=Bytes.init 128(fun i->Char.chr((i*7)land 255)) in
  assert(Cpm.Filesystem.add_file fs ~name:"INPUT.BIN" data=Ok());
  let runtime=Cpm.Bdos.create ~filesystem:fs in
  let fcb=Cpm.Fcb.at memory ~address:0x3000 in
  Cpm.Fcb.set_drive fcb 0;
  String.iteri(fun i c->Cpm.Fcb.set fcb ~offset:(i+1)(Char.code c))"INPUT   ";
  String.iteri(fun i c->Cpm.Fcb.set fcb ~offset:(i+9)(Char.code c))"BIN";
  let state=I8080.State.create() in
  P.seed_initial_registers p (snapshot state);
  let call fn = I8080.State.set_c state fn; I8080.State.set_de state 0x3000;
    Cpm.Bdos.dispatch_with_effects ~runtime ~memory ~state ~output:(fun _->())
      ~on_event:(P.observe_bdos_event p ~step_index:10)
      ~on_effect:(P.observe_bdos_effect p) |> function Ok _->()|Error _->failwith "BDOS failed" in
  call 15; call 20;
  (match P.node p (match P.memory_root p ~address:(0x3000+13) with Node n->n|_->failwith "FCB update untracked") with
   | {kind=Source(External_result {operation="FCB update";_});_}->()
   | _->failwith "BDOS FCB mutation left stale provenance");
  (match P.node p (match P.memory_root p ~address:0x80 with Node n->n|_->failwith "read byte untracked") with
   | {kind=Source(P.File_byte {file;offset=0;value});_}->assert(file.name="INPUT.BIN"&&value=0)
   | _->failwith "BDOS read did not inject source leaf");
  I8080.State.set_c state 12; I8080.State.set_de state 0;
  ignore(Cpm.Bdos.dispatch_with_effects ~runtime ~memory ~state ~output:(fun _->())
    ~on_event:(fun _->()) ~on_effect:(P.observe_bdos_effect p));
  (match P.node p (match P.register_root p ~register:I8080.Instr.A with Node n->n|_->failwith "A untracked") with
   | {kind=Source(P.External_result {subsystem="BDOS";_});_}->()
   | _->failwith "BDOS register output was not synchronized")

let test_sink_history_and_slice () =
  let p=P.create() and memory=I8080.Memory.create() in
  let fs=Cpm.Filesystem.create() in let runtime=Cpm.Bdos.create ~filesystem:fs in
  let output=file "OUT.REL" in
  let key=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:"OUT.REL" with Ok x->x|_->failwith "key" in
  ignore output;
  let fcb=Cpm.Fcb.at memory ~address:0x3000 in
  Cpm.Fcb.set_drive fcb 0;
  String.iteri(fun i c->Cpm.Fcb.set fcb ~offset:(i+1)(Char.code c))"OUT     ";
  String.iteri(fun i c->Cpm.Fcb.set fcb ~offset:(i+9)(Char.code c))"REL";
  let state=I8080.State.create() in
  let apply_effect e=P.observe_bdos_effect p e in
  let event i e=P.observe_bdos_event p ~step_index:i e in
  let call fn de=I8080.State.set_c state fn;I8080.State.set_de state de;
    Cpm.Bdos.dispatch_with_effects ~runtime ~memory ~state ~output:(fun _->()) ~on_event:(event 20) ~on_effect:apply_effect |> function Ok _->()|Error _->failwith "BDOS sink call" in
  call 22 0x3000;
  I8080.Memory.write memory 0x4000 0x11; I8080.Memory.write memory 0x4001 0x22;
  P.seed_memory p ~class_:P.System ~address:0x4000 (Bytes.of_string "\x11\x22");
  call 26 0x4000; call 21 0x3000;
  Cpm.Fcb.set_current_record fcb 0;
  I8080.Memory.write memory 0x4000 0x33;
  P.seed_memory p ~class_:P.System ~address:0x4000 (Bytes.of_string "\x33");
  call 21 0x3000;
  let history=P.output_byte_history p ~file:key ~offset:0 in
  assert(List.length history=2);
  assert((List.hd history).value=0x11 && (List.hd(List.rev history)).value=0x33);
  assert(P.output_bytes_rewritten p ~file:key=128);
  let selected=List.hd(List.rev history) in
  let slice=P.slice p [selected.root] in
  assert(List.exists(function P.Initial_memory_byte {address=0x4000;value=0x33;_}->true|_->false)(P.source_leaves slice));
  assert(P.output_bytes_with_roots p ~file:key=128)
  ;
  assert(P.slice_json p ~roots:[selected.root]=P.slice_json p ~roots:[selected.root]);
  assert(List.exists(fun summary->summary.P.group=P.Initial_memory_input P.System && summary.distinct_bytes=1)
    (P.source_summary slice));
  assert(String.starts_with ~prefix:"RUNES_PROVENANCE_SLICE 1\n{" (P.slice_json p ~roots:[selected.root]))

let test_execution_origin_invalidation_is_independent () =
  let program=Bytes.of_string "\x3e\x00\x32\x00\x01\x76" in
  let p,map,_,_=run_program program 3 in
  (match Analysis.Execution_map.origin_at map 0x100 with
   | Analysis.Execution_map.Unknown -> ()
   | _ -> failwith "CPU store did not invalidate Execution Map origin");
  (match P.node p (match P.memory_root p ~address:0x100 with Node id->id|_->failwith "store root missing") with
   | {P.kind=P.Operation "STA";_} -> ()
   | _ -> failwith "provenance did not retain CPU store result")

let test_branch_observation_keeps_flag_root () =
  let p,_,_,_=run_program (Bytes.of_string "\xc2\x05\x01\x76\x76\x76") 1 in
  match P.branch_observations p with
  | [branch] ->
      assert(branch.P.step_index=0 && branch.pc=0x100);
      assert(branch.condition=I8080.Instr.Not_zero && branch.taken && branch.target=Some 0x105);
      assert(branch.flag_inputs=[P.flag_root p ~flag:`Zero]);
      assert(match P.node p (match List.hd branch.flag_inputs with Node n->n|_->failwith "branch flag untracked") with
        | {P.kind=P.Source(P.Initial_register {register="Z";_});_}->true|_->false)
  | _ -> failwith "conditional branch observation missing"

let control_edges n=List.filter_map(function P.Control,id->Some id|_->None)n.P.inputs

let test_shared_path_control_contexts () =
  let program=Bytes.of_string "\x3e\x01\xb7\xc2\x06\x01\x0e\x22\x16\x33\x76" in
  let p,_,_,_=run_program program 6 in
  let branches=P.branch_observations p in
  (match branches with
   |[b]->
       assert(b.taken && b.condition=I8080.Instr.Not_zero && b.step_index=2);
       assert(b.origin=Some{P.image=file "TEST.COM";offset=3;runtime_pc=0x103});
       assert(b.flag_inputs=[P.flag_root p ~flag:`Zero]);
       let decision=P.node p b.decision_node and context=P.node p b.context_node in
       assert(decision.kind=P.Operation "Control.Decision" && decision.value=1 && decision.width=1);
       assert(decision.origin=b.origin && decision.step_index=Some b.step_index);
       assert(List.mem(P.Flag,(match List.hd b.flag_inputs with Node n->n|_->assert false))decision.inputs);
       assert(control_edges decision=[]);
       assert(context.kind=P.Operation "Control.Context" && control_edges context=[b.decision_node]);
       assert(P.control_decisions_of_context p (Node b.context_node)=[b]);
       let before=P.node p (match P.register_root p ~register:I8080.Instr.A with Node n->n|_->assert false) in
       assert(control_edges before=[]);
       let after=P.node p (match P.register_root p ~register:I8080.Instr.D with Node n->n|_->assert false) in
       assert(control_edges after=[b.context_node]);
       assert(P.controlled_operation_count p>0);
       let data=P.slice ~roles:P.data_edge_roles p [P.register_root p ~register:I8080.Instr.D] in
       assert(List.for_all(fun (n:P.node)->n.id>=0)data.nodes);
       let combined=P.slice p [P.register_root p ~register:I8080.Instr.D] in
       assert(List.exists(fun (n:P.node)->n.id=b.decision_node)combined.nodes);
       assert(List.exists(fun (n:P.node)->n.kind=P.Operation "ALU.ORA.Z")combined.nodes);
       assert(List.length(P.control_decisions_of_context p (P.current_control_context p))=1);
       P.seed_memory p ~class_:P.Runner ~address:0x5000 (Bytes.make 128 'X');
       let sink_file=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:"PATH.OUT" with Ok k->k|_->assert false in
       P.observe_bdos_event p ~step_index:99 (Cpm.Bdos.Write_record {file=sink_file;logical_record=0;dma=0x5000;data=Bytes.make 128 'X'});
       let observation=Option.get(P.final_output_byte p ~file:sink_file ~offset:0) in
       assert(observation.root<>Untracked);
       assert(P.output_control_context p observation=P.current_control_context p);
       (match observation.root with Node n->assert(control_edges(P.node p n)=[])|_->assert false)
   |_->failwith "one branch should establish one shared path context");
  let source_root=P.memory_root p ~address:0x5000 in
  (match source_root with Node n->let source=P.node p n in
     assert(match source.kind with P.Source _->source.inputs=[]|_->false)
   |Untracked->failwith "post-branch source was not seeded");

  let two=Bytes.of_string "\xc2\x03\x01\xc2\x06\x01\x06\x2a\x76" in
  let p2,_,_,_=run_program two 4 in
  let bs=P.branch_observations p2 in
  assert(List.length bs=2 && List.for_all(fun (b:P.branch_observation)->b.taken)bs);
  let latest=List.hd(List.rev bs) in
  assert(List.length(P.control_decisions_of_context p2 (Node latest.context_node))=2);
  let result=P.node p2 (match P.register_root p2 ~register:I8080.Instr.B with Node n->n|_->assert false) in
  assert(control_edges result=[latest.context_node]);
  assert(P.logical_control_node_count p2=4);

  let call_not_taken=Bytes.of_string "\xcc\x06\x01\x06\x2a\x76\x76" in
  let p3,_,_,_=run_program call_not_taken 3 in
  (match P.branch_observations p3 with [b]->assert(not b.taken)|_->assert false);
  let call_taken_ret_taken=Bytes.of_string "\xaf\xcc\x07\x01\x76\x00\x00\xc8\x76" in
  let p4,_,_,_=run_program call_taken_ret_taken 4 in
  (match P.branch_observations p4 with
   |[call;ret]->assert(call.taken && ret.taken && call.condition=I8080.Instr.Zero && ret.condition=I8080.Instr.Zero)
   |_->failwith(Printf.sprintf "conditional CALL/RET decisions missing: %s"
      (String.concat "," (List.map(fun (b:P.branch_observation)->Printf.sprintf "%04X/%b" b.pc b.taken)(P.branch_observations p4)))));
  let ret_not_taken=Bytes.of_string "\x3e\x01\xc8\x76" in
  let p5,_,_,_=run_program ret_not_taken 3 in
  (match P.branch_observations p5 with [b]->assert(not b.taken)|_->assert false);
  let unconditional=Bytes.of_string "\xc3\x04\x01\xcd\x0a\x01\x76\x00\x00\xc9" in
  let pu,_,_,_=run_program unconditional 4 in
  assert(P.branch_observations pu=[]);
  let rst=Bytes.of_string "\xc7" in let pr,_,_,_=run_program rst 1 in
  assert(P.branch_observations pr=[])

let test_opcode_shadow_coverage () =
  for opcode=0 to 255 do
    let program=Bytes.make 4 '\000' in Bytes.set program 0 (Char.chr opcode);
    let p=P.create() in
    let id=file "OPCODES.BIN" in
    let memory=I8080.Memory.create() in I8080.Memory.load memory ~address:0x100 program;
    P.seed_image p ~image:id ~runtime_base:0x100 program;
    let state=I8080.State.create() in
    I8080.State.set_pc state 0x100; I8080.State.set_sp state 0x8000;
    I8080.State.set_bc state 0x2030; I8080.State.set_de state 0x2040; I8080.State.set_hl state 0x2050;
    I8080.State.set_a state 0x53;
    let f=I8080.State.flags state in
    I8080.Flags.set_sign f true; I8080.Flags.set_zero f false;
    I8080.Flags.set_auxiliary_carry f true; I8080.Flags.set_parity f false; I8080.Flags.set_carry f true;
    P.seed_initial_registers p (snapshot state);
    let bus=I8080.Bus.create ~input:(fun ~port:_ -> 0x37) ~output:(fun ~port:_ ~value:_ -> ()) memory in
    let cpu=I8080.Cpu.create ~state ~bus in
    match I8080.Cpu.step cpu with
    | Error _ -> failwith(Printf.sprintf "CPU opcode %02X unexpectedly failed" opcode)
    | Ok step ->
        (try P.observe_step p ~step_index:0 (snapshot state) step with
         | P.Provenance_error (P.Concrete_mismatch e) ->
             failwith(Printf.sprintf "opcode %02X mismatch %s predicted=%X concrete=%X" opcode e.location e.predicted e.concrete))
  done

let test_compact_chunk_boundary () =
  let p=P.create() in
  let bytes=Bytes.init 32_770(fun i->Char.chr(i land 255)) in
  P.seed_memory p ~class_:P.Runner ~address:0 bytes;
  assert(P.node_count p=32_770);
  assert(P.memory_root p ~address:32_767=Node 32_767);
  assert(P.memory_root p ~address:32_768=Node 32_768);
  assert(P.memory_root p ~address:32_769=Node 32_769);
  (match P.node p 32_768 with
   |{kind=Source(P.Initial_memory_byte{address=32_768;value=0;class_=P.Runner});width=8;step_index=None;origin=None;inputs=[];_}->()
   |_->failwith "compact arena chunk boundary changed public node semantics")

let read_file path =
  let channel=open_in_bin path in
  let length=in_channel_length channel in
  let bytes=Bytes.create length in really_input channel bytes 0 length; close_in channel; bytes

let contains text fragment =
  let n=String.length text and m=String.length fragment in
  let rec seek i=i+m<=n && (String.sub text i m=fragment || seek(i+1)) in seek 0

let historical_run () =
  match Sys.getenv_opt "RUNES_HISTORICAL_DIR" with
  | None -> ()
  | Some directory ->
      let find name=read_file(Filename.concat directory name) in
      let com=find "PLI.COM" in
      let fs=Cpm.Filesystem.create() in
      List.iter(fun name->assert(Cpm.Filesystem.add_file fs ~name (find name)=Ok()))
        ["PLI0.OVL";"PLI1.OVL";"PLI2.OVL";"OPTIMIST.PLI"];
      let map=Analysis.Execution_map.create() and prov=P.create() in
      let image name=match Analysis.Execution_map.image_id ~drive:0 ~user:0 ~filename:name with
        |Ok x->x|Error _->failwith("bad image "^name) in
      let pli=image "PLI.COM" in
      assert(Analysis.Execution_map.seed_image map ~image:pli ~runtime_base:0x100 com=Ok());
      P.seed_image prov ~image:pli ~runtime_base:0x100 com;
      let output=Buffer.create 128 in
      let started=Sys.time() in
      let result=Runner.run_bytes ~max_steps:3_000_000 ~filesystem:fs
          ~command_tail:(Bytes.of_string " OPTIMIST") ~output:(Buffer.add_char output)
          ~on_start:(fun page->P.seed_memory prov ~class_:P.System ~address:0 page;
            P.seed_command_tail prov ~address:0x81 (Bytes.of_string " OPTIMIST");
            P.seed_command_tail_mapping prov ~address:0x5d ~tail_offset:1 (Bytes.of_string "OPTIMIST"))
          ~on_start_state:(P.seed_initial_registers prov)
          ~on_step_state:(fun ~step_index state step->
            let resolve ~pc ~fetched=match Analysis.Execution_map.origin_at map pc with
              |Analysis.Execution_map.Image_byte {image;offset}->
                  let good=ref true in Bytes.iteri(fun i _->if Analysis.Execution_map.origin_at map ((pc+i)land 0xffff)<>Analysis.Execution_map.Image_byte {image;offset=offset+i} then good:=false) fetched;
                  if !good then Some {P.image;offset;runtime_pc=pc} else None
              |_->None in
            P.observe_step ~origin_at:resolve prov ~step_index state step)
          ~on_event:(Analysis.Execution_map.observe_runner_event map)
          ~on_bdos_event:(fun ~step_index event->
            P.observe_bdos_event prov ~step_index event;
            Analysis.Execution_map.observe_bdos_event ~step_index map event)
          ~on_bdos_effect:(P.observe_bdos_effect prov) com in
      let result=match result with Ok x->x|Error _->failwith "historical PL/I run failed" in
      assert(result.termination=Runner.Warm_boot);
      assert(result.steps=2_535_509);
      let console=Buffer.contents output in
      assert(contains console "NO ERROR(S) IN PASS 1");
      assert(contains console "NO ERROR(S) IN PASS 2");
      assert(contains console "END  COMPILATION");
      let elapsed=Sys.time()-.started in
      let rel_key=match Cpm.Filesystem.key_of_name ~drive:0 ~user:0 ~name:"OPTIMIST.REL" with
        |Ok x->x|Error _->assert false in
      let rel=match Cpm.Filesystem.get_file fs ~name:"OPTIMIST.REL" () with
        |Ok(Some x)->x|_->failwith "historical REL missing" in
      assert(Bytes.length rel=1408);
      assert(Cpm.Filesystem.get_file fs ~name:"OPTIMIST.INT" ()=Ok None);
      assert(P.output_bytes_with_roots prov ~file:rel_key=1408);
      let execution_images=List.map file ["PLI.COM";"PLI0.OVL";"PLI1.OVL";"PLI2.OVL"] in
      let execution=match Analysis.Execution_report.report_of_map map ~images:execution_images with
        |Ok report->report|Error _->failwith "execution report for provenance explorer failed" in
      let classify key=match key.Cpm.Filesystem.name with
        |"OPTIMIST.PLI"->Analysis.Provenance_report.Program_input
        |"OPTIMIST.INT"->Intermediate
        |"PLI.COM"|"PLI0.OVL"|"PLI1.OVL"|"PLI2.OVL"->Program_image
        |"OPTIMIST.REL"->Output|_->Other "other" in
      let selected=List.map(fun offset->{Analysis.Provenance_report.file=rel_key;offset;generation=None})[0;0x2c0;0x57f] in
      let projection_started=Sys.time() in
      let explorer=match Analysis.Provenance_report.report_of_provenance ~provenance:prov ~execution ~classify
        ~output_file:rel_key ~output_bytes:rel ~selected () with
        |Ok report->report|Error _->failwith "historical provenance projection failed" in
      Printf.printf "EXPLORER projection_time=%.3f output_bytes=%d selected=%d\n%!"
        (Sys.time()-.projection_started)(List.length(Analysis.Provenance_report.output_bytes explorer))
        (List.length(Analysis.Provenance_report.projections explorer));
      List.iter(fun (projection:Analysis.Provenance_report.projection)->
        Printf.printf "EXPLORER_SINK off=%04X value=%02X step=%s root=%s nodes=%d leaves=%d locations=%d producer_steps=%d roles=%d/%d/%d/%d\n%!"
          projection.sink.offset (Option.value projection.sink_value ~default:0)
          (Option.fold ~none:"-" ~some:string_of_int projection.write_step)
          (match projection.root with Node n->string_of_int n|Untracked->"untracked")
          projection.full_node_count projection.source_leaf_count projection.producer_location_count
          projection.distinct_producer_steps projection.roles.value projection.roles.address projection.roles.flag projection.roles.control;
        let top_sources=projection.sources |> List.sort(fun (a:Analysis.Provenance_report.source_group) (b:Analysis.Provenance_report.source_group)->compare b.leaf_occurrences a.leaf_occurrences) in
        List.iter(fun (s:Analysis.Provenance_report.source_group)->Printf.printf "  EXPLORER_SOURCE %s class=%s distinct=%d occurrences=%d ranges=%d\n%!"
          s.identity (Option.fold ~none:s.kind ~some:(function Analysis.Provenance_report.Program_input->"program input"|Intermediate->"intermediate"|Program_image->"program image"|Output->"output"|Other x->x) s.classification)
          (List.length s.distinct_offsets) s.leaf_occurrences (List.length s.ranges))top_sources;
        let locations=projection.producer_location_count in
        Printf.printf "  COMPRESSION nodes=%d -> locations=%d leaves=%d -> distinct_file_offsets=%d\n%!"
          projection.full_node_count locations projection.source_leaf_count
          (List.fold_left(fun n (s:Analysis.Provenance_report.source_group)->n+List.length s.distinct_offsets)0 projection.sources))
        (Analysis.Provenance_report.projections explorer);
      Printf.printf "HIST steps=%d time=%.3f output=%S nodes=%d edges=%d rel=%d\n%!"
        result.steps elapsed console (P.node_count prov) (P.edge_count prov) (Bytes.length rel);
      Printf.printf "MAP total=%d attributed=%d unknown=%d mixed=%d\n%!"
        (Analysis.Execution_map.summary map).total_instruction_executions
        (Analysis.Execution_map.summary map).attributed_instruction_executions
        (Analysis.Execution_map.summary map).unknown_executions
        (Analysis.Execution_map.summary map).mixed_or_unresolved_executions;
      let branches=P.branch_observations prov in
      let branch_pcs=Hashtbl.create 128 and by_image=Hashtbl.create 8 in
      List.iter(fun (b:P.branch_observation)->
        let image,location=match b.origin with
          |Some o->o.image.name,Some(o.offset,o.runtime_pc)
          |None->"unknown/system",None in
        Option.iter(fun loc->Hashtbl.replace branch_pcs (image,loc) ())location;
        let total,taken,not_taken,pcs=Option.value(Hashtbl.find_opt by_image image)
            ~default:(0,0,0,Hashtbl.create 32) in
        Hashtbl.replace by_image image (total+1,taken+(if b.taken then 1 else 0),
          not_taken+(if b.taken then 0 else 1),pcs);
        Option.iter(fun loc->Hashtbl.replace pcs loc ())location)branches;
      Printf.printf "BRANCH total=%d taken=%d not_taken=%d distinct_locations=%d distinct_runtime_pcs=%d\n%!"
        (List.length branches)
        (List.fold_left(fun n (b:P.branch_observation)->n+(if b.taken then 1 else 0))0 branches)
        (List.fold_left(fun n (b:P.branch_observation)->n+(if b.taken then 0 else 1))0 branches)
        (Hashtbl.length branch_pcs)
        (let h=Hashtbl.create 128 in List.iter(fun (b:P.branch_observation)->Hashtbl.replace h b.pc ())branches;Hashtbl.length h);
      Hashtbl.fold(fun image (total,taken,not_taken,pcs) acc->(image,total,taken,not_taken,Hashtbl.length pcs)::acc)by_image[]
      |> List.sort compare |> List.iter(fun(image,total,taken,not_taken,locations)->
        Printf.printf "BRANCH_IMAGE %s total=%d taken=%d not_taken=%d locations=%d\n%!"
          image total taken not_taken locations);
      let out_dir=Option.value(Sys.getenv_opt "RUNES_PROVENANCE_OUT")~default:"." in
      let rel_out=open_out_bin(Filename.concat out_dir "OPTIMIST.REL") in output_bytes rel_out rel;close_out rel_out;
      let report_path=Filename.concat out_dir "provenance-report.json" in
      let report_write_started=Sys.time() in
      let report_out=open_out_bin report_path in
      Analysis.Provenance_report.write_json ~output:(output_string report_out) explorer;close_out report_out;
      let report_input=open_in_bin report_path in let report_size=in_channel_length report_input in close_in report_input;
      Printf.printf "EXPLORER_JSON bytes=%d write_time=%.3f\n%!" report_size (Sys.time()-.report_write_started);
      let control_started=Sys.time() in
      let control_report=match Analysis.Provenance_report.path_control_report_of_provenance
        ~provenance:prov ~selected with
        |Ok report->report|Error _->failwith "historical path-control projection failed" in
      Printf.printf "CONTROL_REPORT projection_time=%.3f decisions=%d contexts=%d logical_control_nodes=%d controlled_operations=%d control_relations=%d sharing=%.2f\n%!"
        (Sys.time()-.control_started)(P.control_decision_count prov)(P.control_context_count prov)
        (P.logical_control_node_count prov)(P.controlled_operation_count prov)(P.control_relation_count prov)
        (float(P.controlled_operation_count prov)/.float(max 1(P.control_context_count prov)));
      List.iter(fun (path:Analysis.Provenance_report.path_control_projection)->
        Printf.printf "PATH_SINK off=%04X depth=%d locations=%d steps=%s..%s context_nodes=%d decisions=%d flag_ancestors=%d combined=%d control_relations=%d\n%!"
          path.sink.offset path.context_depth path.distinct_branch_locations
          (Option.fold ~none:"-" ~some:string_of_int path.earliest_decision_step)
          (Option.fold ~none:"-" ~some:string_of_int path.latest_decision_step)
          path.additional_context_nodes path.additional_decision_nodes path.additional_flag_ancestors
          path.combined_reachable_nodes path.control_relations)
        control_report.paths;
      let control_path=Filename.concat out_dir "provenance-control-report.json" in
      let control_out=open_out_bin control_path in
      let control_json_started=Sys.time() in
      Analysis.Provenance_report.write_control_report_json ~output:(output_string control_out) control_report;
      close_out control_out;
      let control_in=open_in_bin control_path in let control_size=in_channel_length control_in in close_in control_in;
      Printf.printf "CONTROL_JSON bytes=%d write_time=%.3f\n%!" control_size (Sys.time()-.control_json_started);
      List.iter(fun offset->match P.final_output_byte prov ~file:rel_key ~offset with
        |None->failwith "missing sampled output byte"
        |Some obs->let slice=P.slice ~roles:P.data_edge_roles prov [obs.root] in
          Printf.printf "SINK off=%d value=%02X step=%d root=%s nodes=%d producers=%d leaves=%d\n%!"
            offset obs.value obs.write_step_index (match obs.root with Node n->string_of_int n|Untracked->"untracked")
            (List.length slice.nodes)(List.length(P.producer_nodes slice))(List.length(P.source_leaves slice));
          List.iter(fun s->Printf.printf "  SOURCE %s count=%d\n%!"
            (match s.P.group with File_input f->f.name|Command_tail_input->"command-tail"|Initial_memory_input _->"initial-memory"|Initial_register_input x->"register:"^x|External_input(a,b)->a^":"^b) s.distinct_bytes)(P.source_summary slice);
          let path=Filename.concat out_dir (Printf.sprintf "slice-%04X.json" offset) in
          let ch=open_out_bin path in P.write_slice_json ch prov ~roots:[obs.root];close_out ch)
        [0;704;1407];
      let sample_roots=List.filter_map(fun offset->Option.map(fun o->o.P.root)(P.final_output_byte prov ~file:rel_key ~offset))[0;704;1407] in
      let sampled=P.slice ~roles:P.data_edge_roles prov sample_roots in
      Printf.printf "SAMPLE_UNION nodes=%d sources=%d\n%!" (List.length sampled.nodes) (List.length(P.source_leaves sampled));
      List.iter(fun s->Printf.printf "UNION_SOURCE %s distinct=%d\n%!"
        (match s.P.group with File_input f->f.name|Command_tail_input->"command-tail"|Initial_memory_input _->"initial-memory"|Initial_register_input x->"register:"^x|External_input(a,b)->a^":"^b) s.distinct_bytes)
        (P.source_summary sampled);
      List.iter(fun summary->Printf.printf "IMAGE %s known=%d fetched=%d starts=%d exec=%d first=%s last=%s\n%!"
        summary.Analysis.Execution_map.image.name summary.known_byte_count summary.unique_fetched_byte_count
        summary.unique_instruction_starts summary.total_instruction_executions
        (match summary.first_execution with None->"-"|Some(pc,off,st)->Printf.sprintf "%04X/%04X/%d" pc off st)
        (Option.fold ~none:"-" ~some:string_of_int summary.last_execution_step))
        (Analysis.Execution_map.image_summaries map);
      Printf.printf "REL_ROOTS=%d UNTRACKED=%d REWRITTEN=%d\n%!"
        (P.output_bytes_with_roots prov ~file:rel_key) (P.output_bytes_untracked prov ~file:rel_key)
        (P.output_bytes_rewritten prov ~file:rel_key)

let () =
  test_copy_alu_and_memory ();
  test_flags_stack_and_special_memory ();
  test_bdos_read_and_external_sync ();
  test_sink_history_and_slice ();
  test_execution_origin_invalidation_is_independent ();
  test_branch_observation_keeps_flag_root ();
  test_shared_path_control_contexts ();
  test_opcode_shadow_coverage ();
  test_compact_chunk_boundary ();
  historical_run ()
