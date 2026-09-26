[@@@warning "-4-27-40-41-42-69"]

module S=Analysis.Dynamic_structure
module B=Analysis.Dynamic_blocks
module M=Analysis.Execution_map
module I=I8080.Instr

let image name=match M.image_id ~drive:0 ~user:0 ~filename:name with Ok x->x|Error _->failwith "image id"
let seed map name base bytes=let id=image name in assert(M.seed_image map ~image:id ~runtime_base:base bytes=Ok());id
let decoded bytes=match I8080.Decode.decode bytes ~offset:0 with Ok d->d|Error _->failwith "decode"
let make_step ?(flow=I8080.Step.Sequential) pc next bytes=
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:next
    ~decoded:(decoded bytes) ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow
let nop pc=make_step pc ((pc+1)land 0xffff) (Bytes.of_string "\000")
let jmp pc target=make_step ~flow:(I8080.Step.Jump{target;taken=true}) pc target
  (Bytes.of_string(Printf.sprintf "\xC3%c%c"(Char.chr(target land 255))(Char.chr((target lsr 8)land 255))))
let jnz pc target taken=make_step ~flow:(I8080.Step.Jump{target;taken}) pc (if taken then target else (pc+3)land 0xffff)
  (Bytes.of_string(Printf.sprintf "\xC2%c%c"(Char.chr(target land 255))(Char.chr((target lsr 8)land 255))))
let call pc target taken=make_step ~flow:(I8080.Step.Call{target;taken}) pc (if taken then target else (pc+3)land 0xffff)
  (Bytes.of_string(Printf.sprintf "\xCD%c%c"(Char.chr(target land 255))(Char.chr((target lsr 8)land 255))))
let ccall pc target taken=make_step ~flow:(I8080.Step.Call{target;taken}) pc (if taken then target else (pc+3)land 0xffff)
  (Bytes.of_string(Printf.sprintf "\xC4%c%c"(Char.chr(target land 255))(Char.chr((target lsr 8)land 255))))
let ret ?(conditional=false) pc target taken=
  let bytes=Bytes.of_string(if conditional then "\xC0" else "\xC9") in
  make_step ~flow:(I8080.Step.Return{target=(if taken then Some target else None);taken}) pc
    (if taken then target else (pc+1)land 0xffff) bytes
let observe structure blocks map index step=
  let owner=S.observe_step_detailed structure map ~step_index:index step in
  B.observe_step blocks map ~routine_id:owner.routine_id ~routine_entry:owner.routine_entry ~step_index:index step
let finish structure blocks=B.materialize blocks (S.routines structure)

let test_formatter ()=
  assert(I8080.Instr_format.format(I.Mov(I.Register I.A,I.Memory_at_HL))="MOV A,M");
  assert(I8080.Instr_format.format(I.Mvi(I.Register I.C,9))="MVI C,09H");
  assert(I8080.Instr_format.format(I.Lxi(I.HL,0x1234))="LXI H,1234H");
  assert(I8080.Instr_format.format(I.Call(Some I.Not_zero,0x1ad4))="CNZ 1AD4H");
  assert(I8080.Instr_format.format(I.Jump(Some I.Not_zero,0x320))="JNZ 0320H");
  assert(I8080.Instr_format.format(I.Return(Some I.Zero))="RZ");
  assert(I8080.Instr_format.format(I.Return None)="RET");
  assert(I8080.Instr_format.format(I.Push I.Stack_HL)="PUSH H");
  assert(I8080.Instr_format.format(I.Dad I.DE)="DAD D")

let late_split_run reverse_order=
  let bytes=Bytes.make 0x108 '\000' in
  let put pc text=Bytes.blit_string text 0 bytes (pc-0x100)(String.length text) in
  put 0x100 "\000";put 0x101 "\000";put 0x102 "\xC3\x00\x02";
  put 0x200 "\xC2\x00\x01";put 0x203 "\xC3\x01\x01";
  let map=M.create()in ignore(seed map "SPLIT.COM" 0x100 bytes);
  let structure=S.create()and blocks=B.create()and index=ref 0 in
  let emit step=observe structure blocks map !index step;incr index in
  let a=nop 0x100 and b=nop 0x101 and c=jmp 0x102 0x200 and x0=jnz 0x200 0x100 false
  and x1=jnz 0x200 0x100 true and y=jmp 0x203 0x101 in
  if reverse_order then (emit x1;emit a;emit b;emit c;emit x0;emit y;emit b;emit c;emit x1;emit a;emit b)
  else (emit a;emit b;emit c;emit x0;emit y;emit b;emit c;emit x1;emit a;emit b);
  finish structure blocks

let block_signature report=
  B.blocks report |>List.map(fun (b:B.block)->
    (b.image |>Option.map(fun i->i.Cpm.Filesystem.name),b.start_offset,b.runtime_start,
     List.map(fun id->let i=List.find(fun (x:B.instruction)->x.id=id)(B.instructions report)in
       i.runtime_pc,Bytes.to_string i.bytes)b.instruction_ids))
  |>List.sort compare

let test_late_split_order_independence ()=
  let earlier_straight=late_split_run false and earlier_target=late_split_run true in
  let split=block_signature earlier_straight in
  assert(split=block_signature earlier_target);
  let b_blocks=B.blocks earlier_straight |>List.filter(fun (b:B.block)->b.start_offset=Some 1) in
  assert(List.length b_blocks=1);
  let block=List.hd b_blocks in
  assert(List.mem B.Branch_target block.tags && List.mem B.Multi_predecessor block.tags);
  assert(List.map(fun id->(List.find(fun (i:B.instruction)->i.id=id)(B.instructions earlier_straight)).runtime_pc)block.instruction_ids=[0x101;0x102]);
  assert(List.exists(fun (edge:B.instruction_transition)->edge.kind=B.Branch_taken)(B.instruction_transitions earlier_straight))

let block_has_tag report pc tag=List.exists(fun (b:B.block)->b.runtime_start=pc && List.mem tag b.tags)(B.blocks report)
let run_steps name code steps =
  let map=M.create()in ignore(seed map name 0x100 code);
  let structure=S.create()and blocks=B.create()in
  List.iteri(fun index step->observe structure blocks map index step)steps;
  finish structure blocks

let test_conditional_jump_boundaries ()=
  let code=Bytes.make 0x20 '\000' in
  let taken=run_steps "JT.COM" code [jnz 0x100 0x110 true;nop 0x110] in
  let fallthrough=run_steps "JF.COM" code [jnz 0x100 0x110 false;nop 0x103] in
  assert(block_has_tag taken 0x110 B.Branch_target);
  assert(block_has_tag fallthrough 0x103 B.Branch_fallthrough_tag);
  assert(List.for_all(fun (b:B.block)->not(List.exists(fun id->
    let i=List.find(fun (x:B.instruction)->x.id=id)(B.instructions taken)in i.runtime_pc=0x110) b.instruction_ids))
    (List.filter(fun (b:B.block)->b.runtime_start=0x100)(B.blocks taken)))

let test_narrative_first_kind_is_chronological ()=
  let code=Bytes.make 0x10 '\000' in
  let report=run_steps "FIRSTKND.COM" code
      [jnz 0x100 0x103 false;nop 0x103;jmp 0x104 0x100;jnz 0x100 0x103 true;nop 0x103] in
  let pair=List.find(fun (e:B.block_transition)->e.kinds=[B.Branch_taken;B.Branch_fallthrough])
      (B.transitions report) in
  let narrative=List.find(fun (n:B.narrative_entry)->
      n.source_routine=pair.source_routine && n.source_block=pair.source_block &&
      n.target_routine=pair.target_routine && n.target_block=pair.target_block)
      (B.narrative report) in
  assert(narrative.first_kind=B.Branch_fallthrough)

let test_call_and_return_continuations ()=
  let code=Bytes.make 0x120 '\000' in
  let taken=run_steps "CT.COM" code [ccall 0x100 0x200 true;ret 0x200 0x103 true;nop 0x103] in
  let not_taken=run_steps "CF.COM" code [ccall 0x100 0x200 false;nop 0x103] in
  let ret_not_taken=run_steps "RTN.COM" code [call 0x100 0x200 true;ret ~conditional:true 0x200 0x103 false;nop 0x201] in
  let ret_taken=run_steps "RT.COM" code [call 0x100 0x200 true;ret ~conditional:true 0x200 0x103 true;nop 0x103] in
  assert(block_has_tag taken 0x103 B.Return_continuation);
  assert(block_has_tag not_taken 0x103 B.Call_continuation && block_has_tag not_taken 0x103 B.Branch_fallthrough_tag);
  assert(block_has_tag ret_not_taken 0x201 B.Return_continuation && block_has_tag ret_not_taken 0x201 B.Branch_fallthrough_tag);
  assert(block_has_tag ret_taken 0x103 B.Return_continuation);
  let call_owner=List.find(fun(i:B.instruction)->i.runtime_pc=0x100)(B.instructions taken)in
  let callee_owner=List.find(fun(i:B.instruction)->i.runtime_pc=0x200)(B.instructions taken)in
  let continuation_owner=List.find(fun(i:B.instruction)->i.runtime_pc=0x103)(B.instructions taken)in
  assert(call_owner.routine_id=0 && callee_owner.routine_id=1 && continuation_owner.routine_id=0)

let loop_run iterations=
  let code=Bytes.make 0x10 '\000' in
  let map=M.create()in ignore(seed map "LOOP.COM" 0x100 code);
  let structure=S.create()and blocks=B.create()and step_index=ref 0 and remaining=ref iterations in
  let emit step=observe structure blocks map !step_index step;incr step_index in
  let running=ref true in
  while !running do
    emit(nop 0x100);
    decr remaining;
    let taken= !remaining>0 in
    emit(jnz 0x101 0x100 taken);
    if not taken then (emit(make_step ~flow:I8080.Step.Halt 0x104 0x104(Bytes.of_string "\x76"));running:=false)
  done;
  finish structure blocks

let edge_signature report=B.transitions report|>List.map(fun(e:B.block_transition)->
  e.source_routine,e.source_block,e.target_routine,e.target_block,e.kinds)|>List.sort compare
let test_loop_iteration_invariance ()=
  let few=loop_run 2 and many=loop_run 50 in
  assert(block_signature few=block_signature many);
  assert(edge_signature few=edge_signature many);
  assert(List.map(fun(n:B.narrative_entry)->n.source_routine,n.source_block,n.target_routine,n.target_block)(B.narrative few)=
    List.map(fun(n:B.narrative_entry)->n.source_routine,n.source_block,n.target_routine,n.target_block)(B.narrative many));
  assert(List.exists(fun (e:B.block_transition)->e.occurrence_count>1)(B.transitions many))

let test_overlays_remain_distinct ()=
  let map=M.create()in
  let main=Bytes.of_string "\xCD\x00\x22\xCD\x00\x22\xCD\x00\x22\x76" in
  ignore(seed map "MAIN.COM" 0x100 main);
  let structure=S.create()and blocks=B.create()and n=ref 0 in
  let emit step=observe structure blocks map !n step;incr n in
  let overlay name=
    let bytes=Bytes.of_string "\000\xC9" in ignore(seed map name 0x2200 bytes) in
  overlay "PLI0.OVL";emit(call 0x100 0x2200 true);emit(nop 0x2200);emit(ret 0x2201 0x103 true);
  overlay "PLI1.OVL";emit(call 0x103 0x2200 true);emit(nop 0x2200);emit(ret 0x2201 0x106 true);
  overlay "PLI2.OVL";emit(call 0x106 0x2200 true);emit(nop 0x2200);emit(ret 0x2201 0x109 true);
  let report=finish structure blocks in
  let relevant name=List.filter(fun (b:B.block)->match b.image with Some i->i.Cpm.Filesystem.name=name|None->false)(B.blocks report) in
  List.iter(fun name->
    let found=relevant name in assert(found<>[]);
    assert(List.exists(fun (b:B.block)->b.runtime_start=0x2200 && b.start_offset=Some 0 && b.image<>None)found);
    assert(List.exists(fun (i:B.instruction)->i.runtime_pc=0x2200 && match i.origin with B.Image_byte {image;offset=0}->image.Cpm.Filesystem.name=name|_->false)(B.instructions report)))
    ["PLI0.OVL";"PLI1.OVL";"PLI2.OVL"];
  assert(List.length(List.concat_map relevant ["PLI0.OVL";"PLI1.OVL";"PLI2.OVL"])>=3)

let test_origin_disagreement_and_mixed_instruction ()=
  let map=M.create()in ignore(seed map "MIX.COM" 0x100 (Bytes.of_string "\x00\x3E\x42\x00"));
  let structure=S.create()and blocks=B.create()in
  let writer=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:0x100 ~pc_after:0x101
      ~decoded:(decoded(Bytes.of_string "\000")) ~fetched_bytes:(Bytes.of_string "\000")
      ~memory_accesses:[I8080.Step.Write{address=0x101;value=0x3e}] ~control_flow:I8080.Step.Sequential in
  observe structure blocks map 0 writer;
  ignore(M.observe_step map ~step_index:0 writer);
  observe structure blocks map 1(make_step 0x101 0x103(Bytes.of_string "\x3E\x42"));
  observe structure blocks map 2(nop 0x103);
  let mixed=B.materialize blocks(S.routines structure)in
  let instruction=List.find(fun(i:B.instruction)->i.runtime_pc=0x101)(B.instructions mixed)in
  assert(instruction.text="MVI A,42H" && instruction.origin=B.Mixed_origin);
  assert(List.mem B.Mixed_bytes instruction.tags);
  assert(List.length(B.blocks mixed)=3);
  assert(List.exists(fun(b:B.block)->b.runtime_start=0x101 && b.origin=B.Mixed_origin &&
    List.mem B.Mixed_block_origin b.tags)(B.blocks mixed))

let test_changed_instruction_bytes_are_explicit ()=
  let map=M.create()in ignore(seed map "VARIANT.COM" 0x100(Bytes.of_string "\x3E\x42\x3E\x43"));
  let structure=S.create()and blocks=B.create()in
  observe structure blocks map 0(make_step 0x100 0x102(Bytes.of_string "\x3E\x42"));
  observe structure blocks map 1(make_step 0x100 0x102(Bytes.of_string "\x3E\x43"));
  let report=finish structure blocks in
  let variants=List.filter(fun (i:B.instruction)->i.runtime_pc=0x100)(B.instructions report)in
  assert(List.length variants=2);
  assert(List.for_all(fun (i:B.instruction)->List.mem B.Byte_variant i.tags)(variants));
  assert(List.exists(fun (a:B.anomaly)->a.kind=B.Instruction_bytes_changed)(B.anomalies report));
  assert(List.for_all(fun (b:B.block)->List.mem B.Variant_boundary b.tags)
    (List.filter(fun (b:B.block)->b.runtime_start=0x100)(B.blocks report)))

let test_unknown_origin_is_explicit ()=
  let map=M.create()in
  let structure=S.create()and blocks=B.create()in
  observe structure blocks map 0(nop 0x100);
  let report=finish structure blocks in
  let instruction=List.hd(B.instructions report)and block=List.hd(B.blocks report)in
  assert(instruction.origin=B.Unknown_origin && List.mem B.Unresolved_origin instruction.tags);
  assert(block.image=None && block.start_offset=None && List.mem B.Unresolved_block_origin block.tags)

let test_report_schema_and_identity ()=
  let map=M.create()in ignore(seed map "REPORT.COM" 0x100(Bytes.of_string "\x3E\x09\xC9"));
  let structure=S.create()and blocks=B.create()in
  observe structure blocks map 0(make_step 0x100 0x102(Bytes.of_string "\x3E\x09"));
  observe structure blocks map 1(ret 0x102 0x102 true);
  let report=finish structure blocks in
  let json=B.to_json_string report in
  assert(String.starts_with ~prefix:"RUNES_DYNAMIC_BLOCKS 1\n" json);
  assert(json=B.to_json_string report);
  assert(List.exists(fun (i:B.instruction)->i.text="MVI A,09H")(B.instructions report));
  assert(List.for_all(fun (b:B.block)->match b.image,b.start_offset with
    |Some expected_image,Some start_offset->List.for_all(fun id->let i=List.find(fun(i:B.instruction)->i.id=id)(B.instructions report)in
        match i.origin with B.Image_byte{image;offset}->image=expected_image && offset>=start_offset|_->false)b.instruction_ids
    |_->true)(B.blocks report))

let ()=
  test_formatter();test_late_split_order_independence();test_conditional_jump_boundaries();
  test_narrative_first_kind_is_chronological();test_call_and_return_continuations();
  test_loop_iteration_invariance();test_overlays_remain_distinct();
  test_origin_disagreement_and_mixed_instruction();test_changed_instruction_bytes_are_explicit();
  test_unknown_origin_is_explicit();test_report_schema_and_identity()
