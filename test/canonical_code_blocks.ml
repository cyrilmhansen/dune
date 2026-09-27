[@@@warning "-4-27-40-41-42-69"]

module M=Analysis.Execution_map
module B=Analysis.Dynamic_blocks
module C=Analysis.Canonical_code_blocks

let image name=match M.image_id ~drive:0 ~user:0 ~filename:name with Ok x->x|Error _->failwith "image"
let step pc bytes flow=let decoded=match I8080.Decode.decode bytes ~offset:0 with Ok x->x|Error _->failwith "decode" in
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:((pc+Bytes.length bytes)land 0xffff)
    ~decoded ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow
let nop pc=step pc(Bytes.of_string "\000")I8080.Step.Sequential
let halt pc=step pc(Bytes.of_string "\x76")I8080.Step.Halt
let run ?(extra_seeds=[]) bytes observations=
  let map=M.create()in ignore(M.seed_image map ~image:(image "CANON.COM") ~runtime_base:0x100 bytes);
  List.iter(fun (name,base,data)->ignore(M.seed_image map ~image:(image name) ~runtime_base:base data))extra_seeds;
  let blocks=B.create()in
  List.iter(fun(owner,entry,index,instruction)->B.observe_step blocks map ~routine_id:owner ~routine_entry:entry ~step_index:index instruction)observations;
  B.materialize blocks []

let test_union_boundaries_and_context_relations ()=
  let bytes=Bytes.make 16 '\000' in
  Bytes.set bytes 3 '\x76';
  let report=run bytes
    [0,true,0,nop 0x100;0,false,1,nop 0x101;0,false,2,nop 0x102;0,false,3,halt 0x103;
     1,false,4,nop 0x100;1,true,5,nop 0x101;1,false,6,nop 0x102;1,false,7,halt 0x103] in
  let canonical=C.materialize report and s=C.summary(C.materialize report)in
  assert(s.canonical_instruction_count=4);
  assert(s.canonical_block_count=2);
  let blocks=C.blocks canonical in
  assert(List.map(fun (b:C.block)->b.start_offset,b.end_offset)blocks=[0,1;1,4]);
  let shared=Option.get(C.block_at canonical ~image:(image "CANON.COM") ~offset:1)in
  let owners=C.block_contexts canonical|>List.filter(fun (x:C.block_context)->x.canonical_block_id=shared.id)
    |>List.map(fun (x:C.block_context)->x.routine_id)|>List.sort_uniq compare in
  assert(owners=[0;1]);
  assert(List.for_all(fun (b:C.block)->b.image=image "CANON.COM")blocks);
  assert(C.partition_anomalies canonical=[])

let test_overlay_identity_and_runtime_overlap ()=
  let a=image "A.OVL"and b=image "B.OVL" in
  let map=M.create()in
  let code=Bytes.of_string "\000\x76" in
  assert(M.seed_image map ~image:a ~runtime_base:0x2200 code=Ok());
  let blocks=B.create()in
  B.observe_step blocks map ~routine_id:0 ~routine_entry:true ~step_index:0(nop 0x2200);
  B.observe_step blocks map ~routine_id:0 ~routine_entry:false ~step_index:1( halt 0x2201);
  assert(M.seed_image map ~image:b ~runtime_base:0x2200 code=Ok());
  B.observe_step blocks map ~routine_id:1 ~routine_entry:true ~step_index:2(nop 0x2200);
  B.observe_step blocks map ~routine_id:1 ~routine_entry:false ~step_index:3( halt 0x2201);
  let canonical=C.materialize(B.materialize blocks [])in
  let summary=C.summary canonical in
  assert(summary.canonical_instruction_count=4 && summary.canonical_block_count=2);
  assert(List.map(fun (x:C.block)->x.image.Cpm.Filesystem.name)(C.blocks canonical)=["A.OVL";"B.OVL"]);
  assert(Option.is_some(C.block_at canonical ~image:a ~offset:0));
  assert(Option.is_some(C.block_at canonical ~image:b ~offset:0));
  assert(List.map(fun (x:C.instruction)->x.image.Cpm.Filesystem.name)(C.instructions canonical)|>List.sort_uniq compare=["A.OVL";"B.OVL"])

let test_changed_code_stays_exceptional ()=
  let map=M.create()in
  let a=image "VAR.OVL"in
  let blocks=B.create()in
  let nop_bytes=Bytes.of_string "\000"in
  assert(M.seed_image map ~image:a ~runtime_base:0x2200 nop_bytes=Ok());
  B.observe_step blocks map ~routine_id:0 ~routine_entry:true ~step_index:0(nop 0x2200);
  (* Same image coordinate, but fetched bytes disagree with the immutable image. *)
  B.observe_step blocks map ~routine_id:1 ~routine_entry:true ~step_index:1(halt 0x2200);
  let canonical=C.materialize(B.materialize blocks [])in
  let summary=C.summary canonical in
  assert(summary.canonical_instruction_count=0);
  assert(summary.exceptional_instruction_count=2);
  assert(summary.exceptional_block_count=2);
  let reasons=C.exceptional_instructions canonical|>List.map(fun (x:C.exceptional_instruction)->x.reason)|>List.sort_uniq compare in
  assert(List.mem "fetched-bytes-disagree-at-image-coordinate" reasons);
  assert(List.mem "observed-bytes-or-origin-variant" reasons)

let test_deterministic_export ()=
  let bytes=Bytes.of_string "\000\x76" in
  let report=run bytes[0,true,0,nop 0x100;0,false,1,halt 0x101]in
  let canonical=C.materialize report in
  assert(C.to_json_string canonical=C.to_json_string(C.materialize report));
  assert(String.starts_with ~prefix:"RUNES_CANONICAL_CODE_BLOCKS 1\n"(C.to_json_string canonical))

let ()=
  test_union_boundaries_and_context_relations();
  test_overlay_identity_and_runtime_overlap();
  test_changed_code_stays_exceptional();
  test_deterministic_export();
  print_endline "canonical code block tests passed"
