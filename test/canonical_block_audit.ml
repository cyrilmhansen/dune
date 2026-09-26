[@@@warning "-4-27-40-41-42-69"]

module Map=Analysis.Execution_map
module Blocks=Analysis.Dynamic_blocks
module Audit=Analysis.Canonical_block_audit

let image name=match Map.image_id ~drive:0 ~user:0 ~filename:name with Ok x->x|Error _->failwith"image"
let seed map name bytes=let key=image name in assert(Map.seed_image map ~image:key ~runtime_base:0x100 bytes=Ok());key
let decode bytes=match I8080.Decode.decode bytes ~offset:0 with Ok x->x|Error _->failwith"decode"
let step ?(flow=I8080.Step.Sequential) pc bytes=
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:((pc+Bytes.length bytes)land 0xffff)
    ~decoded:(decode bytes) ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow
let nop pc=step pc(Bytes.of_string"\000")
let halt pc=step ~flow:I8080.Step.Halt pc(Bytes.of_string"\x76")
let observe blocks map ~owner ~entry ~index instruction=
  Blocks.observe_step blocks map ~routine_id:owner ~routine_entry:entry ~step_index:index instruction
let materialize map bytes steps=
  let image=seed map"CANON.COM"bytes and blocks=Blocks.create()in
  List.iter(fun(owner,entry,index,instruction)->observe blocks map ~owner ~entry ~index instruction)steps;
  ignore image;Blocks.materialize blocks []

let test_union_partition_and_boundary_classification ()=
  let map=Map.create()in
  let report=materialize map (Bytes.make 8 '\000')
    [0,true,0,nop 0x100;0,false,1,nop 0x101;0,false,2,nop 0x102;
     1,true,3,nop 0x101;1,false,4,nop 0x102] in
  let audit=Audit.analyze report in
  let s=Audit.summary audit in
  assert(s.canonical_instruction_coordinates=3);
  assert(s.owner_qualified_image_instruction_records=5);
  assert(s.duplicated_owner_qualified_instruction_records=2);
  assert(s.multi_owner_instruction_coordinates=2);
  assert(s.byte_disagreement_coordinates=0 && s.decoded_disagreement_coordinates=0);
  assert(s.block_start_some_owners=1 && s.block_start_no_owners=1 && s.block_start_all_owners=0);
  assert(s.boundary_conflict_count=2);
  assert(s.current_owner_qualified_blocks=2 && s.current_canonical_image_blocks=2);
  assert(s.candidate_canonical_blocks=2 && s.estimated_block_deduplication=0);
  let shared=Audit.shared_coordinates audit in
  let at offset=List.find(fun(c:Audit.shared_coordinate)->c.offset=offset)shared in
  assert((at 1).block_start_status=Audit.Some_owners);
  assert(not(at 1).boundaries_identical);
  assert((at 2).block_start_status=Audit.No_owners);
  assert(List.map(fun(c:Audit.candidate_block)->c.start_offset,c.end_offset)(Audit.candidate_blocks audit)=[0,1;1,3]);
  assert(Audit.to_json_string audit=Audit.to_json_string(Audit.analyze report));
  assert(String.starts_with ~prefix:"RUNES_CANONICAL_BLOCK_AUDIT 1\n"(Audit.to_json_string audit))

let test_agreement_and_all_owners_start ()=
  let map=Map.create()in
  let report=materialize map (Bytes.of_string"\000\000")
    [0,true,0,nop 0x100;1,true,1,nop 0x100]in
  let audit=Audit.analyze report in
  let c=List.find(fun(c:Audit.shared_coordinate)->c.offset=0)(Audit.shared_coordinates audit)in
  assert(c.bytes_agree && c.decoded_agree);
  assert(c.block_start_status=Audit.All_owners && c.boundaries_identical)

let test_instruction_variant_is_reported ()=
  let map=Map.create()in
  let report=materialize map (Bytes.of_string"\000")
    [0,true,0,nop 0x100;1,true,1,halt 0x100]in
  let audit=Audit.analyze report in
  let c=List.find(fun(c:Audit.shared_coordinate)->c.offset=0)(Audit.shared_coordinates audit)in
  assert(not c.bytes_agree && not c.decoded_agree);
  assert(c.block_start_status=Audit.All_owners && c.boundaries_identical);
  assert((Audit.summary audit).byte_disagreement_coordinates=1)

let ()=
  test_union_partition_and_boundary_classification();
  test_agreement_and_all_owners_start();
  test_instruction_variant_is_reported();
  print_endline"canonical block audit tests passed"
