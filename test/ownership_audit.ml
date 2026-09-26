[@@@warning "-4-27-40-41-42-69"]

module Map=Analysis.Execution_map
module Structure=Analysis.Dynamic_structure
module Audit=Analysis.Ownership_audit

let image name=match Map.image_id ~drive:0 ~user:0 ~filename:name with Ok x->x|Error _->failwith"image"
let seed map name base size=let image=image name in
  assert(Map.seed_image map ~image ~runtime_base:base(Bytes.make size '\000')=Ok());image
let decode bytes=match I8080.Decode.decode bytes ~offset:0 with Ok x->x|Error _->failwith"decode"
let make_step ?(flow=I8080.Step.Sequential) pc after bytes=
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:after
    ~decoded:(decode bytes) ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow
let nop pc=make_step pc(pc+1)(Bytes.of_string"\000")
let call pc target=make_step ~flow:(I8080.Step.Call{target;taken=true}) pc target
  (Bytes.of_string(Printf.sprintf"\xcd%c%c"(Char.chr(target land 255))(Char.chr(target lsr 8))))
let jump pc target=make_step ~flow:(I8080.Step.Jump{target;taken=true}) pc target
  (Bytes.of_string(Printf.sprintf"\xc3%c%c"(Char.chr(target land 255))(Char.chr(target lsr 8))))
let ret pc target=make_step ~flow:(I8080.Step.Return{target=Some target;taken=true}) pc target(Bytes.of_string"\xc9")

let observe structure audit map ~index ~sp_before ~sp_after step=
  let attributed=Structure.observe_step_detailed ~sp_before ~sp_after structure map ~step_index:index step in
  Audit.observe_step audit map ~routine_id:attributed.routine_id ~step_index:index step attributed.audit_events;
  attributed

let test_known_entry_jump_and_bounded_samples ()=
  let map=Map.create()in ignore(seed map"MAIN.COM"0x100 0x200);
  let structure=Structure.create()and audit=Audit.create ~max_examples:2()in
  ignore(observe structure audit map ~index:0 ~sp_before:0xfffe ~sp_after:0xfffe(nop 0x100));
  ignore(observe structure audit map ~index:1 ~sp_before:0xfffe ~sp_after:0xfffc(call 0x101 0x180));
  ignore(observe structure audit map ~index:2 ~sp_before:0xfffc ~sp_after:0xfffe(ret 0x180 0x104));
  let first_jump=observe structure audit map ~index:3 ~sp_before:0xfffe ~sp_after:0xfffe(jump 0x104 0x180)in
  let second_jump=observe structure audit map ~index:4 ~sp_before:0xfffe ~sp_after:0xfffe(jump 0x104 0x180)in
  assert(first_jump.routine_id=0 && second_jump.routine_id=0);
  let summary=Audit.summary audit in
  assert(summary.known_entry_jmp_sites=1 && summary.known_entry_jmp_observations=2);
  assert(summary.source_target_candidate_pairs=1);
  match Audit.example_events audit with
  |[Structure.Known_entry_jump first;Structure.Known_entry_jump second]->
      assert(first.step=3 && first.owner=0 && first.target_candidate=1
        && first.source.pc=0x104 && first.target.pc=0x180 && first.sp_before=Some 0xfffe && first.sp_after=Some 0xfffe);
      assert(second.step=4)
  |_->failwith"known-entry JMP examples must be retained up to the per-site bound"

let test_multi_owner_coordinate_and_return_mismatch ()=
  let map=Map.create()in let main=seed map"M.COM"0x100 0x200 in
  let structure=Structure.create()and audit=Audit.create()in
  (* Offset +0000 is first executed by R000, then reached under R001 after a JMP. *)
  ignore(observe structure audit map ~index:0 ~sp_before:0xfffe ~sp_after:0xfffe(nop 0x100));
  ignore(observe structure audit map ~index:1 ~sp_before:0xfffe ~sp_after:0xfffc(call 0x101 0x180));
  ignore(observe structure audit map ~index:2 ~sp_before:0xfffc ~sp_after:0xfffe(ret 0x180 0x109));
  ignore(observe structure audit map ~index:3 ~sp_before:0xfffe ~sp_after:0xfffc(call 0x101 0x180));
  ignore(observe structure audit map ~index:4 ~sp_before:0xfffc ~sp_after:0xfffc(jump 0x180 0x100));
  ignore(observe structure audit map ~index:5 ~sp_before:0xfffc ~sp_after:0xfffc(nop 0x100));
  let overlaps=Audit.multi_owner_coordinates audit in
  assert(List.exists(fun(i,off,owners)->i=main && off=0 && owners=[0;1])overlaps);
  let summary=Audit.summary audit in
  assert(summary.multi_owner_coordinate_count>=1 && summary.return_mismatch_observations=1);
  let json=Audit.to_json_string audit in
  assert(String.starts_with ~prefix:"RUNES_OWNERSHIP_AUDIT 1\n" json);
  assert(json=Audit.to_json_string audit);
  let contains haystack needle=
    let rec loop i=i+String.length needle<=String.length haystack &&
      (String.sub haystack i(String.length needle)=needle||loop(i+1))in loop 0 in
  assert(contains json "\"expected_return_pc\":260")

let test_known_image_reentered_under_unchanged_owner ()=
  let map=Map.create()in ignore(seed map"MAIN.COM"0x100 0x20);ignore(seed map"OVERLAY.OVL"0x300 0x20);
  let structure=Structure.create()and audit=Audit.create()in
  ignore(observe structure audit map ~index:0 ~sp_before:0xfffe ~sp_after:0xfffe(nop 0x100));
  ignore(observe structure audit map ~index:1 ~sp_before:0xfffe ~sp_after:0xfffe(jump 0x101 0x300));
  ignore(observe structure audit map ~index:2 ~sp_before:0xfffe ~sp_after:0xfffe(nop 0x300));
  (* MAIN+0010 is a previously observed image but not a candidate entry. *)
  ignore(observe structure audit map ~index:3 ~sp_before:0xfffe ~sp_after:0xfffe(jump 0x301 0x110));
  ignore(observe structure audit map ~index:4 ~sp_before:0xfffe ~sp_after:0xfffe(nop 0x110));
  let events=Audit.example_events audit in
  assert(List.exists(function Structure.Known_image_under_other_owner e->
    e.owner=1 && e.target.image=Some(image"MAIN.COM") && e.target.pc=0x110
    && (match e.transfer with Some t->t.transfer=Structure.Jump_transfer|None->false)
    |_->false)events);
  assert((Audit.summary audit).ownership_conflict_observations=1)

let ()=
  test_known_entry_jump_and_bounded_samples();
  test_multi_owner_coordinate_and_return_mismatch();
  test_known_image_reentered_under_unchanged_owner();
  print_endline"ownership audit tests passed"
