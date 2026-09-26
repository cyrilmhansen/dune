[@@@warning "-4-27-40-41-42-69"]

module M=Analysis.Dynamic_structure
module Map=Analysis.Execution_map

let key name=match Map.image_id ~drive:0 ~user:0 ~filename:name with Ok x->x|Error _->failwith"image key"
let seed map name base length = let image=key name in
  assert(Map.seed_image map ~image ~runtime_base:base (Bytes.make length '\000')=Ok()); image

let instruction bytes = match I8080.Decode.decode bytes ~offset:0 with Ok x->x|Error _->failwith"decode"
let step ?(flow=I8080.Step.Sequential) ~pc ~after bytes =
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:after
    ~decoded:(instruction bytes) ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:flow

let observe t map index step=M.observe_step t map ~step_index:index step
let nop pc=step ~pc ~after:(pc+1) (Bytes.of_string"\000")
let call ?(taken=true) pc target=let bytes=Bytes.of_string(Printf.sprintf"\xcd%c%c"(Char.chr(target land 255))(Char.chr(target lsr 8)))in
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:(if taken then target else (pc+3)land 0xffff)
    ~decoded:(instruction bytes) ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:(I8080.Step.Call{target;taken})
let jump pc target=let bytes=Bytes.of_string(Printf.sprintf"\xc3%c%c"(Char.chr(target land 255))(Char.chr(target lsr 8)))in
  I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:target ~decoded:(instruction bytes)
    ~fetched_bytes:bytes ~memory_accesses:[] ~control_flow:(I8080.Step.Jump{target;taken=true})
let ret ?(taken=true) pc target=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:(if taken then target else pc+1)
    ~decoded:(instruction(Bytes.of_string"\xc9")) ~fetched_bytes:(Bytes.of_string"\xc9")
    ~memory_accesses:[] ~control_flow:(I8080.Step.Return{target=(if taken then Some target else None);taken})
let rst pc target=I8080.Step.create ~source:I8080.Step.Memory ~pc_before:pc ~pc_after:target
    ~decoded:(instruction(Bytes.of_string"\xcf")) ~fetched_bytes:(Bytes.of_string"\xcf")
    ~memory_accesses:[] ~control_flow:(I8080.Step.Restart{target})

let pair_ids t=List.map(fun (e:M.narrative_entry)->e.source,e.target)(M.narrative t)

let run_calls extra_cycles =
  let map=Map.create()in ignore(seed map"TRACE.COM"0x100 0x600);
  let t=M.create()and i=ref 0 in let emit s=observe t map !i s;incr i in
  emit(nop 0x100);                         (* A *)
  emit(call 0x101 0x200);                  (* A -> B *)
  emit(call 0x200 0x300);                  (* B -> C *)
  emit(ret 0x300 0x203);                   (* C -> B *)
  for _=0 to extra_cycles do
    emit(call 0x203 0x300);                (* repeated B -> C *)
    emit(ret 0x300 0x206)
  done;
  emit(call 0x206 0x400);                  (* B -> D *)
  emit(ret 0x400 0x209);                   (* D -> B *)
  emit(ret 0x209 0x104);                   (* B -> A *)
  emit(call 0x104 0x500);                  (* A -> E *)
  emit(ret 0x500 0x107);                   (* E -> A *)
  t

let test_first_pair_narrative_and_weight_invariance () =
  let a=run_calls 0 and b=run_calls 100 in
  let expected=[0,1;1,2;2,1;1,3;3,1;1,0;0,4;4,0] in
  assert(pair_ids a=expected && pair_ids b=expected);
  let repeated=List.find(fun (e:M.transition)->e.source=1 && e.target=2)(M.transitions b)in
  assert(repeated.occurrence_count=102 && repeated.first_step<repeated.last_step);
  assert((M.summary a).narrative_transition_count=8)

let test_self_and_mutual_recursion () =
  let map=Map.create()in ignore(seed map"REC.COM"0x100 0x200);
  let self=M.create()in observe self map 0(nop 0x100);observe self map 1(call 0x101 0x100);
  observe self map 2(call 0x100 0x100);observe self map 3(ret 0x100 0x104);observe self map 4(ret 0x100 0x104);
  let r=List.hd(M.routines self)in assert(List.length(M.routines self)=1 && r.recursive && r.self_call_count=2);
  assert(M.narrative self=[]);
  let mutual=M.create()in observe mutual map 0(nop 0x100);observe mutual map 1(call 0x101 0x200);
  observe mutual map 2(call 0x200 0x100);observe mutual map 3(ret 0x100 0x203);observe mutual map 4(ret 0x200 0x104);
  assert(pair_ids mutual=[0,1;1,0])

let test_return_anomaly_and_jmp_not_candidate () =
  let map=Map.create()in ignore(seed map"FLOW.COM"0x100 0x300);
  let t=M.create()in observe t map 0(nop 0x100);observe t map 1(call 0x101 0x200);
  observe t map 2(jump 0x200 0x250);
  assert(List.length(M.routines t)=2); (* ordinary JMP did not create a routine *)
  observe t map 3(ret 0x250 0x109);
  assert(List.exists(fun a->a.M.kind=M.Return_target_mismatch)(M.anomalies t));
  let j=M.create()in observe j map 0(nop 0x100);observe j map 1(call 0x101 0x200);
  observe j map 2(ret 0x200 0x104);observe j map 3(jump 0x104 0x200);
  assert(List.length(M.routines j)=2);
  let pair=List.hd(M.transitions j)in
  assert(pair.kinds=[M.Call;M.Other_observed] && pair.occurrence_count=2 && pair.first_step<pair.last_step);
  assert(List.exists(fun a->a.M.kind=M.Jump_into_known_entry)(M.anomalies j))

let test_image_entry_and_restart () =
  let map=Map.create()in ignore(seed map"MAIN.COM"0x100 0x200);ignore(seed map"NEW.OVL"0x3000 8);
  let t=M.create()in observe t map 0(nop 0x100);
  observe t map 1(jump 0x101 0x3000);observe t map 2(nop 0x3000);
  assert((M.summary t).routine_count=2 && (List.hd(M.transitions t)).kinds=[M.Image_entry]);
  let restart_map=Map.create()in ignore(seed restart_map"RSTMAIN.COM"0x100 0x20);ignore(seed restart_map"RST.SYS"8 4);
  let r=M.create()in observe r restart_map 0(nop 0x100);observe r restart_map 1(rst 0x101 8);
  observe r restart_map 2(ret 8 0x102);
  assert((List.hd(M.transitions r)).kinds=[M.Restart])

let test_conditional_outcomes () =
  let map=Map.create()in ignore(seed map"COND.COM"0x100 0x200);
  let t=M.create()in observe t map 0(nop 0x100);
  observe t map 1(call ~taken:false 0x101 0x180);
  assert(List.length(M.routines t)=1 && M.narrative t=[]);
  observe t map 2(call 0x104 0x180);observe t map 3(nop 0x180);
  observe t map 4(ret ~taken:false 0x181 0x107);
  assert((M.summary t).narrative_transition_count=1);
  observe t map 5(ret 0x182 0x107);
  assert(pair_ids t=[0,1;1,0] && (List.length(M.routines t)=2))

let test_overlay_identity () =
  let map=Map.create()in let com=seed map"PLI.COM"0x100 0x300 in
  let ov0=seed map"PLI0.OVL"0x2200 8 in
  let t=M.create()in observe t map 0(nop 0x100);observe t map 1(call 0x101 0x2200);
  observe t map 2(nop 0x2200);observe t map 3(ret 0x2201 0x104);
  let ov1=seed map"PLI1.OVL"0x2200 8 in
  observe t map 4(call 0x104 0x2200);observe t map 5(nop 0x2200);observe t map 6(ret 0x2201 0x107);
  let ov2=seed map"PLI2.OVL"0x2200 8 in
  observe t map 7(call 0x107 0x2200);observe t map 8(nop 0x2200);
  let overlays=List.filter(fun (r:M.routine)->r.runtime_entry_pc=0x2200)(M.routines t)in
  assert(List.length overlays=3);
  assert(List.map(fun (r:M.routine)->(Option.get r.image).Cpm.Filesystem.name)overlays=["PLI0.OVL";"PLI1.OVL";"PLI2.OVL"]);
  assert(com.Cpm.Filesystem.name="PLI.COM" && ov0<>ov1 && ov1<>ov2)

let test_json_stable () =
  let a=run_calls 1 and b=run_calls 1 in
  assert(String.starts_with ~prefix:"RUNES_DYNAMIC_STRUCTURE 1\n"(M.to_json_string a));
  assert(M.to_json_string a=M.to_json_string b)

let ()=test_first_pair_narrative_and_weight_invariance();test_self_and_mutual_recursion();
  test_return_anomaly_and_jmp_not_candidate();test_image_entry_and_restart();test_conditional_outcomes();
  test_overlay_identity();test_json_stable()
