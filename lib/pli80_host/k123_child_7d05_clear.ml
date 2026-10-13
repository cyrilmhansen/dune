(** The Pass79 front followed by the already proved Pass57 +73A7/+7397 law.
    Stops at the first +7D05 instruction after the child's hardware RET. *)
module Front = K123_child_7d05_front
module Family = Acquisition_family
module Frame = Acquisition_parent
module R = Recursive_mapped

let run memory ~(entry:Front.state) ~observe =
  let index = entry.bc land 255 in
  if index > 5 || entry.sp < 0xb000 || entry.sp > 0xfffc then
    invalid_arg "k123 +73A7: outside proved index/frame scope";
  if State.read memory 0x201d land 1 <> 0 ||
     State.read memory 0x2029 land 1 <> 0 ||
     State.read memory 0x1c2c = 0 then
    invalid_arg "k123 +73A7: inherited output scope";
  let code start bytes =
    List.iteri (fun i byte ->
      if State.read memory (start+i) <> byte then
        invalid_arg "k123 +73A7: canonical child code changed") bytes in
  code 0x9597 [0x21;0xc2;0xad;0x71;0x2a;0xc2;0xad;0x26;
               0x00;0x01;0xab;0xad;0x09;0x36;0x00;0xc9];
  code 0x95a7 [0x21;0xc3;0xad;0x71;0x3a;0xc3;0xad;0xfe;
               0x06;0xc2;0xb4;0x95;0xc9;0x2a;0xc3;0xad;
               0x4d;0xcd;0x97;0x95;0x3a;0xc3;0xad;0x3c;
               0x4f;0xcd;0x97;0x95;0xc9];
  let q = Front.run memory ~entry ~observe in
  if q.pc <> 0x95a7 then invalid_arg "k123 +73A7: wrong child";
  let stack = ref q.sp in
  let frames = ref [] in
  let write address value =
    State.write memory address value;
    observe (Front.Write (address, value)) in
  let read address =
    let value = State.read memory address in
    observe (Front.Read (address, value)); value in
  let push continuation =
    let high = U16.wrap (!stack - 1) in
    let low = U16.wrap (!stack - 2) in
    write high (continuation lsr 8);
    write low (continuation land 255);
    stack := low in
  let pop expected =
    let low = read !stack in
    let high = read (U16.wrap (!stack + 1)) in
    let actual = low lor (high lsl 8) in
    if actual <> expected then invalid_arg "k123 +73A7: modified child continuation";
    stack := U16.wrap (!stack + 2) in
  let compatibility = function
    | Frame.Enter (site, target) ->
        let first = State.read memory site in
        let low = State.read memory (U16.wrap (site + 1)) in
        let high = State.read memory (U16.wrap (site + 2)) in
        if first <> 0xcd || low lor (high lsl 8) <> target then
          invalid_arg "k123 +73A7: child CALL changed";
        frames := (site + 3) :: !frames;
        push (site + 3)
    | Frame.Leave ->
        (match !frames with
         | return_to :: rest -> pop return_to; frames := rest
         | [] -> invalid_arg "k123 +73A7: extra child RET")
    | _ -> invalid_arg "k123 +73A7: unexpected stack operation" in
  let fail () = invalid_arg "k123 +73A7: unexpected descendant" in
  let input : R.returned = { a=q.a; bc=q.bc; de=q.de; hl=q.hl; flags=q.flags } in
  let result = Family.run (Family.Pli2_output 0x73a7) memory ~entry:input
      ~write:(fun ~site:_ ~address ~value -> observe (Front.Write (address, value)))
      ~compatibility ~adjust:(fun ~site:_ ~delta:_ -> fail ())
      ~sp:(fun () -> !stack)
      ~guard_field:(fun _ _ -> fail ())
      ~native:(fun ~site:_ ~target:_ _ -> fail ())
      ~follow_spine:false ~software:(fun ~site:_ ~consumed:_ -> fail ()) in
  if !frames <> [] || !stack <> q.sp then
    invalid_arg "k123 +73A7: child frame imbalance";
  pop 0x9f1f;
  let r = result.returned in
  { Front.pc=0x9f1f; sp= !stack; a=r.a; bc=r.bc; de=r.de; hl=r.hl;
    flags=r.flags }
