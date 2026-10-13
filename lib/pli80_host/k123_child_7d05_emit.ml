(** Pass80 prefix, actual +7D1F adapter, and canonical Pass54 +75CE. *)
module Front = K123_child_7d05_front
module Clear = K123_child_7d05_clear
module Family = Acquisition_family
module Frame = Acquisition_parent
module R = Recursive_mapped

let run memory ~(entry:Front.state) ~observe =
  let code start bytes =
    List.iteri (fun i byte ->
      if State.read memory (start+i) <> byte then
        invalid_arg "k123 +75CE: historical code changed") bytes in
  code 0x9f1f [0x2a;0x2d;0xae;0xeb;0x0e;0x01;0xcd;0xce;0x97];
  code 0x97ce [0x21;0xd7;0xad;0x73;0x2b;0x71;0x2a;0xd6;
               0xad;0x4d;0xcd;0x6f;0x96;0x2a;0xd7;0xad;
               0x4d;0xcd;0xc7;0x96;0x3a;0xd7;0xad;0x87;
               0x87;0x87;0x21;0xd6;0xad;0xb6;0x4f;0xcd;
               0x57;0x97;0xc9];
  let position = State.word memory 0x1c2c in
  let sentinel = State.word memory 0x2155 in
  if State.read memory 0x201d land 1 <> 0 ||
     State.read memory 0x2029 land 1 <> 0 ||
     State.read memory 0x1d8a > 125 ||
     State.read memory 0x1d8b >= 8 ||
     position = 0 || position >= 0xfffe ||
     (sentinel >= 0x1c2c && sentinel < 0x1d8c) ||
     (sentinel >= 0x201d && sentinel < 0x20b9) ||
     (sentinel >= entry.sp-32 && sentinel < entry.sp+2) then
    invalid_arg "k123 +75CE: unsupported output state";
  let q = Clear.run memory ~entry ~observe in
  if q.pc <> 0x9f1f then invalid_arg "k123 +75CE: wrong adapter entry";
  let read address =
    let value = State.read memory address in
    observe (Front.Read (address,value)); value in
  let write address value =
    State.write memory address value;
    observe (Front.Write (address,value)) in
  let stack = ref q.sp in
  let frames = ref [] in
  let push value =
    write (U16.wrap (!stack-1)) (value lsr 8);
    write (U16.wrap (!stack-2)) (value land 255);
    stack := U16.wrap (!stack-2) in
  let pop ?expected () =
    let lo = read !stack in
    let hi = read (U16.wrap (!stack+1)) in
    let value = lo lor (hi lsl 8) in
    (match expected with Some x when x <> value ->
      invalid_arg "k123 +75CE: changed continuation" | _ -> ());
    stack := U16.wrap (!stack+2) in
  (* +7D1F LHLD AE2D; XCHG; MVI C,1; CALL +75CE. *)
  let lo = read 0xae2d in
  let hi = read 0xae2e in
  let de = lo lor (hi lsl 8) in
  let hl = q.de in
  let bc = (q.bc land 0xff00) lor 1 in
  push 0x9f28;
  let compatibility = function
    | Frame.Enter (site,target) ->
        let op = State.read memory site in
        let lo = State.read memory (U16.wrap(site+1)) in
        let hi = State.read memory (U16.wrap(site+2)) in
        if op <> 0xcd || lo lor (hi lsl 8) <> target then
          invalid_arg "k123 +75CE: child CALL changed";
        frames := (site+3)::!frames;
        push (site+3)
    | Frame.Leave ->
        (match !frames with
         | address::rest -> pop ~expected:address ();frames:=rest
         | [] -> invalid_arg "k123 +75CE: extra RET")
    | Frame.Push (_,value) -> push value
    | Frame.Pop -> pop ()
    | _ -> invalid_arg "k123 +75CE: unexpected stack action" in
  let fail () = invalid_arg "k123 +75CE: unexpected descendant" in
  let input:R.returned={a=q.a;bc;de;hl;flags=q.flags} in
  let result=Family.run (Family.Pli2_output 0x75ce) memory ~entry:input
      ~write:(fun ~site:_ ~address ~value -> observe (Front.Write(address,value)))
      ~compatibility ~adjust:(fun ~site:_ ~delta:_ -> fail ())
      ~sp:(fun () -> !stack) ~guard_field:(fun _ _ -> fail ())
      ~native:(fun ~site:_ ~target:_ _ -> fail ())
      ~follow_spine:false ~software:(fun ~site:_ ~consumed:_ -> fail ()) in
  if !frames <> [] || !stack <> U16.wrap(q.sp-2) then
    invalid_arg "k123 +75CE: unbalanced child frames";
  pop ~expected:0x9f28 ();
  let r=result.returned in
  { Front.pc=0x9f28;sp= !stack;a=r.a;bc=r.bc;de=r.de;hl=r.hl;
    flags=r.flags }
