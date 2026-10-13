(** The existing Pass68 +785C/+77CC law applied to a proved FACTOR state. *)
module Front = K123_child_7d05_front
module Family = Acquisition_family
module Frame = Acquisition_parent
module R = Recursive_mapped

let run memory ~pli2 ~(entry:Front.state) ~observe =
  if entry.pc <> 0x9a5c || entry.sp < 0xb000 || entry.sp > 0xfffc then
    invalid_arg "k123 +785C: wrong entry or stack";
  let code a b =
    for offset=a to b-1 do
      if State.read memory (offset+0x2200) <> Char.code (Bytes.get pli2 offset) then
        invalid_arg "k123 +785C: historical code changed"
    done in
  code 0x785c 0x7897;
  code 0x77cc 0x785c;
  let pointer = entry.bc in
  let sentinel = State.word memory 0x2155 in
  if pointer < 0xf000 || pointer > 0xfff7 ||
     pointer+8 > entry.sp-512 ||
     (sentinel >= 0xac9f && sentinel < 0xae00) ||
     (sentinel >= 0x1c2c && sentinel < 0x1d8c) ||
     (sentinel >= entry.sp-32 && sentinel < entry.sp+2) ||
     State.read memory 0x201d land 1 <> 0 ||
     State.read memory 0x2029 land 1 <> 0 ||
     State.read memory 0x1d8a > 120 ||
     State.read memory 0x1d8b >= 8 then
    invalid_arg "k123 +785C: pointer, output or alias scope";
  let stack = ref entry.sp in
  let frames = ref [] in
  let read address =
    let value = State.read memory address in
    observe (Front.Read(address,value));value in
  let write address value =
    State.write memory address value;
    observe (Front.Write(address,value)) in
  let push value =
    write (U16.wrap(!stack-1)) (value lsr 8);
    write (U16.wrap(!stack-2)) (value land 255);
    stack := U16.wrap(!stack-2) in
  let pop ?expected () =
    let lo=read !stack and hi=read (U16.wrap(!stack+1)) in
    let actual=lo lor (hi lsl 8) in
    (match expected with Some value when value<>actual ->
       invalid_arg "k123 +785C: changed continuation" | _ -> ());
    stack := U16.wrap(!stack+2) in
  let compatibility = function
    | Frame.Enter(site,target) ->
        let op=State.read memory site in
        let lo=State.read memory (U16.wrap(site+1)) in
        let hi=State.read memory (U16.wrap(site+2)) in
        if op<>0xcd || lo lor (hi lsl 8)<>target then
          invalid_arg "k123 +785C: child CALL changed";
        frames := (site+3)::!frames;push(site+3)
    | Frame.Leave ->
        (match !frames with
         | address::rest -> pop ~expected:address ();frames:=rest
         | [] -> invalid_arg "k123 +785C: extra RET")
    | Frame.Push(_,value) -> push value
    | Frame.Pop -> pop ()
    | _ -> invalid_arg "k123 +785C: unexpected stack action" in
  let guard_field pointer width =
    if pointer < 0xf000 || width<0 || pointer+width > !stack-512 then
      invalid_arg "k123 +77CC: active pointer/stack alias" in
  let fail () = invalid_arg "k123 +785C: unexpected descendant" in
  let input:R.returned={a=entry.a;bc=entry.bc;de=entry.de;
                        hl=entry.hl;flags=entry.flags} in
  let result=Family.run (Family.Pli2_output 0x785c) memory ~entry:input
      ~write:(fun ~site:_ ~address ~value -> observe(Front.Write(address,value)))
      ~compatibility ~adjust:(fun ~site:_ ~delta:_ -> fail ())
      ~sp:(fun()-> !stack) ~guard_field
      ~native:(fun ~site:_ ~target:_ _ -> fail ())
      ~follow_spine:false ~software:(fun ~site:_ ~consumed:_ -> fail ()) in
  if !frames<>[] || !stack<>entry.sp then
    invalid_arg "k123 +785C: unbalanced frames";
  pop ~expected:0x9f30 ();
  let r=result.returned in
  { Front.pc=0x9f30;sp= !stack;a=r.a;bc=r.bc;de=r.de;hl=r.hl;
    flags=r.flags }
