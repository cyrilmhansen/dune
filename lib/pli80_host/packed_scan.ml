type write = { address : int; value : int; phase : string }
type result = {
  position : int; initial_index : int; fresh_index : int;
  initial_word : int; shifted_word : int; counter : int; shifts : int;
  auxiliary_address : int; discarded_ae39 : int; publication_word : int;
  positive_mask : int; equality_mask : int; writes : write list;
}
let validate memory ~position ~protected =
  U8.check position; List.iter U16.check protected;
  let map = 0xaa1f + position in
  let j = State.read memory map in
  let word = 0xab49 + 2*j and auxiliary = 0xad08+j in
  let scratch = 0xae38 :: 0xae39 :: List.init 12 (fun i -> 0xae43+i) in
  let selected = [map;word;word+1;auxiliary] in
  let unique = List.sort_uniq compare (scratch @ selected) in
  if List.length unique <> List.length scratch + List.length selected
     || List.exists (fun a -> List.mem a unique) protected
  then invalid_arg "Packed_scan: declared alias overlap";
  ignore (State.read memory 0xae39)

let run memory ~position ~protected =
  validate memory ~position ~protected;
  let writes = ref [] in
  let put phase address value =
    State.write memory address value;
    writes := {address;value;phase} :: !writes in
  let put_word phase address value =
    put phase address (value land 255); put phase (address+1) (value lsr 8) in
  (* +7BBF..+7BCF and +7A79: actual setup order, including the discarded
     high byte of the historical LHLD AE38 / MVI H,0 sequence. *)
  put "input_position" 0xae4b position;
  put "counter_initialization" 0xae4c 15;
  let saved_position = State.word memory 0xae4b land 255 in
  put "mapped_word_position" 0xae38 saved_position;
  let saved_lookup = State.word memory 0xae38 in
  let discarded_ae39 = saved_lookup lsr 8 in
  let initial_index = State.read memory (0xaa1f + (saved_lookup land 255)) in
  let initial_word = State.word memory (0xab49 + 2*initial_index) in
  put_word "initial_word" 0xae4d initial_word;
  let shifts = ref 0 in
  let rec loop () =
    let counter = State.read memory 0xae4c in
    let positive_mask = if counter <> 0 then 255 else 0 in
    (* +82E1 reads the scratch word; +82BB reads that same word twice.
       Preserve these accesses and word publication, not a closed-form scan. *)
    let old_top = State.word memory 0xae4d land 0x8000 in
    let left = State.word memory 0xae4d in
    let right = State.word memory 0xae4d in
    let shifted_word = U16.wrap (left + right) in
    put_word "shifted_word" 0xae4d shifted_word;
    incr shifts;
    let new_top = shifted_word land 0x8000 in
    let equality_mask = if old_top = new_top then 255 else 0 in
    if positive_mask land equality_mask <> 0 then (
      put "counter_decrement" 0xae4c (U8.wrap (counter-1));
      loop ())
    else shifted_word,positive_mask,equality_mask in
  let shifted_word,positive_mask,equality_mask = loop () in
  (* +7C0C/+7C10 read neighboring bytes; +7B2E saves E before C and
     independently rereads the position map at the publication boundary. *)
  let final_position = State.word memory 0xae4b land 255 in
  let publication_word = State.word memory 0xae4c in
  let counter = publication_word land 255 in
  put "auxiliary_value" 0xae44 counter;
  put "auxiliary_position" 0xae43 final_position;
  let fresh_position = State.word memory 0xae43 land 255 in
  let fresh_index = State.read memory (0xaa1f + fresh_position) in
  let auxiliary_address = 0xad08 + fresh_index in
  put "auxiliary_publication" auxiliary_address (State.read memory 0xae44);
  let counter = State.read memory 0xae4c in
  {position;initial_index;fresh_index;initial_word;shifted_word;counter;publication_word;
   shifts= !shifts;auxiliary_address;discarded_ae39;positive_mask;equality_mask;
   writes=List.rev !writes}
