type publication = {
  position : int; value : int; index : int; address : int; old_value : int;
  discarded_high : int;
}
type recycle = {
  position : int; old_word : int; initial_carrier : int; fresh_carrier : int;
  child : publication; fresh_index : int;
}
type result = Publication of publication | Recycle of recycle
let guard protected addresses =
  List.iter U16.check protected;
  if List.exists (fun a -> List.mem a protected) addresses then
    invalid_arg "Mapped_publication: declared scratch/table/stack alias"
let put memory write phase address value =
  State.write memory address value; write {Mapped_lookup.address;value;phase}
let publish memory ~position ~value ~protected ~write =
  U8.check position; U8.check value;
  let map_address=0xaa1f+position in
  guard protected [0xae3c;0xae3d;map_address];
  put memory write "mapped_write_value" 0xae3d value;
  put memory write "mapped_write_position" 0xae3c position;
  let carrier=State.word memory 0xae3c in
  let accessed_map=0xaa1f+(carrier land 255) in
  guard protected [accessed_map];
  let index=State.read memory accessed_map in
  let address=0xaab4+index in
  guard (accessed_map::protected) [address];
  (* Diagnostic old value for differential reports; not an algorithm input. *)
  let old_value=State.read memory address in
  let value=State.read memory 0xae3d in
  put memory write "mapped_publication" address value;
  {position;value;index;address;old_value;discarded_high=carrier lsr 8}
let recycle memory ~position ~protected ~write =
  U8.check position;
  guard protected [0xae4a;0xae4b;0xae33;0xae34;0xaa1f+position];
  put memory write "recycle_position" 0xae4a position;
  let initial_carrier=State.word memory 0xae4a in
  let old_word=State.word memory 0xae33 in
  let child=publish memory ~position:(initial_carrier land 255)
    ~value:(old_word land 255) ~protected ~write in
  (* Independent LHLD after child mutation; never substitute child.index. *)
  let fresh_carrier=State.word memory 0xae4a in
  guard protected [0xaa1f+(fresh_carrier land 255)];
  let fresh_index=State.read memory (0xaa1f+(fresh_carrier land 255)) in
  put memory write "recycle_cached_index" 0xae33 fresh_index;
  {position;old_word;initial_carrier;fresh_carrier;child;fresh_index}
