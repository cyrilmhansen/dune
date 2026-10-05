type access = { position : int; index : int; address : int; value : int; discarded_high : int }
let guard protected addresses =
  List.iter U16.check protected;
  if List.exists (fun a -> List.mem a protected) addresses then
    invalid_arg "Auxiliary: declared scratch/table/stack alias"
let put memory write phase address value =
  State.write memory address value; write {Mapped_lookup.address;value;phase}
let read memory ~position ~protected ~write =
  U8.check position; guard protected [0xae3a;0xae3b;0xaa1f+position];
  put memory write "auxiliary_read_position" 0xae3a position;
  let carrier=State.word memory 0xae3a in
  let index=State.read memory (0xaa1f+(carrier land 255)) in
  let address=0xad08+index in guard protected [address];
  {position;index;address;value=State.read memory address;discarded_high=carrier lsr 8}
let publish memory ~position ~value ~protected ~write =
  U8.check position; U8.check value;
  guard protected [0xae43;0xae44;0xaa1f+position];
  put memory write "auxiliary_value" 0xae44 value;
  put memory write "auxiliary_position" 0xae43 position;
  let carrier=State.word memory 0xae43 in
  let index=State.read memory (0xaa1f+(carrier land 255)) in
  let address=0xad08+index in guard protected [address];
  let value=State.read memory 0xae44 in
  put memory write "auxiliary_publication" address value;
  {position;index;address;value;discarded_high=carrier lsr 8}
let read_secondary memory ~position ~protected ~write =
  U8.check position;guard protected [0xae3b;0xae3c;0xaa1f+position];
  put memory write "secondary_auxiliary_position" 0xae3b position;
  let carrier=State.word memory 0xae3b in
  let map_address=0xaa1f+(carrier land 255) in guard protected [map_address];
  let index=State.read memory map_address in
  let address=0xad9d+index in guard (0xae3b::0xae3c::map_address::protected) [address];
  {position;index;address;value=State.read memory address;discarded_high=carrier lsr 8}
