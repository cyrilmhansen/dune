type write = { address : int; value : int; phase : string }
type mapped = { position : int; index : int; byte : int; discarded_ae37 : int }
type attribute = { mapped : mapped; packed_byte : int; low3 : int; discarded_ae38 : int }
let guard ~protected addresses =
  List.iter U16.check protected;
  if List.exists(fun a->List.mem a protected)addresses then
    invalid_arg "Mapped_lookup: scratch/table/stack alias"
let publish memory write phase address value =
  State.write memory address value;write {address;value;phase}
let mapped_byte memory ~position ~protected ~write =
  U8.check position;guard ~protected [0xae36;0xae37;0xaa1f+position];
  publish memory write "mapped_position" 0xae36 position;
  let carrier=State.word memory 0xae36 in
  let position=carrier land 255 and discarded_ae37=carrier lsr 8 in
  let index=State.read memory (0xaa1f+position) in
  guard ~protected [0xaab4+index];
  let byte=State.read memory (0xaab4+index) in
  {position;index;byte;discarded_ae37}
let low_attribute memory ~position ~protected ~write =
  U8.check position;guard ~protected [0xae36;0xae37;0xae38];
  publish memory write "attribute_position" 0xae37 position;
  let carrier=State.word memory 0xae37 in
  let discarded_ae38=carrier lsr 8 in
  let mapped=mapped_byte memory ~position:(carrier land 255) ~protected ~write in
  guard ~protected [0x1b4b+mapped.byte];
  let packed_byte=State.read memory (0x1b4b+mapped.byte) in
  {mapped;packed_byte;low3=packed_byte land 7;discarded_ae38}
