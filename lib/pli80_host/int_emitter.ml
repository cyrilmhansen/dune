type write = { address : int; value : int; phase : string }
type operation = Write of write | Set_dma of int | Sequential_write of int
type plan = {
  input_byte : int; index : int; discarded_neighbor : int; destination : int;
  fresh_scratch : int; reloaded_index : int; incremented_index : int;
  flush : bool; effects : operation list;
}
let plan state ~input_byte ~protected =
  U8.check input_byte;
  List.iter U16.check protected;
  let accessed=0x20b0::0x1e0c::0x1e0d::List.init 128(fun i->0x1d8c+i) in
  if List.exists(fun a->List.mem a protected)accessed then
    invalid_arg "INT emitter scratch/buffer/index alias";
  if State.read state 0x1e0c>=128 then invalid_arg "INT emitter unsupported index domain";
  let effects=ref [] in
  let publish address value phase =
    State.write state address value;
    effects:=Write{address;value;phase}::!effects in
  publish 0x20b0 input_byte "append scratch";
  let pair=State.word state 0x1e0c in
  let index=pair land 255 and discarded_neighbor=pair lsr 8 in
  let destination=U16.wrap(0x1d8c+index) in
  let fresh_scratch=State.read state 0x20b0 in
  publish destination fresh_scratch "fresh scratch to buffer";
  let reloaded_index=State.read state 0x1e0c in
  let incremented_index=U8.wrap(reloaded_index+1) in
  publish 0x1e0c incremented_index "incremented index";
  let flush=incremented_index=0x80 in
  let effects=List.rev !effects @ if flush then
    [Set_dma 0x1d8c;Write{address=0x1e0c;value=0;phase="post-DMA index reset"};Sequential_write 0x1ca2]
    else [] in
  {input_byte;index;discarded_neighbor;destination;fresh_scratch;reloaded_index;
   incremented_index;flush;effects}
