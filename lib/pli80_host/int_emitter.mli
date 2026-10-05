(** Resident +0EF6's demonstrated record-producing scope. Services are ordered
    requests, never implemented here. The caller owns transaction application. *)
type write = { address : int; value : int; phase : string }
type operation = Write of write | Set_dma of int | Sequential_write of int
type plan = {
  input_byte : int;
  index : int;
  discarded_neighbor : int;
  destination : int;
  fresh_scratch : int;
  reloaded_index : int;
  incremented_index : int;
  flush : bool;
  effects : operation list;
}
val plan : State.t -> input_byte:int -> protected:int list -> plan
