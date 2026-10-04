(** Faithful PLI1+7BBF bounded operation at its nonaliasing contract scope. *)
type write = { address : int; value : int; phase : string }
type result = {
  position : int; initial_index : int; fresh_index : int;
  initial_word : int; shifted_word : int; counter : int; shifts : int;
  auxiliary_address : int; discarded_ae39 : int; publication_word : int;
  positive_mask : int; equality_mask : int; writes : write list;
}
val validate : State.t -> position:int -> protected:int list -> unit

(** Check all selected input/output/scratch cells against bridge-owned stack
    cells, before any mutation. Numeric table aliases are not abstracted away. *)
val run : State.t -> position:int -> protected:int list -> result
