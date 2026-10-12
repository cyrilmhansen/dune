(** Complete instruction-derived PLI2.OVL+16B3 leaf through its actual RET.
    No parent or native gateway installation. *)
type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int
val run : State.t -> entry:state -> observe:(access -> unit) -> state
