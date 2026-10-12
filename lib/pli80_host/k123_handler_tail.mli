(** Faithful instruction-derived tail at PLI2.OVL+2578 after the unresolved
    +247B child and canonical +059E have returned. No gateway installation. *)
type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int
val run : State.t -> entry:state -> observe:(access -> unit) -> state
