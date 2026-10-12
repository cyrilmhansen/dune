(** Instruction-derived branch and child CALL at PLI2.OVL+24BC. The operation
    stops at the first instruction of +A3AA or +A5DC; neither child runs here. *)
type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int
val run : State.t -> entry:state -> observe:(access -> unit) -> state
