(** Bounded +7D05 front through the hardware CALL to +73A7.
    The +7A17 child is supported only on its historical AE04=0 early return.
    The +73A7 descendant does not execute here. *)
type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int
val run : State.t -> entry:state -> observe:(access -> unit) -> state
