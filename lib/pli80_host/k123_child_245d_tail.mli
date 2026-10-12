(** +245D instructions after the separately proved canonical +052C returns.
    The optional composition stops at the next branch-selected child CALL. *)
type state = {
  pc : int; sp : int; a : int; bc : int; de : int; hl : int;
  flags : Recursive_mapped.flags;
}
type access = Read of int * int | Write of int * int
val run : State.t -> entry:state -> observe:(access -> unit) -> state
val through_branch :
  State.t -> entry:state -> observe:(access -> unit) ->
  K123_child_branch.state
