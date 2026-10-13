(** Complete +7D05 operation for the two proved FACTOR state-defined paths.
    No +7D31 or gateway native installation follows from this interface. *)
val run : State.t -> pli2:bytes ->
  entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) ->
  K123_child_7d05_front.state
