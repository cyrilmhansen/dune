(** Scoped Pass68 +785C/+77CC operation for the actual k123 child state.
    Returns at +7D30; no encompassing +7D05 return is implied. *)
val run : State.t -> pli2:bytes ->
  entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) ->
  K123_child_7d05_front.state
