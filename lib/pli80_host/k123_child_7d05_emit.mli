(** Pass80 +7D05 prefix, +7D1F adapter, and bounded canonical +75CE.
    Returns at +7D28 before the +785C adapter. *)
val run : State.t ->
  entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) ->
  K123_child_7d05_front.state
