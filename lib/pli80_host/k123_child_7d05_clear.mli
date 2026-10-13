(** Bounded executable +7D05 front and canonical +73A7 non-6 route.
    Returns at +7D1F; no later +7D05 instruction executes. *)
val run : State.t ->
  entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) ->
  K123_child_7d05_front.state
