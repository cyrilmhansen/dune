(** Scoped +7D31 parent with canonical +052C and complete +7D05. *)
val run : State.t -> pli2:bytes -> entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) -> K123_child_7d05_front.state
