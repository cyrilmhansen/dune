(** Scoped +256E software handler, returning through gateway's +20AF word.
    This is a proved operation, not a dispatcher installation. *)
val run : State.t -> pli2:bytes -> pli_com:bytes -> entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) -> K123_child_7d05_front.state
