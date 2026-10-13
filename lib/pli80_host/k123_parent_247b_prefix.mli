(** Common natural +247B prefix through its state-selected branch CALL.
    The selected +83DC or +81AA child has not executed on return. *)
val run : State.t -> pli2:bytes -> entry:K123_child_7d05_front.state ->
  observe:(K123_child_7d05_front.access -> unit) -> K123_child_7d05_front.state
