(** +7B7A: conditional termination exactly as historically established.
    No iteration bound, cycle guard or alternative stopping rule. *)
type iteration = {
  cursor : int; lookup : Mapped_lookup.attribute;
  balance_before : int; temporary_sum : int; balance_after : int;
  cursor_wrapped : bool;
}
type result = { start_cursor : int; stop_cursor : int;
  iterations : iteration list; writes : Mapped_lookup.write list }
val update_balance : attribute:int -> balance:int -> int * int
val run : State.t -> cursor:int -> protected:int list -> result
