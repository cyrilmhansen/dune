(** End<=94 bounded +7E5F composition on shared historical memory. *)
type result={end_before:int;old_index:int;displaced:int;
 byte:Mapped_publication.publication;word:Mapped_word.publication;
 primary:Auxiliary.access;secondary:Auxiliary.access;returned_a:int;increment_before:int;end_after:int}
val supported_end : int -> unit
val run : State.t -> input_c:int -> input_de:int -> protected:int list ->
 write:(site:int -> address:int -> value:int -> unit) -> call:(int -> unit) ->
 save_destination:(int -> unit) -> result
