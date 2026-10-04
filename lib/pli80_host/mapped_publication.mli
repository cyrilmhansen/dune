(** Complete scoped historical +7AD5/+7BA2 logical operations on shared RAM.
    [protected] lists caller/stack/code cells outside the declared alias scope.
    The write observer normally records chronology; no emulator dependency.
    Unsupported states may have changed this private State before rejection,
    so callers must validate on an owned clone before publishing a transition. *)
type publication = {
  position : int; value : int; index : int; address : int; old_value : int;
  discarded_high : int;
}
type recycle = {
  position : int; old_word : int; initial_carrier : int; fresh_carrier : int;
  child : publication; fresh_index : int;
}
type result = Publication of publication | Recycle of recycle
val publish : State.t -> position:int -> value:int -> protected:int list ->
  write:(Mapped_lookup.write -> unit) -> publication
val recycle : State.t -> position:int -> protected:int list ->
  write:(Mapped_lookup.write -> unit) -> recycle
