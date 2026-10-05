(** Distinct historical +7E46/+7E56 compositions. [emit] is the native child
    operation; it runs after the wrapper's reads/cache publications. No retained
    word value is accepted by [high]. *)
type selection={low_wrapper:bool;paired_word:int;neighbor:int;lookup:Mapped_word.result option;
 selected_word:int;emitted_byte:int;writes:Mapped_word.write list}
val low : State.t -> protected:int list -> emit:(State.t -> selection -> 'a) -> selection * 'a
val high : State.t -> protected:int list -> emit:(State.t -> selection -> 'a) -> selection * 'a
