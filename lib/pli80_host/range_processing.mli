module R=Recursive_mapped
type operation=Mapping|Recursive|Balance|Emit|High_attribute|Primary|Secondary|Low_word|High_word|Recycle
type reverse={cursor:int;sentinel:int;mapped:int option;result:int option;stop:int option;psw:int}
type forward={cursor:int;mapped:int;attribute:int;channels:(string*int)list}
type result={path:string;returned:R.returned;reverse:reverse list;forward:forward list}
val supported_attribute : int -> unit
val supported_forward_cursor : int -> unit
val unary : R.flags -> int -> bool -> int * R.flags
val psw : R.flags -> int
val run : State.t -> entry:R.returned ->
 write:(site:int -> address:int -> value:int -> unit) ->
 push_psw:(a:int -> flags:int -> unit) ->
 call:(site:int -> operation:operation -> R.returned -> R.returned) -> result
