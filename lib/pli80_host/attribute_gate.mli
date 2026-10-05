module R=Recursive_mapped
type operation=Input_process|Range_process|Gate
type result={route:string;input:int;discarded_high:int;packed:int option;rotated:int option;fresh_input:int option;returned:R.returned}
val gate : State.t -> entry:R.returned -> write:(site:int -> address:int -> value:int -> unit) -> call:(site:int -> operation:operation -> R.returned -> R.returned) -> result
val saved : State.t -> entry:R.returned -> write:(site:int -> address:int -> value:int -> unit) -> call:(site:int -> operation:operation -> R.returned -> R.returned) -> result
