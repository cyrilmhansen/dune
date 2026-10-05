module R=Recursive_mapped
type operation=Range_publish|Range_process|Emit|Control_read|Control_publish|Primary_read|Primary_publish|Secondary_read|Secondary_publish
type channel={name:string;predecessor:int;position:int;value:int}
type result={route:string;input:int;gate:int option;rotated_gate:int option;channels:channel list;emitted:int option;returned:R.returned}
val run : State.t -> entry:R.returned -> write:(site:int -> address:int -> value:int -> unit) -> call:(site:int -> operation:operation -> R.returned -> R.returned) -> result
