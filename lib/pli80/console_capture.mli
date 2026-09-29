type message = { text : string; first_step : int; last_step : int }
type t

val observed_messages : string list
val create : unit -> t
val emit : t -> step_index:int -> char -> unit
val text : t -> string
val messages : t -> message list
