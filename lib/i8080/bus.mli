(** Concrete memory and I/O interface exposed to the 8080 CPU. *)
type t

type io_error =
  | Input_port_not_configured of int
  | Output_port_not_configured of int

val create :
  ?input:(port:int -> int) ->
  ?output:(port:int -> value:int -> unit) ->
  Memory.t ->
  t

val read_memory : t -> address:int -> int
val write_memory : t -> address:int -> value:int -> unit

val input : t -> port:int -> (int, io_error) result
(** Return an explicit error if no input handler is configured. Ports must be
    in [0..255], and configured handlers must return a byte. *)

val output : t -> port:int -> value:int -> (unit, io_error) result
(** Return an explicit error if no output handler is configured. Port numbers
    and values must be in [0..255]. *)
