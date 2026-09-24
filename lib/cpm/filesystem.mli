(** Deterministic, memory-backed CP/M 2.2 logical filesystem.  Files are
    keyed by zero-based drive and user number and transferred as 128-byte
    records; no physical allocation geometry is modeled. *)

type t
type key = { drive : int; user : int; name : string }

type error = Invalid_name of string | Invalid_drive of int | Invalid_user of int

val create : unit -> t
val canonical_name : string -> (string, error) result

val add_file :
  t -> ?drive:int -> ?user:int -> name:string -> bytes -> (unit, error) result

val get_file :
  t -> ?drive:int -> ?user:int -> name:string -> unit -> (bytes option, error) result

val list_files : t -> ?drive:int -> ?user:int -> unit -> string list

val delete : t -> key -> bool
val make : t -> key -> unit
val record_count : t -> key -> int option
val read_record : t -> key -> record:int -> bytes option
val write_record : t -> key -> record:int -> bytes -> unit

val key_of_fcb :
  memory:I8080.Memory.t -> fcb_address:int -> current_drive:int -> current_user:int ->
  (key, error) result

val key_of_name : drive:int -> user:int -> name:string -> (key, error) result
