(** Loader for flat CP/M .COM programs. *)

val load_address : int

type loaded = { entry_point : int; size : int }

type error =
  | Program_too_large of { size : int; maximum : int }
  | File_error of { path : string; message : string }

val load_bytes : I8080.Memory.t -> bytes -> (loaded, error) result
(** Load bytes contiguously at [0x0100]. Programs that would pass the end of
    memory are rejected instead of wrapping. *)

val load_file : I8080.Memory.t -> path:string -> (loaded, error) result
