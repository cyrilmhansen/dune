(** Owned value-semantic historical memory; no CPU/emulator dependency. *)
type t
val of_bytes : bytes -> t
val copy : t -> bytes
val read : t -> int -> int
val write : t -> int -> int -> unit
val word : t -> int -> int
