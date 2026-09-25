(** CP/M 2.2 File Control Block fields visible in guest memory. *)

type t

val at : I8080.Memory.t -> address:int -> t
val address : t -> int
val get : t -> offset:int -> int
val set : t -> offset:int -> int -> unit
val drive : t -> int
val set_drive : t -> int -> unit
val filename : t -> string
val extension : t -> string
(* Logical extent: EX's low five bits plus S2's low four module-number bits. *)
val extent : t -> int
val set_extent : t -> int -> unit
(* S2 module number occupies bits 0..3; bits 4..7 are preserved. *)
val module_number : t -> int
val set_module_number : t -> int -> unit
(* S2 bit 7, the CP/M 2 file-write flag. *)
val file_write_flag : t -> bool
val set_file_write_flag : t -> bool -> unit
val s1 : t -> int
val set_s1 : t -> int -> unit
val s2 : t -> int
val set_s2 : t -> int -> unit
val record_count : t -> int
val set_record_count : t -> int -> unit
val current_record : t -> int
val set_current_record : t -> int -> unit
val allocation : t -> bytes
val set_allocation : t -> bytes -> unit
val random_record : t -> int
val set_random_record : t -> int -> unit
