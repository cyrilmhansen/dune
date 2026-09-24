(** A flat 64 KiB Intel 8080 address space. *)
type t

val size : int
(** The fixed memory size, 65536 bytes. *)

val create : unit -> t
(** [create ()] returns 65536 zero-filled bytes. *)

val read : t -> int -> int
(** Read one byte. Addresses outside [0x0000..0xffff] raise [Invalid_argument]. *)

val write : t -> int -> int -> unit
(** Write one byte. Invalid addresses or values outside [0..255] raise
    [Invalid_argument]; values are not silently masked. *)

val load : t -> address:int -> bytes -> unit
(** Copy [bytes] at [address]. The range must fit contiguously in memory;
    loads do not wrap at [0xffff]. *)

val read_range : t -> address:int -> length:int -> bytes
(** Return a copy of a contiguous memory range. *)

val read16 : t -> int -> int
(** Read a little-endian 16-bit value. The second byte address wraps from
    [0xffff] to [0x0000]. *)

val write16 : t -> int -> int -> unit
(** Write a little-endian 16-bit value. The second byte address wraps from
    [0xffff] to [0x0000]. Invalid addresses or values outside [0..65535]
    raise [Invalid_argument]. *)
