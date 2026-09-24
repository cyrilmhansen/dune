(** Deterministic decoding of one instruction from a byte buffer. Offsets are
    indices into the supplied buffer, not 8080 addresses. *)

type encoding_status = Documented | Undocumented_alias | Uncertain of string

type opcode_info = { instruction_length : int; encoding_status : encoding_status }

type decoded = {
  opcode : int;
  instr : Instr.t;
  length : int;
  status : encoding_status;
}

type error =
  | Invalid_offset of int
  | Truncated of { opcode : int; required : int; available : int }

val opcode_info : int -> opcode_info
(** Return the instruction length and encoding classification for an opcode
    byte. Values outside [0..255] raise [Invalid_argument]. *)

val decode : bytes -> offset:int -> (decoded, error) result
(** Decode one instruction beginning at [offset]. If an opcode byte is present
    but its immediate bytes are missing, return [Error (Truncated _)]. An
    offset outside the buffer, including its end, returns [Error
    (Invalid_offset _)]. 16-bit immediates use low byte followed by high byte. *)
