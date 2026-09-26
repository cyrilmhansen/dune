(** Deterministic, human-readable Intel 8080 assembly formatting.
    This is presentation only and does not affect decoding or execution. *)

val format : Instr.t -> string
