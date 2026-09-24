(** Concrete Intel 8080 single-step execution. *)
type t

type error =
  | Decode_error of Decode.error
  | Unsupported_instruction of Decode.decoded
  | Bus_io_error of Bus.io_error
  | Cpu_halted

val create : state:State.t -> bus:Bus.t -> t
val is_halted : t -> bool
val step : t -> (Step.t, error) result
(** Executes one instruction. EI/DI remain explicitly unsupported until an
    interrupt model is defined; this failure preserves architectural state. *)
