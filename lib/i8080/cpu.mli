(** Concrete Intel 8080 single-step execution. *)
type t

type error =
  | Decode_error of Decode.error
  | Unsupported_instruction of Decode.decoded
  | Bus_io_error of Bus.io_error
  (** A supplied interrupt-acknowledge stream was not exactly one instruction. *)
  | Interrupt_acknowledge_length of {
      opcode : int option;
      required : int option;
      provided : int;
    }
  | Cpu_halted

val create : state:State.t -> bus:Bus.t -> t
val is_halted : t -> bool
val step : ?interrupt:bytes -> t -> (Step.t, error) result
(** Executes one instruction. [interrupt], when supplied, represents a
    caller-held request and its acknowledge byte stream. It is considered only
    when acceptance is enabled and not delayed by EI; otherwise it is neither
    validated nor consumed and a normal instruction is executed (or a halted
    CPU remains halted). An accepted payload must contain exactly one complete
    8080 instruction. *)
