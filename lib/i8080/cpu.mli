(** Concrete Intel 8080 single-step execution. *)
type t

type error =
  | Decode_error of Decode.error
  | Unsupported_instruction of Decode.decoded

val create : state:State.t -> bus:Bus.t -> t
val step : t -> (Step.t, error) result
