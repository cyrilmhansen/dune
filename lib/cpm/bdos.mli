(** Minimal host-side CP/M BDOS services used by the first runner milestone. *)

type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }

val dispatch :
  memory:I8080.Memory.t ->
  state:I8080.State.t ->
  output:(char -> unit) ->
  (action, error) result
(** Dispatch the function number in C. Function 9 prints the '$'-terminated
    string at DE, wrapping through the 16-bit address space and examining at
    most 65536 bytes. *)
