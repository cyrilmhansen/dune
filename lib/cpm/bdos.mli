(** Minimal CP/M 2.2 BDOS personality for one transient process. *)

type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }
  (* Runes model-limit diagnostic, not a CP/M BDOS return code. *)
  | Filesystem_model_limit of Filesystem.error

type t

val create : filesystem:Filesystem.t -> t
val filesystem : t -> Filesystem.t
val dma : t -> int
val current_drive : t -> int
val current_user : t -> int

val dispatch :
  runtime:t ->
  memory:I8080.Memory.t ->
  state:I8080.State.t ->
  output:(char -> unit) ->
  (action, error) result

(** Function 9 wraps in the 16-bit address space and examines at most 65536
    bytes. Function 2 emits E once. Functions 11 and 12 provide deterministic
    batch-console and CP/M 2.2 version behavior. Standard CP/M 2.2 functions
    not implemented here return [Unsupported_function]; numbers above the
    CP/M 2.2 BDOS range use its observed zero-return fallback. *)
