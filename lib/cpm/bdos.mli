(** Minimal CP/M 2.2 BDOS personality for one transient process. *)

type action = Continue | Terminate

type error =
  | Unsupported_function of int
  | Unterminated_string of { start_address : int; scanned : int }
  (* Runes model-limit diagnostic, not a CP/M BDOS return code. *)
  | Filesystem_model_limit of Filesystem.error

type event =
  | Read_record of {
      file : Filesystem.key;
      logical_record : int;
      dma : int;
      data : bytes;
    }
  | Write_record of {
      file : Filesystem.key;
      logical_record : int;
      dma : int;
      data : bytes;
    }

type register = A | B | C | D | E | H | L | SP
type memory_write_cause = Fcb_update
type external_effect =
  | Register_write of { register : register; value : int }
  | Memory_write of { address : int; value : int; cause : memory_write_cause }

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

val dispatch_instrumented :
  on_event:(event -> unit) ->
  runtime:t ->
  memory:I8080.Memory.t ->
  state:I8080.State.t ->
  output:(char -> unit) ->
  (action, error) result

val dispatch_with_effects :
  on_event:(event -> unit) ->
  on_effect:(external_effect -> unit) ->
  runtime:t -> memory:I8080.Memory.t -> state:I8080.State.t ->
  output:(char -> unit) -> (action, error) result

(** Like [dispatch_instrumented], with factual post-dispatch register writes
    and guest-visible FCB byte writes. These effects contain no analysis or
    provenance types. Successful record transfers remain [event] values. *)

(** Successful record transfers only. The event contains a copy of the 128
    bytes transferred, so observers may retain or mutate it safely. *)

(** Function 9 wraps in the 16-bit address space and examines at most 65536
    bytes. Function 2 emits E once. Functions 11 and 12 provide deterministic
    batch-console and CP/M 2.2 version behavior. Standard CP/M 2.2 functions
    not implemented here return [Unsupported_function]; numbers above the
    CP/M 2.2 BDOS range use its observed zero-return fallback. *)
