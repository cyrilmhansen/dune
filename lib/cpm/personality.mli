(** The CP/M userspace contract used to launch and run one transient process.

    Runes currently implements the deterministic CP/M 2.2 personality only.
    Historical CP/M Plus observations are reference evidence, not a second
    runtime personality. *)

type t = Cpm22

val cpm22 : t

type process

val warm_boot_address : t -> int
val bdos_entry_address : t -> int
val transient_stack_word_address : t -> int
val initial_stack_pointer : t -> int
val maximum_command_tail_length : t -> int

val load_bytes : t -> I8080.Memory.t -> bytes -> (Loader.loaded, Loader.error) result
val load_file : t -> I8080.Memory.t -> path:string -> (Loader.loaded, Loader.error) result
val entry_point : t -> Loader.loaded -> int

(** Install CP/M page zero and create the process's BDOS state. The memory is
    expected to contain the transient program already loaded by [load_bytes]
    or [load_file]. *)
val launch :
  t -> filesystem:Filesystem.t -> command_tail:bytes -> I8080.Memory.t -> process

val dispatch_with_effects :
  t ->
  process ->
  on_event:(Bdos.event -> unit) ->
  on_effect:(Bdos.external_effect -> unit) ->
  memory:I8080.Memory.t ->
  state:I8080.State.t ->
  output:(char -> unit) ->
  (Bdos.action, Bdos.error) result

val dispatch_with_file_events :
  t -> process -> on_event:(Bdos.event -> unit) -> on_file_event:(Bdos.file_event -> unit) ->
  on_effect:(Bdos.external_effect -> unit) -> memory:I8080.Memory.t -> state:I8080.State.t ->
  output:(char -> unit) -> (Bdos.action, Bdos.error) result
