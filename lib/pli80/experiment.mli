type analysis = Run | Execution | Data | Path
type report = No_report | Summary | Explorer

type input = {
  pli_com : bytes;
  pli0_ovl : bytes;
  pli1_ovl : bytes;
  pli2_ovl : bytes;
  source_name : string;
  source_bytes : bytes;
  module_name : string;
  command_tail : bytes;
  max_steps : int;
}

type timings = { setup_seconds : float; execution_seconds : float }
type file_event_operation = Open | Close | Make | Delete | Sequential_read | Sequential_write
type file_event = {
  step_index : int;
  operation : file_event_operation;
  file : Cpm.Filesystem.key;
  succeeded : bool;
  logical_record : int option;
  byte_range : (int * int) option;
}
type result = {
  run : Runner.run_result;
  console : string;
  console_messages : Console_capture.message list;
  file_events : file_event list;
  filesystem : Cpm.Filesystem.t;
  rel_name : string;
  rel_bytes : bytes option;
  int_name : string;
  int_bytes : bytes option;
  execution_map : Analysis.Execution_map.t option;
  provenance : Analysis.Provenance.t option;
  dynamic_structure : Analysis.Dynamic_structure.t option;
  dynamic_blocks : Analysis.Dynamic_blocks.report option;
  ownership_audit : Analysis.Ownership_audit.t option;
  event_witnesses : Analysis.Event_witness.t option;
  timings : timings;
}

type error = Invalid_module_name of string | Filesystem_error of Cpm.Filesystem.error
  | Run_error of Runner.error | Structure_requires_execution_map | Witnesses_require_execution_map | Interception_requires_execution_only

val analysis_name : analysis -> string
val parse_analysis : string -> (analysis, string) Stdlib.result
val report_name : report -> string
val parse_report : string -> (report, string) Stdlib.result
val parse_offset : string -> (int, string) Stdlib.result
val select_rel_offsets : ?requested:int list -> int -> (int list, string) Stdlib.result
val derive_module_name : string -> (string, error) Stdlib.result
val validate_module_name : string -> (string, error) Stdlib.result
val output_names : string -> ((string * string), error) Stdlib.result
val normalize_cpm_source : bytes -> bytes
val prepare_source : normalize:bool -> bytes -> bytes
val sha256_hex : bytes -> string

(** Read-only hooks preserve normal execution/capture behavior. Interception is
    limited to execution-only analysis without structure, witnesses or provenance;
    native writes to historical-image cells are rejected. Real guest Steps and
    host transitions remain distinct. Record observers receive BDOS transfer data. *)
val run : ?on_bdos_record:(step_index:int -> Cpm.Bdos.event -> unit) -> ?intercept:(origin:Analysis.Execution_map.origin -> step_index:int -> Runner.instruction_boundary -> Runner.instruction_action) -> ?on_guest_step:(step_index:int -> before:Runner.state_snapshot -> after:Runner.state_snapshot -> I8080.Step.t -> unit) -> ?on_before_instruction:(origin:Analysis.Execution_map.origin -> step_index:int -> Runner.instruction_boundary -> unit) -> ?structure:bool -> ?event_witnesses:bool -> analysis:analysis -> input -> (result, error) Stdlib.result
