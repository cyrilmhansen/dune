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
type result = {
  run : Runner.run_result;
  console : string;
  filesystem : Cpm.Filesystem.t;
  rel_name : string;
  rel_bytes : bytes option;
  int_name : string;
  int_bytes : bytes option;
  execution_map : Analysis.Execution_map.t option;
  provenance : Analysis.Provenance.t option;
  timings : timings;
}

type error = Invalid_module_name of string | Filesystem_error of Cpm.Filesystem.error | Run_error of Runner.error

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
val run : analysis:analysis -> input -> (result, error) Stdlib.result
