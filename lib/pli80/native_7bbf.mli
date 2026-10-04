(** Bounded differential experiment. All historical invocations are independent. *)
type case = {
  entry_step : int; return_step : int; input : Runner.state_snapshot;
  output : Runner.state_snapshot; result : Pli80_host.Packed_scan.result;
  entry_memory_sha256 : string; final_memory_sha256 : string;
  logical_writes_sha256 : string;
  compatibility_writes : (int * int) list;
}

(** Unforgeable proof token containing all successful shadow cases and exact
    input identity; hybrid() rejects changed inputs or changed per-case state. *)
type validated
val cases : validated -> case list
val record_summaries : validated -> (string * int * string) list
val shadow : Experiment.input -> (validated * Experiment.result, Experiment.error) result

val hybrid : validated -> Experiment.input -> (int * Experiment.result, Experiment.error) result
