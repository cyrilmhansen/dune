type case = {
  caller : string; entry_step : int; return_step : int;
  input : Runner.state_snapshot; output : Runner.state_snapshot;
  result : Pli80_host.Balance_scan.result;
  entry_memory_sha256 : string; final_memory_sha256 : string;
  logical_writes_sha256 : string; compatibility_writes : (int * int) list;
}
type validated
val cases : validated -> case list
val shadow : Experiment.input -> (validated * Experiment.result, Experiment.error) result

val record_summaries : validated -> (string * int * string) list
val controller : validated -> Experiment.input -> Native_dispatch.t
val hybrid : validated -> Experiment.input -> (int * Experiment.result, Experiment.error) result
val cumulative : validated -> Native_7bbf.validated -> Experiment.input -> ((int * int) * Experiment.result, Experiment.error) result
