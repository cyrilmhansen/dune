module R=Pli80_host.Recursive_mapped
module B=Recursive_mapped_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:R.result;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list;final_writers:B.residue list}
type validated
val cases : validated -> case list
val roots : validated -> case list
val shadow : Experiment.input -> (validated * Experiment.result,Experiment.error) result
val record_summaries : validated -> (string * int * string) list
val controller : ?exclude_entry_steps:int list -> validated -> Experiment.input -> Native_dispatch.t
val hybrid : validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val cumulative : validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result

val logical_write : I8080.Step.t -> Runner.state_snapshot -> int -> bool
