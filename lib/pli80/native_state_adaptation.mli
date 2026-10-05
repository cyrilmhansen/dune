module B=State_adaptation_bridge
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 prepared:B.prepared;services:Runner.host_service list;entry_cells:(int*int)list;
 entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int;entry_filesystem_sha256:string;post_filesystem_sha256:string}
type validated
val cases : validated -> case list
val record_summaries : validated -> (string * int * string) list
val shadow : B.operation -> Experiment.input -> (validated * Experiment.result,Experiment.error) result
val controller : ?exclude_entry_steps:int list -> validated -> Experiment.input -> Native_dispatch.t
val single : validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result

val run : validated -> Experiment.input -> Native_dispatch.t list -> (int list * Experiment.result,Experiment.error) result
