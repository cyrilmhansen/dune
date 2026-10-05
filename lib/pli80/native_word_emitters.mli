module B=Word_emitter_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
 input:Runner.state_snapshot;output:Runner.state_snapshot;result:B.result;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list;
 residue_writers:(int*int*int)list;services:Runner.host_service list;
 entry_cells:(int*int)list;entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type validated
val record_summaries : validated -> (string * int * string) list
val cases : validated -> case list
val operation : case -> B.operation
val selected : B.operation -> validated -> case list
val shadow : Experiment.input -> (validated * Experiment.result,Experiment.error) result
val controller : ?exclude_entry_steps:int list -> B.operation -> validated -> Experiment.input -> Native_dispatch.t
val single : B.operation -> validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val hierarchical : validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val cumulative : validated -> Native_int_emitter.validated -> Native_attribute_auxiliary.validated -> Native_mapped_publication.validated -> Native_7c1b.validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
