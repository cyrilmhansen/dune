module B=Range_processing_bridge
type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 prepared:B.prepared;services:Runner.host_service list;entry_cells:(int*int)list;
 entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type validated
val cases : validated -> case list
val record_summaries : validated -> (string * int * string) list
val shadow : Experiment.input -> (validated * Experiment.result,Experiment.error) result
val controller : ?exclude_entry_steps:int list -> validated -> Experiment.input -> Native_dispatch.t
val single : validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val cumulative : validated -> Native_word_emitters.validated -> Native_int_emitter.validated -> Native_attribute_auxiliary.validated -> Native_mapped_publication.validated -> Native_7c1b.validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result

val controllers : ?exclude_windows:(int * int) list -> validated -> Native_word_emitters.validated -> Native_int_emitter.validated -> Native_attribute_auxiliary.validated -> Native_mapped_publication.validated -> Native_7c1b.validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> Native_dispatch.t list
