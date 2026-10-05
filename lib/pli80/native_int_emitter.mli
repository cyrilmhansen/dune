type case={caller:string;entry_step:int;return_step:int;input:Runner.state_snapshot;output:Runner.state_snapshot;
 plan:Pli80_host.Int_emitter.plan;logical_writes:(int*int)list;compatibility_writes:(int*int)list;
 services:Runner.host_service list;entry_memory_sha256:string;post_memory_sha256:string;entry_dma:int;post_dma:int}
type validated
val cases : validated -> case list
val shadow : Experiment.input -> (validated * Experiment.result,Experiment.error) result
val single : validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val cumulative : validated -> Native_attribute_auxiliary.validated -> Native_mapped_publication.validated -> Native_7c1b.validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result

(** Source-bound child exclusions for proved native parent windows. *)
val controller : ?exclude_entry_steps:int list -> validated -> Experiment.input -> Native_dispatch.t
val compare_external : validated -> Experiment.result -> unit
