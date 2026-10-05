(** Independent full-memory shadows and source-bound proof tokens for two
    explicitly established operations. The native algorithm uses current memory;
    oracle identity is confined to differential execution/compatibility. *)
module B=Publication_primitives_bridge
type case={caller:string;entry_step:int;return_step:int;parent_entry_step:int option;
  input:Runner.state_snapshot;output:Runner.state_snapshot;result:B.result;
  writes:Pli80_host.Mapped_lookup.write list;entry_scratch:(int*int)list;
  entry_memory_sha256:string;final_memory_sha256:string;logical_writes_sha256:string;
  compatibility_writes:(int*int)list}
type validated
val cases : validated -> case list
val mapped_words : validated -> case list
val secondary_bytes : validated -> case list
val record_summaries : validated -> (string * int * string) list
val shadow : Experiment.input -> (validated * Experiment.result,Experiment.error) result
val controller : ?exclude_entry_steps:int list -> B.operation -> validated -> Experiment.input -> Native_dispatch.t
val single : B.operation -> validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
val cumulative : validated -> Native_range_processing.validated -> Native_word_emitters.validated -> Native_int_emitter.validated -> Native_attribute_auxiliary.validated -> Native_mapped_publication.validated -> Native_7c1b.validated -> Native_7bbf.validated -> Native_7b7a.validated -> Experiment.input -> (int list * Experiment.result,Experiment.error) result
