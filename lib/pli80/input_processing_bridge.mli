module H=Pli80_host.Input_processing
type t
type call=private{coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;children:child list;
 range:Range_processing_bridge.prepared option;publication:Range_publication_bridge.prepared option;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
val create : pli_com:bytes -> pli1:bytes -> t
val origin : string -> int -> Analysis.Execution_map.origin
val verify_call : t -> Native_dispatch.previous -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> Runner.instruction_boundary -> prepared
