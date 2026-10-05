module H=Pli80_host.Attribute_gate
type operation=Gate|Saved
type t
type call=private{coordinate:string;site:int;resume:int}
type write=Range_processing_bridge.write={address:int;value:int;writer:int;depth:int;kind:string}
type child={site:int;operation:H.operation;input:Runner.state_snapshot;output:Runner.state_snapshot}
type prepared={result:H.result;program:Runner.host_program;state:Runner.state_snapshot;journal:write list;children:child list;
 range:Range_processing_bridge.prepared option;input:Input_processing_bridge.prepared option;gate:prepared option;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
val create : pli_com:bytes -> pli1:bytes -> t
val bounds : operation -> int*int
val origin : string -> int -> Analysis.Execution_map.origin
val internal_call : t -> operation -> int -> call
val verify_call : t -> operation -> Native_dispatch.previous -> entry:Runner.state_snapshot -> call
val prepare : t -> operation -> call:call -> origin:Analysis.Execution_map.origin -> Runner.instruction_boundary -> prepared
