type t
type call={coordinate:string;site:int;resume:int;image:string;offset:int}
type prepared={plan:Pli80_host.Int_emitter.plan;program:Runner.host_program;state:Runner.state_snapshot;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list}
val create : pli_com:bytes -> pli1:bytes -> t
val verify_call : t -> Native_dispatch.previous -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> state:Runner.state_snapshot -> memory:bytes -> prepared
