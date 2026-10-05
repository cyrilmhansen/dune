type t
type call=private{coordinate:string;runtime_site:int;resume:int}
type journal={address:int;value:int;writer:int;depth:int;kind:string}
type prepared={result:Pli80_host.Range_publication.result;writes:Pli80_host.Mapped_lookup.write list;
 journal:journal list;compatibility_writes:(int*int)list;memory:bytes;state:Runner.state_snapshot}
val create : pli1:bytes -> t
val verify_call : t -> origin:Analysis.Execution_map.origin -> before:Runner.state_snapshot -> after:Runner.state_snapshot -> I8080.Step.t -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> state:Runner.state_snapshot -> memory:bytes -> prepared
