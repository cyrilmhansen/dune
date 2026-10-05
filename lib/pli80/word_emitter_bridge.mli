type operation=Mapped_word|Low|High
type t
type call={coordinate:string;site:int;resume:int;operation:operation}
type result=Word of Pli80_host.Mapped_word.result|Emission of Pli80_host.Word_emitter.selection * Pli80_host.Int_emitter.plan
type prepared={result:result;program:Runner.host_program;state:Runner.state_snapshot;
 logical_writes:(int*int)list;compatibility_writes:(int*int)list;residue_writers:(int*int*int)list}
val extent : operation -> int * int
val operation : int -> operation
val create : pli_com:bytes -> pli1:bytes -> t
val verify_call : t -> Native_dispatch.previous -> entry:Runner.state_snapshot -> call
val prepare : t -> call:call -> origin:Analysis.Execution_map.origin -> state:Runner.state_snapshot -> memory:bytes -> prepared
