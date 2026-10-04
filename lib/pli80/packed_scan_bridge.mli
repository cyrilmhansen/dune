(** Historical +7BBF ABI compatibility, separate from the native algorithm. *)
type t
type prepared = {
  result : Pli80_host.Packed_scan.result;
  memory : bytes;
  state : Runner.state_snapshot;
  compatibility_writes : (int * int) list;
}
val create : pli_com:bytes -> pli1:bytes -> t
val prepare : t -> origin:Analysis.Execution_map.origin ->
  state:Runner.state_snapshot -> memory:bytes -> prepared
val verify_call : before:Runner.state_snapshot -> after:Runner.state_snapshot ->
  I8080.Step.t -> entry:Runner.state_snapshot -> unit
