type instruction_source = Memory | Interrupt_acknowledge

type memory_access =
  | Read of { address : int; value : int }
  | Write of { address : int; value : int }

type control_flow =
  | Sequential
  | Jump of { target : int; taken : bool }
  | Call of { target : int; taken : bool }
  | Return of { target : int option; taken : bool }
  | Restart of { target : int }
  | Halt

type t = {
  source : instruction_source;
  pc_before : int;
  pc_after : int;
  decoded : Decode.decoded;
  fetched_bytes : bytes;
  memory_accesses : memory_access list;
  control_flow : control_flow;
}

let create ~source ~pc_before ~pc_after ~decoded ~fetched_bytes ~memory_accesses ~control_flow =
  {
    source;
    pc_before;
    pc_after;
    decoded;
    fetched_bytes = Bytes.copy fetched_bytes;
    memory_accesses;
    control_flow;
  }

let pc_before step = step.pc_before
let pc_after step = step.pc_after
let decoded step = step.decoded
let source step = step.source
let fetched_bytes step = Bytes.copy step.fetched_bytes
let memory_accesses step = step.memory_accesses
let control_flow step = step.control_flow
