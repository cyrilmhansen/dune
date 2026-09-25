[@@@warning "-69"]
[@@@warning "-40-41-42"]
[@@@warning "-4-43"]

type node_id = int
type edge_role = Value | Address | Flag | Control
type producer_origin = { image : Cpm.Filesystem.key; offset : int; runtime_pc : int }
type origin_resolver = pc:int -> fetched:bytes -> producer_origin option
type initial_class = System | Runner | Unclassified
type source =
  | File_byte of { file : Cpm.Filesystem.key; offset : int; value : int }
  | Command_tail_byte of { offset : int; value : int }
  | Initial_memory_byte of { address : int; value : int; class_ : initial_class }
  | Initial_register of { register : string; value : int }
  | External_result of { subsystem : string; operation : string; value : int }
type node_kind = Source of source | Operation of string
type node = {
  id : node_id; kind : node_kind; value : int; width : int;
  step_index : int option; origin : producer_origin option;
  inputs : (edge_role * node_id) list;
}
type root = Untracked | Node of node_id
type output_observation = {
  file : Cpm.Filesystem.key; offset : int; value : int;
  write_step_index : int; root : root;
}
type branch_observation = {
  step_index : int; pc : int; condition : I8080.Instr.condition;
  taken : bool; target : int option; flag_inputs : root list;
}
type slice = { roots : root list; nodes : node list }
type source_group =
  | File_input of Cpm.Filesystem.key
  | Command_tail_input
  | Initial_memory_input of initial_class
  | Initial_register_input of string
  | External_input of string * string
type source_summary = { group : source_group; distinct_bytes : int }
type error = Concrete_mismatch of {
  step_index : int; instruction : string; location : string;
  predicted : int; concrete : int;
}
exception Provenance_error of error

type cell = { mutable value : int; mutable root : root }
type access = { address : int; value : int }

(* The public DAG is unchanged, but its physical representation is columnar.
   Fixed-size Bigarray chunks avoid a boxed OCaml record/option/variant per
   node and avoid copying multi-million-element arrays when growing. *)
open Bigarray

let node_chunk_size = 32_768
let edge_chunk_size = 262_144

type node_chunk = {
  tags : (int, int8_unsigned_elt, c_layout) Array1.t;
  values : (int, int16_unsigned_elt, c_layout) Array1.t;
  widths : (int, int8_unsigned_elt, c_layout) Array1.t;
  steps : (int64, int64_elt, c_layout) Array1.t;
  origin_images : (int32, int32_elt, c_layout) Array1.t;
  origin_offsets : (int32, int32_elt, c_layout) Array1.t;
  runtime_pcs : (int, int16_unsigned_elt, c_layout) Array1.t;
  payloads : (int32, int32_elt, c_layout) Array1.t;
  edge_starts : (int32, int32_elt, c_layout) Array1.t;
  edge_lengths : (int32, int32_elt, c_layout) Array1.t;
}

type edge_chunk = {
  roles : (int, int8_unsigned_elt, c_layout) Array1.t;
  targets : (int32, int32_elt, c_layout) Array1.t;
}

type source_identity =
  | Source_file of int
  | Source_command_tail
  | Source_initial_memory of initial_class
  | Source_initial_register of string
  | Source_external of string * string

type t = {
  mutable node_chunks : node_chunk option array;
  mutable used : int;
  mutable edges : int;
  mutable edge_chunks : edge_chunk option array;
  operation_ids : (string, int) Hashtbl.t;
  mutable operation_names : string array;
  mutable operation_count : int;
  mutable image_keys : Cpm.Filesystem.key option array;
  mutable image_count : int;
  image_ids : (Cpm.Filesystem.key, int) Hashtbl.t;
  mutable source_identities : source_identity option array;
  mutable source_count : int;
  source_ids : (source_identity, int) Hashtbl.t;
  memory : cell array;
  regs : cell array;
  flags : cell array;
  outputs : ((Cpm.Filesystem.key * int), output_observation list) Hashtbl.t;
  mutable branches_rev : branch_observation list;
}

let create () =
  { node_chunks = [||]; used = 0; edges = 0; edge_chunks = [||];
    operation_ids = Hashtbl.create 32; operation_names = Array.make 32 "";
    operation_count = 0;
    image_keys = [||]; image_count = 0; image_ids = Hashtbl.create 16;
    source_identities = [||]; source_count = 0; source_ids = Hashtbl.create 32;
    memory = Array.init 65536 (fun _ -> { value = 0; root = Untracked });
    regs = Array.init 8 (fun _ -> { value = 0; root = Untracked });
    flags = Array.init 5 (fun _ -> { value = 0; root = Untracked });
    outputs = Hashtbl.create 4093; branches_rev = [] }

let intern_operation p name =
  match Hashtbl.find_opt p.operation_ids name with
  | Some id -> id
  | None ->
      if p.operation_count = Array.length p.operation_names then (
        let grown = Array.make (2 * p.operation_count) "" in
        Array.blit p.operation_names 0 grown 0 p.operation_count;
        p.operation_names <- grown);
      let id = p.operation_count in
      p.operation_count <- id + 1;
      p.operation_names.(id) <- name;
      Hashtbl.add p.operation_ids name id;
      id

let create_node_chunk () = {
  tags=Array1.create int8_unsigned c_layout node_chunk_size;
  values=Array1.create int16_unsigned c_layout node_chunk_size;
  widths=Array1.create int8_unsigned c_layout node_chunk_size;
  steps=Array1.create int64 c_layout node_chunk_size;
  origin_images=Array1.create int32 c_layout node_chunk_size;
  origin_offsets=Array1.create int32 c_layout node_chunk_size;
  runtime_pcs=Array1.create int16_unsigned c_layout node_chunk_size;
  payloads=Array1.create int32 c_layout node_chunk_size;
  edge_starts=Array1.create int32 c_layout node_chunk_size;
  edge_lengths=Array1.create int32 c_layout node_chunk_size;
}

let create_edge_chunk () = {
  roles=Array1.create int8_unsigned c_layout edge_chunk_size;
  targets=Array1.create int32 c_layout edge_chunk_size;
}

let grow_option_array xs =
  let next=Array.make (max 1 (2*Array.length xs)) None in
  Array.blit xs 0 next 0 (Array.length xs);next

let node_chunk p id =
  let i=id/node_chunk_size in
  if i>=Array.length p.node_chunks then p.node_chunks<-grow_option_array p.node_chunks;
  match p.node_chunks.(i) with
  |Some chunk->chunk
  |None->let chunk=create_node_chunk() in p.node_chunks.(i)<-Some chunk;chunk

let edge_chunk p id =
  let i=id/edge_chunk_size in
  if i>=Array.length p.edge_chunks then p.edge_chunks<-grow_option_array p.edge_chunks;
  match p.edge_chunks.(i) with
  |Some chunk->chunk
  |None->let chunk=create_edge_chunk() in p.edge_chunks.(i)<-Some chunk;chunk

let intern_image p image =
  match Hashtbl.find_opt p.image_ids image with
  |Some id->id
  |None->
      if p.image_count=Array.length p.image_keys then (
        let next=Array.make (max 4 (2*Array.length p.image_keys)) None in
        Array.blit p.image_keys 0 next 0 p.image_count;p.image_keys<-next);
      let id=p.image_count in p.image_count<-id+1;
      p.image_keys.(id)<-Some image;Hashtbl.add p.image_ids image id;id

let intern_source_identity p identity =
  match Hashtbl.find_opt p.source_ids identity with
  |Some id->id
  |None->
      if p.source_count=Array.length p.source_identities then (
        let next=Array.make (max 4 (2*Array.length p.source_identities)) None in
        Array.blit p.source_identities 0 next 0 p.source_count;p.source_identities<-next);
      let id=p.source_count in p.source_count<-id+1;
      p.source_identities.(id)<-Some identity;Hashtbl.add p.source_ids identity id;id

let pack_source p = function
  |File_byte {file;offset;_}->0,intern_source_identity p (Source_file(intern_image p file)),offset
  |Command_tail_byte {offset;_}->1,intern_source_identity p Source_command_tail,offset
  |Initial_memory_byte {address;class_;_}->2,intern_source_identity p (Source_initial_memory class_),address
  |Initial_register {register;_}->3,intern_source_identity p (Source_initial_register register),0
  |External_result {subsystem;operation;_}->4,intern_source_identity p (Source_external(subsystem,operation)),0

let add_node p ~kind ~value ~width ?step_index ?origin inputs =
  let id = p.used in
  if id>=Int32.to_int Int32.max_int then invalid_arg "Provenance: node id exceeds compact arena range";
  let step=Option.fold ~none:Int64.minus_one ~some:Int64.of_int step_index in
  let tag,payload,stored_offset=match kind with
    |Operation name->5,intern_operation p name,0
    |Source source->let tag,id,offset=pack_source p source in tag,id,offset in
  let origin_image,origin_offset,runtime_pc=match origin with
    |None->Int32.minus_one,Int32.of_int stored_offset,0
    |Some (o:producer_origin)->
        if o.offset<0 || Int64.of_int o.offset>Int64.of_int32 Int32.max_int then invalid_arg "Provenance: origin offset exceeds compact arena range";
        Int32.of_int(intern_image p o.image),Int32.of_int o.offset,o.runtime_pc land 0xffff in
  let chunk=node_chunk p id and slot=id mod node_chunk_size in
  Array1.set chunk.tags slot tag;Array1.set chunk.values slot (value land 0xffff);
  Array1.set chunk.widths slot width;Array1.set chunk.steps slot step;
  Array1.set chunk.origin_images slot origin_image;Array1.set chunk.origin_offsets slot origin_offset;
  Array1.set chunk.runtime_pcs slot runtime_pc;Array1.set chunk.payloads slot (Int32.of_int payload);
  let edge_start=p.edges in
  p.used <- p.used + 1;
  let edge_length=List.length inputs in
  if p.edges>Int32.to_int Int32.max_int-edge_length then
    invalid_arg "Provenance: edge index exceeds compact arena range";
  List.iter(fun(role,target)->
    if target<0 || target>=p.used then invalid_arg "Provenance: edge target is not an existing node";
    let chunk=edge_chunk p p.edges and slot=p.edges mod edge_chunk_size in
    let role=match role with Value->0|Address->1|Flag->2|Control->3 in
    Array1.set chunk.roles slot role;Array1.set chunk.targets slot (Int32.of_int target);p.edges<-p.edges+1)inputs;
  Array1.set chunk.edge_starts slot (Int32.of_int edge_start);
  Array1.set chunk.edge_lengths slot (Int32.of_int edge_length);
  Node id

let source p source value width = add_node p ~kind:(Source source) ~value ~width []
let root_node = function Untracked -> [] | Node id -> [ id ]
let edges role roots = List.concat_map (fun root -> List.map (fun id -> role, id) (root_node root)) roots
let op p ~name ~value ~width ~step_index ~origin inputs =
  add_node p ~kind:(Operation name) ~value ~width ~step_index ?origin inputs

let seed_file p ~image ~runtime_base data =
  if runtime_base < 0 || runtime_base >= 65536 || Bytes.length data > 65536 then
    invalid_arg "Provenance.seed_image";
  for i = 0 to Bytes.length data - 1 do
    let value = Char.code (Bytes.get data i) in
    let root = source p (File_byte { file = image; offset = i; value }) value 8 in
    let dst = p.memory.((runtime_base + i) land 0xffff) in
    dst.value <- value; dst.root <- root
  done

let seed_image = seed_file

let seed_memory p ~class_ ~address data =
  if address < 0 || address >= 65536 || Bytes.length data > 65536 then
    invalid_arg "Provenance.seed_memory";
  for i = 0 to Bytes.length data - 1 do
    let value = Char.code (Bytes.get data i) in
    let root = source p (Initial_memory_byte { address = (address + i) land 0xffff; value; class_ }) value 8 in
    let dst = p.memory.((address + i) land 0xffff) in dst.value <- value; dst.root <- root
  done

let seed_command_tail p ~address data =
  for i = 0 to Bytes.length data - 1 do
    let value = Char.code (Bytes.get data i) in
    let root = source p (Command_tail_byte { offset = i; value }) value 8 in
    let dst = p.memory.((address + i) land 0xffff) in dst.value <- value; dst.root <- root
  done

let seed_command_tail_mapping p ~address ~tail_offset data =
  if address < 0 || address >= 65536 || tail_offset < 0 then invalid_arg "Provenance.seed_command_tail_mapping";
  for i = 0 to Bytes.length data - 1 do
    let value = Char.code (Bytes.get data i) in
    let root = source p (Command_tail_byte { offset = tail_offset+i; value }) value 8 in
    let dst = p.memory.((address+i)land 0xffff) in dst.value<-value;dst.root<-root
  done

let register_names = [| "A"; "B"; "C"; "D"; "E"; "H"; "L"; "SP" |]
let seed_initial_registers p (s : Runner.state_snapshot) =
  let values = [|s.a;s.b;s.c;s.d;s.e;s.h;s.l;s.sp|] in
  Array.iteri (fun i value -> p.regs.(i).value <- value;
    p.regs.(i).root <- source p (Initial_register { register = register_names.(i); value }) value (if i=7 then 16 else 8)) values;
  let flags = [|s.sign;s.zero;s.auxiliary_carry;s.parity;s.carry|] in
  let names = [|"S";"Z";"AC";"P";"CY"|] in
  Array.iteri (fun i flag -> let value = if flag then 1 else 0 in
    p.flags.(i).value <- value;
    p.flags.(i).root <- source p (Initial_register { register = names.(i); value }) value 1) flags

let reg_index = function
  | I8080.Instr.A -> 0 | B -> 1 | C -> 2 | D -> 3 | E -> 4 | H -> 5 | L -> 6
let flag_names = [|"S";"Z";"AC";"P";"CY"|]
let flag_index = function `S -> 0 | `Z -> 1 | `AC -> 2 | `P -> 3 | `CY -> 4
let bool_int x = if x then 1 else 0
let flag_snapshot (s : Runner.state_snapshot) =
  [|bool_int s.sign; bool_int s.zero; bool_int s.auxiliary_carry; bool_int s.parity; bool_int s.carry|]
let reg_snapshot (s : Runner.state_snapshot) = [|s.a;s.b;s.c;s.d;s.e;s.h;s.l;s.sp|]

let instruction_label (step : I8080.Step.t) =
  Printf.sprintf "opcode %02X" (I8080.Step.decoded step).I8080.Decode.opcode

let producer_origin step origin_at fetched =
  match I8080.Step.source step, origin_at with
  | I8080.Step.Memory, Some resolve -> resolve ~pc:(I8080.Step.pc_before step) ~fetched
  | _ -> None

let materialize_initial p ~step_index ~instruction ~address ~value =
  let address = address land 0xffff in
  let cell = p.memory.(address) in
  if cell.root = Untracked then (
    let root = source p (Initial_memory_byte { address; value; class_ = Unclassified }) value 8 in
    cell.value <- value; cell.root <- root);
  if cell.value<>value then
    raise(Provenance_error(Concrete_mismatch {step_index;instruction;location=Printf.sprintf "memory[%04X]" address;predicted=cell.value;concrete=value}));
  cell.root

let get_pair_inputs p pair =
  let open I8080.Instr in
  match pair with
  | BC -> [p.regs.(1);p.regs.(2)] | DE -> [p.regs.(3);p.regs.(4)]
  | HL -> [p.regs.(5);p.regs.(6)] | SP -> [p.regs.(7)]
let pair_value p pair = match pair with
  | I8080.Instr.SP -> p.regs.(7).value
  | _ -> List.fold_left (fun acc (c : cell) -> (acc lsl 8) lor (c.value land 255)) 0 (get_pair_inputs p pair)
let set_pair p pair value root =
  let open I8080.Instr in
  match pair with
  | BC -> p.regs.(1).value <- (value lsr 8) land 255; p.regs.(1).root <- root;
          p.regs.(2).value <- value land 255; p.regs.(2).root <- root
  | DE -> p.regs.(3).value <- (value lsr 8) land 255; p.regs.(3).root <- root;
          p.regs.(4).value <- value land 255; p.regs.(4).root <- root
  | HL -> p.regs.(5).value <- (value lsr 8) land 255; p.regs.(5).root <- root;
          p.regs.(6).value <- value land 255; p.regs.(6).root <- root
  | SP -> p.regs.(7).value <- value land 0xffff; p.regs.(7).root <- root

let set_pair_parts p pair value ~name ~step_index ~origin ~high_inputs ~low_inputs =
  let high=(value lsr 8)land 255 and low=value land 255 in
  let root name value inputs = op p ~name ~value ~width:8 ~step_index ~origin inputs in
  match pair with
  | I8080.Instr.BC -> p.regs.(1).value<-high;p.regs.(1).root<-root (name^".high") high high_inputs;
      p.regs.(2).value<-low;p.regs.(2).root<-root (name^".low") low low_inputs
  | DE -> p.regs.(3).value<-high;p.regs.(3).root<-root (name^".high") high high_inputs;
      p.regs.(4).value<-low;p.regs.(4).root<-root (name^".low") low low_inputs
  | HL -> p.regs.(5).value<-high;p.regs.(5).root<-root (name^".high") high high_inputs;
      p.regs.(6).value<-low;p.regs.(6).root<-root (name^".low") low low_inputs
  | SP -> p.regs.(7).value<-value land 0xffff;p.regs.(7).root<-root (name^".word") (value land 0xffff) high_inputs

let address_roots_for_hl p = [p.regs.(5).root;p.regs.(6).root]
let address_roots_for_pair p = function
  | I8080.Instr.Indirect_BC -> [p.regs.(1).root;p.regs.(2).root]
  | Indirect_DE -> [p.regs.(3).root;p.regs.(4).root]

let create_operation p ~name ~value ~width ~step_index ~origin inputs =
  op p ~name ~value ~width ~step_index ~origin inputs

let read_cell p ~instruction step_index origin address concrete =
  let root = materialize_initial p ~step_index ~instruction ~address ~value:concrete in
  let loaded = create_operation p ~name:"Load8" ~value:concrete ~width:8 ~step_index ~origin
      (edges Value [root]) in
  loaded

let write_cell p ~address ~value ~root =
  let dst = p.memory.(address land 0xffff) in dst.value <- value land 255; dst.root <- root

let origin_inputs p ~step_index ~instruction pc size fetched =
  List.init size (fun i ->
    let address = (pc + i) land 0xffff in
    let value = Char.code (Bytes.get fetched i) in
    materialize_initial p ~step_index ~instruction ~address ~value)

let set_flag_op p ~step_index ~origin ~name ~value inputs index =
  let root = create_operation p ~name ~value ~width:1 ~step_index ~origin inputs in
  p.flags.(index).value <- value; p.flags.(index).root <- root

let observe_step ?origin_at p ~step_index (after : Runner.state_snapshot) step =
  let decoded = (I8080.Step.decoded step).I8080.Decode.instr in
  let fetched = I8080.Step.fetched_bytes step in
  let pc = I8080.Step.pc_before step in
  let origin = producer_origin step origin_at fetched in
  let label = instruction_label step in
  let conditional = match decoded with
    | I8080.Instr.Jump (Some condition, _) | I8080.Instr.Call (Some condition, _) | I8080.Instr.Return (Some condition) -> Some condition
    | _ -> None in
  (match conditional, I8080.Step.control_flow step with
   | Some condition, (I8080.Step.Jump {target;taken} | I8080.Step.Call {target;taken}) ->
       let index=match condition with
         | Not_zero | Zero -> 1 | Not_carry | Carry -> 4
         | Parity_odd | Parity_even -> 3 | Positive | Minus -> 0 in
       p.branches_rev <- {step_index;pc;condition;taken;target=Some target;
         flag_inputs=[p.flags.(index).root]} :: p.branches_rev
   | Some condition, I8080.Step.Return {target;taken} ->
       let index=match condition with
         | Not_zero | Zero -> 1 | Not_carry | Carry -> 4
         | Parity_odd | Parity_even -> 3 | Positive | Minus -> 0 in
       p.branches_rev <- {step_index;pc;condition;taken;target;flag_inputs=[p.flags.(index).root]} :: p.branches_rev
   | _ -> ());
  let immediates =
    if I8080.Step.source step = I8080.Step.Interrupt_acknowledge then
      List.init (Bytes.length fetched) (fun i -> let value=Char.code(Bytes.get fetched i) in
        source p (External_result {subsystem="8080 interrupt acknowledge";operation="instruction byte";value}) value 8)
    else origin_inputs p ~step_index ~instruction:label pc (Bytes.length fetched) fetched
  in
  let imm i = try List.nth immediates i with _ -> Untracked in
  let accesses = I8080.Step.memory_accesses step in
  let reads = List.filter_map (function I8080.Step.Read {address;value} -> Some {address;value} | _ -> None) accesses in
  let writes = List.filter_map (function I8080.Step.Write {address;value} -> Some {address;value} | _ -> None) accesses in
  let read_index = ref 0 and write_index = ref 0 in
  let read_next () =
    match List.nth_opt reads !read_index with
    | None -> failwith "Provenance: Step missing expected memory read"
    | Some r -> incr read_index; r
  in
  let write_next () =
    match List.nth_opt writes !write_index with
    | None -> failwith "Provenance: Step missing expected memory write"
    | Some w -> incr write_index; w
  in
  let store_access (w : access) predicted root =
    if (w.value land 255) <> (predicted land 255) then
      raise (Provenance_error (Concrete_mismatch { step_index; instruction=label;
        location=Printf.sprintf "memory[%04X]" w.address;
        predicted=predicted land 255; concrete=w.value land 255 }));
    write_cell p ~address:w.address ~value:w.value ~root
  in
  let assign_reg index value root = p.regs.(index).value <- value land 255; p.regs.(index).root <- root in
  let assign_pair pair value root = set_pair p pair value root in
  let op_root name value width inputs = create_operation p ~name ~value ~width ~step_index ~origin inputs in
  let observed_flags = flag_snapshot after in
  let set_flag_checked name index value inputs =
    let value = value land 1 in
    if observed_flags.(index) <> value then
      raise (Provenance_error (Concrete_mismatch {step_index;instruction=label;
        location=flag_names.(index);predicted=value;concrete=observed_flags.(index)}));
    set_flag_op p ~step_index ~origin ~name ~value inputs index
  in
  let szp value =
    let rec ones x n = if x=0 then n else ones (x land (x-1)) (n+1) in
    (value land 0x80) lsr 7, bool_int (value land 255=0), bool_int (ones (value land 255) 0 mod 2=0)
  in
  let reg_input idx = p.regs.(idx).root in
  let pair_roots pair = List.map (fun c -> c.root) (get_pair_inputs p pair) in
  let result8 = ref None in
  let flags_written = ref false in
  let arithmetic name inputs writes_a preserve_a =
    let a = p.regs.(0).value and b = match inputs with (v,_)::_ -> v | [] -> 0 in
    let cin = if name="ADC" || name="SBB" then p.flags.(4).value else 0 in
    let result, carry, ac =
      match name with
      | "ADD" | "ADC" -> let sum=a+b+cin in sum land 255, sum>255, (a land 15)+(b land 15)+cin>15
      | "SUB" | "SBB" | "CMP" ->
          let sub=b+cin in
          let ac=((a land 15)+((b lxor 255) land 15)+(1-cin))>15 in
          (a-sub) land 255, a<sub, ac
      | "ANA" -> a land b, false, (a lor b) land 8 <> 0
      | "XRA" -> a lxor b, false, false
      | "ORA" -> a lor b, false, false
      | _ -> assert false
    in
    let input_roots = [reg_input 0] @ List.map snd inputs in
    let input_edges = edges Value input_roots @ (if name="ADC" || name="SBB" then edges Flag [p.flags.(4).root] else []) in
    let op_name = "ALU." ^ name in
    let result_root = op_root op_name result 8 input_edges in
    result8 := Some result;
    if writes_a then assign_reg 0 result result_root;
    if not preserve_a then ();
    let sign,zero,parity=szp result in
    set_flag_checked (op_name^".S") 0 sign input_edges;
    set_flag_checked (op_name^".Z") 1 zero input_edges;
    set_flag_checked (op_name^".AC") 2 (bool_int ac) input_edges;
    set_flag_checked (op_name^".P") 3 parity input_edges;
    set_flag_checked (op_name^".CY") 4 (bool_int carry) input_edges;
    flags_written := true
  in
  let cond_roots () = List.map (fun c->c.root) (Array.to_list p.flags) in
  let address_immediate = edges Address [imm 1; imm 2] in
  let stack_address_roots = [p.regs.(7).root] in
  let sequential_pc = if I8080.Step.source step=I8080.Step.Interrupt_acknowledge then pc
      else (pc + Bytes.length fetched) land 0xffff in
  let load_register_or_memory = function
    | I8080.Instr.Register r -> let c=p.regs.(reg_index r) in c.value,c.root
    | I8080.Instr.Memory_at_HL ->
        let r=read_next () in
        let loaded=read_cell p ~instruction:label step_index origin r.address r.value in
        r.value,op_root "Load.M" r.value 8 (edges Value [loaded] @ edges Address (address_roots_for_hl p))
  in
  let store_register_or_memory dest value root = match dest with
    | I8080.Instr.Register r -> assign_reg (reg_index r) value root
    | I8080.Instr.Memory_at_HL ->
        let w=write_next () in
        let addr=address_roots_for_hl p in
        let store=op_root "Store8" value 8 (edges Value [root] @ edges Address addr) in
        if w.value <> value then raise (Provenance_error (Concrete_mismatch {step_index;instruction=label;location="memory store";predicted=value;concrete=w.value}));
        store_access w value store
  in
  let unary_update incr_ dest =
    let old,root=load_register_or_memory dest in
    let value=if incr_ then (old+1) land 255 else (old-1) land 255 in
    let name=if incr_ then "INR" else "DCR" in
    let inputs=edges Value [root] in
    let newroot=op_root name value 8 inputs in
    store_register_or_memory dest value newroot;
    let sign,zero,parity=szp value in
    set_flag_checked (name^".S") 0 sign inputs;
    set_flag_checked (name^".Z") 1 zero inputs;
    set_flag_checked (name^".AC") 2 (bool_int (if incr_ then old land 15=15 else old land 15<>0)) inputs;
    set_flag_checked (name^".P") 3 parity inputs;
    flags_written:=true
  in
  (match decoded with
  | Nop | Ei | Di | Hlt -> ()
  | Mov (dst,src) -> let value,root=load_register_or_memory src in store_register_or_memory dst value root
  | Mvi (dst,value) ->
      let root=op_root "MVI" value 8 (edges Value [imm 1]) in
      store_register_or_memory dst value root
  | Lxi (pair,value) ->
      (match pair with
       | I8080.Instr.BC -> assign_reg 1 ((value lsr 8)land 255) (op_root "LXI.high" ((value lsr 8)land 255) 8 (edges Value [imm 2])); assign_reg 2 (value land 255) (op_root "LXI.low" (value land 255) 8 (edges Value [imm 1]))
       | DE -> assign_reg 3 ((value lsr 8)land 255) (op_root "LXI.high" ((value lsr 8)land 255) 8 (edges Value [imm 2])); assign_reg 4 (value land 255) (op_root "LXI.low" (value land 255) 8 (edges Value [imm 1]))
       | HL -> assign_reg 5 ((value lsr 8)land 255) (op_root "LXI.high" ((value lsr 8)land 255) 8 (edges Value [imm 2])); assign_reg 6 (value land 255) (op_root "LXI.low" (value land 255) 8 (edges Value [imm 1]))
       | SP -> assign_pair SP value (op_root "LXI.SP" value 16 (edges Value [imm 1;imm 2])))
  | Ldax pair ->
      let addr=pair_value p (match pair with Indirect_BC->BC|Indirect_DE->DE) in
      let value,root=(let r=read_next() in r.value,read_cell p ~instruction:label step_index origin r.address r.value) in
      let root=op_root "LDAX" value 8 (edges Value [root] @ edges Address (address_roots_for_pair p pair)) in assign_reg 0 value root; ignore addr
  | Stax pair ->
      let value,vr= p.regs.(0).value,p.regs.(0).root in
      let w=write_next() in let root=op_root "STAX" value 8 (edges Value [vr] @ edges Address (address_roots_for_pair p pair)) in
      store_access w value root
  | Lda _ -> let v,r= (let rr=read_next() in rr.value,read_cell p ~instruction:label step_index origin rr.address rr.value) in
      assign_reg 0 v (op_root "LDA" v 8 (edges Value [r] @ address_immediate))
  | Sta _ -> let w=write_next() in let root=op_root "STA" p.regs.(0).value 8 (edges Value [p.regs.(0).root] @ address_immediate) in store_access w p.regs.(0).value root
  | Lhld _ ->
      let lo=read_next() in let hi=read_next() in
      let lr=read_cell p ~instruction:label step_index origin lo.address lo.value in
      let hr=read_cell p ~instruction:label step_index origin hi.address hi.value in
      assign_reg 6 lo.value (op_root "LHLD.L" lo.value 8 (edges Value [lr]@address_immediate));
      assign_reg 5 hi.value (op_root "LHLD.H" hi.value 8 (edges Value [hr]@address_immediate))
  | Shld _ ->
      let l=write_next() in let h=write_next() in
      store_access l p.regs.(6).value (op_root "SHLD.L" l.value 8 (edges Value [p.regs.(6).root]@address_immediate));
      store_access h p.regs.(5).value (op_root "SHLD.H" h.value 8 (edges Value [p.regs.(5).root]@address_immediate))
  | Inr x -> unary_update true x | Dcr x -> unary_update false x
  | Inx pair | Dcx pair as instruction ->
      let old=pair_value p pair in let inc=match instruction with Inx _->true|_->false in
      let v=(if inc then old+1 else old-1) land 0xffff in
      set_pair_parts p pair v ~name:(if inc then "INX" else "DCX") ~step_index ~origin
        ~low_inputs:(edges Value [List.hd (List.rev (pair_roots pair))])
        ~high_inputs:(edges Value (pair_roots pair))
  | Dad pair ->
      let a=pair_value p HL and b=pair_value p pair in let sum=a+b in
      let value=sum land 0xffff in let inputs=edges Value (pair_roots HL @ pair_roots pair) in
      let pair_byte_roots pair = match pair with
        | I8080.Instr.BC -> p.regs.(1).root,p.regs.(2).root
        | DE -> p.regs.(3).root,p.regs.(4).root
        | HL -> p.regs.(5).root,p.regs.(6).root
        | SP -> p.regs.(7).root,p.regs.(7).root in
      let ah,al=pair_byte_roots HL and bh,bl=pair_byte_roots pair in
      set_pair_parts p HL value ~name:"DAD" ~step_index ~origin
        ~low_inputs:(edges Value [al;bl])
        ~high_inputs:(edges Value [ah;al;bh;bl]);
      set_flag_checked "DAD.CY" 4 (bool_int (sum>0xffff)) inputs; flags_written:=true
  | Alu (operation,source_) ->
      let value,root=load_register_or_memory source_ in
      let name=match operation with Add->"ADD"|Add_with_carry->"ADC"|Subtract->"SUB"|Subtract_with_borrow->"SBB"|And->"ANA"|Xor->"XRA"|Or->"ORA"|Compare->"CMP" in
      arithmetic name [value,root] (operation<>Compare) (operation=Compare)
  | Alu_immediate (operation,value) ->
      let name=match operation with Add->"ADD"|Add_with_carry->"ADC"|Subtract->"SUB"|Subtract_with_borrow->"SBB"|And->"ANA"|Xor->"XRA"|Or->"ORA"|Compare->"CMP" in
      arithmetic name [value,imm 1] (operation<>Compare) (operation=Compare)
  | Rotate rotation ->
      let a=p.regs.(0).value and cin=p.flags.(4).value in
      let value,carry=match rotation with
       | Rotate_left -> ((a lsl 1) lor (a lsr 7)) land 255,a lsr 7
       | Rotate_right -> ((a lsr 1) lor ((a land 1) lsl 7)),a land 1
       | Rotate_left_through_carry -> ((a lsl 1) lor cin) land 255,a lsr 7
       | Rotate_right_through_carry -> ((a lsr 1) lor (cin lsl 7)),a land 1 in
      let inputs=edges Value [p.regs.(0).root] @ (match rotation with Rotate_left_through_carry|Rotate_right_through_carry->edges Flag [p.flags.(4).root]|_->[]) in
      assign_reg 0 value (op_root "ROTATE" value 8 inputs);
      let cin=if rotation=Rotate_left_through_carry || rotation=Rotate_right_through_carry then p.flags.(4).value else 0 in
      ignore cin;
      let carry_root=op p ~name:"ROTATE.CY.input" ~value:carry ~width:1 ~step_index ~origin [] in
      set_flag_checked "ROTATE.CY" 4 carry
        (inputs @ edges Flag [carry_root]);
      flags_written:=true
  | Daa ->
      let inputs=edges Value [p.regs.(0).root] @ edges Flag [p.flags.(2).root;p.flags.(4).root] in
      let a=p.regs.(0).value and ac=p.flags.(2).value<>0 and cy=p.flags.(4).value<>0 in
      let low=if ac || a land 15>9 then 6 else 0 in
      let high=cy || a>0x99 in
      let correction=low+(if high then 0x60 else 0) in
      let sum=a+correction in let v=sum land 255 in
      assign_reg 0 v (op_root "DAA.A" v 8 inputs);
      let sign,zero,parity=szp v in
      set_flag_checked "DAA.S" 0 sign inputs;
      set_flag_checked "DAA.Z" 1 zero inputs;
      set_flag_checked "DAA.P" 3 parity inputs;
      set_flag_checked "DAA.AC" 2 (bool_int ((a land 15)+(correction land 15)>15)) inputs;
      set_flag_checked "DAA.CY" 4 (bool_int high) inputs;
      flags_written:=true
  | Cma -> let v=(lnot p.regs.(0).value) land 255 in assign_reg 0 v (op_root "CMA" v 8 (edges Value [p.regs.(0).root]))
  | Stc | Cmc as ins -> let old=p.flags.(4).value in let v=if ins=Stc then 1 else 1-old in
      set_flag_op p ~step_index ~origin ~name:(if ins=Stc then "STC" else "CMC") ~value:v (if ins=Stc then [] else edges Flag [p.flags.(4).root]) 4; flags_written:=true
  | Push pair ->
      let value,high_roots,low_roots =
        match pair with
        | PSW ->
            let psw = (p.regs.(0).value lsl 8) lor ((p.flags.(0).value lsl 7) lor (p.flags.(1).value lsl 6) lor (p.flags.(2).value lsl 4) lor (p.flags.(3).value lsl 2) lor p.flags.(4).value lor 2) in
            psw, [p.regs.(0).root], [p.flags.(0).root;p.flags.(1).root;p.flags.(2).root;p.flags.(3).root;p.flags.(4).root]
        | Stack_BC -> pair_value p BC,[p.regs.(1).root],[p.regs.(2).root]
        | Stack_DE -> pair_value p DE,[p.regs.(3).root],[p.regs.(4).root]
        | Stack_HL -> pair_value p HL,[p.regs.(5).root],[p.regs.(6).root] in
      let high=write_next() in let low=write_next() in
      store_access high ((value lsr 8)land 255) (op_root "PUSH.high" ((value lsr 8)land 255) 8 (edges Value high_roots @ edges Address stack_address_roots));
      store_access low (value land 255) (op_root "PUSH.low" (value land 255) 8 (edges Value low_roots @ edges Address stack_address_roots));
      let sp=after.sp in set_pair p SP sp (op_root "PUSH.SP" sp 16 (edges Address [p.regs.(7).root]))
  | Pop pair ->
      let lo=read_next() in let hi=read_next() in
      let lr=read_cell p ~instruction:label step_index origin lo.address lo.value in
      let hr=read_cell p ~instruction:label step_index origin hi.address hi.value in
      let v=lo.value lor (hi.value lsl 8) in
      (match pair with
      | Stack_BC -> set_pair_parts p BC v ~name:"POP.BC" ~step_index ~origin
          ~low_inputs:(edges Value [lr] @ edges Address stack_address_roots)
          ~high_inputs:(edges Value [hr] @ edges Address stack_address_roots)
      | Stack_DE -> set_pair_parts p DE v ~name:"POP.DE" ~step_index ~origin
          ~low_inputs:(edges Value [lr] @ edges Address stack_address_roots)
          ~high_inputs:(edges Value [hr] @ edges Address stack_address_roots)
      | Stack_HL -> set_pair_parts p HL v ~name:"POP.HL" ~step_index ~origin
          ~low_inputs:(edges Value [lr] @ edges Address stack_address_roots)
          ~high_inputs:(edges Value [hr] @ edges Address stack_address_roots)
      | PSW -> assign_reg 0 hi.value (op_root "POP.PSW.A" hi.value 8 (edges Value [hr]@edges Address stack_address_roots));
          List.iter(fun(i,n,bit)->let v=(lo.value lsr bit) land 1 in
            set_flag_checked ("POP.PSW."^n) i v (edges Value [lr]@edges Address stack_address_roots))
            [0,"S",7;1,"Z",6;2,"AC",4;3,"P",2;4,"CY",0]);
      let sp=after.sp in set_pair p SP sp (op_root "POP.SP" sp 16 (edges Address [p.regs.(7).root]))
  | Call (condition,_) ->
      Option.iter (fun _ -> ignore (cond_roots ())) condition;
      if writes<>[] then (
          let ret=sequential_pc in let roots=edges Address stack_address_roots in
          let hi=write_next() in let lo=write_next() in
          store_access hi (ret lsr 8) (op_root "Control.push-return.high" (ret lsr 8) 8 roots);
          store_access lo (ret land 255) (op_root "Control.push-return.low" (ret land 255) 8 roots);
          let sp=after.sp in set_pair p SP sp (op_root "SP.call" sp 16 (edges Address [p.regs.(7).root])))
  | Rst _ ->
      let ret=sequential_pc in let roots=edges Address stack_address_roots in
      let hi=write_next() in let lo=write_next() in
      store_access hi (ret lsr 8) (op_root "RST.push-return.high" (ret lsr 8) 8 roots);
      store_access lo (ret land 255) (op_root "RST.push-return.low" ret 8 roots);
      let sp=after.sp in set_pair p SP sp (op_root "SP.RST" sp 16 (edges Address [p.regs.(7).root]))
  | Return condition ->
      Option.iter (fun _ -> ignore (cond_roots ())) condition;
      if reads<>[] then (
          let lo=read_next() in let hi=read_next() in ignore(read_cell p ~instruction:label step_index origin lo.address lo.value);ignore(read_cell p ~instruction:label step_index origin hi.address hi.value);
          let sp=after.sp in set_pair p SP sp (op_root "SP.return" sp 16 (edges Address [p.regs.(7).root])))
  | Jump (condition,_) -> Option.iter (fun _ -> ignore (cond_roots ())) condition
  | Pchl -> ()
  | Input port ->
      let v=after.a in let extroot=source p (External_result {subsystem="8080 I/O";operation=Printf.sprintf "IN %02X" port;value=v}) v 8 in
      assign_reg 0 v (op_root "IN" v 8 (edges Value [extroot]))
  | Output _ -> ()
  | Xchg ->
      let d,e,h,l=p.regs.(3),p.regs.(4),p.regs.(5),p.regs.(6) in
      let dv,dr,ev,er,hv,hr,lv,lr=d.value,d.root,e.value,e.root,h.value,h.root,l.value,l.root in
      p.regs.(3).value<-hv;p.regs.(3).root<-hr;p.regs.(4).value<-lv;p.regs.(4).root<-lr;
      p.regs.(5).value<-dv;p.regs.(5).root<-dr;p.regs.(6).value<-ev;p.regs.(6).root<-er
  | Xthl ->
      let lo=read_next() in let hi=read_next() in
      let lr=read_cell p ~instruction:label step_index origin lo.address lo.value in
      let hr=read_cell p ~instruction:label step_index origin hi.address hi.value in
      let oldl=p.regs.(6) and oldh=p.regs.(5) in let lv,lr0,hv,hr0=oldl.value,oldl.root,oldh.value,oldh.root in
      let loww=write_next() in let highw=write_next() in
      store_access loww lv (op_root "XTHL.store" lv 8 (edges Value [lr0]@edges Address stack_address_roots));
      store_access highw hv (op_root "XTHL.store" hv 8 (edges Value [hr0]@edges Address stack_address_roots));
      assign_reg 6 lo.value (op_root "XTHL.load" lo.value 8 (edges Value [lr]@edges Address stack_address_roots));
      assign_reg 5 hi.value (op_root "XTHL.load" hi.value 8 (edges Value [hr]@edges Address stack_address_roots))
  | Sphl -> let v=pair_value p HL in let roots=pair_roots HL in assign_pair SP v (op_root "SPHL" v 16 (edges Value roots)));
  (* Apply writes not consumed by an explicit data-transfer case (e.g. stores
     already consumed are tracked by the write cursor). *)
  if !read_index <> List.length reads then failwith "Provenance: unconsumed Step read";
  if !write_index <> List.length writes then (
    (* Instructions such as MVI M and MOV M,r are handled by the helpers; a
       mismatch here would otherwise silently lose a store root. *)
    failwith "Provenance: unconsumed Step write");
  ignore result8; ignore flags_written;
  (* Architectural post-state is authoritative for validation, never as an
     input to transfer equations. *)
  let actual_regs=reg_snapshot after in
  Array.iteri (fun i concrete ->
    let predicted=p.regs.(i).value in
    if predicted<>concrete then raise (Provenance_error (Concrete_mismatch {step_index;instruction=label;location=register_names.(i);predicted;concrete}))) actual_regs;
  let actual_flags=flag_snapshot after in
  Array.iteri (fun i concrete ->
    let predicted=p.flags.(i).value in
    if predicted<>concrete then raise (Provenance_error (Concrete_mismatch {step_index;instruction=label;location=flag_names.(i);predicted;concrete}))) actual_flags

let observe_bdos_event p ~step_index = function
  | Cpm.Bdos.Read_record {file;logical_record;dma;data} ->
      for i=0 to Bytes.length data-1 do
        let value=Char.code(Bytes.get data i) in
        let root=source p (File_byte {file;offset=logical_record*128+i;value}) value 8 in
        write_cell p ~address:(dma+i) ~value ~root
      done
  | Cpm.Bdos.Write_record {file;logical_record;dma;data} ->
      for i=0 to Bytes.length data-1 do
        let value=Char.code(Bytes.get data i) and offset=logical_record*128+i in
        let cell=p.memory.((dma+i)land 0xffff) in
        let root=if cell.root=Untracked then
          source p (Initial_memory_byte {address=(dma+i)land 0xffff;value;class_=Unclassified}) value 8
          else if cell.value=value then cell.root
          else raise (Provenance_error (Concrete_mismatch {
            step_index; instruction="BDOS WRITE SEQUENTIAL";
            location=Printf.sprintf "memory[%04X]" ((dma+i)land 0xffff);
            predicted=cell.value; concrete=value })) in
        cell.value<-value; cell.root<-root;
        let observation={file;offset;value;write_step_index=step_index;root} in
        let key=file,offset in
        Hashtbl.replace p.outputs key (observation :: Option.value (Hashtbl.find_opt p.outputs key) ~default:[])
      done

let observe_bdos_effect p = function
  | Cpm.Bdos.Register_write {register;value} ->
      let idx=match register with A->0|B->1|C->2|D->3|E->4|H->5|L->6|SP->7 in
      let root=source p (External_result {subsystem="BDOS";operation="register result";value}) value (if idx=7 then 16 else 8) in
      p.regs.(idx).value<-value;p.regs.(idx).root<-root
  | Cpm.Bdos.Memory_write {address;value;cause=Fcb_update} ->
      let root=source p (External_result {subsystem="BDOS";operation="FCB update";value}) value 8 in
      write_cell p ~address ~value ~root

let output_byte_history p ~file ~offset =
  Option.value (Hashtbl.find_opt p.outputs (file,offset)) ~default:[] |> List.rev
let final_output_byte p ~file ~offset = match output_byte_history p ~file ~offset with []->None|xs->Some(List.hd(List.rev xs))
let branch_observations p = List.rev p.branches_rev

let edge_at p id =
  let chunk=edge_chunk p id and slot=id mod edge_chunk_size in
  let role=match Array1.get chunk.roles slot with 0->Value|1->Address|2->Flag|3->Control
    |_->failwith "Provenance: corrupt compact edge role" in
  role,Int32.to_int(Array1.get chunk.targets slot)

let node p id =
  if id<0 || id>=p.used then invalid_arg "Provenance.node: invalid node id";
  let chunk=node_chunk p id and slot=id mod node_chunk_size in
  let tag=Array1.get chunk.tags slot and payload=Int32.to_int(Array1.get chunk.payloads slot) in
  let value=Array1.get chunk.values slot and width=Array1.get chunk.widths slot in
  let offset=Int32.to_int(Array1.get chunk.origin_offsets slot) in
  let kind=if tag=5 then Operation p.operation_names.(payload) else
    let identity=Option.get p.source_identities.(payload) in
    Source(match tag,identity with
      |0,Source_file image->File_byte {file=Option.get p.image_keys.(image);offset;value}
      |1,Source_command_tail->Command_tail_byte {offset;value}
      |2,Source_initial_memory class_->Initial_memory_byte {address=offset;value;class_}
      |3,Source_initial_register register->Initial_register {register;value}
      |4,Source_external(subsystem,operation)->External_result {subsystem;operation;value}
      |_->failwith "Provenance.node: corrupt compact source tag") in
  let raw_step=Array1.get chunk.steps slot in
  let step_index=if raw_step=Int64.minus_one then None else Some(Int64.to_int raw_step) in
  let raw_image=Array1.get chunk.origin_images slot in
  let origin=if raw_image=Int32.minus_one then None else Some {
    image=Option.get p.image_keys.(Int32.to_int raw_image);offset;
    runtime_pc=Array1.get chunk.runtime_pcs slot } in
  let edge_start=Int32.to_int(Array1.get chunk.edge_starts slot) in
  let edge_length=Int32.to_int(Array1.get chunk.edge_lengths slot) in
  {id;kind;value;width;step_index;origin;
   inputs=List.init edge_length(fun i->edge_at p (edge_start+i))}

let slice p roots =
  let seen=Hashtbl.create 1024 and pending=Stack.create() in
  List.iter (function Untracked->()|Node id->Stack.push id pending) roots;
  while not(Stack.is_empty pending) do
    let id=Stack.pop pending in if not(Hashtbl.mem seen id) then (
      Hashtbl.add seen id ();
      let chunk=node_chunk p id and slot=id mod node_chunk_size in
      let edge_start=Int32.to_int(Array1.get chunk.edge_starts slot) in
      let edge_length=Int32.to_int(Array1.get chunk.edge_lengths slot) in
      for index=0 to edge_length-1 do
        let _,target=edge_at p (edge_start+index) in Stack.push target pending
      done)
  done;
  let nodes=Hashtbl.fold(fun id () acc->node p id::acc)seen[] |> List.sort(fun (a:node) (b:node)->compare a.id b.id) in
  {roots;nodes}

let fold_reachable p ~roots ~init ~f =
  let seen=Hashtbl.create 1024 in
  let pending=ref(List.filter_map(function Untracked->None|Node id->Some id)roots) in
  let accumulator=ref init in
  while !pending<>[] do
    match !pending with
    | [] -> ()
    | id::rest ->
        pending:=rest;
        if not(Hashtbl.mem seen id) then (
          Hashtbl.add seen id ();
          let current=node p id in
          accumulator:=f !accumulator current;
          (* Prepending input targets preserves the stored edge order during
             this depth-first walk. No Hashtbl iteration order is observable. *)
          let children=List.map snd current.inputs in
          pending:=children @ !pending)
  done;
  !accumulator

let source_leaves (s : slice) = List.filter_map(fun (n : node)->match n.kind with Source x->Some x|_->None)s.nodes
let producer_nodes (s : slice) = List.filter(fun (n : node)->match n.kind with Operation _->true|_->false)s.nodes
let source_summary s =
  let table=Hashtbl.create 31 in
  let add group offset =
    let offsets=Option.value (Hashtbl.find_opt table group) ~default:(Hashtbl.create 17) in
    Hashtbl.replace offsets offset ();
    Hashtbl.replace table group offsets
  in
  List.iter(function
    | File_byte {file;offset;_} -> add (File_input file) offset
    | Command_tail_byte {offset;_} -> add Command_tail_input offset
    | Initial_memory_byte {address;class_;_} -> add (Initial_memory_input class_) address
    | Initial_register {register;_} -> add (Initial_register_input register) 0
    | External_result {subsystem;operation;value} -> add (External_input (subsystem,operation)) value) (source_leaves s);
  Hashtbl.fold(fun group offsets acc->{group;distinct_bytes=Hashtbl.length offsets}::acc)table[]
  |> List.sort(fun a b->compare a.group b.group)

let node_count p=p.used
let edge_count p=p.edges
let memory_root p ~address = p.memory.(address land 0xffff).root
let memory_value p ~address = p.memory.(address land 0xffff).value
let register_root p ~register = p.regs.(reg_index register).root
let flag_root p ~flag = p.flags.(flag_index (match flag with `Sign->`S|`Zero->`Z|`Auxiliary_carry->`AC|`Parity->`P|`Carry->`CY)).root
let output_byte_count p ~file=Hashtbl.fold(fun (f,_) (_ : output_observation list) n->if f=file then n+1 else n)p.outputs 0
let output_bytes_with_roots p ~file=Hashtbl.fold(fun (f,_) (xs : output_observation list) n->if f=file && (List.hd xs).root<>Untracked then n+1 else n)p.outputs 0
let output_bytes_untracked p ~file=output_byte_count p ~file-output_bytes_with_roots p ~file
let output_bytes_rewritten p ~file=Hashtbl.fold(fun (f,_) (xs : output_observation list) n->if f=file && List.length xs>1 then n+1 else n)p.outputs 0

let slice_json p ~roots =
  let s=slice p roots in
  let q=Printf.sprintf "%S" in
  let buffer=Buffer.create 4096 in
  let add=Buffer.add_string buffer in
  let printf fmt=Printf.ksprintf add fmt in
  let comma ()=Buffer.add_char buffer ',' in
  let idset=Hashtbl.create (List.length roots+1) in
  List.iter(function Node id->Hashtbl.replace idset id ()|Untracked->())roots;
  add "RUNES_PROVENANCE_SLICE 1\n{\"roots\":[";
  List.iteri(fun i->function Untracked->if i>0 then comma();add "null"|Node id->if i>0 then comma();printf "%d" id)s.roots;
  add "],\"sinks\":[";
  let sinks=Hashtbl.fold(fun _ (observations : output_observation list) acc ->
    List.filter(fun (o : output_observation)->match o.root with Node id->Hashtbl.mem idset id|Untracked->false) observations @ acc)p.outputs []
    |> List.sort(fun a b->let f=compare a.file b.file in if f<>0 then f else let o=compare a.offset b.offset in if o<>0 then o else compare a.write_step_index b.write_step_index) in
  List.iteri(fun i o->if i>0 then comma();
    printf "{\"drive\":%d,\"user\":%d,\"file\":%s,\"offset\":%d,\"value\":%d,\"step\":%d,\"root\":"
      o.file.drive o.file.user (q o.file.name) o.offset o.value o.write_step_index;
    (match o.root with Node id->printf "%d" id|Untracked->add "null");Buffer.add_char buffer '}')sinks;
  add "],\"nodes\":[";
  List.iteri(fun i (n : node)->if i>0 then comma();printf "{\"id\":%d,\"value\":%d,\"width\":%d,\"step\":%s,\"kind\":" n.id n.value n.width (match n.step_index with None->"null"|Some x->string_of_int x);
    (match n.kind with
     | Operation name->printf "{\"operation\":%s}" (q name)
     | Source (File_byte {file;offset;value})->printf "{\"drive\":%d,\"user\":%d,\"file\":%s,\"offset\":%d,\"value\":%d}" file.drive file.user (q file.name) offset value
     | Source (Command_tail_byte {offset;value})->printf "{\"command_tail_offset\":%d,\"value\":%d}" offset value
     | Source (Initial_memory_byte {address;value;class_})->printf "{\"initial_memory\":%d,\"value\":%d,\"class\":%s}" address value (q(match class_ with System->"system"|Runner->"runner"|Unclassified->"unclassified"))
     | Source (Initial_register {register;value})->printf "{\"initial_register\":%s,\"value\":%d}" (q register) value
     | Source (External_result {subsystem;operation;value})->printf "{\"external\":%s,\"operation\":%s,\"value\":%d}" (q subsystem)(q operation)value);
    add ",\"origin\":";
    (match n.origin with None->add "null"|Some o->printf "{\"drive\":%d,\"user\":%d,\"image\":%s,\"offset\":%d,\"runtime_pc\":%d}" o.image.drive o.image.user (q o.image.name)o.offset o.runtime_pc);
    add ",\"inputs\":[";
    List.iteri(fun j(role,id)->if j>0 then comma();printf "{\"role\":%s,\"node\":%d}" (q(match role with Value->"value"|Address->"address"|Flag->"flag"|Control->"control"))id)n.inputs;
    add "]}")s.nodes;
  add "]}\n";
  Buffer.contents buffer

let write_slice_json oc p ~roots = output_string oc (slice_json p ~roots)
