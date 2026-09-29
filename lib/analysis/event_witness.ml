type origin = { image : Cpm.Filesystem.key; offset : int }
type memory_read = { address : int; value : int }
type memory_write = { address : int; old_value : int option; new_value : int }
type frame = { call_step : int; callsite : origin option; call_pc : int;
               return_address : int; target_pc : int; target : origin option }
type certainty = Certain | Uncertain of string list
type instruction = {
  step_index : int; pc : int; pc_after : int; origin : origin option; target_origin : origin option; runtime_pc : int;
  bytes : bytes; disassembly : string; source : I8080.Step.instruction_source;
  before : Runner.state_snapshot; after : Runner.state_snapshot;
  reads : memory_read list; writes : memory_write list;
  flow : I8080.Step.control_flow; sp_before : int; sp_after : int;
}
type event =
  | Instruction of instruction
  | Bdos_call of { step_index : int; function_number : int; state : Runner.state_snapshot;
                   dma : int; fcb_address : int option; fcb_bytes : bytes option;
                   bridge_step : int option; bridge_origin : origin option;
                   frames : frame list; recent_transfers : instruction list; certainty : certainty }
  | Bdos_record of { step_index : int; operation : string; file : Cpm.Filesystem.key;
                     logical_record : int; dma : int; data : bytes }
  | File_operation of { step_index : int; operation : string; file : Cpm.Filesystem.key;
                        succeeded : bool; logical_record : int option }
  | Host_effect of { step_index : int; old_value : int option; detail : Cpm.Bdos.external_effect }
  | Bdos_resume of { step_index : int; state : Runner.state_snapshot }
  | Call_mismatch of { step_index : int; observed_target : int option; expected_frame : frame option }
  | Termination of { step_index : int; reason : string }

open I8080.Step

type t = {
  run_id : string;
  origin_at : pc:int -> fetched:bytes -> origin option;
  mutable reversed_events : event list;
  mutable instruction_count : int;
  mutable file_event_count : int;
  mutable mismatch_count : int;
  mutable frames : frame list;
  mutable recent_transfers : instruction list;
  mutable uncertainty : string list;
  mutable last_instruction : instruction option;
}

let create ~run_id ~origin_at = { run_id; origin_at; reversed_events=[];
  instruction_count=0; file_event_count=0; mismatch_count=0; frames=[];
  recent_transfers=[]; uncertainty=[]; last_instruction=None }
let push t event = t.reversed_events <- event :: t.reversed_events
let origin_for t ~pc ~fetched = t.origin_at ~pc ~fetched
let target_origin t pc = origin_for t ~pc ~fetched:Bytes.empty

let is_transfer = function I8080.Step.Sequential | Halt -> false | _ -> true
let sequential_address pc bytes = (pc + Bytes.length bytes) land 0xffff

let observe_step t ~step_index ~before ~after step =
  let mismatch = ref None in
  let pc=I8080.Step.pc_before step and bytes=I8080.Step.fetched_bytes step in
  let origin=origin_for t ~pc ~fetched:bytes in
  let known_memory=Hashtbl.create 4 in
  let reads,writes=List.fold_left(fun (reads,writes) -> function
    |I8080.Step.Read {address;value}->Hashtbl.replace known_memory address value;({address;value}::reads,writes)
    |I8080.Step.Write {address;value}->let old_value=Hashtbl.find_opt known_memory address in Hashtbl.replace known_memory address value;
      (reads,{address;old_value;new_value=value}::writes))
    ([],[]) (I8080.Step.memory_accesses step) in
  let target_pc=match I8080.Step.control_flow step with
    |Jump{target;_}|Call{target;_}|Restart{target}->Some target
    |Return{target;_}->target|Sequential|Halt->None in
  let instruction={step_index;pc;pc_after=I8080.Step.pc_after step;origin;
    target_origin=Option.bind target_pc (target_origin t);runtime_pc=pc;bytes;
    disassembly=I8080.Instr_format.format (I8080.Step.decoded step).instr;
    source=I8080.Step.source step;before;after;reads=List.rev reads;writes=List.rev writes;
    flow=I8080.Step.control_flow step;sp_before=before.Runner.sp;sp_after=after.Runner.sp} in
  (match instruction.flow with
   |I8080.Step.Call {target;taken=true}|I8080.Step.Restart {target}->
       t.frames <- {call_step=step_index;callsite=origin;call_pc=pc;
         return_address=sequential_address pc bytes;target_pc=target;target=target_origin t target}::t.frames
   |I8080.Step.Return {target; taken=true}->
       (match t.frames with
        |frame::rest when target=Some frame.return_address -> t.frames<-rest
        |frame::rest ->
            t.mismatch_count<-t.mismatch_count+1;
            mismatch:=Some (target,Some frame);
            let detail=Printf.sprintf "return target %s at step %d did not match expected %04X from call step %d"
              (Option.fold ~none:"unknown" ~some:(Printf.sprintf "%04X") target) step_index frame.return_address frame.call_step in
            if t.uncertainty=[] then t.uncertainty<-[detail];
            (* The observed RET consumes one active frame; ownership after a
               mismatch remains explicitly uncertain. *) t.frames<-rest
        |[]->t.mismatch_count<-t.mismatch_count+1;mismatch:=Some(target,None);if t.uncertainty=[] then t.uncertainty<-[Printf.sprintf "return at step %d has no observed active CALL frame" step_index])
   |_ -> ());
  if is_transfer instruction.flow then (
    t.recent_transfers <- instruction :: t.recent_transfers;
    if List.length t.recent_transfers>32 then t.recent_transfers<-List.rev(List.tl(List.rev t.recent_transfers)));
  t.last_instruction<-Some instruction;
  t.instruction_count<-t.instruction_count+1;
  push t (Instruction instruction);
  Option.iter(fun(observed_target,expected_frame)->push t(Call_mismatch{step_index;observed_target;expected_frame}))!mismatch

let observe_bdos_call t ~step_index ~state ~dma ~read_memory =
  let function_number=state.Runner.c in
  let fcb_address=if List.mem function_number [15;16;17;19;20;21;22] then Some (state.Runner.d*256+state.Runner.e) else None in
  let fcb_bytes=Option.map(fun address->Bytes.init 36(fun i->Char.chr(read_memory ((address+i)land 0xffff))))fcb_address in
  let certainty=match List.rev t.uncertainty with []->Certain|xs->Uncertain xs in
  push t (Bdos_call {step_index;function_number;state;dma;fcb_address;fcb_bytes;
    bridge_step=Option.map(fun i->i.step_index)t.last_instruction;
    bridge_origin=Option.bind t.last_instruction (fun i->i.origin);
    frames=t.frames;recent_transfers=List.rev t.recent_transfers;certainty})

let observe_bdos_record t ~step_index = function
  |Cpm.Bdos.Read_record {file;logical_record;dma;data}->push t(Bdos_record{step_index;operation="read_record";file;logical_record;dma;data})
  |Write_record {file;logical_record;dma;data}->push t(Bdos_record{step_index;operation="write_record";file;logical_record;dma;data})
let observe_file_operation t ~step_index (event:Cpm.Bdos.file_event) =
  t.file_event_count<-t.file_event_count+1;
  let operation=match event.operation with Open->"open"|Close->"close"|Make->"make"|Delete->"delete"|Sequential_read->"sequential_read"|Sequential_write->"sequential_write" in
  push t(File_operation{step_index;operation;file=event.file;succeeded=event.succeeded;logical_record=event.logical_record})
let observe_host_effect t ~step_index detail=
  let old_value=match detail with
    |Cpm.Bdos.Register_write{register;_}->
        let state=List.find_map(function Bdos_call e when e.step_index=step_index->Some e.state|_->None)t.reversed_events in
        Option.map(fun s->match register with Cpm.Bdos.A->s.Runner.a|Cpm.Bdos.B->s.b|Cpm.Bdos.C->s.c|Cpm.Bdos.D->s.d|Cpm.Bdos.E->s.e|Cpm.Bdos.H->s.h|Cpm.Bdos.L->s.l|Cpm.Bdos.SP->s.sp)state
    |Memory_write{address;_}->
        List.find_map(function Bdos_call e when e.step_index=step_index->
          (match e.fcb_address,e.fcb_bytes with Some base,Some bytes->let offset=(address-base)land 0xffff in if offset<Bytes.length bytes then Some(Char.code(Bytes.get bytes offset))else None|_->None)
          |_->None)t.reversed_events in
  push t(Host_effect{step_index;old_value;detail})
let observe_bdos_resume t ~step_index state=push t(Bdos_resume{step_index;state})
let observe_termination t ~step_index = function
  |Runner.Warm_boot->push t(Termination{step_index;reason="warm_boot"})
  |Bdos_function n->push t(Termination{step_index;reason="bdos_"^string_of_int n})
let run_id t=t.run_id
let events t=List.rev t.reversed_events
let instruction_count t=t.instruction_count
let file_event_count t=t.file_event_count
let transfer_mismatch_count t=t.mismatch_count

let quote s =
  let b=Buffer.create(String.length s+8) in Buffer.add_char b '"';
  String.iter(fun c->match c with '"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"|c when Char.code c<32->Buffer.add_string b(Printf.sprintf"\\u%04x"(Char.code c))|c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b
let key_json (key:Cpm.Filesystem.key)=Printf.sprintf"{\"drive\":%d,\"user\":%d,\"name\":%s,\"identity\":%s}" key.drive key.user (quote key.name) (quote(Printf.sprintf"%d:%d:%s" key.drive key.user key.name))
let origin_json=function None->"null"|Some o->Printf.sprintf"{\"image\":%s,\"offset\":%d}"(key_json o.image)o.offset
let bool b=if b then"true"else"false"
let opt_int=function None->"null"|Some x->string_of_int x
let bytes_hex bytes=let b=Buffer.create(Bytes.length bytes*2)in Bytes.iter(fun c->Buffer.add_string b(Printf.sprintf"%02X"(Char.code c)))bytes;Buffer.contents b
let snapshot_json s=Printf.sprintf"{\"a\":%d,\"b\":%d,\"c\":%d,\"d\":%d,\"e\":%d,\"h\":%d,\"l\":%d,\"sp\":%d,\"pc\":%d,\"flags\":{\"sign\":%s,\"zero\":%s,\"auxiliary_carry\":%s,\"parity\":%s,\"carry\":%s}}" s.Runner.a s.b s.c s.d s.e s.h s.l s.sp s.pc (bool s.sign)(bool s.zero)(bool s.auxiliary_carry)(bool s.parity)(bool s.carry)
let flow_json=function
  |I8080.Step.Sequential->"{\"kind\":\"sequential\"}"
  |Jump{target;taken}->Printf.sprintf"{\"kind\":\"jump\",\"target\":%d,\"taken\":%s}"target(bool taken)
  |Call{target;taken}->Printf.sprintf"{\"kind\":\"call\",\"target\":%d,\"taken\":%s}"target(bool taken)
  |Return{target;taken}->Printf.sprintf"{\"kind\":\"return\",\"target\":%s,\"taken\":%s}"(opt_int target)(bool taken)
  |Restart{target}->Printf.sprintf"{\"kind\":\"restart\",\"target\":%d}"target
  |Halt->"{\"kind\":\"halt\"}"
let instruction_json i=
  let reads=String.concat","(List.map(fun (x:memory_read)->Printf.sprintf"{\"address\":%d,\"value\":%d}"x.address x.value)i.reads)in
  let writes=String.concat","(List.map(fun (x:memory_write)->Printf.sprintf"{\"address\":%d,\"old_value\":%s,\"new_value\":%d}"x.address(opt_int x.old_value)x.new_value)i.writes)in
  let source=match i.source with I8080.Step.Memory->"memory"|Interrupt_acknowledge->"interrupt_acknowledge"in
  let return_address=match i.flow with I8080.Step.Call{taken=true;_}|Restart _->Some(sequential_address i.pc i.bytes)|_->None in
  Printf.sprintf"{\"step_index\":%d,\"pc\":%d,\"pc_after\":%d,\"origin\":%s,\"target_origin\":%s,\"runtime_pc\":%d,\"bytes\":%s,\"disassembly\":%s,\"source\":%s,\"before\":%s,\"after\":%s,\"sp_before\":%d,\"sp_after\":%d,\"call_return_address\":%s,\"reads\":[%s],\"writes\":[%s],\"control\":%s}"
    i.step_index i.pc i.pc_after(origin_json i.origin)(origin_json i.target_origin)i.runtime_pc(quote(bytes_hex i.bytes))(quote i.disassembly)(quote source)(snapshot_json i.before)(snapshot_json i.after)i.sp_before i.sp_after(opt_int return_address)reads writes(flow_json i.flow)
let frame_json f=Printf.sprintf"{\"call_step\":%d,\"call_pc\":%d,\"callsite\":%s,\"return_address\":%d,\"target_pc\":%d,\"target\":%s}"f.call_step f.call_pc(origin_json f.callsite)f.return_address f.target_pc(origin_json f.target)
let event_json=function
 |Instruction i->"{\"type\":\"instruction\",\"witness\":"^instruction_json i^"}"
 |Bdos_call e->let frames=String.concat","(List.map frame_json e.frames)and recent=String.concat","(List.map instruction_json e.recent_transfers)in
   let fcb=Option.map bytes_hex e.fcb_bytes in
   let certainty=match e.certainty with Certain->"{\"status\":\"certain\",\"reasons\":[]}"|Uncertain reasons->"{\"status\":\"uncertain\",\"reasons\":["^String.concat","(List.map quote reasons)^"]}"in
   Printf.sprintf"{\"type\":\"bdos_call\",\"step_index\":%d,\"function\":%d,\"state\":%s,\"dma\":%d,\"fcb_address\":%s,\"fcb_bytes\":%s,\"bridge_step\":%s,\"bridge_origin\":%s,\"frames\":[%s],\"recent_transfers\":[%s],\"call_context\":%s}"
    e.step_index e.function_number(snapshot_json e.state)e.dma(opt_int e.fcb_address)(match fcb with None->"null"|Some x->quote x)(opt_int e.bridge_step)(origin_json e.bridge_origin)frames recent certainty
 |Bdos_record e->Printf.sprintf"{\"type\":\"bdos_record\",\"step_index\":%d,\"operation\":%s,\"file\":%s,\"record\":%d,\"dma\":%d,\"data\":%s}"e.step_index(quote e.operation)(key_json e.file)e.logical_record e.dma(quote(bytes_hex e.data))
 |File_operation e->Printf.sprintf"{\"type\":\"file_operation\",\"step_index\":%d,\"operation\":%s,\"file\":%s,\"succeeded\":%s,\"record\":%s}"e.step_index(quote e.operation)(key_json e.file)(bool e.succeeded)(opt_int e.logical_record)
 |Host_effect e->let effect_json=match e.detail with
     |Cpm.Bdos.Register_write{register;value}->let r=match register with Cpm.Bdos.A->"A"|Cpm.Bdos.B->"B"|Cpm.Bdos.C->"C"|Cpm.Bdos.D->"D"|Cpm.Bdos.E->"E"|Cpm.Bdos.H->"H"|Cpm.Bdos.L->"L"|Cpm.Bdos.SP->"SP"in Printf.sprintf"{\"kind\":\"register_write\",\"register\":%s,\"old_value\":%s,\"new_value\":%d}"(quote r)(opt_int e.old_value)value
     |Cpm.Bdos.Memory_write{address;value;cause}->Printf.sprintf"{\"kind\":\"memory_write\",\"address\":%d,\"old_value\":%s,\"new_value\":%d,\"cause\":%s}"address(opt_int e.old_value)value(quote(match cause with Cpm.Bdos.Fcb_update->"fcb_update"))in
   Printf.sprintf"{\"type\":\"host_effect\",\"step_index\":%d,\"effect\":%s}"e.step_index effect_json
 |Bdos_resume e->Printf.sprintf"{\"type\":\"bdos_resume\",\"step_index\":%d,\"state\":%s}"e.step_index(snapshot_json e.state)
 |Call_mismatch e->Printf.sprintf"{\"type\":\"call_context_mismatch\",\"step_index\":%d,\"observed_return_target\":%s,\"expected_frame\":%s}"e.step_index(opt_int e.observed_target)(Option.fold ~none:"null" ~some:frame_json e.expected_frame)
 |Termination e->Printf.sprintf"{\"type\":\"termination\",\"step_index\":%d,\"reason\":%s}"e.step_index(quote e.reason)
let write_json ~output t=
  output"RUNES_EVENT_WITNESSES 1\n{\"run_id\":";output(quote t.run_id);
  Printf.ksprintf output ",\"summary\":{\"instruction_witnesses\":%d,\"file_events\":%d,\"transfer_mismatches\":%d},\"events\":[" t.instruction_count t.file_event_count t.mismatch_count;
  List.iteri(fun i event->if i>0 then output",";output(event_json event))(events t);
  output"]}\n"

let write_chunked_json ~chunk_size ~write_chunk ~write_index t =
  if chunk_size <= 0 then invalid_arg "Event_witness.write_chunked_json: chunk_size must be positive";
  let all = events t in
  let chunks_rev = ref [] and current = ref [] and current_id = ref 0 and in_chunk = ref 0 in
  List.iter (fun event ->
    current := event :: !current;
    incr in_chunk;
    if !in_chunk = chunk_size then (
      chunks_rev := (!current_id, List.rev !current) :: !chunks_rev;
      incr current_id; current := []; in_chunk := 0)) all;
  if !current <> [] then chunks_rev := (!current_id, List.rev !current) :: !chunks_rev;
  let chunks = List.rev !chunks_rev in
  let call_chunks = Hashtbl.create 1024 and coord_chunks = Hashtbl.create 16384 in
  let file_rows = ref [] in
  List.iter (fun (chunk_id, chunk_events) ->
    List.iter (function
      | Instruction i -> Option.iter (fun origin ->
          let key = origin.image, origin.offset in
          let ids = Option.value (Hashtbl.find_opt coord_chunks key) ~default:[] in
          if not (List.mem chunk_id ids) then Hashtbl.replace coord_chunks key (chunk_id :: ids)) i.origin
      | Bdos_call e -> Hashtbl.replace call_chunks e.step_index chunk_id
      | File_operation e -> file_rows := (chunk_id,e.step_index,"file_operation",e.operation,e.file,e.succeeded,e.logical_record)::!file_rows
      | Bdos_record e -> file_rows := (chunk_id,e.step_index,"bdos_record",e.operation,e.file,true,Some e.logical_record)::!file_rows
      | _ -> ()) chunk_events) chunks;
  List.iter (fun (chunk_id, chunk_events) ->
    let body = String.concat "," (List.map event_json chunk_events) in
    write_chunk chunk_id (Printf.sprintf "RUNES_EVENT_WITNESS_CHUNK 1\n{\"run_id\":%s,\"chunk_id\":%d,\"events\":[%s]}\n" (quote t.run_id) chunk_id body)) chunks;
  let b = Buffer.create 8192 and add = Buffer.add_string in
  add b "RUNES_EVENT_WITNESSES 1\n{\"run_id\":"; add b (quote t.run_id);
  Printf.bprintf b ",\"encoding\":\"chronological-chunks\",\"chunk_prefix\":\"event-witnesses/chunks/\",\"summary\":{\"instruction_witnesses\":%d,\"file_events\":%d,\"transfer_mismatches\":%d},\"chunks\":["
    t.instruction_count t.file_event_count t.mismatch_count;
  List.iteri (fun index (chunk_id,items) -> if index>0 then add b ",";
    Printf.bprintf b "{\"id\":%d,\"event_count\":%d}" chunk_id (List.length items)) chunks;
  add b "],\"instruction_index\":[";
  let coords = Hashtbl.fold (fun (image,offset) ids acc -> (image,offset,List.sort compare ids)::acc) coord_chunks []
    |> List.sort (fun (a,x,_) (b,y,_) -> let c=compare a b in if c=0 then compare x y else c) in
  List.iteri (fun index (image,offset,ids) -> if index>0 then add b ",";
    Printf.bprintf b "{\"image\":%s,\"offset\":%d,\"chunks\":[%s]}" (key_json image) offset
      (String.concat "," (List.map string_of_int ids))) coords;
  add b "],\"file_events\":[";
  List.iteri (fun index (chunk,step,kind,operation,file,succeeded,record) -> if index>0 then add b ",";
    Printf.bprintf b "{\"chunk\":%d,\"step_index\":%d,\"kind\":%s,\"operation\":%s,\"file\":%s,\"succeeded\":%s,\"record\":%s,\"byte_range\":%s,\"bdos_call_chunk\":%s}"
      chunk step (quote kind) (quote operation) (key_json file) (bool succeeded) (opt_int record)
      (match record with None->"null"|Some n->Printf.sprintf "[%d,%d]" (n*128) ((n+1)*128))
      (match Hashtbl.find_opt call_chunks step with None->"null"|Some id->string_of_int id)) (List.rev !file_rows);
  add b "]}\n";
  write_index (Buffer.contents b)
