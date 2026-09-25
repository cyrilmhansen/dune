[@@@warning "-40-41-42-69"]

open Provenance

type classification = Program_input | Intermediate | Program_image | Output | Other of string
type classifier = Cpm.Filesystem.key -> classification
type sink = { file : Cpm.Filesystem.key; offset : int; generation : int option }
type offset_range = { first : int; last : int }
type output_byte = { offset : int; value : int; write_step : int option; root_present : bool; rewrite_count : int; projection_embedded : bool }
type source_leaf = { node_id : Provenance.node_id; kind : string; identity : string; classification : classification option; offset : int option; virtual_offset : int option; value : int }
type source_group = { kind : string; identity : string; classification : classification option; distinct_offsets : int list; ranges : offset_range list; leaf_occurrences : int }
type producer = {
  id : string; image : Cpm.Filesystem.key; image_offset : int; virtual_offset : int option;
  runtime_pc : int; operation_kind : string; operation_nodes : int; producer_steps : int;
  operation_kinds : string list; value_edges : int; address_edges : int; flag_edges : int;
  control_edges : int; first_step : int option; last_step : int option;
}
type operation_summary = { kind : string; node_count : int; producer_locations : int; producer_steps : int; value_edges : int; address_edges : int; flag_edges : int; control_edges : int }
type preview_node = { id : Provenance.node_id; label : string; value : int; width : int; step : int option; origin : Provenance.producer_origin option; depth : int }
type preview_edge = { from_id : int; to_id : int; role : Provenance.edge_role }
type preview = { nodes : preview_node list; edges : preview_edge list; max_depth : int; max_nodes : int; omitted_frontier_count : int }
type role_counts = { value : int; address : int; flag : int; control : int }
type projection = {
  sink : sink; sink_value : int option; write_step : int option; root : Provenance.root;
  full_node_count : int; source_leaf_count : int; producers : producer list;
  producer_location_count : int; distinct_producer_steps : int; unlocated_operation_nodes : int;
  operations : operation_summary list; roles : role_counts; sources : source_group list;
  source_leaves : source_leaf list; preview : preview;
}
type t = { output_file : Cpm.Filesystem.key; output_bytes : output_byte list; projections : projection list; execution : Execution_report.t }
type error = Missing_output_byte of sink
type control_decision_row = {
  image:Cpm.Filesystem.key option; image_offset:int option; runtime_pc:int;
  condition:string; taken:bool; decision_count:int; first_step:int; last_step:int;
  distinct_flag_roots:int;
}
type path_control_projection = {
  sink:sink; context_depth:int; distinct_branch_locations:int;
  earliest_decision_step:int option; latest_decision_step:int option;
  additional_context_nodes:int; additional_decision_nodes:int;
  additional_flag_ancestors:int; combined_reachable_nodes:int;
  control_relations:int; locations:control_decision_row list; preview:preview;
}
type control_report = {decisions:control_decision_row list;paths:path_control_projection list}

let output_file t=t.output_file
let output_bytes t=t.output_bytes
let projections t=t.projections
let execution t=t.execution

let key_string (key : Cpm.Filesystem.key) = Printf.sprintf "%c:%d:%s" (Char.chr (Char.code 'A'+key.drive)) key.user key.name
let class_name = function Program_input->"program input"|Intermediate->"intermediate"|Program_image->"program image"|Output->"output"|Other x->x
let source_kind = function
  | Provenance.File_byte _ -> "file_byte"
  | Command_tail_byte _ -> "command_tail"
  | Initial_memory_byte _ -> "initial_memory"
  | Initial_register _ -> "initial_register"
  | External_result _ -> "external_result"

let source_identity classify = function
  | Provenance.File_byte {file;_} -> key_string file,Some(classify file)
  | Command_tail_byte _ -> "command tail",None
  | Initial_memory_byte {class_;_} -> "initial memory/"^(match class_ with System->"system"|Runner->"runner"|Unclassified->"unclassified"),None
  | Initial_register {register;_} -> "initial register/"^register,None
  | External_result {subsystem;operation;_} -> subsystem^"/"^operation,None

let source_offset = function
  | Provenance.File_byte {offset;_}|Command_tail_byte {offset;_}->Some offset
  | Initial_memory_byte {address;_}->Some address
  | Initial_register _|External_result _->None
let source_value = function
  | Provenance.File_byte {value;_}|Command_tail_byte {value;_}|Initial_memory_byte {value;_}|Initial_register {value;_}|External_result {value;_}->value

let group_key kind identity classification = kind^"\000"^identity^"\000"^(Option.fold ~none:"" ~some:class_name classification)
let producer_key image offset runtime_pc = Printf.sprintf "%d:%d:%s:%d:%04X" image.Cpm.Filesystem.drive image.user image.name offset runtime_pc
let producer_id key = "producer:"^key

let sorted_offsets set = Hashtbl.fold(fun offset () acc->offset::acc)set[] |> List.sort compare
let ranges_of_offsets offsets =
  let rec loop acc start last = function
    | [] -> (match start with None->List.rev acc|Some first->{first;last}::acc |> List.rev)
    | x::xs -> (match start with
      | None -> loop acc (Some x) x xs
      | Some first when x<=last+1 -> loop acc (Some first) (max last x) xs
      | Some first -> loop ({first;last}::acc) (Some x) x xs)
  in loop [] None 0 offsets

let virtual_bases execution =
  let table=Hashtbl.create 8 in
  List.iter(fun (image : Execution_report.image)->Hashtbl.replace table image.id (image.virtual_base,image.span))(Execution_report.images execution);
  table

let choose_generation p selection =
  match selection.generation with
  | None -> Provenance.final_output_byte p ~file:selection.file ~offset:selection.offset
  | Some index -> List.nth_opt (Provenance.output_byte_history p ~file:selection.file ~offset:selection.offset) index

let preview_of_root ~max_depth ~max_nodes provenance root =
  let queue=Queue.create() and seen=Hashtbl.create 512 and skipped=Hashtbl.create 128 in
  (match root with Provenance.Untracked->()|Node id->Queue.add(id,0)queue);
  let nodes=ref [] in
  while not(Queue.is_empty queue) do
    let id,depth=Queue.take queue in
    if depth>max_depth then Hashtbl.replace skipped id ()
    else if not(Hashtbl.mem seen id) then
      if List.length !nodes>=max_nodes then Hashtbl.replace skipped id ()
      else (
        Hashtbl.add seen id depth;
        let n=Provenance.node provenance id in
        let label=match n.kind with
          | Operation name->"operation/"^name
          | Source source->source_kind source^"/"^(fst(source_identity (fun _->Other "") source)) in
        nodes := {id=n.id;label;value=n.value;width=n.width;step=n.step_index;origin=n.origin;depth}::!nodes;
        List.iter(fun(role,child)->if List.mem role Provenance.data_edge_roles && not(Hashtbl.mem seen child) then Queue.add(child,depth+1)queue)n.inputs)
  done;
  let nodes=List.rev !nodes in
  let visible=Hashtbl.create(List.length nodes) in List.iter(fun n->Hashtbl.replace visible n.id ())nodes;
  let edges=List.concat_map(fun n->(Provenance.node provenance n.id).inputs
    |> List.filter_map(fun(role,target)->if List.mem role Provenance.data_edge_roles && Hashtbl.mem visible target then Some{from_id=n.id;to_id=target;role}else None))nodes in
  {nodes;edges;max_depth;max_nodes;omitted_frontier_count=Hashtbl.length skipped}

type producer_acc = {
  p_image : Cpm.Filesystem.key; p_offset : int; p_pc : int; p_virtual : int option;
  p_kind : string; mutable p_nodes : int; p_steps : (int,unit) Hashtbl.t;
  p_kinds : (string,unit) Hashtbl.t; mutable p_value : int; mutable p_address : int;
  mutable p_flag : int; mutable p_control : int; mutable p_first : int option; mutable p_last : int option;
}
type operation_acc = { mutable o_nodes:int; o_locations:(string,unit)Hashtbl.t; o_steps:(int,unit)Hashtbl.t; mutable o_value:int;mutable o_address:int;mutable o_flag:int;mutable o_control:int }
type source_acc = { s_kind:string;s_identity:string;s_class:classification option;s_offsets:(int,unit)Hashtbl.t;mutable s_occurrences:int }

let increment_role target = function
  | Provenance.Value->target.p_value<-target.p_value+1
  | Address->target.p_address<-target.p_address+1
  | Flag->target.p_flag<-target.p_flag+1
  | Control->target.p_control<-target.p_control+1

let project_one ~max_depth ~max_nodes ~classify ~bases provenance selection =
  let observation=choose_generation provenance selection in
  let root=Option.fold ~none:Provenance.Untracked ~some:(fun (o:Provenance.output_observation)->o.root) observation in
  let producer_table=Hashtbl.create 2048 and operation_table=Hashtbl.create 32 and source_table=Hashtbl.create 512 in
  let producer_steps=(Hashtbl.create 1024 : (int,unit)Hashtbl.t) in
  let source_leaves=ref [] and node_count=ref 0 and source_count=ref 0 and unlocated=ref 0 in
  let roles=Array.make 4 0 in
  let role_index=function Provenance.Value->0|Address->1|Flag->2|Control->3 in
  let add_source n source =
    incr source_count;
    let kind=source_kind source and identity,classification=source_identity classify source in
    let key=group_key kind identity classification in
    let acc=match Hashtbl.find_opt source_table key with
      |Some acc->acc
      |None->let acc={s_kind=kind;s_identity=identity;s_class=classification;s_offsets=Hashtbl.create 16;s_occurrences=0}in Hashtbl.add source_table key acc;acc in
    acc.s_occurrences<-acc.s_occurrences+1;
    Option.iter(fun offset->Hashtbl.replace acc.s_offsets offset ()) (source_offset source);
    let offset=source_offset source in
    let virtual_offset=match source with
      | Provenance.File_byte {file;offset;_}->Option.map(fun(base,_)->base+offset)(Hashtbl.find_opt bases file)
      |_->None in
    source_leaves:={node_id=n.Provenance.id;kind;identity;classification;offset;virtual_offset;value=source_value source}::!source_leaves
  in
  let visit () (n : Provenance.node) =
    incr node_count;
    (match n.kind with
     | Source source -> add_source n source
     | Operation name ->
         let oa=match Hashtbl.find_opt operation_table name with
           |Some a->a
           |None->let a={o_nodes=0;o_locations=Hashtbl.create 16;o_steps=Hashtbl.create 32;o_value=0;o_address=0;o_flag=0;o_control=0} in Hashtbl.add operation_table name a;a in
         oa.o_nodes<-oa.o_nodes+1;
         List.iter(fun(role,_)->if List.mem role Provenance.data_edge_roles then (let i=role_index role in roles.(i)<-roles.(i)+1;
           (match role with Value->oa.o_value<-oa.o_value+1|Address->oa.o_address<-oa.o_address+1|Flag->oa.o_flag<-oa.o_flag+1|Control->oa.o_control<-oa.o_control+1))) n.inputs;
         (match n.step_index,n.origin with
          |Some step,Some origin ->
              let key=producer_key origin.image origin.offset origin.runtime_pc in
              let basekey=key in
              let p=match Hashtbl.find_opt producer_table basekey with
                |Some p->p
                |None->let p={p_image=origin.image;p_offset=origin.offset;p_pc=origin.runtime_pc;
                  p_virtual=Option.map(fun(base,_)->base+origin.offset)(Hashtbl.find_opt bases origin.image);
                  p_kind=name;p_nodes=0;p_steps=Hashtbl.create 8;p_kinds=Hashtbl.create 4;
                  p_value=0;p_address=0;p_flag=0;p_control=0;p_first=None;p_last=None} in
                  Hashtbl.add producer_table basekey p;p in
              p.p_nodes<-p.p_nodes+1;Hashtbl.replace p.p_steps step ();Hashtbl.replace p.p_kinds name ();
              Hashtbl.replace producer_steps step ();
              p.p_first<-Some(Option.fold ~none:step ~some:(min step)p.p_first);
              p.p_last<-Some(Option.fold ~none:step ~some:(max step)p.p_last);
              List.iter(fun(role,_)->if List.mem role Provenance.data_edge_roles then increment_role p role;
                match role with Value->()|Address->()|Flag->()|Control->())n.inputs;
              Hashtbl.replace oa.o_locations key ();Hashtbl.replace oa.o_steps step ()
          |_->incr unlocated)
    );
    ()
  in
  let ()=Provenance.fold_reachable ~roles:Provenance.data_edge_roles provenance ~roots:[root] ~init:() ~f:visit in
  let producer_rows = Hashtbl.fold (fun _ (p : producer_acc) acc ->
    let location = producer_key p.p_image p.p_offset p.p_pc in
    let kinds=Hashtbl.fold(fun name () xs->name::xs)p.p_kinds[]|>List.sort compare in
    let kind=String.concat ";" kinds in
    { id = producer_id location; image = p.p_image;
      image_offset = p.p_offset; virtual_offset = p.p_virtual;
      runtime_pc = p.p_pc; operation_kind = kind; operation_nodes = p.p_nodes;
      producer_steps = Hashtbl.length p.p_steps; operation_kinds = kinds;
      value_edges = p.p_value; address_edges = p.p_address; flag_edges = p.p_flag;
      control_edges = p.p_control; first_step = p.p_first; last_step = p.p_last } :: acc
  ) producer_table [] |> List.sort (fun (a : producer) (b : producer) ->
    let c = compare b.producer_steps a.producer_steps in
    if c <> 0 then c else compare (a.image.name,a.image_offset,a.runtime_pc,a.operation_kind)
      (b.image.name,b.image_offset,b.runtime_pc,b.operation_kind)) in
  let producer_location_count =
    let locations = Hashtbl.create 256 in
    List.iter (fun (p:producer) -> Hashtbl.replace locations (producer_key p.image p.image_offset p.runtime_pc) ()) producer_rows;
    Hashtbl.length locations
  in
  let source_groups=Hashtbl.fold(fun _ a acc->
    let offsets=sorted_offsets a.s_offsets in
    {kind=a.s_kind;identity=a.s_identity;classification=a.s_class;distinct_offsets=offsets;ranges=ranges_of_offsets offsets;leaf_occurrences=a.s_occurrences}::acc)source_table[]
    |> List.sort(fun (a : source_group) (b : source_group)->compare(a.kind,a.identity)(b.kind,b.identity)) in
  let operations=Hashtbl.fold(fun name a acc->{kind=name;node_count=a.o_nodes;producer_locations=Hashtbl.length a.o_locations;producer_steps=Hashtbl.length a.o_steps;value_edges=a.o_value;address_edges=a.o_address;flag_edges=a.o_flag;control_edges=a.o_control}::acc)operation_table[]
    |> List.sort(fun (a : operation_summary) (b : operation_summary)->let n=compare b.node_count a.node_count in if n<>0 then n else compare a.kind b.kind) in
  let producers=producer_rows in
  let preview=preview_of_root ~max_depth ~max_nodes provenance root in
  let sink_value=Option.map(fun (o:Provenance.output_observation)->o.value)observation in
  let write_step=Option.map(fun (o:Provenance.output_observation)->o.write_step_index)observation in
  {sink=selection;sink_value;write_step;root;full_node_count= !node_count;source_leaf_count= !source_count;
   producers;producer_location_count;distinct_producer_steps=Hashtbl.length producer_steps;unlocated_operation_nodes= !unlocated;
   operations;roles={value=roles.(0);address=roles.(1);flag=roles.(2);control=roles.(3)};
   sources=source_groups;source_leaves=List.rev !source_leaves;preview}

let output_meta provenance output_file output_bytes selected =
  List.init(Bytes.length output_bytes)(fun offset->
    let history=Provenance.output_byte_history provenance ~file:output_file ~offset in
    let n=List.length history in let final=match history with []->None|xs->Some(List.hd(List.rev xs)) in
    let projection_embedded=List.exists(fun s->s.file=output_file && s.offset=offset)selected in
    {offset;value=Char.code(Bytes.get output_bytes offset);write_step=Option.map(fun (o:Provenance.output_observation)->o.write_step_index)final;
     root_present=Option.fold ~none:false ~some:(fun (o:Provenance.output_observation)->o.root<>Provenance.Untracked)final;
     rewrite_count=max 0 (n-1);projection_embedded})

let report_of_provenance ?(preview_depth=6) ?(preview_nodes=250) ~provenance ~execution ~classify ~output_file ~output_bytes ~selected () =
  if preview_depth<0 || preview_nodes<1 then invalid_arg "Provenance_report preview bounds";
  let bases=virtual_bases execution in
  (* Missing report images are preserved as sources with unavailable virtual
     coordinates; they are not discarded or treated as an error. *)
  let rec projections acc=function
    |[]->Ok(List.rev acc)
    |selection::_ when selection.file<>output_file || selection.offset<0 || selection.offset>=Bytes.length output_bytes->Error(Missing_output_byte selection)
    |selection::rest->
        (match choose_generation provenance selection with
         |None->Error(Missing_output_byte selection)
         |Some _->projections(project_one ~max_depth:preview_depth ~max_nodes:preview_nodes ~classify ~bases provenance selection::acc)rest)
  in
  match projections [] selected with
  |Error _ as e->e
  |Ok projections->Ok{output_file;output_bytes=output_meta provenance output_file output_bytes selected;projections;execution}

let quote s =
  let b=Buffer.create(String.length s+8) in Buffer.add_char b '"';
  String.iter(fun c->match c with
   |'"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"
   |c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf "\\u%04X"(Char.code c))
   |c->Buffer.add_char b c)s;Buffer.add_char b '"';Buffer.contents b
let opt_int=function None->"null"|Some n->string_of_int n
let classification_json=function None->"null"|Some c->quote(class_name c)
let file_json (f:Cpm.Filesystem.key)=Printf.sprintf "{\"drive\":%d,\"user\":%d,\"name\":%s,\"identity\":%s}" f.drive f.user (quote f.name)(quote(key_string f))
let flow_edge = function Provenance.Value->"value"|Address->"address"|Flag->"flag"|Control->"control"
let to_json_string report =
  let out=Buffer.create 1024 in let add=Buffer.add_string out in let comma b i=if i>0 then Buffer.add_char b ',' in
  let json_execution=Execution_report.to_json_string report.execution in
  add "RUNES_PROVENANCE_REPORT 1\n{\"output_file\":";add(file_json report.output_file);add ",\"execution\":";add json_execution;
  add ",\"output_bytes\":[";
  List.iteri(fun i (byte:output_byte)->comma out i;Printf.bprintf out "{\"offset\":%d,\"value\":%d,\"write_step\":%s,\"root_present\":%b,\"rewrite_count\":%d,\"projection_embedded\":%b}" byte.offset byte.value(opt_int byte.write_step) byte.root_present byte.rewrite_count byte.projection_embedded)report.output_bytes;
  add "],\"selections\":[";
  List.iteri(fun si (p:projection)->comma out si;add "{\"sink\":{\"file\":";add(file_json p.sink.file);Printf.bprintf out ",\"offset\":%d,\"generation\":%s},\"value\":%s,\"write_step\":%s,\"root\":" p.sink.offset (opt_int p.sink.generation) (opt_int p.sink_value)(opt_int p.write_step);
    (match p.root with Provenance.Untracked->add "null"|Node id->Printf.bprintf out "%d" id);
    Printf.bprintf out ",\"full_node_count\":%d,\"source_leaf_count\":%d,\"producer_location_count\":%d,\"distinct_producer_steps\":%d,\"unlocated_operation_nodes\":%d,\"roles\":{\"value\":%d,\"address\":%d,\"flag\":%d,\"control\":%d},\"sources\":[" p.full_node_count p.source_leaf_count p.producer_location_count p.distinct_producer_steps p.unlocated_operation_nodes p.roles.value p.roles.address p.roles.flag p.roles.control;
    List.iteri(fun i (s:source_group)->comma out i;add "{\"kind\":";add(quote s.kind);add ",\"identity\":";add(quote s.identity);add ",\"classification\":";add(classification_json s.classification);Printf.bprintf out ",\"leaf_occurrences\":%d,\"distinct_source_bytes\":%d,\"offsets\":[" s.leaf_occurrences(List.length s.distinct_offsets);
      List.iteri(fun j off->comma out j;add(string_of_int off))s.distinct_offsets;add "],\"ranges\":[";
      List.iteri(fun j (r:offset_range)->comma out j;Printf.bprintf out "{\"first\":%d,\"last\":%d}" r.first r.last)s.ranges;add "]}")p.sources;
    add "],\"source_leaves\":[";
    List.iteri(fun i (s:source_leaf)->comma out i;Printf.bprintf out "{\"node_id\":%d,\"kind\":%s,\"identity\":%s,\"classification\":%s,\"offset\":%s,\"virtual_offset\":%s,\"value\":%d}" s.node_id(quote s.kind)(quote s.identity)(classification_json s.classification)(opt_int s.offset)(opt_int s.virtual_offset)s.value)p.source_leaves;
    add "],\"producers\":[";
    List.iteri(fun i (p:producer)->comma out i;Printf.bprintf out "{\"id\":%s,\"image\":%s,\"image_offset\":%d,\"virtual_offset\":%s,\"runtime_pc\":%d,\"operation_kind\":%s,\"operation_nodes\":%d,\"producer_steps\":%d,\"operation_kinds\":["(quote p.id)(file_json p.image)p.image_offset(opt_int p.virtual_offset)p.runtime_pc(quote p.operation_kind)p.operation_nodes p.producer_steps;
      List.iteri(fun j k->comma out j;add(quote k))p.operation_kinds;
      Printf.bprintf out "],\"value_edges\":%d,\"address_edges\":%d,\"flag_edges\":%d,\"control_edges\":%d,\"first_step\":%s,\"last_step\":%s}"p.value_edges p.address_edges p.flag_edges p.control_edges(opt_int p.first_step)(opt_int p.last_step))p.producers;
    add "],\"operations\":[";
    List.iteri(fun i (o:operation_summary)->comma out i;Printf.bprintf out "{\"kind\":%s,\"node_count\":%d,\"producer_locations\":%d,\"producer_steps\":%d,\"value_edges\":%d,\"address_edges\":%d,\"flag_edges\":%d,\"control_edges\":%d}"(quote o.kind)o.node_count o.producer_locations o.producer_steps o.value_edges o.address_edges o.flag_edges o.control_edges)p.operations;
    add "],\"preview\":{";Printf.bprintf out "\"max_depth\":%d,\"max_nodes\":%d,\"visible_nodes\":%d,\"omitted_frontier_count\":%d,\"truncated\":%b,\"nodes\":["p.preview.max_depth p.preview.max_nodes(List.length p.preview.nodes)p.preview.omitted_frontier_count(p.preview.omitted_frontier_count>0);
    List.iteri(fun i (n:preview_node)->comma out i;add "{\"id\":";add(string_of_int n.id);add ",\"label\":";add(quote n.label);Printf.bprintf out ",\"value\":%d,\"width\":%d,\"step\":%s,\"depth\":%d,\"origin\":"n.value n.width(opt_int n.step)n.depth;
      (match n.origin with None->add "null"|Some o->Printf.bprintf out "{\"image\":%s,\"offset\":%d,\"virtual_offset\":%s,\"runtime_pc\":%d}"(file_json o.image)o.offset(opt_int(Option.map(fun(base,_)->base+o.offset)(Hashtbl.find_opt (virtual_bases report.execution) o.image)))o.runtime_pc);add "}")p.preview.nodes;
    add "],\"edges\":[";
    List.iteri(fun i (e:preview_edge)->comma out i;Printf.bprintf out "{\"from\":%d,\"to\":%d,\"role\":%s}"e.from_id e.to_id(quote(flow_edge e.role)))p.preview.edges;
    add "]}}")report.projections;
  add "]}\n";Buffer.contents out

let write_json ~output report=output(to_json_string report)

type decision_acc = {
  da_image:Cpm.Filesystem.key option; da_offset:int option; da_pc:int;
  da_condition:string; da_taken:bool; mutable da_count:int;
  mutable da_first:int; mutable da_last:int; da_flags:(int,unit)Hashtbl.t;
}

let condition_name = function
  |I8080.Instr.Not_zero->"NZ"|Zero->"Z"|Not_carry->"NC"|Carry->"C"
  |Parity_odd->"PO"|Parity_even->"PE"|Positive->"P"|Minus->"M"

let decision_key (b:Provenance.branch_observation) =
  let image,offset=match b.origin with None->"",-1|Some o->key_string o.image,o.offset in
  Printf.sprintf "%s\000%d\000%d\000%s\000%b" image offset b.pc (condition_name b.condition) b.taken

let aggregate_decisions branches =
  let table=Hashtbl.create 512 in
  List.iter(fun (b:Provenance.branch_observation)->
    let key=decision_key b in
    let image,offset=match b.origin with None->None,None|Some o->Some o.image,Some o.offset in
    let acc=match Hashtbl.find_opt table key with
      |Some x->x
      |None->let x={da_image=image;da_offset=offset;da_pc=b.pc;da_condition=condition_name b.condition;
        da_taken=b.taken;da_count=0;da_first=b.step_index;da_last=b.step_index;da_flags=Hashtbl.create 2} in
        Hashtbl.add table key x;x in
    acc.da_count<-acc.da_count+1;acc.da_first<-min acc.da_first b.step_index;acc.da_last<-max acc.da_last b.step_index;
    List.iter(function Provenance.Node id->Hashtbl.replace acc.da_flags id ()|Untracked->())b.flag_inputs
  )branches;
  Hashtbl.fold(fun _ a xs->{image=a.da_image;image_offset=a.da_offset;runtime_pc=a.da_pc;
    condition=a.da_condition;taken=a.da_taken;decision_count=a.da_count;first_step=a.da_first;
    last_step=a.da_last;distinct_flag_roots=Hashtbl.length a.da_flags}::xs)table[]
  |>List.sort(fun (a:control_decision_row) (b:control_decision_row)->
    let image_name=function None->""|Some (x:Cpm.Filesystem.key)->key_string x in
    compare(image_name a.image,a.image_offset,a.runtime_pc,a.condition,a.taken)
      (image_name b.image,b.image_offset,b.runtime_pc,b.condition,b.taken))

let branch_location_key (b:Provenance.branch_observation) =
  match b.origin with None->Printf.sprintf "?:%04X" b.pc
  |Some o->Printf.sprintf "%s:%d:%d" (key_string o.image) o.offset b.pc

let control_preview provenance root =
  let max_depth=6 and max_nodes=120 in
  let queue=Queue.create() and seen=Hashtbl.create 256 and skipped=Hashtbl.create 32 in
  (match root with Untracked->()|Node id->Queue.add(id,0)queue);
  let nodes=ref [] in
  while not(Queue.is_empty queue) do
    let id,depth=Queue.take queue in
    if depth>max_depth then Hashtbl.replace skipped id ()
    else if not(Hashtbl.mem seen id) then
      if List.length !nodes>=max_nodes then Hashtbl.replace skipped id ()
      else (
        Hashtbl.add seen id depth;
        let n=Provenance.node provenance id in
        let label=match n.kind with Operation name->"operation/"^name
          |Source source->"source/"^source_kind source in
        nodes:={id=n.id;label;value=n.value;width=n.width;step=n.step_index;origin=n.origin;depth}::!nodes;
        List.iter(fun(_,child)->if not(Hashtbl.mem seen child)then Queue.add(child,depth+1)queue)n.inputs)
  done;
  let nodes=List.rev !nodes in
  let visible=Hashtbl.create(List.length nodes) in List.iter(fun n->Hashtbl.replace visible n.id())nodes;
  let edges=List.concat_map(fun n->(Provenance.node provenance n.id).inputs
    |>List.filter_map(fun(role,target)->if Hashtbl.mem visible target then Some{from_id=n.id;to_id=target;role}else None))nodes in
  {nodes;edges;max_depth;max_nodes;omitted_frontier_count=Hashtbl.length skipped}

let path_control_projection provenance (selection:sink) =
  match choose_generation provenance selection with
  |None->Error(Missing_output_byte selection)
  |Some observation->
      let context=Provenance.output_control_context provenance observation in
      let branches=Provenance.control_decisions_of_context provenance context in
      let locations=aggregate_decisions branches in
      let branch_locations=Hashtbl.create 512 in
      List.iter(fun b->Hashtbl.replace branch_locations (branch_location_key b)())branches;
      let data_ids=Hashtbl.create 4096 in
      ignore(Provenance.fold_reachable ~roles:Provenance.data_edge_roles provenance
        ~roots:[observation.root] ~init:() ~f:(fun () n->Hashtbl.replace data_ids n.Provenance.id()));
      let combined_nodes=ref 0 and control_relations=ref 0 in
      let context_nodes=ref 0 and decision_nodes=ref 0 and flag_ancestors=ref 0 in
      ignore(Provenance.fold_reachable ~roles:Provenance.all_edge_roles provenance
        ~roots:[observation.root;context] ~init:() ~f:(fun () n->
          incr combined_nodes;
          List.iter(fun(role,_)->if role=Provenance.Control then incr control_relations)n.inputs;
          if not(Hashtbl.mem data_ids n.Provenance.id) then
            match n.kind with
            |Provenance.Operation "Control.Context"->incr context_nodes
            |Operation "Control.Decision"->incr decision_nodes
            |Operation _|Source _->incr flag_ancestors));
      let step_extreme f=List.fold_left(fun acc (b:Provenance.branch_observation)->
        Some(Option.fold ~none:b.step_index ~some:(f b.step_index)acc))None branches in
      Ok {sink=selection;context_depth=List.length branches;distinct_branch_locations=Hashtbl.length branch_locations;
        earliest_decision_step=step_extreme min;latest_decision_step=step_extreme max;
        additional_context_nodes= !context_nodes;additional_decision_nodes= !decision_nodes;
        additional_flag_ancestors= !flag_ancestors;combined_reachable_nodes= !combined_nodes;
        control_relations= !control_relations;locations;preview=control_preview provenance context}

let path_control_report_of_provenance ~provenance ~selected =
  let rec build acc=function
    |[]->Ok {decisions=aggregate_decisions(Provenance.branch_observations provenance);paths=List.rev acc}
    |sink::rest->(match path_control_projection provenance sink with
      |Error e->Error e|Ok projection->build(projection::acc)rest)
  in build[]selected

let control_report_to_json_string report =
  let b=Buffer.create 65536 and q=Printf.sprintf "%S" in
  let add=Buffer.add_string b and fmt format=Printf.ksprintf (Buffer.add_string b) format in
  let comma ()=Buffer.add_char b ',' in
  let image_string=function None->"null"|Some (f:Cpm.Filesystem.key)->
    Printf.sprintf "{\"drive\":%d,\"user\":%d,\"name\":%s,\"identity\":%s}"
      f.drive f.user (q f.name)(q(key_string f)) in
  let row r=fmt "{\"image\":%s,\"image_offset\":%s,\"runtime_pc\":%d,\"condition\":%s,\"taken\":%s,\"decision_count\":%d,\"first_step\":%d,\"last_step\":%d,\"distinct_flag_roots\":%d}"
    (image_string r.image)(Option.fold ~none:"null" ~some:string_of_int r.image_offset)
    r.runtime_pc(q r.condition)(if r.taken then "true" else "false")r.decision_count
    r.first_step r.last_step r.distinct_flag_roots in
  add "RUNES_PROVENANCE_CONTROL_REPORT 1\n{\"decisions\":[";
  List.iteri(fun i r->if i>0 then comma();row r)report.decisions;
  add "],\"selections\":[";
  List.iteri(fun i p->if i>0 then comma();
    fmt "{\"file\":%s,\"offset\":%d,\"context_depth\":%d,\"distinct_branch_locations\":%d,\"earliest_decision_step\":%s,\"latest_decision_step\":%s,\"additional_context_nodes\":%d,\"additional_decision_nodes\":%d,\"additional_flag_ancestors\":%d,\"combined_reachable_nodes\":%d,\"control_relations\":%d,\"locations\":["
      (image_string(Some p.sink.file))p.sink.offset p.context_depth p.distinct_branch_locations
      (Option.fold ~none:"null" ~some:string_of_int p.earliest_decision_step)
      (Option.fold ~none:"null" ~some:string_of_int p.latest_decision_step)
      p.additional_context_nodes p.additional_decision_nodes p.additional_flag_ancestors
      p.combined_reachable_nodes p.control_relations;
    List.iteri(fun j r->if j>0 then comma();row r)p.locations;
    fmt "],\"preview\":{\"max_depth\":%d,\"max_nodes\":%d,\"visible_nodes\":%d,\"omitted_frontier_count\":%d,\"nodes\":["
      p.preview.max_depth p.preview.max_nodes(List.length p.preview.nodes)p.preview.omitted_frontier_count;
    List.iteri(fun j (n:preview_node)->if j>0 then comma();
      fmt "{\"id\":%d,\"label\":%s,\"value\":%d,\"width\":%d,\"step\":%s,\"depth\":%d,\"origin\":"
        n.id(q n.label)n.value n.width(Option.fold ~none:"null" ~some:string_of_int n.step)n.depth;
      (match n.origin with None->add "null"|Some o->fmt "{\"image\":{\"drive\":%d,\"user\":%d,\"name\":%s,\"identity\":%s},\"offset\":%d,\"runtime_pc\":%d}"
        o.image.drive o.image.user(q o.image.name)(q(key_string o.image))o.offset o.runtime_pc);
      add "}")p.preview.nodes;
    add "],\"edges\":[";
    List.iteri(fun j (e:preview_edge)->if j>0 then comma();
      fmt "{\"from\":%d,\"to\":%d,\"role\":%s}"e.from_id e.to_id(q(flow_edge e.role)))p.preview.edges;
    add "]}}")report.paths;
  add "]}\n";Buffer.contents b

let write_control_report_json ~output report=output(control_report_to_json_string report)
