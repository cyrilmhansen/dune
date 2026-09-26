[@@@warning "-4-27-40-41-42-69"]

type origin = Image_byte of { image:Execution_map.image_id; offset:int }
  | Unknown_origin | Mixed_origin | Interrupt_origin
type instruction_representation = Image_source | Observed_bytes
type instruction_tag = Unresolved_origin | Mixed_bytes | Interrupt_supplied | Byte_variant | Origin_variant
  | Image_bytes_disagree
type instruction = { id:int; routine_id:int; origin:origin; runtime_pc:int; bytes:bytes;
  decoded:I8080.Instr.t; text:string; representation:instruction_representation; variant:int; tags:instruction_tag list;
  first_step:int; last_step:int; execution_count:int }
type instruction_transition_kind = Sequential | Branch_taken | Branch_fallthrough | Call | Return | Restart | Other
type instruction_transition = { source_instruction:int; target_instruction:int; kind:instruction_transition_kind;
  occurrence_count:int; first_step:int; last_step:int }
type block_tag = Routine_entry | Branch_target | Branch_fallthrough_tag | Call_continuation
  | Return_continuation | Control_continuation | Multi_predecessor | Backward_edge_target
  | Unresolved_block_origin | Mixed_block_origin | Interrupt_block_origin | Variant_boundary
  | Observed_bytes_block
type block = { routine_id:int; id:int; display_name:string; image:Execution_map.image_id option;
  start_offset:int option; byte_length:int; runtime_start:int; origin:origin; tags:block_tag list;
  representation:instruction_representation;
  first_execution_step:int; last_execution_step:int; entry_count:int; instruction_count:int;
  predecessor_block_count:int; successor_block_count:int; instruction_ids:int list }
type block_transition = { source_routine:int; source_block:int; target_routine:int; target_block:int;
  occurrence_count:int; first_step:int; last_step:int; kinds:instruction_transition_kind list }
type narrative_entry = { ordinal:int; source_routine:int; source_block:int; target_routine:int;
  target_block:int; first_step:int; first_kind:instruction_transition_kind }
type anomaly_kind = Instruction_bytes_changed | Instruction_origin_changed | Decoded_length_mismatch
  | Instruction_image_bytes_disagree
type anomaly = { kind:anomaly_kind; routine_id:int; runtime_pc:int; first_step:int; last_step:int;
  occurrence_count:int; detail:string }
type code_key = Canonical_image_code | Observed_instruction_bytes of string
type node_code = Canonical_image of {length:int}
  | Observed_code of {bytes:string;decoded:I8080.Instr.t}
type report_code = Image_block_member of {block_index:int;relative_offset:int;length:int}
  | Observed_report_code of {origin:origin;runtime_pc:int;bytes:string;decoded:I8080.Instr.t}
type compact_instruction = { id:int; routine_id:int; code:report_code;
  variant:int; tags:instruction_tag list; first_step:int; last_step:int; execution_count:int }
type image_source = { mutable data:bytes; mutable known:bytes }
type summary = { instruction_count:int; block_count:int; transition_count:int;
  backward_edge_target_count:int; anomaly_count:int; anomaly_observation_count:int }
type report = { routine_names:(int*string) list; instructions_:compact_instruction array;
  instruction_transitions_:instruction_transition list; blocks_:block array;
  transitions_:block_transition list; narrative_:narrative_entry list; anomalies_:anomaly list;
  image_snapshots:(Execution_map.image_id*image_source) list; summary_:summary }

type core = { routine_id:int; origin:origin; pc:int }
type node_acc = { id:int; core:core; code:node_code; variant:int;
  mutable tags:instruction_tag list; mutable block_tags:block_tag list; mutable first:int; mutable last:int; mutable count:int;
  mutable terminates:bool }
type edge_key = int*int*instruction_transition_kind
type edge_acc = { source:int; target:int; kind:instruction_transition_kind; mutable count:int;
  mutable first:int; mutable last:int }
type previous = { node_id:int; routine_id:int; step_index:int; step:I8080.Step.t }
type anomaly_acc = { kind:anomaly_kind; routine_id:int; pc:int; first:int; mutable last:int;
  mutable count:int; detail:string }
type t = { mutable next_id:int; nodes_rev:node_acc list ref; nodes_by_id:(int,node_acc)Hashtbl.t;
  variants:((core*code_key),int)Hashtbl.t; variants_by_core:(core,(code_key*int)list)Hashtbl.t;
  nodes_by_pc:((int*int),int list)Hashtbl.t; origins_by_pc:((int*int),origin list)Hashtbl.t;
  edges:(edge_key,edge_acc)Hashtbl.t; predecessors:(int,(int,unit)Hashtbl.t)Hashtbl.t;
  successors:(int,(int,unit)Hashtbl.t)Hashtbl.t; mutable previous:previous option;
  anomalies:(anomaly_kind*int*int*string,anomaly_acc)Hashtbl.t; anomalies_rev:anomaly_acc list ref;
  image_sources:(Execution_map.image_id,image_source)Hashtbl.t }

let create () = { next_id=0; nodes_rev=ref []; nodes_by_id=Hashtbl.create 4096;
  variants=Hashtbl.create 4096; variants_by_core=Hashtbl.create 4096; nodes_by_pc=Hashtbl.create 4096;
  origins_by_pc=Hashtbl.create 4096; edges=Hashtbl.create 4096; predecessors=Hashtbl.create 4096;
  successors=Hashtbl.create 4096; previous=None; anomalies=Hashtbl.create 64; anomalies_rev=ref [];
  image_sources=Hashtbl.create 8 }

let instruction_transition_kind_name = function Sequential->"sequential"|Branch_taken->"branch-taken"
  |Branch_fallthrough->"branch-fallthrough"|Call->"call"|Return->"return"|Restart->"restart"|Other->"other"
let instruction_tag_name = function Unresolved_origin->"unresolved-origin"|Mixed_bytes->"mixed-origin"
  |Interrupt_supplied->"interrupt-supplied"|Byte_variant->"instruction-bytes-variant"|Origin_variant->"origin-variant"
  |Image_bytes_disagree->"image-bytes-disagree"
let block_tag_name = function Routine_entry->"routine-entry"|Branch_target->"branch-target"
  |Branch_fallthrough_tag->"branch-fallthrough"|Call_continuation->"call-continuation"
  |Return_continuation->"return-continuation"|Control_continuation->"control-continuation"
  |Multi_predecessor->"multi-predecessor"|Backward_edge_target->"backward-edge-target"
  |Unresolved_block_origin->"unresolved-origin"|Mixed_block_origin->"mixed-origin"
  |Interrupt_block_origin->"interrupt-origin"|Variant_boundary->"variant-boundary"|Observed_bytes_block->"observed-bytes"
let anomaly_kind_name = function Instruction_bytes_changed->"instruction-bytes-changed"
  |Instruction_origin_changed->"instruction-origin-changed"|Decoded_length_mismatch->"decoded-length-mismatch"
  |Instruction_image_bytes_disagree->"instruction-image-bytes-disagree"

let add_node_tag node tag = if not(List.mem tag node.tags) then node.tags<-tag::node.tags
let add_block_tag node tag = if not(List.mem tag node.block_tags) then node.block_tags<-tag::node.block_tags
let hex_bytes bytes = let b=Buffer.create(Bytes.length bytes*2) in
  Bytes.iter(fun c->Buffer.add_string b(Printf.sprintf "%02X" (Char.code c)))bytes;Buffer.contents b
let origin_at_step map step fetched =
  if I8080.Step.source step=I8080.Step.Interrupt_acknowledge then Interrupt_origin else
  let pc=I8080.Step.pc_before step in
  if Bytes.length fetched=0 then Unknown_origin else
  match Execution_map.origin_at map pc with
  |Execution_map.Unknown->
      let all_unknown=ref true in
      for i=1 to Bytes.length fetched-1 do
        if Execution_map.origin_at map ((pc+i) land 0xffff)<>Execution_map.Unknown then all_unknown:=false
      done;
      if !all_unknown then Unknown_origin else Mixed_origin
  |Execution_map.Image_byte {image;offset}->
      let consistent=ref true in
      for i=1 to Bytes.length fetched-1 do
        if Execution_map.origin_at map ((pc+i) land 0xffff)
          <>Execution_map.Image_byte {image;offset=offset+i} then consistent:=false
      done;
      if !consistent then Image_byte {image;offset} else Mixed_origin

let origin_text = function
  |Image_byte {image;offset}->Printf.sprintf "%s+%04X" image.Cpm.Filesystem.name offset
  |Unknown_origin->"unknown"|Mixed_origin->"mixed"|Interrupt_origin->"interrupt-acknowledge"
let origin_image_offset = function Image_byte {image;offset}->Some image,Some offset|_->None,None

let add_anomaly t ~kind ~routine_id ~pc ~step detail =
  let key=kind,routine_id,pc,detail in
  match Hashtbl.find_opt t.anomalies key with
  |Some anomaly->anomaly.last<-step;anomaly.count<-anomaly.count+1
  |None->let anomaly={kind;routine_id;pc;first=step;last=step;count=1;detail} in
    Hashtbl.add t.anomalies key anomaly;t.anomalies_rev:=anomaly::!(t.anomalies_rev)

let add_to_set table key value =
  let values=match Hashtbl.find_opt table key with Some values->values|None->let values=Hashtbl.create 4 in Hashtbl.add table key values;values in
  if Hashtbl.mem values value then false else (Hashtbl.add values value ();true)
let set_cardinal table key = match Hashtbl.find_opt table key with Some set->Hashtbl.length set|None->0

let grow_bytes old required =
  if required<=Bytes.length old then old else (
    let length=ref(max 64 (Bytes.length old)) in
    while !length<required do length:= !length*2 done;
    let next=Bytes.make !length '\000' in Bytes.blit old 0 next 0 (Bytes.length old);next)

let source_for t image = match Hashtbl.find_opt t.image_sources image with
  |Some source->source
  |None->let source={data=Bytes.empty;known=Bytes.empty}in Hashtbl.add t.image_sources image source;source

let remember_image_bytes t image offset fetched =
  let required=offset+Bytes.length fetched in
  if offset<0 || required<offset then false else
  let source=source_for t image in
  source.data<-grow_bytes source.data required;source.known<-grow_bytes source.known required;
  let consistent=ref true in
  Bytes.iteri(fun i byte->
    let at=offset+i in
    if Bytes.get source.known at<>'\000' && Bytes.get source.data at<>byte then consistent:=false
    else (Bytes.set source.data at byte;Bytes.set source.known at '\001'))fetched;
  !consistent

let remembered_bytes_match t image offset fetched =
  match Hashtbl.find_opt t.image_sources image with
  |None->None
  |Some source when offset>=0 && offset+Bytes.length fetched<=Bytes.length source.data->
      let known=ref true and equal=ref true in
      Bytes.iteri(fun i value->let at=offset+i in
        if Bytes.get source.known at='\000' then known:=false
        else if Bytes.get source.data at<>value then equal:=false)fetched;
      if !known then Some !equal else None
  |Some _->None

let source_slice sources image offset length =
  match List.find_opt(fun(id,_)->id=image)sources with
  |None->failwith "Dynamic_blocks: missing canonical image bytes"
  |Some(_,source)->
      if offset<0 || length<0 || offset+length>Bytes.length source.data then
        failwith "Dynamic_blocks: canonical instruction outside image snapshot";
      for i=offset to offset+length-1 do
        if Bytes.get source.known i='\000' then failwith "Dynamic_blocks: canonical image byte unavailable"
      done;
      Bytes.sub source.data offset length

let code_is_image = function Canonical_image _->true|Observed_code _->false

let mark_core_variants t core =
  match Hashtbl.find_opt t.variants_by_core core with
  |None->()
  |Some variants->List.iter(fun (_,id)->let n=Hashtbl.find t.nodes_by_id id in
      add_node_tag n Byte_variant;add_block_tag n Variant_boundary)variants

let instruction_node t map ~routine_id ~step_index step =
  let pc=I8080.Step.pc_before step land 0xffff and bytes=I8080.Step.fetched_bytes step in
  let origin=origin_at_step map step bytes in
  let decoded=I8080.Step.decoded step in
  let core={routine_id;origin;pc} in
  let existing_canonical=match origin with
    |Image_byte _->Hashtbl.find_opt t.variants(core,Canonical_image_code)
    |_->None in
  let existing_matches=match origin,existing_canonical with
    |Image_byte{image;offset},Some _ when decoded.length=Bytes.length bytes->
        remembered_bytes_match t image offset bytes=Some true
    |_->false in
  match existing_canonical,existing_matches with
  |Some id,true->
      let node=Hashtbl.find t.nodes_by_id id in node.last<-step_index;node.count<-node.count+1;node
  |_->
  let canonical=match origin with
    |Image_byte{image;offset} when existing_canonical=None && decoded.length=Bytes.length bytes->
        let matches=match remembered_bytes_match t image offset bytes with
          |Some result->result
          |None->
              let result=ref true in
              Bytes.iteri(fun index value->match Execution_map.byte_at map ~image ~offset:(offset+index) with
                |Some expected when expected=Char.code value->()
                |_->result:=false)bytes;
              if !result then result:=remember_image_bytes t image offset bytes;
              !result in
        if matches then
          (match I8080.Decode.decode bytes ~offset:0 with
           |Ok actual when actual.instr=decoded.instr->Some(image,offset,Bytes.length bytes)
           |_->None)
        else None
    |_->None in
  let code,key=match canonical with
    |Some(_,_,length)->Canonical_image{length},Canonical_image_code
    |None->let observed=Bytes.unsafe_to_string bytes in
        Observed_code{bytes=observed;decoded=decoded.instr},Observed_instruction_bytes observed in
  match Hashtbl.find_opt t.variants (core,key) with
  |Some id->
      let node=Hashtbl.find t.nodes_by_id id in node.last<-step_index;node.count<-node.count+1;
      node
  |None->
      let pc_key=routine_id,pc in
      let previous_origins=Option.value(Hashtbl.find_opt t.origins_by_pc pc_key)~default:[] in
      let origin_changed=previous_origins<>[] && not(List.mem origin previous_origins) in
      if origin_changed then (
        add_anomaly t ~kind:Instruction_origin_changed ~routine_id ~pc ~step:step_index
          (Printf.sprintf "origin changed from %s to %s" (origin_text(List.hd previous_origins)) (origin_text origin));
        List.iter(fun id->let n=Hashtbl.find t.nodes_by_id id in add_node_tag n Origin_variant;add_block_tag n Variant_boundary)
          (Option.value(Hashtbl.find_opt t.nodes_by_pc pc_key)~default:[]));
      if not(List.mem origin previous_origins) then Hashtbl.replace t.origins_by_pc pc_key (previous_origins@[origin]);
      let prior_variants=Option.value(Hashtbl.find_opt t.variants_by_core core)~default:[] in
      if prior_variants<>[] then (
        let old_code,_=List.hd prior_variants in
        add_anomaly t ~kind:Instruction_bytes_changed ~routine_id ~pc ~step:step_index
          (Printf.sprintf "instruction representation changed from %s to %s"
            (match old_code with Canonical_image_code->"canonical image bytes"
             |Observed_instruction_bytes old->hex_bytes(Bytes.of_string old)) (hex_bytes bytes));
        mark_core_variants t core);
      if decoded.I8080.Decode.length<>Bytes.length bytes then
        add_anomaly t ~kind:Decoded_length_mismatch ~routine_id ~pc ~step:step_index
          (Printf.sprintf "decoder length %d differs from fetched length %d" decoded.length (Bytes.length bytes));
      (match origin,canonical with
       |Image_byte _,None->add_anomaly t ~kind:Instruction_image_bytes_disagree ~routine_id ~pc ~step:step_index
           "fetched instruction bytes or decoder result do not match the referenced image bytes"
       |_->());
      let id=t.next_id in t.next_id<-id+1;
      let variant=List.length prior_variants in
      let tags=match origin with Image_byte _->[]|Unknown_origin->[Unresolved_origin]
        |Mixed_origin->[Mixed_bytes]|Interrupt_origin->[Interrupt_supplied] in
      let node={id;core;code;
        variant;tags;block_tags=[];first=step_index;last=step_index;count=1;
        terminates=(I8080.Step.control_flow step<>I8080.Step.Sequential)} in
      (match origin,canonical with Image_byte _,None->add_node_tag node Image_bytes_disagree;add_block_tag node Variant_boundary|_->());
      if prior_variants<>[] then (add_node_tag node Byte_variant;add_block_tag node Variant_boundary;mark_core_variants t core);
      if origin_changed then (add_node_tag node Origin_variant;add_block_tag node Variant_boundary);
      Hashtbl.add t.variants (core,key) id;
      Hashtbl.replace t.variants_by_core core (prior_variants@[key,id]);
      Hashtbl.add t.nodes_by_id id node;t.nodes_rev:=node::!(t.nodes_rev);
      Hashtbl.replace t.nodes_by_pc pc_key (id::Option.value(Hashtbl.find_opt t.nodes_by_pc pc_key)~default:[]);
      node

let edge_kind step = match I8080.Step.control_flow step with
  |I8080.Step.Sequential->Sequential
  |Jump {taken=true;_}->Branch_taken|Jump {taken=false;_}->Branch_fallthrough
  |Call {taken=true;_}->Call|Call {taken=false;_}->Branch_fallthrough
  |Return {taken=true;_}->Return|Return {taken=false;_}->Branch_fallthrough
  |Restart _->Restart|Halt->Other

let add_instruction_edge t ~source ~target ~kind ~step =
  let key=source,target,kind in
  match Hashtbl.find_opt t.edges key with
  |Some edge->edge.count<-edge.count+1;edge.last<-step;false
  |None->Hashtbl.add t.edges key {source;target;kind;count=1;first=step;last=step};
      let new_predecessor=add_to_set t.predecessors target source in
      ignore(add_to_set t.successors source target);
      new_predecessor

let observed_successor_tag t (prior:previous) (current:node_acc) kind new_predecessor =
  let same_routine=prior.routine_id=current.core.routine_id in
  (match kind with
   |Branch_taken->add_block_tag current Branch_target
   |Branch_fallthrough->add_block_tag current Branch_fallthrough_tag
   |_->());
  (match I8080.Step.control_flow prior.step with
   |I8080.Step.Call {taken=false;_}->add_block_tag current Call_continuation
   |I8080.Step.Return _->add_block_tag current Return_continuation
   |_->());
  if same_routine && I8080.Step.control_flow prior.step<>I8080.Step.Sequential then
    add_block_tag current Control_continuation;
  if new_predecessor && set_cardinal t.predecessors current.id>1 then add_block_tag current Multi_predecessor;
  if kind=Branch_taken then
    match (Hashtbl.find t.nodes_by_id prior.node_id).core.origin with
    |Image_byte {image=source_image;offset=source_offset}->
        (match current.core.origin with Image_byte {image=target_image;offset=target_offset}
          when source_image=target_image && target_offset<source_offset->add_block_tag current Backward_edge_target|_->())
    |_->()

let observe_step t map ~routine_id ~routine_entry ~step_index step =
  let current=instruction_node t map ~routine_id ~step_index step in
  if routine_entry then add_block_tag current Routine_entry;
  current.terminates<-current.terminates || I8080.Step.control_flow step<>I8080.Step.Sequential;
  (match t.previous with
   |None->()
   |Some prior->
       let kind=edge_kind prior.step in
       (* The transition is observed at the source instruction's step index. *)
       let new_predecessor=add_instruction_edge t ~source:prior.node_id ~target:current.id ~kind ~step:prior.step_index in
       observed_successor_tag t prior current kind new_predecessor);
  t.previous<-Some{node_id=current.id;routine_id;step_index;step}

let instruction_tag_rank = function Unresolved_origin->0|Mixed_bytes->1|Interrupt_supplied->2|Byte_variant->3
  |Origin_variant->4|Image_bytes_disagree->5
let ordered_instruction_tags tags=List.sort(fun a b->compare(instruction_tag_rank a)(instruction_tag_rank b))tags
let block_tag_rank = function Routine_entry->0|Branch_target->1|Branch_fallthrough_tag->2|Call_continuation->3
  |Return_continuation->4|Control_continuation->5|Multi_predecessor->6|Backward_edge_target->7
  |Unresolved_block_origin->8|Mixed_block_origin->9|Interrupt_block_origin->10|Variant_boundary->11|Observed_bytes_block->12
let ordered_block_tags tags=List.sort(fun a b->compare(block_tag_rank a)(block_tag_rank b))tags
let kind_rank = function Sequential->0|Branch_taken->1|Branch_fallthrough->2|Call->3|Return->4|Restart->5|Other->6
let node_length n=match n.code with Canonical_image{length;_}->length|Observed_code{bytes;_}->String.length bytes
let image_source_snapshots t = Hashtbl.fold(fun image source acc->
  (image,{data=Bytes.copy source.data;known=Bytes.copy source.known})::acc)t.image_sources []
let decode_instruction bytes=match I8080.Decode.decode bytes ~offset:0 with
  |Ok decoded->decoded.instr|Error _->failwith "Dynamic_blocks: canonical image instruction cannot be decoded"
let compact_node_snapshots t node_blocks block_indices blocks sources =
  List.rev !(t.nodes_rev) |>List.map(fun n->
    let routine_id,block_id=Hashtbl.find node_blocks n.id in
    let block_index=Hashtbl.find block_indices (routine_id,block_id) in
    let block=blocks.(block_index) in
    let code=match n.code,block.representation with
      |Canonical_image{length},Image_source->
          let image,offset=match n.core.origin with
            |Image_byte{image;offset}->image,offset
            |_->failwith "Dynamic_blocks: canonical node has no image origin" in
          let block_start=Option.get block.start_offset in
          if block.image<>Some image || offset<block_start || offset+length>block_start+block.byte_length then
            failwith "Dynamic_blocks: canonical instruction is outside its image block";
          Image_block_member{block_index;relative_offset=offset-block_start;length}
      |Canonical_image{length},Observed_bytes->
          let image,offset=match n.core.origin with
            |Image_byte{image;offset}->image,offset
            |_->failwith "Dynamic_blocks: canonical node has no image origin" in
          let bytes=source_slice sources image offset length in
          Observed_report_code{origin=n.core.origin;runtime_pc=n.core.pc;bytes=Bytes.unsafe_to_string bytes;
            decoded=decode_instruction bytes}
      |Observed_code{bytes;decoded},_->
          Observed_report_code{origin=n.core.origin;runtime_pc=n.core.pc;bytes;decoded} in
    {id=n.id;routine_id;code;variant=n.variant;tags=ordered_instruction_tags n.tags;
     first_step=n.first;last_step=n.last;execution_count=n.count})
  |>Array.of_list
let instruction_of_compact report (x:compact_instruction) =
  let bytes,decoded,representation,origin,runtime_pc=match x.code with
    |Image_block_member{block_index;relative_offset;length}->
        let block=report.blocks_.(block_index) in
        let image=Option.get block.image and start=Option.get block.start_offset in
        let offset=start+relative_offset in
        let bytes=source_slice report.image_snapshots image offset length in
        let decoded=decode_instruction bytes in
        bytes,decoded,Image_source,Image_byte{image;offset},(block.runtime_start+relative_offset)land 0xffff
    |Observed_report_code{origin;runtime_pc;bytes;decoded}->
        Bytes.of_string bytes,decoded,Observed_bytes,origin,runtime_pc
  in
  {id=x.id;routine_id=x.routine_id;origin;runtime_pc;bytes;decoded;
   text=I8080.Instr_format.format decoded;representation;variant=x.variant;tags=x.tags;
   first_step=x.first_step;last_step=x.last_step;execution_count=x.execution_count}
let edge_snapshots t = Hashtbl.fold(fun _ e acc->{source_instruction=e.source;target_instruction=e.target;kind=e.kind;
  occurrence_count=e.count;first_step=e.first;last_step=e.last}::acc)t.edges []
  |>List.sort(fun (a:instruction_transition) (b:instruction_transition)->let c=compare a.first_step b.first_step in if c<>0 then c else
     let c=compare a.source_instruction b.source_instruction in if c<>0 then c else
     let c=compare a.target_instruction b.target_instruction in if c<>0 then c else compare(kind_rank a.kind)(kind_rank b.kind))
let anomaly_snapshots t = List.rev !(t.anomalies_rev) |>List.map(fun a->{kind=a.kind;routine_id=a.routine_id;runtime_pc=a.pc;
  first_step=a.first;last_step=a.last;occurrence_count=a.count;detail=a.detail})

type pending_block={routine_id:int;node_ids:int list;entry_step:int;entry_node:int}
type block_edge_acc={sr:int;sb:int;tr:int;tb:int;mutable occurrences:int;mutable first:int;mutable last:int;
  first_kind:instruction_transition_kind;mutable edge_kinds:instruction_transition_kind list}
let add_kind kind kinds=if List.mem kind kinds then kinds else kind::kinds

let materialize t routines =
  let nodes=Array.of_list(List.rev !(t.nodes_rev)) in
  let edges=edge_snapshots t in
  let count=Array.length nodes in
  let node id=nodes.(id) in
  let entry_boundary = function Routine_entry|Branch_target|Branch_fallthrough_tag|Call_continuation
    |Return_continuation|Control_continuation|Multi_predecessor|Variant_boundary->true|_->false in
  let has_entry_tag n=List.exists entry_boundary n.block_tags in
  let has_variant_tag n=List.mem Byte_variant n.tags || List.mem Origin_variant n.tags || List.mem Image_bytes_disagree n.tags in
  let edge_table=Hashtbl.create(List.length edges) in
  List.iter(fun e->Hashtbl.replace edge_table(e.source_instruction,e.target_instruction,e.kind)e)edges;
  let outgoing_edges=Array.make count [] in
  Hashtbl.iter(fun (source,_,_) edge->outgoing_edges.(source)<-edge::outgoing_edges.(source))edge_table;
  let merge_to=Array.make count None in
  for source_id=0 to count-1 do
    let source=node source_id in
    let outs=outgoing_edges.(source_id) in
    match outs with
    |[edge] when edge.kind=Sequential && not source.terminates && code_is_image source.code && not(has_variant_tag source)->
        let target=node edge.target_instruction in
        let single_predecessor=match Hashtbl.find_opt t.predecessors target.id with
          |Some predecessors->Hashtbl.length predecessors=1 && Hashtbl.mem predecessors source.id
          |None->false in
        let origins_contiguous=match source.code,target.code,source.core.origin,target.core.origin with
          |Canonical_image _,Canonical_image _,Image_byte{image=left;offset=left_offset},Image_byte{image=right;offset=right_offset}->
              left=right && right_offset=left_offset+node_length source
          |_->false in
        let runtime_contiguous=target.core.pc=((source.core.pc+node_length source)land 0xffff) in
        if source.core.routine_id=target.core.routine_id && single_predecessor
           && code_is_image target.code && not(has_entry_tag target) && not(has_variant_tag target)
           && runtime_contiguous && origins_contiguous then merge_to.(source_id)<-Some target.id
    |_->()
  done;
  let is_merged_target=Array.make count false in
  Array.iteri(fun _ target->Option.iter(fun id->is_merged_target.(id)<-true)target)merge_to;
  let starts=ref [] in
  for id=0 to count-1 do if not is_merged_target.(id) then starts:=id::!starts done;
  let starts=List.sort(fun a b->let x=node a and y=node b in let c=compare x.first y.first in if c<>0 then c else compare a b)!starts in
  let assigned=Array.make count false in
  let walk start =
    let rec loop id acc =
      if assigned.(id) then List.rev acc else (
        assigned.(id)<-true;
        match merge_to.(id) with Some next->loop next (id::acc)|None->List.rev(id::acc))
    in loop start [] in
  let chains=ref(List.map(fun start->walk start)starts) in
  for id=0 to count-1 do if not assigned.(id) then chains:= !chains@[walk id] done;
  let chains=List.filter((<>)[])!chains in
  let entry_step ids=(node(List.hd ids)).first in
  let entry_node ids=List.hd ids in
  let chains=List.map(fun ids->{routine_id=(node(entry_node ids)).core.routine_id;node_ids=ids;
      entry_step=entry_step ids;entry_node=entry_node ids})chains
    |>List.sort(fun a b->let c=compare a.routine_id b.routine_id in if c<>0 then c else
       let c=compare a.entry_step b.entry_step in if c<>0 then c else compare a.entry_node b.entry_node) in
  let next_block_id=Hashtbl.create 64 in
  let node_blocks=Hashtbl.create count in
  let block_chains=ref [] in
  List.iter(fun chain->
    let id=Option.value(Hashtbl.find_opt next_block_id chain.routine_id)~default:0 in
    Hashtbl.replace next_block_id chain.routine_id(id+1);
    List.iter(fun instruction_id->Hashtbl.replace node_blocks instruction_id(chain.routine_id,id))chain.node_ids;
    block_chains:=(chain.routine_id,id,chain.node_ids)::!block_chains)chains;
  let block_chains=List.rev !block_chains in
  let make_block routine_id id node_ids =
    let first=node(List.hd node_ids) in
    let origin=first.core.origin in
    let byte_length=List.fold_left(fun n node_id->n+node_length(node node_id))0 node_ids in
    let canonical=match origin with Image_byte{image=expected_image;offset=expected_offset}->
      List.for_all(fun node_id->let n=node node_id in code_is_image n.code && not(has_variant_tag n))node_ids &&
      (match first.code with Canonical_image _->true|_->false) &&
      (match first.core.origin with Image_byte{image;offset}->image=expected_image && offset=expected_offset|_->false)
      |_->false in
    if canonical then (match origin with
     |Image_byte {image=expected_image;offset=expected_offset}->
         let next_offset=ref expected_offset and next_pc=ref first.core.pc in
         List.iter(fun instruction_id->let n=node instruction_id in
           (match n.core.origin,n.code with
             |Image_byte{image;offset},Canonical_image _
                when image=expected_image && offset= !next_offset->()
             |_->failwith "Dynamic_blocks: image-backed block spans origins or non-contiguous offsets");
           if n.core.pc<> !next_pc then failwith "Dynamic_blocks: image-backed block spans non-contiguous runtime PCs";
           next_offset:= !next_offset+node_length n;next_pc:=(!next_pc+node_length n)land 0xffff)node_ids;
         if !next_offset-expected_offset<>byte_length then failwith "Dynamic_blocks: image-backed block length invariant"
     |_->failwith "Dynamic_blocks: canonical block has no image origin");
    let tags=ref first.block_tags in
    (match origin with Unknown_origin->tags:=Unresolved_block_origin::!tags|Mixed_origin->tags:=Mixed_block_origin::!tags
      |Interrupt_origin->tags:=Interrupt_block_origin::!tags|Image_byte _->());
    if List.exists(fun node_id->has_variant_tag(node node_id))node_ids then tags:=Variant_boundary::!tags;
    if not canonical then tags:=Observed_bytes_block::!tags;
    let image,start_offset=if canonical then origin_image_offset origin else None,None in
    let first_execution_step=List.fold_left(fun best node_id->min best(node node_id).first)max_int node_ids in
    let last_execution_step=List.fold_left(fun best node_id->max best(node node_id).last)min_int node_ids in
    {routine_id;id;display_name=Printf.sprintf "R%03d.B%03d · %s" routine_id id
        (match origin with Image_byte {image;offset}->Printf.sprintf "%s+%04X" image.Cpm.Filesystem.name offset
          |Unknown_origin->Printf.sprintf "PC%04X" first.core.pc|Mixed_origin->Printf.sprintf "MIXED-PC%04X" first.core.pc
          |Interrupt_origin->Printf.sprintf "ACK-PC%04X" first.core.pc);
      image;start_offset;byte_length;runtime_start=first.core.pc;origin;tags=ordered_block_tags !tags;
      representation=(if canonical then Image_source else Observed_bytes);
      first_execution_step;last_execution_step;entry_count=first.count;instruction_count=List.length node_ids;
      predecessor_block_count=0;successor_block_count=0;instruction_ids=node_ids}
  in
  let raw_blocks=List.map(fun(rid,bid,node_ids)->make_block rid bid node_ids)block_chains in
  let block_edges=Hashtbl.create 4096 in
  List.iter(fun edge->
    let sr,sb=Hashtbl.find node_blocks edge.source_instruction and tr,tb=Hashtbl.find node_blocks edge.target_instruction in
    if (sr,sb)<>(tr,tb) || edge.kind<>Sequential then (
      let key=sr,sb,tr,tb in
      match Hashtbl.find_opt block_edges key with
      |Some acc->acc.occurrences<-acc.occurrences+edge.occurrence_count;acc.first<-min acc.first edge.first_step;
          acc.last<-max acc.last edge.last_step;acc.edge_kinds<-add_kind edge.kind acc.edge_kinds
      |None->Hashtbl.add block_edges key {sr;sb;tr;tb;occurrences=edge.occurrence_count;first=edge.first_step;
          last=edge.last_step;first_kind=edge.kind;edge_kinds=[edge.kind]}))edges;
  let transitions=Hashtbl.fold(fun _ e acc->{source_routine=e.sr;source_block=e.sb;target_routine=e.tr;
    target_block=e.tb;occurrence_count=e.occurrences;first_step=e.first;last_step=e.last;
    kinds=List.sort(fun a b->compare(kind_rank a)(kind_rank b))e.edge_kinds}::acc)block_edges []
    |>List.sort(fun (a:block_transition) (b:block_transition)->let c=compare a.first_step b.first_step in if c<>0 then c else
      compare(a.source_routine,a.source_block,a.target_routine,a.target_block)(b.source_routine,b.source_block,b.target_routine,b.target_block)) in
  let incoming=Hashtbl.create 256 and outgoing=Hashtbl.create 256 in
  List.iter(fun (e:block_transition)->
    ignore(add_to_set outgoing (e.source_routine,e.source_block) (e.target_routine,e.target_block));
    ignore(add_to_set incoming (e.target_routine,e.target_block) (e.source_routine,e.source_block)))transitions;
  let blocks=List.map(fun (b:block)->{b with predecessor_block_count=set_cardinal incoming(b.routine_id,b.id);
    successor_block_count=set_cardinal outgoing(b.routine_id,b.id)})raw_blocks in
  let blocks_array=Array.of_list blocks in
  let block_indices=Hashtbl.create(List.length blocks) in
  Array.iteri(fun index (b:block)->Hashtbl.add block_indices(b.routine_id,b.id)index)blocks_array;
  let seen=Hashtbl.create 256 and narrative_rev=ref [] in
  List.iter(fun (e:block_transition)->if e.source_routine=e.target_routine then (
    let key=e.source_routine,e.source_block,e.target_routine,e.target_block in
    if not(Hashtbl.mem seen key)then (
      Hashtbl.add seen key();
      narrative_rev:={ordinal=List.length !narrative_rev;source_routine=e.source_routine;source_block=e.source_block;
        target_routine=e.target_routine;target_block=e.target_block;first_step=e.first_step;
        first_kind=(Hashtbl.find block_edges (e.source_routine,e.source_block,e.target_routine,e.target_block)).first_kind}::!narrative_rev)))transitions;
  let narrative=List.rev !narrative_rev in
  let image_snapshots=image_source_snapshots t in
  let instructions=compact_node_snapshots t node_blocks block_indices blocks_array image_snapshots in
  let instruction_transitions=edge_snapshots t and anomalies=anomaly_snapshots t in
  let backward_edge_target_count=List.fold_left(fun n (b:block)->if List.mem Backward_edge_target b.tags then n+1 else n)0 blocks in
  let summary={instruction_count=Array.length instructions;block_count=List.length blocks;transition_count=List.length transitions;
    backward_edge_target_count;anomaly_count=List.length anomalies;
    anomaly_observation_count=List.fold_left(fun n a->n+a.occurrence_count)0 anomalies} in
  {routine_names=List.map(fun (r:Dynamic_structure.routine)->r.id,r.display_name)routines;
   instructions_=instructions;instruction_transitions_=instruction_transitions;blocks_=blocks_array;
   transitions_=transitions;narrative_=narrative;anomalies_=anomalies;image_snapshots;summary_=summary}

let instructions r=Array.to_list(Array.map(instruction_of_compact r)r.instructions_)
let instruction_by_id r id =
  if id<0 || id>=Array.length r.instructions_ then None
  else Some(instruction_of_compact r r.instructions_.(id))
let instruction_transitions r=r.instruction_transitions_
let blocks r=Array.to_list r.blocks_
let transitions r=r.transitions_
let narrative r=r.narrative_
let anomalies r=r.anomalies_
let summary r=r.summary_

let json_quote s = let b=Buffer.create(String.length s+8) in Buffer.add_char b '"';
  String.iter(fun c->match c with '"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"
    |'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"
    |c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf "\\u%04x"(Char.code c))|c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b
let json_origin = function
  |Image_byte {image;offset}->Printf.sprintf "{\"kind\":\"image\",\"drive\":%d,\"user\":%d,\"image\":%s,\"offset\":%d}"
      image.Cpm.Filesystem.drive image.user (json_quote image.name) offset
  |Unknown_origin->"{\"kind\":\"unknown\"}"|Mixed_origin->"{\"kind\":\"mixed\"}"
  |Interrupt_origin->"{\"kind\":\"interrupt-acknowledge\"}"
let json_tags name values = "["^String.concat "," (List.map(fun x->json_quote(name x))values)^"]"
let json_block_tags tags=json_tags block_tag_name (List.filter((<>)Observed_bytes_block)tags)
let to_json_string report =
  let b=Buffer.create 32768 and add=Buffer.add_string in
  add b "RUNES_DYNAMIC_BLOCKS 1\n{\"routines\":[";
  List.iteri(fun i (id,name)->if i>0 then add b ",";Printf.bprintf b "{\"id\":%d,\"display\":%s}" id(json_quote name))report.routine_names;
  add b "],\"instructions\":[";
  Array.iteri(fun i compact->if i>0 then add b ",";let x=instruction_of_compact report compact in Printf.bprintf b
    "{\"id\":%d,\"routine\":%d,\"origin\":%s,\"runtime_pc\":%d,\"bytes\":%s,\"text\":%s,\"variant\":%d,\"tags\":%s,\"first_step\":%d,\"last_step\":%d,\"executions\":%d}"
    x.id x.routine_id(json_origin x.origin)x.runtime_pc(json_quote(hex_bytes x.bytes))(json_quote x.text)x.variant
    (json_tags instruction_tag_name x.tags)x.first_step x.last_step x.execution_count)report.instructions_;
  add b "],\"instruction_transitions\":[";
  List.iteri(fun i (e:instruction_transition)->if i>0 then add b ",";Printf.bprintf b
    "{\"from\":%d,\"to\":%d,\"kind\":%s,\"count\":%d,\"first_step\":%d,\"last_step\":%d}"
    e.source_instruction e.target_instruction(json_quote(instruction_transition_kind_name e.kind))e.occurrence_count e.first_step e.last_step)report.instruction_transitions_;
  add b "],\"blocks\":[";
  Array.iteri(fun i (x:block)->if i>0 then add b ",";Printf.bprintf b
    "{\"routine\":%d,\"id\":%d,\"display\":%s,\"image\":%s,\"start_offset\":%s,\"byte_length\":%d,\"runtime_start\":%d,\"origin\":%s,\"tags\":%s,\"first_step\":%d,\"last_step\":%d,\"entries\":%d,\"instruction_count\":%d,\"predecessors\":%d,\"successors\":%d,\"instructions\":[%s]}"
    x.routine_id x.id(json_quote x.display_name)
    (match x.image with None->"null"|Some image->Printf.sprintf "{\"drive\":%d,\"user\":%d,\"name\":%s}"image.Cpm.Filesystem.drive image.user(json_quote image.name))
    (match x.start_offset with None->"null"|Some offset->string_of_int offset)x.byte_length x.runtime_start(json_origin x.origin)
    (json_block_tags x.tags)x.first_execution_step x.last_execution_step x.entry_count x.instruction_count
    x.predecessor_block_count x.successor_block_count(String.concat ","(List.map string_of_int x.instruction_ids)))report.blocks_;
  add b "],\"transitions\":[";
  List.iteri(fun i (e:block_transition)->if i>0 then add b ",";Printf.bprintf b
    "{\"from\":[%d,%d],\"to\":[%d,%d],\"count\":%d,\"first_step\":%d,\"last_step\":%d,\"kinds\":%s}"
    e.source_routine e.source_block e.target_routine e.target_block e.occurrence_count e.first_step e.last_step
    (json_tags instruction_transition_kind_name e.kinds))report.transitions_;
  add b "],\"narrative\":[";
  List.iteri(fun i (e:narrative_entry)->if i>0 then add b ",";Printf.bprintf b
    "{\"ordinal\":%d,\"from\":[%d,%d],\"to\":[%d,%d],\"first_step\":%d,\"kind\":%s}"
    e.ordinal e.source_routine e.source_block e.target_routine e.target_block e.first_step
    (json_quote(instruction_transition_kind_name e.first_kind)))report.narrative_;
  add b "],\"anomalies\":[";
  List.iteri(fun i (a:anomaly)->if i>0 then add b ",";Printf.bprintf b
    "{\"kind\":%s,\"routine\":%d,\"runtime_pc\":%d,\"first_step\":%d,\"last_step\":%d,\"count\":%d,\"detail\":%s}"
    (json_quote(anomaly_kind_name a.kind))a.routine_id a.runtime_pc a.first_step a.last_step a.occurrence_count(json_quote a.detail))report.anomalies_;
  Printf.bprintf b "],\"summary\":{\"routines\":%d,\"blocks\":%d,\"instructions\":%d,\"transitions\":%d,\"backward_edge_targets\":%d,\"anomalies\":%d,\"anomaly_observations\":%d}}\n"
    (List.length report.routine_names)report.summary_.block_count report.summary_.instruction_count report.summary_.transition_count
    report.summary_.backward_edge_target_count report.summary_.anomaly_count report.summary_.anomaly_observation_count;
  Buffer.contents b
let write_json ~output report=output(to_json_string report)

let to_text ?(routine_limit=2) ?(blocks_per_routine=3) ?(instructions_per_block=6) report =
  if routine_limit<0 || blocks_per_routine<0 || instructions_per_block<0 then invalid_arg "Dynamic_blocks.to_text";
  let s=report.summary_ and b=Buffer.create 2048 in
  Printf.bprintf b "observed basic blocks: %d\nobserved instructions: %d\nblock transitions: %d\nbackward-edge targets: %d\nblock anomalies: %d groups (%d observations)\n"
    s.block_count s.instruction_count s.transition_count s.backward_edge_target_count s.anomaly_count s.anomaly_observation_count;
  let shown=Hashtbl.create routine_limit in
  let routine_display id=Option.value(List.assoc_opt id report.routine_names)~default:(Printf.sprintf "R%03d" id) in
  Array.iter (fun (block:block) ->
    if Hashtbl.length shown<routine_limit && not (Hashtbl.mem shown block.routine_id) then begin
      Hashtbl.add shown block.routine_id ();
      Printf.bprintf b "\n%s\n" (routine_display block.routine_id);
      let sibling=Array.to_list report.blocks_ |>List.filter (fun (x:block)->x.routine_id=block.routine_id) in
      List.iteri (fun index (x:block) ->
        if index<blocks_per_routine then begin
          Printf.bprintf b "  B%03d %s\n" x.id
            (match x.start_offset with Some offset->Printf.sprintf "+%04X" offset|None->Printf.sprintf "PC%04X" x.runtime_start);
          List.iteri (fun j id ->
            if j<instructions_per_block then
              match instruction_by_id report id with
              |Some instruction->Printf.bprintf b "    %04X  %s\n" instruction.runtime_pc instruction.text
              |None->assert false) x.instruction_ids
        end) sibling
    end) report.blocks_;
  Buffer.contents b
