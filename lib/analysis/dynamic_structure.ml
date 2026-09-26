[@@@warning "-4-27-40-41-42-69"]

type routine_id = int
type transition_kind = Call | Return | Restart | Image_entry | Other_observed
type tag = Entry | Image_entry_tag | Called | Returns | Recursive | Unresolved_origin

type routine = {
  id : routine_id; image : Execution_map.image_id option; entry_offset : int option;
  runtime_entry_pc : int; display_name : string; tags : tag list;
  first_execution_step : int option; last_execution_step : int option;
  instruction_executions : int; distinct_instruction_starts : int;
  incoming_routine_count : int; outgoing_routine_count : int;
  call_count : int; return_count : int; self_call_count : int; recursive : bool;
}

type transition = { source:int; target:int; occurrence_count:int; first_step:int;
  last_step:int; kinds:transition_kind list }
type narrative_entry = { ordinal:int; source:int; target:int; first_step:int; first_kind:transition_kind }
type anomaly_kind = Return_without_call | Return_target_mismatch | Jump_into_known_entry
  | Image_entry_without_transfer | Image_change_without_new_entry | Unknown_instruction_origin
type anomaly = { step:int; last_step:int; occurrence_count:int; kind:anomaly_kind; runtime_pc:int; detail:string }
type summary = { routine_count:int; narrative_transition_count:int; aggregate_pair_count:int;
  recursive_candidate_count:int; anomaly_count:int; anomaly_observation_count:int }

type identity = { image:Execution_map.image_id option; offset:int option; pc:int }
type routine_acc = {
  id:int; identity:identity; mutable tags:tag list; mutable first_step:int option;
  mutable last_step:int option; mutable executions:int; starts:(identity,unit)Hashtbl.t;
  mutable calls:int; mutable returns:int; mutable self_calls:int;
}
type pair_acc = { source:int; target:int; mutable count:int; first:int; mutable last:int;
  mutable kinds:transition_kind list }
type anomaly_acc = { first:int; mutable last:int; mutable count:int; kind:anomaly_kind; pc:int; detail:string }
type frame = { caller:int; return_pc:int }
type pending = { source:int; target_pc:int; real_transfer:bool }
type t = {
  by_identity:(identity,int)Hashtbl.t; by_id:(int,routine_acc)Hashtbl.t;
  mutable routines_rev:routine_acc list; pairs:((int*int),pair_acc)Hashtbl.t;
  mutable narrative_rev:narrative_entry list; mutable next_id:int;
  mutable current:int option; mutable stack:frame list;
  seen_images:(Execution_map.image_id,unit)Hashtbl.t;
  mutable pending:pending option; anomaly_map:((anomaly_kind*int*string),anomaly_acc)Hashtbl.t;
  mutable anomalies_rev:anomaly_acc list;
}

let create () = { by_identity=Hashtbl.create 257; by_id=Hashtbl.create 257;
  routines_rev=[];pairs=Hashtbl.create 257;narrative_rev=[];next_id=0;current=None;
  stack=[];seen_images=Hashtbl.create 17;pending=None;anomaly_map=Hashtbl.create 31;anomalies_rev=[] }

let transition_kind_name = function Call->"CALL"|Return->"RETURN"|Restart->"RST"
  |Image_entry->"IMAGE_ENTRY"|Other_observed->"OTHER"
let tag_name = function Entry->"entry"|Image_entry_tag->"image-entry"|Called->"called"
  |Returns->"returns"|Recursive->"recursive"|Unresolved_origin->"unresolved-origin"
let kind_rank = function Call->0|Return->1|Restart->2|Image_entry->3|Other_observed->4
let add_tag r tag = if not(List.mem tag r.tags)then r.tags<-tag::r.tags

let display_identity id = match id.image,id.offset with
  |Some image,Some offset->Printf.sprintf "%s%s+%04X"
      (if image.Cpm.Filesystem.drive=0 && image.user=0 then ""
       else Printf.sprintf "D%dU%d:" image.drive image.user) image.name offset
  |Some image,None->Printf.sprintf "%s%s+????"
      (if image.Cpm.Filesystem.drive=0 && image.user=0 then ""
       else Printf.sprintf "D%dU%d:" image.drive image.user) image.name
  |None,Some offset->Printf.sprintf "UNKNOWN+%04X" offset
  |None,None->Printf.sprintf "UNKNOWN+PC%04X" id.pc
let routine_name (r:routine) = r.display_name

let get_routine t identity = match Hashtbl.find_opt t.by_identity identity with
  |Some id->Hashtbl.find t.by_id id
  |None->let id=t.next_id in t.next_id<-id+1;
    let r={id;identity;tags=[];first_step=None;last_step=None;executions=0;
      starts=Hashtbl.create 31;calls=0;returns=0;self_calls=0} in
    Hashtbl.add t.by_identity identity id;Hashtbl.add t.by_id id r;t.routines_rev<-r::t.routines_rev;r

let identity_at map pc = match Execution_map.origin_at map (pc land 0xffff) with
  |Execution_map.Image_byte{image;offset}->{image=Some image;offset=Some offset;pc=pc land 0xffff}
  |Execution_map.Unknown->{image=None;offset=None;pc=pc land 0xffff}

let add_anomaly t ~step ~kind ~runtime_pc detail =
  let key=kind,runtime_pc,detail in
  match Hashtbl.find_opt t.anomaly_map key with
  |Some a->a.last<-step;a.count<-a.count+1
  |None->let a={first=step;last=step;count=1;kind;pc=runtime_pc;detail}in
    Hashtbl.add t.anomaly_map key a;t.anomalies_rev<-a::t.anomalies_rev

let add_transition t ~step ~source ~target ~kind =
  if source<>target then (
    let key=source,target in
    match Hashtbl.find_opt t.pairs key with
    |Some p->p.count<-p.count+1;p.last<-step;
      if not(List.mem kind p.kinds)then p.kinds<-kind::p.kinds
    |None->Hashtbl.add t.pairs key {source;target;count=1;first=step;last=step;kinds=[kind]};
      t.narrative_rev<-{ordinal=List.length t.narrative_rev;source;target;first_step=step;first_kind=kind}::t.narrative_rev)

let set_current t r = t.current<-Some r.id

let observe_step t map ~step_index step =
  let pc=I8080.Step.pc_before step in
  let here=identity_at map pc in
  let active=Option.bind t.current(fun id->Hashtbl.find_opt t.by_id id) in
  (match active,here.image with
   |Some current,Some image when not(Hashtbl.mem t.seen_images image) && current.identity.image=Some image ->
       add_tag current Image_entry_tag
   |Some current,Some image when current.identity.image<>Some image && not(Hashtbl.mem t.seen_images image)->
       let entered=get_routine t here in add_tag entered Image_entry_tag;
       let transfer=Option.value t.pending ~default:{source=current.id;target_pc=(-1);real_transfer=false} in
       if transfer.real_transfer && transfer.target_pc=pc then
         add_transition t ~step:step_index ~source:transfer.source ~target:entered.id ~kind:Image_entry
       else add_anomaly t ~step:step_index ~kind:Image_entry_without_transfer ~runtime_pc:pc
         "first execution in image had no immediately observed taken transfer to this PC";
       set_current t entered
   |Some current,Some image when current.identity.image<>Some image ->
       if here.image<>current.identity.image then
         add_anomaly t ~step:step_index ~kind:Image_change_without_new_entry ~runtime_pc:pc
           "execution entered an already observed image outside a known candidate entry"
   |_->());
  let r=match t.current with
    |Some id->Hashtbl.find t.by_id id
    |None->let initial=get_routine t here in add_tag initial Entry;set_current t initial;initial in
  if r.identity.image=None then add_tag r Unresolved_origin;
  if r.first_step=None then r.first_step<-Some step_index;
  r.last_step<-Some step_index;r.executions<-r.executions+1;
  if not(Hashtbl.mem r.starts here)then Hashtbl.add r.starts here ();
  (match here.image with Some image->if not(Hashtbl.mem t.seen_images image)then Hashtbl.add t.seen_images image ()|None->
    add_anomaly t ~step:step_index ~kind:Unknown_instruction_origin ~runtime_pc:pc
      "instruction bytes have no current image origin");
  t.pending<-None;
  let control=I8080.Step.control_flow step in
  let next_pc=I8080.Step.pc_after step in
  let instruction_bytes=I8080.Step.fetched_bytes step in
  let return_pc=(pc+Bytes.length instruction_bytes)land 0xffff in
  match control with
  |I8080.Step.Call{target;taken=true}->
      let callee=get_routine t (identity_at map target) in add_tag callee Called;callee.calls<-callee.calls+1;
      if callee.identity.image=None then add_tag callee Unresolved_origin;
      if callee.id=r.id then (callee.self_calls<-callee.self_calls+1;add_tag callee Recursive)
      else add_transition t ~step:step_index ~source:r.id ~target:callee.id ~kind:Call;
      t.stack<-{caller=r.id;return_pc}::t.stack;set_current t callee;
      t.pending<-Some{source=r.id;target_pc=target;real_transfer=true}
  |I8080.Step.Call{target;taken=false}->
      t.pending<-Some{source=r.id;target_pc=next_pc;real_transfer=false}
  |I8080.Step.Restart{target}->
      let callee=get_routine t (identity_at map target) in add_tag callee Called;callee.calls<-callee.calls+1;
      if callee.identity.image=None then add_tag callee Unresolved_origin;
      if callee.id=r.id then (callee.self_calls<-callee.self_calls+1;add_tag callee Recursive)
      else add_transition t ~step:step_index ~source:r.id ~target:callee.id ~kind:Restart;
      t.stack<-{caller=r.id;return_pc}::t.stack;set_current t callee;
      t.pending<-Some{source=r.id;target_pc=target;real_transfer=true}
  |I8080.Step.Return{target;taken=true}->
      r.returns<-r.returns+1;add_tag r Returns;
      (match t.stack with
       |frame::rest->
           t.stack<-rest;
           if target<>Some frame.return_pc then add_anomaly t ~step:step_index ~kind:Return_target_mismatch ~runtime_pc:pc
             (Printf.sprintf "return target %s, expected %04Xh; restoring observed caller" (match target with None->"unknown"|Some x->Printf.sprintf "%04Xh" x) frame.return_pc);
           add_transition t ~step:step_index ~source:r.id ~target:frame.caller ~kind:Return;
           t.current<-Some frame.caller
       |[]->
           add_anomaly t ~step:step_index ~kind:Return_without_call ~runtime_pc:pc "taken return with empty dynamic routine stack";
           (match target with Some target_pc->
             let dest=identity_at map target_pc in
             (match Hashtbl.find_opt t.by_identity dest with Some id->add_transition t ~step:step_index ~source:r.id ~target:id ~kind:Return;t.current<-Some id|None->())
            |None->()));
      t.pending<-Some{source=r.id;target_pc=Option.value target ~default:next_pc;real_transfer=true}
  |I8080.Step.Jump{target;taken=true}->
      (match Hashtbl.find_opt t.by_identity(identity_at map target)with
       |Some dest when dest<>r.id->add_transition t ~step:step_index ~source:r.id ~target:dest ~kind:Other_observed;
         add_anomaly t ~step:step_index ~kind:Jump_into_known_entry ~runtime_pc:pc
           (Printf.sprintf "taken jump targets known routine R%03d; active routine stack is unchanged" dest)
       |_->());
      t.pending<-Some{source=r.id;target_pc=target;real_transfer=true}
  |I8080.Step.Jump{target;taken=false}->t.pending<-Some{source=r.id;target_pc=next_pc;real_transfer=false}
  |_->()

let routine_snapshots t =
  let incoming=Hashtbl.create 31 and outgoing=Hashtbl.create 31 in
  Hashtbl.iter(fun (source,target) _->
    let add table id=Hashtbl.replace table id (1+Option.value(Hashtbl.find_opt table id)~default:0)in
    add outgoing source;add incoming target)t.pairs;
  List.rev t.routines_rev |> List.map(fun r->{id=r.id;image=r.identity.image;entry_offset=r.identity.offset;
    runtime_entry_pc=r.identity.pc;display_name=Printf.sprintf "R%03d · %s" r.id (display_identity r.identity);
    tags=List.filter(fun x->List.mem x r.tags)[Entry;Image_entry_tag;Called;Returns;Recursive;Unresolved_origin];
    first_execution_step=r.first_step;last_execution_step=r.last_step;instruction_executions=r.executions;
    distinct_instruction_starts=Hashtbl.length r.starts;
    incoming_routine_count=Option.value(Hashtbl.find_opt incoming r.id)~default:0;
    outgoing_routine_count=Option.value(Hashtbl.find_opt outgoing r.id)~default:0;
    call_count=r.calls;return_count=r.returns;self_call_count=r.self_calls;recursive=List.mem Recursive r.tags})

let routines t = routine_snapshots t
let transitions t = Hashtbl.fold(fun _ (p:pair_acc) acc->({source=p.source;target=p.target;occurrence_count=p.count;
  first_step=p.first;last_step=p.last;kinds=List.sort(fun a b->compare(kind_rank a)(kind_rank b))p.kinds}:transition)::acc)t.pairs []
  |>List.sort(fun (a:transition) (b:transition)->let c=compare a.first_step b.first_step in if c<>0 then c else compare(a.source,a.target)(b.source,b.target))
let narrative t = List.rev t.narrative_rev
let anomalies t = List.rev t.anomalies_rev |>List.map(fun a->{step=a.first;last_step=a.last;
  occurrence_count=a.count;kind=a.kind;runtime_pc=a.pc;detail=a.detail})
let summary t = {routine_count=Hashtbl.length t.by_id;narrative_transition_count=List.length t.narrative_rev;
  aggregate_pair_count=Hashtbl.length t.pairs;recursive_candidate_count=List.fold_left(fun n r->if List.mem Recursive r.tags then n+1 else n)0 t.routines_rev;
  anomaly_count=Hashtbl.length t.anomaly_map;
  anomaly_observation_count=Hashtbl.fold(fun _ a n->n+a.count)t.anomaly_map 0}

let json_quote s =
  let b=Buffer.create(String.length s+8)in Buffer.add_char b '"';
  String.iter(fun c->match c with '"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"|c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf"\\u%04x"(Char.code c))|c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b

let to_json_string t =
  let b=Buffer.create 4096 and add=Buffer.add_string in
  add b "RUNES_DYNAMIC_STRUCTURE 1\n{\"routines\":[";
  let routines=routines t in
  List.iteri(fun i (r:routine)->if i>0 then add b ",";
    Printf.bprintf b "{\"id\":%d,\"display\":%s,\"image\":%s,\"offset\":%s,\"runtime_entry_pc\":%d,\"tags\":["
      r.id(json_quote r.display_name)(match r.image with None->"null"|Some x->Printf.sprintf"{\"drive\":%d,\"user\":%d,\"name\":%s}"x.Cpm.Filesystem.drive x.user(json_quote x.name))
      (match r.entry_offset with None->"null"|Some x->string_of_int x)r.runtime_entry_pc;
    List.iteri(fun j tag->if j>0 then add b ",";add b(json_quote(tag_name tag)))r.tags;
    Printf.bprintf b "],\"first_step\":%s,\"last_step\":%s,\"executions\":%d,\"distinct_starts\":%d,\"incoming\":%d,\"outgoing\":%d,\"calls\":%d,\"returns\":%d,\"self_calls\":%d,\"recursive\":%b}"
      (match r.first_execution_step with None->"null"|Some x->string_of_int x)(match r.last_execution_step with None->"null"|Some x->string_of_int x)
      r.instruction_executions r.distinct_instruction_starts r.incoming_routine_count r.outgoing_routine_count r.call_count r.return_count r.self_call_count r.recursive)routines;
  add b "],\"transitions\":[";
  List.iteri(fun i (p:transition)->if i>0 then add b ",";Printf.bprintf b "{\"from\":%d,\"to\":%d,\"count\":%d,\"first_step\":%d,\"last_step\":%d,\"kinds\":["p.source p.target p.occurrence_count p.first_step p.last_step;
    List.iteri(fun j kind->if j>0 then add b ",";add b(json_quote(transition_kind_name kind)))p.kinds;add b "]}")(transitions t);
  add b "],\"narrative\":[";
  List.iteri(fun i (n:narrative_entry)->if i>0 then add b ",";Printf.bprintf b "{\"ordinal\":%d,\"from\":%d,\"to\":%d,\"first_step\":%d,\"kind\":%s}" n.ordinal n.source n.target n.first_step(json_quote(transition_kind_name n.first_kind)))(narrative t);
  add b "],\"anomalies\":[";
  List.iteri(fun i (a:anomaly)->if i>0 then add b ",";Printf.bprintf b "{\"step\":%d,\"last_step\":%d,\"count\":%d,\"kind\":%s,\"pc\":%d,\"detail\":%s}"a.step a.last_step a.occurrence_count
    (json_quote(match a.kind with Return_without_call->"return-without-call"|Return_target_mismatch->"return-target-mismatch"|Jump_into_known_entry->"jump-into-known-entry"|Image_entry_without_transfer->"image-entry-without-transfer"|Image_change_without_new_entry->"image-change-without-new-entry"|Unknown_instruction_origin->"unknown-instruction-origin"))a.runtime_pc(json_quote a.detail))(anomalies t);
  Printf.bprintf b "],\"summary\":{\"routine_candidates\":%d,\"narrative_transitions\":%d,\"aggregate_pairs\":%d,\"recursive_candidates\":%d,\"anomalies\":%d,\"anomaly_observations\":%d}}\n"
    (summary t).routine_count (summary t).narrative_transition_count (summary t).aggregate_pair_count (summary t).recursive_candidate_count (summary t).anomaly_count (summary t).anomaly_observation_count;
  Buffer.contents b
let write_json ~output t=output(to_json_string t)

let to_text ?(limit=20) t =
  if limit<0 then invalid_arg "Dynamic_structure.to_text";
  let b=Buffer.create 1024 and s=summary t and rs=routines t in
  Printf.bprintf b "routine candidates: %d\nnarrative transitions: %d\naggregate directed pairs: %d\nrecursive candidates: %d\nanomalies: %d groups (%d observations)\n"
    s.routine_count s.narrative_transition_count s.aggregate_pair_count s.recursive_candidate_count s.anomaly_count s.anomaly_observation_count;
  let find id=List.find(fun (r:routine)->r.id=id)rs in
  narrative t |>List.iteri(fun i (n:narrative_entry)->if i<limit then Printf.bprintf b "\n%03d  %s\n     -> %s   %s\n" n.ordinal (routine_name(find n.source))(routine_name(find n.target))(transition_kind_name n.first_kind));
  if s.narrative_transition_count>limit then Printf.bprintf b "\n... %d further first-observation transitions in JSON report\n"(s.narrative_transition_count-limit);
  Buffer.contents b
