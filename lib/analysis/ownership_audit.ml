[@@@warning "-4-27-40-41-42-69"]

type example = Dynamic_structure.audit_event
type jump_site = { owner:int; source:Dynamic_structure.identity; target_candidate:int;
  target:Dynamic_structure.identity; mutable observations:int; mutable examples:example list }
type entry_site = { owner:int; target_candidate:int option; target:Dynamic_structure.identity;
  transfer:Dynamic_structure.transfer_site option; cross_image:bool;
  mutable observations:int; mutable examples:example list }
type return_site = { active:int; caller:int; expected_pc:int; observed_pc:int option;
  active_image:Cpm.Filesystem.key option; caller_image:Cpm.Filesystem.key option;
  expected_image:Cpm.Filesystem.key option; observed_image:Cpm.Filesystem.key option;
  mutable observations:int; mutable examples:example list }
type t = {
  max_examples:int;
  coordinates:((Execution_map.image_id*int),(int,unit)Hashtbl.t)Hashtbl.t;
  jumps:((int*Execution_map.image_id option*int option*int*int*int),jump_site)Hashtbl.t;
  pairs:((int*int),unit)Hashtbl.t;
  entries:((int*int option*Execution_map.image_id option*int option*int*bool),entry_site)Hashtbl.t;
  returns:((int*int*int*int option*Execution_map.image_id option*Execution_map.image_id option*
    Execution_map.image_id option*Execution_map.image_id option),return_site)Hashtbl.t;
}

type summary = { known_entry_jmp_sites:int; known_entry_jmp_observations:int;
  source_target_candidate_pairs:int; multi_owner_coordinate_count:int;
  affected_routine_ids:int list; ownership_conflict_observations:int;
  return_mismatch_observations:int }
type routine_impact = { routine_id:int; multi_owner_instructions:int; multi_owner_blocks:int option }

let create ?(max_examples=3) () =
  if max_examples<0 then invalid_arg "Ownership_audit.create";
  {max_examples;coordinates=Hashtbl.create 4096;jumps=Hashtbl.create 64;pairs=Hashtbl.create 64;
   entries=Hashtbl.create 64;returns=Hashtbl.create 64}

let observe_step t map ~routine_id ~step_index:_ step events =
  let pc=I8080.Step.pc_before step land 0xffff in
  (match Execution_map.origin_at map pc with
   |Execution_map.Image_byte{image;offset}->
       let owners=match Hashtbl.find_opt t.coordinates(image,offset)with
         |Some owners->owners|None->let owners=Hashtbl.create 2 in Hashtbl.add t.coordinates(image,offset)owners;owners in
       Hashtbl.replace owners routine_id ()
   |Execution_map.Unknown->());
  List.iter(function
    |Dynamic_structure.Known_entry_jump event->
        let key=event.owner,event.source.image,event.source.offset,event.source.pc,event.target_candidate,event.target.pc in
        let site:jump_site=match Hashtbl.find_opt t.jumps key with
          |Some site->site
          |None->let site={owner=event.owner;source=event.source;target_candidate=event.target_candidate;
              target=event.target;observations=0;examples=[]}in Hashtbl.add t.jumps key site;site in
        site.observations<-site.observations+1;
        if List.length site.examples<t.max_examples then site.examples<-Dynamic_structure.Known_entry_jump event::site.examples;
        Hashtbl.replace t.pairs(event.owner,event.target_candidate)()
    |Dynamic_structure.Known_entry_under_other_owner event->
        let key=event.owner,Some event.target_candidate,event.target.image,event.target.offset,event.target.pc,false in
        let site:entry_site=match Hashtbl.find_opt t.entries key with Some x->x|None->
          let x={owner=event.owner;target_candidate=Some event.target_candidate;target=event.target;
            transfer=event.transfer;cross_image=false;observations=0;examples=[]}in Hashtbl.add t.entries key x;x in
        site.observations<-site.observations+1;
        if List.length site.examples<t.max_examples then site.examples<-Dynamic_structure.Known_entry_under_other_owner event::site.examples
    |Dynamic_structure.Known_image_under_other_owner event->
        let key=event.owner,event.target_candidate,event.target.image,event.target.offset,event.target.pc,true in
        let site:entry_site=match Hashtbl.find_opt t.entries key with Some x->x|None->
          let x={owner=event.owner;target_candidate=event.target_candidate;target=event.target;
            transfer=event.transfer;cross_image=true;observations=0;examples=[]}in Hashtbl.add t.entries key x;x in
        site.observations<-site.observations+1;
        if List.length site.examples<t.max_examples then site.examples<-Dynamic_structure.Known_image_under_other_owner event::site.examples
    |Dynamic_structure.Return_target_mismatch_detail event->
        let key=event.active_routine,event.expected_caller,event.expected_return_pc,event.observed_return_target,
          event.active_image,event.caller_image,event.expected_image,event.observed_image in
        let site:return_site=match Hashtbl.find_opt t.returns key with Some x->x|None->
          let x={active=event.active_routine;caller=event.expected_caller;expected_pc=event.expected_return_pc;
            observed_pc=event.observed_return_target;active_image=event.active_image;caller_image=event.caller_image;
            expected_image=event.expected_image;observed_image=event.observed_image;observations=0;examples=[]}in
          Hashtbl.add t.returns key x;x in
        site.observations<-site.observations+1;
        if List.length site.examples<t.max_examples then site.examples<-Dynamic_structure.Return_target_mismatch_detail event::site.examples
    )events

let multi_owner_coordinates t =
  Hashtbl.fold(fun (image,offset) owners acc->
    if Hashtbl.length owners>1 then (image,offset,Hashtbl.fold(fun id () ids->id::ids)owners []|>List.sort compare)::acc else acc)
    t.coordinates []
  |>List.sort(fun (ia,oa,_) (ib,ob,_)->
    let c=compare(ia.Cpm.Filesystem.drive,ia.user,ia.name)(ib.Cpm.Filesystem.drive,ib.user,ib.name)in
    if c<>0 then c else compare oa ob)

let summary t =
  let overlaps=multi_owner_coordinates t in
  {known_entry_jmp_sites=Hashtbl.length t.jumps;
   known_entry_jmp_observations=Hashtbl.fold(fun _ (x:jump_site) n->n+x.observations)t.jumps 0;
   source_target_candidate_pairs=Hashtbl.length t.pairs;
   multi_owner_coordinate_count=List.length overlaps;
   affected_routine_ids=List.fold_left(fun ids (_,_,owners)->List.fold_left(fun ids id->if List.mem id ids then ids else id::ids)ids owners)[]overlaps|>List.sort compare;
   ownership_conflict_observations=Hashtbl.fold(fun _ (x:entry_site) n->n+x.observations)t.entries 0;
   return_mismatch_observations=Hashtbl.fold(fun _ (x:return_site) n->n+x.observations)t.returns 0}

let routine_impacts t blocks =
  let overlaps=multi_owner_coordinates t in
  let coord_owners=Hashtbl.create(List.length overlaps)in
  List.iter(fun (image,offset,owners)->Hashtbl.add coord_owners(image,offset)owners)overlaps;
  let instruction_ids=Hashtbl.create 32 and block_sets=Hashtbl.create 32 in
  (match blocks with None->()|Some report->
    let instructions=Dynamic_blocks.instructions report in
    let by_id=Hashtbl.create(List.length instructions)in
    List.iter(fun (i:Dynamic_blocks.instruction)->Hashtbl.add by_id i.id i)instructions;
    List.iter(fun (b:Dynamic_blocks.block)->
      let affected=ref false in
      List.iter(fun id->match Hashtbl.find_opt by_id id with
        |Some {origin=Dynamic_blocks.Image_byte{image;offset};routine_id;_} when Hashtbl.mem coord_owners(image,offset)->
            let seen=Option.value(Hashtbl.find_opt instruction_ids routine_id)~default:(Hashtbl.create 8)in
            Hashtbl.replace instruction_ids routine_id seen;
            Hashtbl.replace seen id ();
            affected:=true
        |_->())b.instruction_ids;
      if !affected then (let ids=Option.value(Hashtbl.find_opt block_sets b.routine_id)~default:[] in
        if not(List.mem b.id ids)then Hashtbl.replace block_sets b.routine_id (b.id::ids)))
      (Dynamic_blocks.blocks report));
  let owners=summary t |>fun s->s.affected_routine_ids in
  List.map(fun routine_id->{routine_id;
    multi_owner_instructions=Option.value(Option.map Hashtbl.length(Hashtbl.find_opt instruction_ids routine_id))~default:
      (List.fold_left(fun count (_,_,ids)->if List.mem routine_id ids then count+1 else count)0 overlaps);
    multi_owner_blocks=Option.map(fun _->List.length(Option.value(Hashtbl.find_opt block_sets routine_id)~default:[]))blocks})owners

let json_quote s =
  let b=Buffer.create(String.length s+8)in Buffer.add_char b '"';
  String.iter(fun c->match c with '"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"|'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"|c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf"\\u%04x"(Char.code c))|c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b
let json_image = function None->"null"|Some image->Printf.sprintf"{\"drive\":%d,\"user\":%d,\"name\":%s}"image.Cpm.Filesystem.drive image.user(json_quote image.name)
let json_identity i=Printf.sprintf"{\"image\":%s,\"offset\":%s,\"runtime_pc\":%d}"(json_image i.Dynamic_structure.image)
  (match i.offset with None->"null"|Some x->string_of_int x)i.pc
let json_transfer = function None->"null"|Some x->Printf.sprintf"{\"owner\":%d,\"source\":%s,\"target_pc\":%d,\"kind\":%s}"
  x.Dynamic_structure.owner(json_identity x.source)x.target_pc(json_quote(match x.transfer with Jump_transfer->"JMP"|Call_transfer->"CALL"|Return_transfer->"RETURN"|Restart_transfer->"RST"))
let json_events events = "["^String.concat "," (List.map(function
  |Dynamic_structure.Known_entry_jump e->Printf.sprintf"{\"step\":%d,\"owner\":%d,\"source\":%s,\"target_candidate\":%d,\"target\":%s,\"sp_before\":%s,\"sp_after\":%s}"
      e.step e.owner(json_identity e.source)e.target_candidate(json_identity e.target)
      (match e.sp_before with None->"null"|Some x->string_of_int x)(match e.sp_after with None->"null"|Some x->string_of_int x)
  |Dynamic_structure.Known_entry_under_other_owner e->Printf.sprintf"{\"step\":%d,\"owner\":%d,\"target_candidate\":%d,\"target\":%s,\"transfer\":%s}"
      e.step e.owner e.target_candidate(json_identity e.target)(json_transfer e.transfer)
  |Dynamic_structure.Known_image_under_other_owner e->Printf.sprintf"{\"step\":%d,\"owner\":%d,\"target_candidate\":%s,\"target\":%s,\"transfer\":%s}"
      e.step e.owner(match e.target_candidate with None->"null"|Some x->string_of_int x)(json_identity e.target)(json_transfer e.transfer)
  |Dynamic_structure.Return_target_mismatch_detail e->Printf.sprintf"{\"step\":%d,\"active_routine\":%d,\"active_image\":%s,\"expected_caller\":%d,\"caller_image\":%s,\"expected_return_pc\":%d,\"expected_image\":%s,\"observed_return_target\":%s,\"observed_image\":%s}"
      e.step e.active_routine(json_image e.active_image)e.expected_caller(json_image e.caller_image)e.expected_return_pc(json_image e.expected_image)
      (match e.observed_return_target with None->"null"|Some x->string_of_int x)(json_image e.observed_image))events)^"]"
let event_site_json (site:entry_site) = Printf.sprintf"{\"owner\":%d,\"source\":%s,\"target_candidate\":%s,\"target\":%s,\"cross_image\":%b,\"observations\":%d,\"examples\":%s}"
  site.owner (match site.transfer with None->"null"|Some transfer->json_identity transfer.Dynamic_structure.source)
  (match site.target_candidate with None->"null"|Some x->string_of_int x)
  (json_identity site.target) site.cross_image site.observations(json_events(List.rev site.examples))

let to_json_string ?blocks t =
  let b=Buffer.create 4096 and s=summary t in
  let add=Buffer.add_string in
  add b "RUNES_OWNERSHIP_AUDIT 1\n";
  Printf.bprintf b "{\"summary\":{\"known_entry_jmp_sites\":%d,\"known_entry_jmp_observations\":%d,\"source_target_candidate_pairs\":%d,\"multi_owner_coordinates\":%d,\"affected_routine_ids\":[%s],\"ownership_conflict_observations\":%d,\"return_mismatch_observations\":%d},\"known_entry_jumps\":["
    s.known_entry_jmp_sites s.known_entry_jmp_observations s.source_target_candidate_pairs s.multi_owner_coordinate_count
    (String.concat ","(List.map string_of_int s.affected_routine_ids))s.ownership_conflict_observations s.return_mismatch_observations;
  let identity_key (i:Dynamic_structure.identity)=i.image,i.offset,i.pc in
  let jumps=Hashtbl.fold(fun _ (x:jump_site) xs->x::xs)t.jumps []|>List.sort(fun (a:jump_site) (b:jump_site)->
    compare(a.owner,identity_key a.source,a.target_candidate,identity_key a.target)
      (b.owner,identity_key b.source,b.target_candidate,identity_key b.target))in
  List.iteri(fun i (site:jump_site)->if i>0 then add b ",";Printf.bprintf b "{\"owner\":%d,\"source\":%s,\"target_candidate\":%d,\"target\":%s,\"observations\":%d,\"examples\":%s}"
    site.owner(json_identity site.source)site.target_candidate(json_identity site.target)site.observations
    (json_events(List.rev site.examples)))jumps;
  add b "],\"ownership_conflicts\":[";
  let entries=Hashtbl.fold(fun _ (x:entry_site) xs->x::xs)t.entries []|>List.sort(fun (a:entry_site) (b:entry_site)->
    compare(a.owner,a.target_candidate,identity_key a.target,a.cross_image)
      (b.owner,b.target_candidate,identity_key b.target,b.cross_image))in
  List.iteri(fun i site->if i>0 then add b ",";add b(event_site_json site))entries;
  add b "],\"return_mismatches\":[";
  let returns=Hashtbl.fold(fun _ (x:return_site) xs->x::xs)t.returns []|>List.sort(fun (a:return_site) (b:return_site)->
    compare(a.active,a.caller,a.expected_pc,a.observed_pc,a.active_image,a.caller_image,a.expected_image,a.observed_image)
      (b.active,b.caller,b.expected_pc,b.observed_pc,b.active_image,b.caller_image,b.expected_image,b.observed_image))in
  List.iteri(fun i site->if i>0 then add b ",";Printf.bprintf b "{\"active_routine\":%d,\"active_image\":%s,\"expected_caller\":%d,\"caller_image\":%s,\"expected_return_pc\":%d,\"expected_image\":%s,\"observed_return_target\":%s,\"observed_image\":%s,\"observations\":%d,\"examples\":%s}"
    site.active(json_image site.active_image)site.caller(json_image site.caller_image)site.expected_pc(json_image site.expected_image)
    (match site.observed_pc with None->"null"|Some x->string_of_int x)(json_image site.observed_image)site.observations
    (json_events(List.rev site.examples)))returns;
  add b "],\"multi_owner_examples\":[";
  let overlaps=multi_owner_coordinates t in
  overlaps|>List.iteri(fun i (image,offset,owners)->if i<32 then (if i>0 then add b ",";Printf.bprintf b "{\"image\":%s,\"offset\":%d,\"routine_ids\":[%s]}"
    (json_image(Some image))offset(String.concat ","(List.map string_of_int owners))));
  add b "],\"routine_impacts\":[";
  List.iteri(fun i impact->if i>0 then add b ",";Printf.bprintf b "{\"routine_id\":%d,\"multi_owner_instructions\":%d,\"multi_owner_blocks\":%s}"
    impact.routine_id impact.multi_owner_instructions(match impact.multi_owner_blocks with None->"null"|Some x->string_of_int x))(routine_impacts t blocks);
  add b "]}\n";Buffer.contents b

let example_events t =
  let events=ref [] in
  let collect (examples:example list)=events:=List.rev_append examples !events in
  Hashtbl.iter(fun _ (x:jump_site)->collect x.examples)t.jumps;
  Hashtbl.iter(fun _ (x:entry_site)->collect x.examples)t.entries;
  Hashtbl.iter(fun _ (x:return_site)->collect x.examples)t.returns;
  List.sort(fun a b->
    let step=function
      |Dynamic_structure.Known_entry_jump e->e.step
      |Known_entry_under_other_owner e->e.step
      |Known_image_under_other_owner e->e.step
      |Return_target_mismatch_detail e->e.step in
    compare(step a,json_events[a])(step b,json_events[b]))!events
