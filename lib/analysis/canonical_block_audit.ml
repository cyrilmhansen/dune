[@@@warning "-4-27-40-41-42-69"]

type start_status = All_owners | Some_owners | No_owners
type owner_block = { routine_id:int; block_id:int; start_offset:int option; end_offset:int option;
  canonical_image_span:bool }
type shared_coordinate = { image:Execution_map.image_id; offset:int; routine_ids:int list;
  instruction_record_count:int; bytes_agree:bool; decoded_agree:bool; block_start_status:start_status;
  owner_blocks:(int*owner_block list)list; boundaries_identical:bool }
type candidate_block = { image:Execution_map.image_id; start_offset:int; end_offset:int }
type routine_detail = { routine_id:int; owner_qualified_image_instruction_records:int; shared_coordinates:int;
  boundary_conflicts:int; implicated_blocks:int; examples:shared_coordinate list }
type summary = { canonical_instruction_coordinates:int; owner_qualified_image_instruction_records:int;
  duplicated_owner_qualified_instruction_records:int; multi_owner_instruction_coordinates:int;
  byte_disagreement_coordinates:int; decoded_disagreement_coordinates:int;
  block_start_all_owners:int; block_start_some_owners:int; block_start_no_owners:int;
  boundary_conflict_count:int; current_owner_qualified_blocks:int; current_canonical_image_blocks:int;
  candidate_canonical_blocks:int; estimated_block_deduplication:int }
type report = { summary_:summary; shared_:shared_coordinate list; candidates_:candidate_block list;
  routine_details_:routine_detail list }

type coordinate = Execution_map.image_id * int
let image_compare (a:Execution_map.image_id) (b:Execution_map.image_id) =
  compare(a.Cpm.Filesystem.drive,a.user,a.name)(b.Cpm.Filesystem.drive,b.user,b.name)
let coordinate_compare (ia,oa) (ib,ob)=let c=image_compare ia ib in if c<>0 then c else compare oa ob

let block_spans (instructions:Dynamic_blocks.instruction list) (blocks:Dynamic_blocks.block list) =
  let by_id=Hashtbl.create(List.length instructions) in
  List.iter(fun (instruction:Dynamic_blocks.instruction)->Hashtbl.replace by_id instruction.id instruction)instructions;
  let spans=ref [] and member_blocks=Hashtbl.create(List.length instructions) in
  List.iter(fun (block:Dynamic_blocks.block)->
    List.iter(fun id->Hashtbl.replace member_blocks id block)block.instruction_ids;
    let members=List.filter_map(fun id->Hashtbl.find_opt by_id id)block.instruction_ids in
    match members with
    |[]->()
    |first::rest->
      (match first.origin with
       |Dynamic_blocks.Image_byte{image;offset}->
         let next=ref(offset+Bytes.length first.bytes)and valid=ref true in
         List.iter(fun (instruction:Dynamic_blocks.instruction)->
           (match instruction.origin with
            |Dynamic_blocks.Image_byte{image=other;offset=other_offset}
              when other=image && other_offset= !next -> next:= !next+Bytes.length instruction.bytes
            |_->valid:=false);
           if instruction.runtime_pc <> ((first.runtime_pc + (!next-offset-Bytes.length instruction.bytes)) land 0xffff)
             then valid:=false)rest;
         if !valid then spans:=(image,offset,!next)::!spans
       |_->()))blocks;
  by_id,member_blocks,List.rev !spans

let analyze dynamic =
  let instructions=Dynamic_blocks.instructions dynamic and blocks=Dynamic_blocks.blocks dynamic in
  let by_id,member_blocks,spans=block_spans instructions blocks in
  let grouped:(coordinate,Dynamic_blocks.instruction list)Hashtbl.t=Hashtbl.create(List.length instructions)in
  List.iter(fun (instruction:Dynamic_blocks.instruction)->match instruction.origin with
    |Dynamic_blocks.Image_byte{image;offset}->
        let key=image,offset in
        let entries=Option.value(Hashtbl.find_opt grouped key)~default:[] in
        Hashtbl.replace grouped key(instruction::entries)
    |_->())instructions;
  let shared=Hashtbl.fold(fun (image,offset) records acc->
    let records=List.sort(fun (a:Dynamic_blocks.instruction) (b:Dynamic_blocks.instruction)->
      let c=compare a.routine_id b.routine_id in if c<>0 then c else compare a.id b.id)records in
    let owners=List.map(fun (i:Dynamic_blocks.instruction)->i.routine_id)records|>List.sort_uniq compare in
    if List.length owners<2 then acc else
    let first=List.hd records in
    let bytes_agree=List.for_all(fun (i:Dynamic_blocks.instruction)->Bytes.equal first.bytes i.bytes)records in
    let decoded_agree=List.for_all(fun (i:Dynamic_blocks.instruction)->first.decoded=i.decoded)records in
    let owner_blocks=List.map(fun owner->
      let owner_records=List.filter(fun (i:Dynamic_blocks.instruction)->i.routine_id=owner)records in
      let relevant=List.filter_map(fun (i:Dynamic_blocks.instruction)->Hashtbl.find_opt member_blocks i.id)owner_records
        |>List.sort_uniq(fun (a:Dynamic_blocks.block) (b:Dynamic_blocks.block)->compare(a.routine_id,a.id)(b.routine_id,b.id)) in
      owner,List.map(fun (block:Dynamic_blocks.block)->
        let members=List.filter_map(fun id->Hashtbl.find_opt by_id id)block.instruction_ids in
        let start_offset=match members with
          |({origin=Dynamic_blocks.Image_byte{image=block_image;offset};_})::_ when block_image=image->Some offset
          |_->None in
        let end_offset=match start_offset with
          |None->None
          |Some start->
            let rec last_same_end previous=function
              |[]->Some previous
              |(i:Dynamic_blocks.instruction)::rest->(match i.origin with
                |Dynamic_blocks.Image_byte{image=block_image;offset} when block_image=image && offset=previous->
                    last_same_end(offset+Bytes.length i.bytes)rest
                |_->None) in
            (match members with
             |[]->None
             |first_member::tail->(match first_member.origin with
                 |Dynamic_blocks.Image_byte{offset;_}->last_same_end(offset+Bytes.length first_member.bytes)tail
                 |_->None)) in
        {routine_id=owner;block_id=block.id;start_offset;end_offset;
         canonical_image_span=block.representation=Dynamic_blocks.Image_source && block.image=Some image})relevant)owners in
    let owner_starts=List.map(fun(owner,owner_blocks)->
      owner,List.exists(fun (b:owner_block)->b.start_offset=Some offset)owner_blocks)owner_blocks in
    let starts=List.fold_left(fun n (_,yes)->if yes then n+1 else n)0 owner_starts in
    let block_start_status=if starts=List.length owners then All_owners else if starts=0 then No_owners else Some_owners in
    let signature (b:owner_block)=b.start_offset,b.end_offset in
    let signatures=List.map(fun(_,owner_blocks)->List.map signature owner_blocks|>List.sort_uniq compare)owner_blocks in
    let boundaries_identical=match signatures with []|[_]->true|first::rest->List.for_all((=)first)rest in
    {image;offset;routine_ids=owners;instruction_record_count=List.length records;
      bytes_agree;decoded_agree;block_start_status;owner_blocks;boundaries_identical}::acc
  )grouped []|>List.sort(fun (a:shared_coordinate) (b:shared_coordinate)->coordinate_compare(a.image,a.offset)(b.image,b.offset)) in
  let coordinates=Hashtbl.length grouped in
  let image_records=Hashtbl.fold(fun _ records n->n+List.length records)grouped 0 in
  let boundaries_by_image:(Execution_map.image_id,int list)Hashtbl.t=Hashtbl.create 8 in
  let add_boundary image offset=
    let current=Option.value(Hashtbl.find_opt boundaries_by_image image)~default:[] in
    if not(List.mem offset current)then Hashtbl.replace boundaries_by_image image(offset::current) in
  List.iter(fun(image,start,finish)->add_boundary image start;add_boundary image finish)spans;
  let candidates=Hashtbl.fold(fun image boundaries acc->
    let boundaries=List.sort_uniq compare boundaries in
    let rec adjacent acc=function
      |a::(b::_ as rest)->
        let covered=List.exists(fun(i,start,finish)->i=image && start<=a && finish>=b)spans in
        adjacent(if covered && b>a then {image;start_offset=a;end_offset=b}::acc else acc)rest
      |_->List.rev acc in
    adjacent [] boundaries@acc)boundaries_by_image []
    |>List.sort(fun a b->let c=image_compare a.image b.image in if c<>0 then c else compare a.start_offset b.start_offset) in
  let boundary_conflicts=List.filter(fun c->not c.boundaries_identical)shared in
  let block_count=List.length blocks in
  let canonical_block_count=List.length(List.filter(fun (b:Dynamic_blocks.block)->b.representation=Dynamic_blocks.Image_source)blocks)in
  let candidate_count=List.length candidates in
  let routine_ids=List.concat_map(fun c->c.routine_ids)shared|>List.sort_uniq compare in
  let routine_details=List.map(fun routine_id->
    let owned=List.filter(fun (i:Dynamic_blocks.instruction)->i.routine_id=routine_id && match i.origin with Dynamic_blocks.Image_byte _->true|_->false)instructions in
    let shared_for=List.filter(fun c->List.mem routine_id c.routine_ids)shared in
    let conflicts=List.filter(fun c->List.mem routine_id c.routine_ids && not c.boundaries_identical)shared in
    let implicated=Hashtbl.create 32 in
    List.iter(fun c->List.iter(fun(owner,owner_blocks)->if owner=routine_id then List.iter(fun b->Hashtbl.replace implicated b.block_id ())owner_blocks)c.owner_blocks)shared_for;
    let examples =
      let ordered = List.filter (fun c -> List.mem routine_id c.routine_ids) shared_for in
      let conflicts = List.filter (fun c -> not c.boundaries_identical) ordered in
      let preferred = if conflicts <> [] then conflicts else ordered in
      List.filteri (fun i _ -> i < 8) preferred
    in
    {routine_id;owner_qualified_image_instruction_records=List.length owned;shared_coordinates=List.length shared_for;
      boundary_conflicts=List.length conflicts;implicated_blocks=Hashtbl.length implicated;examples})routine_ids in
  let count_status wanted=List.fold_left(fun n c->if c.block_start_status=wanted then n+1 else n)0 shared in
  let summary_={canonical_instruction_coordinates=coordinates;owner_qualified_image_instruction_records=image_records;
    duplicated_owner_qualified_instruction_records=max 0(image_records-coordinates);
    multi_owner_instruction_coordinates=List.length shared;
    byte_disagreement_coordinates=List.length(List.filter(fun x->not x.bytes_agree)shared);
    decoded_disagreement_coordinates=List.length(List.filter(fun x->not x.decoded_agree)shared);
    block_start_all_owners=count_status All_owners;block_start_some_owners=count_status Some_owners;
    block_start_no_owners=count_status No_owners;boundary_conflict_count=List.length boundary_conflicts;
    current_owner_qualified_blocks=block_count;current_canonical_image_blocks=canonical_block_count;
    candidate_canonical_blocks=candidate_count;estimated_block_deduplication=max 0(canonical_block_count-candidate_count)} in
  {summary_;shared_=shared;candidates_=candidates;routine_details_=routine_details}

let summary r=r.summary_
let shared_coordinates r=r.shared_
let candidate_blocks r=r.candidates_
let routine_details ?routine_ids r=match routine_ids with
  |None->r.routine_details_
  |Some ids->List.filter(fun x->List.mem x.routine_id ids)r.routine_details_

let quote s=
  let b=Buffer.create(String.length s+8)in Buffer.add_char b '"';
  String.iter(fun c->match c with
    |'"'->Buffer.add_string b"\\\""|'\\'->Buffer.add_string b"\\\\"|'\n'->Buffer.add_string b"\\n"
    |'\r'->Buffer.add_string b"\\r"|'\t'->Buffer.add_string b"\\t"
    |c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf"\\u%04x"(Char.code c))
    |c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b
let json_image (i:Execution_map.image_id)=Printf.sprintf"{\"drive\":%d,\"user\":%d,\"name\":%s}"i.Cpm.Filesystem.drive i.user(quote i.name)
let json_status=function All_owners->"all"|Some_owners->"some"|No_owners->"none"
let json_owner_block (b:owner_block)=Printf.sprintf"{\"routine_id\":%d,\"block_id\":%d,\"start_offset\":%s,\"end_offset\":%s,\"canonical_image_span\":%b}"
  b.routine_id b.block_id (match b.start_offset with None->"null"|Some x->string_of_int x)
  (match b.end_offset with None->"null"|Some x->string_of_int x)b.canonical_image_span
let json_shared (c:shared_coordinate)=
  Printf.sprintf"{\"image\":%s,\"offset\":%d,\"routine_ids\":[%s],\"instruction_record_count\":%d,\"bytes_agree\":%b,\"decoded_agree\":%b,\"block_start_status\":%s,\"boundaries_identical\":%b,\"owner_blocks\":[%s]}"
    (json_image c.image)c.offset(String.concat ","(List.map string_of_int c.routine_ids))c.instruction_record_count
    c.bytes_agree c.decoded_agree(quote(json_status c.block_start_status))c.boundaries_identical
    (String.concat ","(List.map(fun(owner,blocks)->Printf.sprintf"{\"routine_id\":%d,\"blocks\":[%s]}"owner
      (String.concat ","(List.map json_owner_block blocks)))c.owner_blocks))

let to_json_string r=
  let s=r.summary_ and b=Buffer.create 16384 and add=Buffer.add_string in
  add b "RUNES_CANONICAL_BLOCK_AUDIT 1\n";
  Printf.bprintf b "{\"summary\":{\"canonical_instruction_coordinates\":%d,\"owner_qualified_image_instruction_records\":%d,\"duplicated_owner_qualified_instruction_records\":%d,\"multi_owner_instruction_coordinates\":%d,\"byte_disagreement_coordinates\":%d,\"decoded_disagreement_coordinates\":%d,\"block_start_all_owners\":%d,\"block_start_some_owners\":%d,\"block_start_no_owners\":%d,\"boundary_conflict_count\":%d,\"current_owner_qualified_blocks\":%d,\"current_canonical_image_blocks\":%d,\"candidate_canonical_blocks\":%d,\"estimated_block_deduplication\":%d},\"shared_coordinates\":["
    s.canonical_instruction_coordinates s.owner_qualified_image_instruction_records s.duplicated_owner_qualified_instruction_records
    s.multi_owner_instruction_coordinates s.byte_disagreement_coordinates s.decoded_disagreement_coordinates
    s.block_start_all_owners s.block_start_some_owners s.block_start_no_owners s.boundary_conflict_count
    s.current_owner_qualified_blocks s.current_canonical_image_blocks s.candidate_canonical_blocks s.estimated_block_deduplication;
  List.iteri(fun i c->if i>0 then add b ",";add b(json_shared c))r.shared_;
  add b "],\"candidate_blocks\":[";
  List.iteri(fun i (c:candidate_block)->if i>0 then add b ",";Printf.bprintf b "{\"image\":%s,\"start_offset\":%d,\"end_offset\":%d}"(json_image c.image)c.start_offset c.end_offset)r.candidates_;
  add b "],\"routine_details\":[";
  List.iteri(fun i d->if i>0 then add b ",";Printf.bprintf b "{\"routine_id\":%d,\"owner_qualified_image_instruction_records\":%d,\"shared_coordinates\":%d,\"boundary_conflicts\":%d,\"implicated_blocks\":%d,\"examples\":[%s]}"
    d.routine_id d.owner_qualified_image_instruction_records d.shared_coordinates d.boundary_conflicts d.implicated_blocks
    (String.concat ","(List.map json_shared d.examples)))r.routine_details_;
  add b "]}\n";Buffer.contents b

let hex n=Printf.sprintf"%04X"n
let to_text ?(routine_ids=[403;422;458]) r=
  let s=r.summary_ and b=Buffer.create 4096 in
  Printf.bprintf b "canonical image instruction coordinates: %d\nowner-qualified image instruction records: %d\nduplicated records beyond canonical coordinates: %d\nmulti-owner instruction coordinates: %d\nbytes/decoded disagree: %d/%d\nblock starts all/some/none owners: %d/%d/%d\nboundary-conflicting coordinates: %d\ncurrent owner-qualified blocks: %d (canonical image spans: %d)\nhypothetical union-boundary candidate blocks: %d\nestimated image-block deduplication: %d\n"
    s.canonical_instruction_coordinates s.owner_qualified_image_instruction_records
    s.duplicated_owner_qualified_instruction_records s.multi_owner_instruction_coordinates
    s.byte_disagreement_coordinates s.decoded_disagreement_coordinates s.block_start_all_owners
    s.block_start_some_owners s.block_start_no_owners s.boundary_conflict_count
    s.current_owner_qualified_blocks s.current_canonical_image_blocks s.candidate_canonical_blocks s.estimated_block_deduplication;
  List.iter(fun d->
    Printf.bprintf b "\nR%03d: %d owner-qualified image instruction records; %d shared coordinates; %d boundary conflicts across %d implicated blocks\n"
      d.routine_id d.owner_qualified_image_instruction_records d.shared_coordinates d.boundary_conflicts d.implicated_blocks;
    List.iter(fun c->
      let blocks=List.concat_map(fun(owner,bs)->List.map(fun x->owner,x)bs)c.owner_blocks in
      Printf.bprintf b "  %s+%04X owners=[%s] start=%s boundaries=%s"
        c.image.Cpm.Filesystem.name c.offset(String.concat ","(List.map(fun id->Printf.sprintf"R%03d"id)c.routine_ids))
        (json_status c.block_start_status)(if c.boundaries_identical then"same"else"conflict");
      List.iter(fun(owner,x)->Printf.bprintf b " R%03d.B%03d[%s,%s)"owner x.block_id
        (Option.fold ~none:"?" ~some:hex x.start_offset)(Option.fold ~none:"?" ~some:hex x.end_offset))blocks;
      Buffer.add_char b '\n')d.examples)(routine_details ~routine_ids r);
  Buffer.contents b
