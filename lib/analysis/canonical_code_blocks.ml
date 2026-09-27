[@@@warning "-4-27-40-41-42-69"]

type instruction_context = { routine_id:int; observed_instruction_ids:int list; runtime_pcs:int list;
  execution_count:int; first_step:int; last_step:int }
type instruction = { image:Execution_map.image_id; offset:int; bytes:bytes; decoded:I8080.Instr.t; text:string;
  execution_count:int; first_step:int; last_step:int; contexts:instruction_context list }
type block = { id:int; image:Execution_map.image_id; start_offset:int; end_offset:int; instruction_offsets:int list }
type block_context = { routine_id:int; canonical_block_id:int; owner_block_id:int;
  tags:Dynamic_blocks.block_tag list; runtime_start:int; first_step:int; last_step:int;
  execution_count:int; instruction_count:int; entry_count:int; split_from_owner_block:bool }
type exceptional_instruction = { owner_routine_id:int; observed_instruction_id:int; origin:Dynamic_blocks.origin;
  runtime_pc:int; bytes:bytes; text:string; tags:Dynamic_blocks.instruction_tag list;
  first_step:int; last_step:int; execution_count:int; reason:string }
type exceptional_block = { owner_routine_id:int; owner_block_id:int; origin:Dynamic_blocks.origin;
  runtime_start:int; byte_length:int; tags:Dynamic_blocks.block_tag list; instruction_ids:int list }
type partition_anomaly = { image:Execution_map.image_id; start_offset:int; end_offset:int; reason:string }
type summary = { canonical_instruction_count:int; exceptional_instruction_count:int; canonical_block_count:int;
  block_context_count:int; exceptional_block_count:int; partition_anomaly_count:int }
type report = { instructions_:instruction list; blocks_:block list; contexts_:block_context list;
  exceptional_instructions_:exceptional_instruction list; exceptional_blocks_:exceptional_block list;
  anomalies_:partition_anomaly list; summary_:summary }

type coord = Execution_map.image_id * int

let image_compare (a:Execution_map.image_id) (b:Execution_map.image_id) =
  compare (a.Cpm.Filesystem.drive,a.user,a.name) (b.Cpm.Filesystem.drive,b.user,b.name)
let coord_compare (ia,oa) (ib,ob) = let c=image_compare ia ib in if c<>0 then c else compare oa ob
let origin_coord = function Dynamic_blocks.Image_byte {image;offset}->Some(image,offset)|_->None
let instruction_order (a:Dynamic_blocks.instruction) (b:Dynamic_blocks.instruction) =
  let c=compare a.routine_id b.routine_id in if c<>0 then c else compare a.id b.id

let materialize dynamic =
  let observed=Dynamic_blocks.instructions dynamic and owner_blocks=Dynamic_blocks.blocks dynamic in
  let observed_by_id=Hashtbl.create(List.length observed) in
  List.iter(fun (i:Dynamic_blocks.instruction)->Hashtbl.replace observed_by_id i.id i)observed;
  let grouped:(coord,Dynamic_blocks.instruction list)Hashtbl.t=Hashtbl.create(List.length observed) in
  List.iter(fun (i:Dynamic_blocks.instruction)->match origin_coord i.origin with
    |None->()
    |Some key->Hashtbl.replace grouped key(i::Option.value(Hashtbl.find_opt grouped key)~default:[]))observed;
  let canonical=ref [] and exceptional=ref [] in
  Hashtbl.iter(fun (image,offset) records->
    let records=List.sort instruction_order records in
    let first=List.hd records in
    let agrees=List.for_all(fun (i:Dynamic_blocks.instruction)->
      i.representation=Dynamic_blocks.Image_source && Bytes.equal first.bytes i.bytes && first.decoded=i.decoded)records in
    if agrees then (
      let contexts=List.map(fun routine_id->
        let xs=List.filter(fun (i:Dynamic_blocks.instruction)->i.routine_id=routine_id)records in
        {routine_id;observed_instruction_ids=List.map(fun (i:Dynamic_blocks.instruction)->i.id)xs;
         runtime_pcs=List.map(fun (i:Dynamic_blocks.instruction)->i.runtime_pc)xs|>List.sort_uniq compare;
         execution_count=List.fold_left(fun n (i:Dynamic_blocks.instruction)->n+i.execution_count)0 xs;
         first_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->min n i.first_step)max_int xs;
         last_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->max n i.last_step)min_int xs})
        (List.map(fun (i:Dynamic_blocks.instruction)->i.routine_id)records|>List.sort_uniq compare) in
      canonical:={image;offset;bytes=Bytes.copy first.bytes;decoded=first.decoded;
        text=I8080.Instr_format.format first.decoded;
        execution_count=List.fold_left(fun n (i:Dynamic_blocks.instruction)->n+i.execution_count)0 records;
        first_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->min n i.first_step)max_int records;
        last_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->max n i.last_step)min_int records;contexts}::!canonical
    ) else
      let bytes_agree=List.for_all(fun (i:Dynamic_blocks.instruction)->Bytes.equal first.bytes i.bytes)records in
      let decoded_agree=List.for_all(fun (i:Dynamic_blocks.instruction)->first.decoded=i.decoded)records in
      List.iter(fun (i:Dynamic_blocks.instruction)->
      exceptional:={owner_routine_id=i.routine_id;observed_instruction_id=i.id;origin=i.origin;
        runtime_pc=i.runtime_pc;bytes=Bytes.copy i.bytes;text=i.text;tags=i.tags;
        first_step=i.first_step;last_step=i.last_step;execution_count=i.execution_count;
        reason=(if i.representation<>Dynamic_blocks.Image_source then "observed-bytes-or-origin-variant"
          else if not bytes_agree then "fetched-bytes-disagree-at-image-coordinate"
          else if not decoded_agree then "decoded-instruction-disagrees-at-image-coordinate"
          else "image-backed-instruction-not-canonical") }::!exceptional)records
  )grouped;
  List.iter(fun (i:Dynamic_blocks.instruction)->if origin_coord i.origin=None then
    exceptional:={owner_routine_id=i.routine_id;observed_instruction_id=i.id;origin=i.origin;
      runtime_pc=i.runtime_pc;bytes=Bytes.copy i.bytes;text=i.text;tags=i.tags;
      first_step=i.first_step;last_step=i.last_step;execution_count=i.execution_count;
      reason=(match i.origin with Dynamic_blocks.Unknown_origin->"unknown-origin"
        |Mixed_origin->"mixed-origin"|Interrupt_origin->"interrupt-supplied-code"|Image_byte _->assert false)}::!exceptional)observed;
  let canonical=List.sort(fun (a:instruction) (b:instruction)->coord_compare(a.image,a.offset)(b.image,b.offset))!canonical in
  let exceptional=List.sort(fun (a:exceptional_instruction) (b:exceptional_instruction)->let c=compare a.owner_routine_id b.owner_routine_id in
    if c<>0 then c else compare a.observed_instruction_id b.observed_instruction_id)!exceptional in
  let canonical_by_image:(Execution_map.image_id,instruction list)Hashtbl.t=Hashtbl.create 8 in
  List.iter(fun (i:instruction)->Hashtbl.replace canonical_by_image i.image(i::Option.value(Hashtbl.find_opt canonical_by_image i.image)~default:[]))canonical;
  Hashtbl.iter(fun image xs->Hashtbl.replace canonical_by_image image(List.sort(fun a b->compare a.offset b.offset)xs))canonical_by_image;
  let audit=Canonical_block_audit.analyze dynamic in
  let candidates=Canonical_block_audit.candidate_blocks audit in
  let blocks_rev=ref [] and anomalies_rev=ref [] in
  List.iter(fun (candidate:Canonical_block_audit.candidate_block)->
    let members=Option.value(Hashtbl.find_opt canonical_by_image candidate.image)~default:[]
      |>List.filter(fun i->i.offset>=candidate.start_offset && i.offset<candidate.end_offset) in
    let next=ref candidate.start_offset and valid=ref true in
    List.iter(fun i->if i.offset<> !next then valid:=false;next:=i.offset+Bytes.length i.bytes)members;
    if members=[] || !next<>candidate.end_offset then valid:=false;
    if !valid then blocks_rev:={id= -1;image=candidate.image;start_offset=candidate.start_offset;
      end_offset=candidate.end_offset;instruction_offsets=List.map(fun i->i.offset)members}::!blocks_rev
    else anomalies_rev:={image=candidate.image;start_offset=candidate.start_offset;end_offset=candidate.end_offset;
      reason="union-boundary interval is not exactly covered by agreeing canonical instructions"}::!anomalies_rev
  )candidates;
  let blocks=List.rev !blocks_rev|>List.sort(fun (a:block) (b:block)->let c=image_compare a.image b.image in
    if c<>0 then c else compare a.start_offset b.start_offset)
    |>List.mapi(fun id b->{b with id}) in
  let contexts_rev=ref [] in
  List.iter(fun (source:Dynamic_blocks.block)->match source.image,source.start_offset with
    |Some image,Some source_start when source.byte_length>0->
      let source_end=source_start+source.byte_length in
      List.iter(fun (block:block)->if block.image=image && block.start_offset<source_end && block.end_offset>source_start then (
        let members=List.filter_map(fun id->Hashtbl.find_opt observed_by_id id)source.instruction_ids
          |>List.filter(fun (i:Dynamic_blocks.instruction)->match i.origin with
            |Dynamic_blocks.Image_byte{image=ii;offset}->ii=image && offset>=block.start_offset && offset<block.end_offset
            |_->false) in
        if members<>[] then (
          let first=List.hd members in
          let at_source_start=block.start_offset=source_start in
          contexts_rev:={routine_id=source.routine_id;canonical_block_id=block.id;owner_block_id=source.id;
            tags=(if at_source_start then source.tags else []);runtime_start=first.runtime_pc;
            first_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->min n i.first_step)max_int members;
            last_step=List.fold_left(fun n (i:Dynamic_blocks.instruction)->max n i.last_step)min_int members;
            execution_count=List.fold_left(fun n (i:Dynamic_blocks.instruction)->n+i.execution_count)0 members;
            instruction_count=List.length members;entry_count=(if at_source_start then source.entry_count else 0);
            split_from_owner_block=(block.start_offset<>source_start || block.end_offset<>source_end)}::!contexts_rev
        )))blocks
    |_->())owner_blocks;
  let contexts=List.rev !contexts_rev|>List.sort(fun a b->let c=compare a.canonical_block_id b.canonical_block_id in
    if c<>0 then c else let c=compare a.routine_id b.routine_id in if c<>0 then c else compare a.owner_block_id b.owner_block_id) in
  let exceptional_ids=Hashtbl.create(List.length exceptional)in
  List.iter(fun (i:exceptional_instruction)->Hashtbl.replace exceptional_ids i.observed_instruction_id ())exceptional;
  let exceptional_blocks=List.filter(fun (b:Dynamic_blocks.block)->b.representation=Dynamic_blocks.Observed_bytes
    ||List.exists(fun id->Hashtbl.mem exceptional_ids id)b.instruction_ids)owner_blocks
    |>List.map(fun (b:Dynamic_blocks.block)->{owner_routine_id=b.routine_id;owner_block_id=b.id;origin=b.origin;
      runtime_start=b.runtime_start;byte_length=b.byte_length;tags=b.tags;instruction_ids=b.instruction_ids}) in
  let anomalies=List.sort(fun a b->let c=image_compare a.image b.image in if c<>0 then c else compare a.start_offset b.start_offset)!anomalies_rev in
  let summary_={canonical_instruction_count=List.length canonical;exceptional_instruction_count=List.length exceptional;
    canonical_block_count=List.length blocks;block_context_count=List.length contexts;
    exceptional_block_count=List.length exceptional_blocks;partition_anomaly_count=List.length anomalies} in
  {instructions_=canonical;blocks_=blocks;contexts_=contexts;exceptional_instructions_=exceptional;
   exceptional_blocks_=exceptional_blocks;anomalies_=anomalies;summary_=summary_}

let instructions r=r.instructions_
let blocks r=r.blocks_
let block_contexts r=r.contexts_
let exceptional_instructions r=r.exceptional_instructions_
let exceptional_blocks r=r.exceptional_blocks_
let partition_anomalies r=r.anomalies_
let summary r=r.summary_
let block_at r ~image ~offset=List.find_opt(fun (b:block)->b.image=image && offset>=b.start_offset && offset<b.end_offset)r.blocks_

let quote s=let b=Buffer.create(String.length s+8)in Buffer.add_char b '"';String.iter(fun c->match c with
  |'"'->Buffer.add_string b "\\\""|'\\'->Buffer.add_string b "\\\\"|'\n'->Buffer.add_string b "\\n"
  |'\r'->Buffer.add_string b "\\r"|'\t'->Buffer.add_string b "\\t"
  |c when Char.code c<0x20->Buffer.add_string b(Printf.sprintf "\\u%04x"(Char.code c))|c->Buffer.add_char b c)s;
  Buffer.add_char b '"';Buffer.contents b
let hex bytes=let b=Buffer.create(Bytes.length bytes*2)in Bytes.iter(fun c->Buffer.add_string b(Printf.sprintf "%02X"(Char.code c)))bytes;Buffer.contents b
let json_image (i:Execution_map.image_id)=Printf.sprintf "{\"drive\":%d,\"user\":%d,\"name\":%s}" i.Cpm.Filesystem.drive i.user(quote i.name)
let json_tags f xs="["^String.concat ","(List.map(fun x->quote(f x))xs)^"]"
let to_json_string r=
  let b=Buffer.create 8192 and add=Buffer.add_string in
  add b "RUNES_CANONICAL_CODE_BLOCKS 1\n{\"summary\":{";
  let s=r.summary_ in
  Printf.bprintf b "\"canonical_instructions\":%d,\"exceptional_instructions\":%d,\"canonical_blocks\":%d,\"routine_block_relations\":%d,\"exceptional_blocks\":%d,\"partition_anomalies\":%d},\"instructions\":["
    s.canonical_instruction_count s.exceptional_instruction_count s.canonical_block_count s.block_context_count s.exceptional_block_count s.partition_anomaly_count;
  List.iteri(fun n (i:instruction)->if n>0 then add b ",";
    Printf.bprintf b "{\"image\":%s,\"offset\":%d,\"bytes\":%s,\"decoded\":%s,\"text\":%s,\"execution_count\":%d,\"first_step\":%d,\"last_step\":%d,\"contexts\":["
      (json_image i.image)i.offset(quote(hex i.bytes))(quote(I8080.Instr_format.format i.decoded))(quote i.text)i.execution_count i.first_step i.last_step;
    List.iteri(fun j (c:instruction_context)->if j>0 then add b ",";Printf.bprintf b "{\"routine_id\":%d,\"observed_ids\":[%s],\"runtime_pcs\":[%s],\"execution_count\":%d,\"first_step\":%d,\"last_step\":%d}"
      c.routine_id(String.concat ","(List.map string_of_int c.observed_instruction_ids))(String.concat ","(List.map string_of_int c.runtime_pcs))c.execution_count c.first_step c.last_step)i.contexts;
    add b "]}")r.instructions_;
  add b "],\"blocks\":[";
  List.iteri(fun n (x:block)->if n>0 then add b ",";Printf.bprintf b "{\"id\":%d,\"image\":%s,\"start_offset\":%d,\"end_offset\":%d,\"byte_length\":%d,\"instruction_offsets\":[%s]}"
    x.id(json_image x.image)x.start_offset x.end_offset(x.end_offset-x.start_offset)(String.concat ","(List.map string_of_int x.instruction_offsets)))r.blocks_;
  add b "],\"routine_block_relations\":[";
  List.iteri(fun n (x:block_context)->if n>0 then add b ",";Printf.bprintf b "{\"routine_id\":%d,\"canonical_block_id\":%d,\"owner_block_id\":%d,\"tags\":%s,\"runtime_start\":%d,\"first_step\":%d,\"last_step\":%d,\"execution_count\":%d,\"instruction_count\":%d,\"entry_count\":%d,\"split_from_owner_block\":%b}"
    x.routine_id x.canonical_block_id x.owner_block_id(json_tags Dynamic_blocks.block_tag_name x.tags)x.runtime_start x.first_step x.last_step x.execution_count x.instruction_count x.entry_count x.split_from_owner_block)r.contexts_;
  add b "],\"exceptional_instructions\":[";
  List.iteri(fun n (x:exceptional_instruction)->if n>0 then add b ",";Printf.bprintf b "{\"owner_routine_id\":%d,\"observed_instruction_id\":%d,\"origin\":%s,\"runtime_pc\":%d,\"bytes\":%s,\"text\":%s,\"tags\":%s,\"first_step\":%d,\"last_step\":%d,\"execution_count\":%d,\"reason\":%s}"
    x.owner_routine_id x.observed_instruction_id (quote(match x.origin with
      |Dynamic_blocks.Image_byte{image;offset}->Printf.sprintf "%s+%04X" image.Cpm.Filesystem.name offset
      |Unknown_origin->"unknown"|Mixed_origin->"mixed"|Interrupt_origin->"interrupt"))x.runtime_pc(quote(hex x.bytes))(quote x.text)
    (json_tags Dynamic_blocks.instruction_tag_name x.tags)x.first_step x.last_step x.execution_count(quote x.reason))r.exceptional_instructions_;
  add b "],\"exceptional_blocks\":[";
  List.iteri(fun n (x:exceptional_block)->if n>0 then add b ",";Printf.bprintf b "{\"owner_routine_id\":%d,\"owner_block_id\":%d,\"origin\":%s,\"runtime_start\":%d,\"byte_length\":%d,\"tags\":%s,\"instruction_ids\":[%s]}"
    x.owner_routine_id x.owner_block_id(quote(match x.origin with Dynamic_blocks.Image_byte{image;offset}->Printf.sprintf "%s+%04X" image.Cpm.Filesystem.name offset
      |Unknown_origin->"unknown"|Mixed_origin->"mixed"|Interrupt_origin->"interrupt"))x.runtime_start x.byte_length
    (json_tags Dynamic_blocks.block_tag_name x.tags)(String.concat ","(List.map string_of_int x.instruction_ids)))r.exceptional_blocks_;
  add b "],\"partition_anomalies\":[";
  List.iteri(fun n (x:partition_anomaly)->if n>0 then add b ",";Printf.bprintf b "{\"image\":%s,\"start_offset\":%d,\"end_offset\":%d,\"reason\":%s}"
    (json_image x.image)x.start_offset x.end_offset(quote x.reason))r.anomalies_;
  add b "]}\n";Buffer.contents b

let to_text r=let s=r.summary_ in Printf.sprintf
  "canonical image instructions: %d\nexceptional owner-qualified instructions: %d\ncanonical union-boundary blocks: %d\nroutine-to-block context relations: %d\nexceptional owner-qualified blocks: %d\npartition anomalies: %d\n"
  s.canonical_instruction_count s.exceptional_instruction_count s.canonical_block_count s.block_context_count
  s.exceptional_block_count s.partition_anomaly_count
