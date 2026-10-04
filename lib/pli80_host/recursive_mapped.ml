(** Bounded historical +7C1B composition. No decoder, CPU stepping, memoization,
    recursion guard, or snapshot-dependent path selection. *)
type flags = { sign:bool; zero:bool; auxiliary_carry:bool; parity:bool; carry:bool }
type inherited = { position:int; hl:int; de:int; sp:int }
type returned = { a:int; bc:int; de:int; hl:int; flags:flags }
type write = { address:int; value:int; writer:int; depth:int; phase:string }
type compatibility = Call of { site:int; sp:int; depth:int }
                   | Position_carrier of { sp:int; position:int; depth:int }
                   | Dispatch_carrier of { sp:int; mapped:int; depth:int }
type helper = Mapping of int * Mapped_lookup.mapped
            | Attribute of int * Mapped_lookup.attribute
            | Auxiliary_read of int * Auxiliary.access
            | Auxiliary_write of int * Auxiliary.access
            | Packed of int * Packed_scan.result
            | Balance of int * Balance_scan.result
type node = { entry:inherited; frame:int; depth:int; initial_frame:int list;
              mapped:int; path:string; children:node list; helpers:helper list;
              final_frame:int list; returned:returned; return_site:int }
type result = { tree:node; writes:write list }
let parity n =
  let rec count n acc=if n=0 then acc else count(n lsr 1)(acc+(n land 1))in count n 0 mod 2=0
let comparison a b =
  U8.check a;U8.check b;
  let n=U8.wrap(a-b)in
  {sign=n land 128<>0;zero=n=0;parity=parity n;
   auxiliary_carry=(a land 15)>=(b land 15);carry=a<b}
let supported_special ~first ~second =
  U8.check first;U8.check second;
  if first>=second then invalid_arg "Recursive_mapped: unvalidated first>=second special outcome";
  let incremented=U8.wrap(second+1)in
  if incremented<=15 then invalid_arg "Recursive_mapped: unvalidated increment<=0F special outcome";
  incremented
let run memory ~entry ~compatibility ~observe =
  let writes=ref [] in
  let rec operation ancestors depth (entry:inherited) =
    U8.check entry.position;List.iter U16.check[entry.hl;entry.de;entry.sp];
    let f=U16.wrap(entry.sp-5)in
    let cells=List.init 15(fun i->U16.wrap(entry.sp-13+i))in
    (* Address ranges follow byte/word indexing, not inferred source arrays.
       The stack may not alias code, selected storage, or an ancestor frame. *)
    if List.exists(fun a->a>=0x100 && a<0xae50)cells
       || List.exists(fun a->List.mem a ancestors)(List.init 8(fun i->U16.wrap(entry.sp-6+i)))
    then invalid_arg "Recursive_mapped: frame/table/scratch/stack alias";
    let protected=List.sort_uniq compare(ancestors@cells)in
    let frame_cells=List.init 7(fun i->U16.wrap(f+i))in
    let record phase writer address value=
      let w={address;value;writer;depth;phase}in
      writes:=w::!writes;observe w in
    let put phase writer address value=
      State.write memory address value;record phase writer address value in
    let set slot site value=put "frame_assignment" site (U16.wrap(f+slot)) value in
    let get slot=State.read memory(U16.wrap(f+slot))in
    (* Actual PUSH order is high byte, low byte. These five retained bytes
       are logical frame data; the discarded sixth byte is bridge residue. *)
    put "inherited_frame" 0x7c1b (U16.wrap(entry.sp-1))(entry.hl lsr 8);
    put "inherited_frame" 0x7c1b (U16.wrap(entry.sp-2))(entry.hl land 255);
    put "inherited_frame" 0x7c1c (U16.wrap(entry.sp-3))(entry.hl lsr 8);
    put "inherited_frame" 0x7c1c (U16.wrap(entry.sp-4))(entry.hl land 255);
    put "input_frame" 0x7c1e f entry.position;
    compatibility(Position_carrier{sp=U16.wrap(entry.sp-4);position=entry.position;depth});
    let initial_frame=List.init 5 get in
    let helpers=ref [] and children=ref [] in
    let call site sp=compatibility(Call{site;sp;depth})in
    let collect writer(w:Mapped_lookup.write)=record w.phase writer w.address w.value in
    let mapping site position=
      call site f;
      let q=Mapped_lookup.mapped_byte memory ~position ~protected ~write:(collect 0x7a50)in
      helpers:=Mapping(site,q)::!helpers;q in
    let attribute site position=
      call site f;call 0x7a6b(U16.wrap(f-2));
      let q=Mapped_lookup.low_attribute memory ~position ~protected ~write:(fun w->collect(if w.address=0xae37 then 0x7a66 else 0x7a50)w)in
      helpers:=Attribute(site,q)::!helpers;q in
    let auxiliary_read site position=
      call site f;
      let q=Auxiliary.read memory ~position ~protected ~write:(collect 0x7aac)in
      helpers:=Auxiliary_read(site,q)::!helpers;q in
    let auxiliary_write site position value=
      call site f;
      let q=Auxiliary.publish memory ~position ~value ~protected ~write:(fun w->
        collect(if w.address=0xae44 then 0x7b31 else if w.address=0xae43 then 0x7b33 else 0x7b47)w)in
      helpers:=Auxiliary_write(site,q)::!helpers;q in
    let balance site position=
      call site f;
      let q=Balance_scan.run memory ~cursor:position ~protected in
      List.iter(fun(w:Mapped_lookup.write)->
        collect(match w.phase with
        |"cursor_initialization"->0x7b7d|"balance_initialization"->0x7b81
        |"attribute_position"->0x7a66|"mapped_position"->0x7a50
        |"balance_publication"->0x7b8f|"cursor_decrement"->0x7b9a|_->assert false)w)q.writes;
      (* The final iteration's two proven CALL words are the surviving residue.
         They are not logical table writes or a synthetic CPU trace. *)
      call 0x7b87(U16.wrap(f-2));call 0x7a6b(U16.wrap(f-4));
      helpers:=Balance(site,q)::!helpers;q in
    let recurse site position hl de=
      call site f;
      let q=operation (ancestors@frame_cells) (depth+1){position;hl;de;sp=U16.wrap(f-2)}in
      children:=q::!children;q.returned in
    let mapped=(mapping 0x7c25 (get 0)).byte in
    set 3 0x7c2c mapped;
    let finish path return_site a bc de flags =
      {entry;frame=f;depth;initial_frame;mapped;path;children=List.rev !children;
       helpers=List.rev !helpers;final_frame=List.init 5 get;return_site;
       returned={a;bc;de;hl=get 3 lor(get 4 lsl 8);flags={flags with carry=false}}}in
    if mapped=0x21 then invalid_arg "Recursive_mapped: mapped21 unsupported historical scope";
    if mapped=0x0a then (
      call 0x7c37 f;
      let q=Packed_scan.run memory ~position:(get 0) ~protected in
      List.iter(fun(w:Packed_scan.write)->collect(match w.phase with
        |"input_position"->0x7bc2|"counter_initialization"->0x7bc6|"mapped_word_position"->0x7a7c
        |"initial_word"->0x7bcf|"shifted_word"->if w.address=0xae4d then 0x7bed else 0x7bef
        |"counter_decrement"->0x7c08|"auxiliary_value"->0x7b31|"auxiliary_position"->0x7b33
        |"auxiliary_publication"->0x7b47|_->assert false) {Mapped_lookup.address=w.address;value=w.value;phase=w.phase})q.writes;
      call 0x7bf3(U16.wrap(f-6));call 0x7bf7(U16.wrap(f-4));call 0x7c14(U16.wrap(f-2));
      helpers:=Packed(0x7c37,q)::!helpers;
      let flags={sign=false;zero=true;parity=true;carry=false;
        auxiliary_carry=(q.positive_mask lor q.equality_mask)land 8<>0}in
      finish "mapped0A" 0x7c3d q.counter q.fresh_index q.publication_word flags)
    else (
      (* +7C48 stores the equality-1E mask and SBB flags; POP B consumes it.
         Values are independently determined by the instruction chain. *)
      let equal=mapped=0x1e in
      compatibility(Dispatch_carrier{sp=f;mapped;depth});
      if equal then (
        let first=recurse 0x7c5d(U8.wrap(get 0-1)) f entry.de in
        set 2 0x7c64 first.a;
        let scan=balance 0x7c6c(U8.wrap(get 0-1))in
        let second=recurse 0x7c71(U8.wrap(scan.stop_cursor-1)) 0xae49 first.de in
        set 4 0x7c78 second.a;
        let incremented=supported_special ~first:(get 2) ~second:(get 4)in
        set 2 0x7c8f(get 4);set 2 0x7c94 incremented;
        let flags=comparison 15 (get 2)in
        set 2 0x7c9f 15;
        let q=auxiliary_write 0x7cab(get 0)(get 2)in
        finish "mapped1E" 0x7cb6 (get 2) q.index (second.de land 0xff00 lor get 2) flags)
      else if mapped=0x17 then (
        let previous=mapping 0x7cc8(U8.wrap(get 0-1))in
        if previous.byte<>0x0a then (
          (* Complete local getter and exact !=0A dispatch justify this operation
             independent of the concretely observed predecessor05. *)
          let flags=comparison previous.byte 10 in
          let q=auxiliary_read 0x7cd5(get 0)in
          finish "mapped17_fallback" 0x7cdb q.value q.index entry.de flags)
        else (
          let child=recurse 0x7ce3(U8.wrap(get 0-1)) f entry.de in
          set 2 0x7cea child.a;
          let q=auxiliary_write 0x7cf5(get 0)(get 2)in
          finish "mapped17_predecessor0A" 0x7d00(get 2)q.index(child.de land 0xff00 lor get 2)child.flags))
      else (
        let cached=auxiliary_read 0x7d06(get 0)in set 4 0x7d0d cached.value;
        let attr=attribute 0x7d13(get 0)in set 1 0x7d1a attr.low3;
        let de=ref entry.de and bc=ref attr.mapped.byte in
        let rec loop ()=if get 1<>0 then (
          set 0 0x7d2b(U8.wrap(get 0-1));
          let child=recurse 0x7d2d(get 0) f !de in set 2 0x7d34 child.a;
          let scan=balance 0x7d3a(get 0)in de:=child.de;bc:=0;
          set 0 0x7d41 scan.stop_cursor;
          set 1 0x7d46(U8.wrap(get 1-1));loop())in
        loop();finish "default" 0x7d52(get 4)!bc !de(comparison 0 0)))in
  let tree=operation [] 0 entry in {tree;writes=List.rev !writes}
