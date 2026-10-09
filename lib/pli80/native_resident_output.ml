[@@@warning "-4-40-41-42"]
module B=Acquisition_family_bridge
module Q=Native_recursive_parent
open Q
type case=Q.case
type result=Q.result
let cases v=v.Q.cases
let record_summaries=Q.record_summaries
let filesystem_hash=Q.filesystem_hash
let require b m=if not b then failwith("resident output proof: "^m)
let compatibility_writes=Q.compatibility_writes
let output_operation offset=if offset>=0x2200 then B.Pli2_output offset else B.Output offset
let image_name offset=if offset>=0x2200 then "PLI2.OVL" else "PLI.COM"
let runtime_base offset=if offset>=0x2200 then 0x2200 else 0x100
let prepare bridge offset ~call ~origin boundary=B.prepare bridge (output_operation offset) ~call ~origin boundary
let shadow ?(offset=0x1272) ?(within=[]) ?(run_negatives=true) input=
 let bridge=B.create_with_images ~pli_com:input.Experiment.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let previous=ref None and origin=ref Analysis.Execution_map.Unknown and active=ref None in
 let cases=ref[]and snapshots=ref[]and records=ref[]and root_records=ref[]and service_index=ref 0 in
 let on_bdos_record ~step_index:_=function Cpm.Bdos.Write_record q->records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!records;(if !active<>None then root_records:=(q.file.name,q.logical_record,Bytes.copy q.data)::!root_records)|_->()in
 let on_guest_step ~step_index:_ ~before ~after step=
  previous:=Some{Native_dispatch.origin= !origin;before;after;step};
  match !active with None->()|Some(_,_,_,_,_,_,_,_,writes,latest,calls)->
   (match I8080.Step.control_flow step with I8080.Step.Call{taken=true;_}->calls:=before.Runner.pc::!calls|_->());
   List.iter(function I8080.Step.Write w->Hashtbl.replace latest w.address(before.pc,w.value);
    if before.pc<>0x1abb&&before.pc<>0x1abc&&before.pc<>0x1ac3&&
     not(List.mem(Char.code(Bytes.get(I8080.Step.fetched_bytes step)0))[0xcd;0xc5;0xd5;0xe5;0xf5])then writes:=(w.address,w.value)::!writes|_->())(I8080.Step.memory_accesses step)in
 let on_before_instruction ~origin:o ~step_index (boundary:Runner.instruction_boundary)=
  origin:=o;let state=boundary.state in
  (match !active with
   |Some(entry_step,call,(entry:Runner.state_snapshot),ram,files,dma,(p:B.prepared),(preview:Runner.host_program_result),writes,latest,calls)when state.pc=call.B.resume&&state.sp=entry.sp+2->
    let prev=Option.get !previous in
    require(I8080.Step.control_flow prev.step=I8080.Step.Return{target=Some call.resume;taken=true}&&prev.before.sp=entry.sp)"RET consumer";
    require(state=p.state)"returned state";
    require(boundary.copy_memory()=preview.memory)"full64KiB RAM";
    require(boundary.dma=preview.dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())preview.filesystem)"DMA/filesystem";
    require(!service_index=List.length preview.services)"service count/order";
    let planned_records=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record q->Some(q.file.name,q.logical_record,q.data)|_->None)s.events)preview.services in
    require(planned_records=List.rev !root_records)"record chronology and bytes";
    require(List.rev !writes=p.logical_writes)"ordered logical writes";
    let final=Hashtbl.create 128 in List.iter(fun(w:B.write)->Hashtbl.replace final w.address(w.writer,w.value))p.journal;
    Hashtbl.iter(fun address value->require(Hashtbl.find_opt latest address=Some value)(Printf.sprintf"last writer %04X"address))final;
    require(Hashtbl.length final=Hashtbl.length latest)"omitted writer";
    let planned_calls=List.filter_map(fun(w:B.write)->if w.kind="compatibility"&&w.address mod 2=entry.sp mod 2&&Char.code(Bytes.get (if w.writer>=0x2200 then input.pli2_ovl else input.pli_com)(w.writer-(if w.writer>=0x2200 then 0x2200 else 0x100)))=0xcd then Some w.writer else None)p.journal in
    require(List.rev !calls=planned_calls)"child CALL chronology";
    require(not(Hashtbl.mem latest entry.sp)&&not(Hashtbl.mem latest(entry.sp+1)))"original continuation lifetime";
    cases:={Q.caller=call.coordinate;entry_step;return_step=step_index-1;input=entry;output=state;route=(if offset=0x1272 then"pending_REL_padding_and_close"else if offset=0x119e then"counted_bits"else if offset=0x1140 then"append_bit"else match List.assoc_opt offset[0x79e2,"fresh_AE05_zero_gate";0x7a17,"fresh_AE04_zero_gate";0x73d0,"bit_gated_indexed_clear";0x8225,"saved_tag_pointer_generation";0x8248,"fixed_C4_pointer_adapter";0x7701,"pointer_trim_and_byte_generation";0x7557,"zero_prefixed_byte";0x756d,"normalized_combined_field";0x75a7,"clear_gate_zero_prefixed_byte";0x75ce,"shifted_field_byte";0x75f1,"two_zero_prefixed_word_bytes";0x7619,"word_carrier_and_byte_pair";0x746f,"clear_gate_byte_carrier";0x74c7,"clear_gate_second_byte_carrier";0x7510,"clear_gate_word_carrier"]with Some route->route|None->"tagged_cached_word");entry_memory_sha256=Experiment.sha256_hex ram;post_memory_sha256=Experiment.sha256_hex preview.memory;stack_cells=List.length(compatibility_writes p);logical_writes=List.length p.logical_writes;prepared=p;services=preview.services;entry_dma=dma;post_dma=preview.dma}::!cases;
    snapshots:=(entry_step,{Q.entry_memory=ram;post_memory=preview.memory;entry_files=files;post_files=boundary.copy_filesystem()})::!snapshots;active:=None
   |_->());
  (match !active with Some(_,_,_,_,_,_,_,(preview:Runner.host_program_result),_,_,_)when state.pc=5->
   let service=List.nth preview.services !service_index in incr service_index;
   require(state=service.resume_state&&boundary.copy_memory()=service.memory_after&&boundary.dma=service.dma_after)"historical ordered service resume boundary"|_->());
  if o=B.origin(image_name offset)offset&&
   (if within<>[]then List.exists(fun(a,b)->a<step_index&&step_index<b)within
    else offset<>0x1140||(Option.get !previous).before.pc=0x13a1) then(
   require(!active=None)"nested output root";
   let call=B.verify_call bridge (output_operation offset)(Option.get !previous)~entry:state in
   let ram=boundary.copy_memory()and files=boundary.copy_filesystem()and dma=boundary.dma in
   let negative=ref 0 in
   let rejects fn=incr negative;match fn()with exception Invalid_argument _->()|_->failwith(Printf.sprintf"unsupported output accepted offset=%04X negative=%d"offset !negative)in
   let altered edits={boundary with copy_memory=(fun()->let b=Bytes.copy ram in List.iter(fun(a,v)->Bytes.set b a(Char.chr v))edits;b);preview_host_program=(fun p->boundary.preview_host_program{p with effects=List.map(fun(a,v)->Runner.Memory_write(a,v))edits@p.effects})}in
   if run_negatives then(
   rejects(fun()->B.verify_call bridge (output_operation offset){(Option.get !previous)with origin=B.origin"PLI1.OVL"0x02e3}~entry:state);
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[call.site,0]));
   rejects(fun()->prepare bridge offset ~call ~origin:(B.origin"PLI1.OVL"offset)boundary);
   rejects(fun()->prepare bridge offset ~call ~origin:o{boundary with state={state with sp=0x20b6}});
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc,0]));
   rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.sp,(Char.code(Bytes.get ram state.sp) lxor 1)]));
   if not(List.mem offset[0x7397;0x73a7;0x7ac4;0x7ad4;0x7ae4;0x79e2;0x7a17;0x73d0;0x7550;0x753c;0x746f;0x74c7;0x7510])then List.iter(fun edits->rejects(fun()->prepare bridge offset ~call ~origin:o(altered edits)))[[0x2029,1];[0x1d8a,128];[0x1d8b,8];[0x2155,0x0a;0x2156,0x1d]];
   if List.mem offset[0x79e2;0x7a17]then rejects(fun()->prepare bridge offset ~call ~origin:o(altered[(if offset=0x79e2 then 0xae05 else 0xae04),(if offset=0x79e2 then 1 else 2)]));
   if List.mem offset[0x793c;0x7b99]then(
    List.iter(fun(index,source)->
     let edits=List.init 8(fun i->0xadab+i,0x20+i)@List.init 8(fun i->0xadb3+i,0x90+i)@[0xae04,0;0xae05,0;0xae06,9;0xae12,0xa5;0x1d8a,127;0x1d8b,7]in
     let staged=altered edits in let staged={staged with state={state with c=index;e=source;d=0x77}}in
     let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let table=Bytes.init 8(fun i->Char.chr(0x20+i))and second=Bytes.init 8(fun i->Char.chr(0x90+i))in
     Bytes.set table index(Char.chr(if source=6 then 0 else 0x20+source));Bytes.set second index(Char.chr(0x90+source));
     require(Bytes.sub result.memory 0xadab 8=table&&Bytes.sub result.memory 0xadb3 8=second)"independent indexed transfer and E6 second-copy law";
     let transferred=List.filter(fun(w:B.write)->List.mem w.writer[0x9b53;0x9b6a;0x9b7d])plan.journal in
     require(List.map(fun(w:B.write)->w.address,w.value)transferred=[0xadab+index,(if source=6 then 0 else 0x20+source);0xadb3+index,0x90+source])"ordered same-index or special clear publications";
     require(List.map(fun(w:B.write)->w.value)(List.filter(fun(w:B.write)->w.writer=0x975a)plan.journal)=[((index lsl 3)lor 0x40 lor source)])"ADD ADD ADD OR field passed to canonical byte emitter";
     let pushes=List.filter(fun(w:B.write)->List.mem w.writer[0x9b61;0x9b74])plan.journal in
     require(List.map(fun(w:B.write)->w.value)pushes=(if source=6 then[0xad;0xb3+source]else[0xad;0xab+source;0xad;0xb3+source]))"exact PUSH temporary source addresses";
     require(plan.state.sp=state.sp+2)"indexed transfer stack ABI"
    )[7,4;5,7;4,6;6,6;0,1;1,1];
    List.iter(fun(c,e)->rejects(fun()->prepare bridge offset ~call ~origin:o{boundary with state={state with c;e}}))[8,1;1,8];
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x2155,0xab;0x2156,0xad]))
   );
   if offset=0x7ae4 then(
    List.iter(fun selector->let bad={boundary with state={state with c=selector}}in
     if selector=7 then rejects(fun()->prepare bridge offset ~call ~origin:o{bad with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b 0xae05 '\001';b)})
     else rejects(fun()->prepare bridge offset ~call ~origin:o{bad with copy_memory=(fun()->let b=Bytes.copy ram in Bytes.set b 0xae04 '\002';b)}))[7;4;5];
    List.iter(fun(selector,pending,count)->
     let staged=altered[0xae04,pending;0xae05,0;0xae06,count;0xae0a,0xee;0x1d8a,127;0x1d8b,7]in
     let staged={staged with state={state with c=selector}}in
     let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let drain=(selector=4||selector=5)&&pending=1 in
     require(Char.code(Bytes.get result.memory 0xae0a)=selector&&Char.code(Bytes.get result.memory 0xae08)=selector&&Char.code(Bytes.get result.memory 0xae09)=selector)"fresh selector carrier provenance";
     require(Char.code(Bytes.get result.memory 0xae04)=(if drain then 0 else pending)&&Char.code(Bytes.get result.memory 0xae06)=(if drain then(count+255)land 255 else count))"pending clear and wrapping decrement law";
     require(List.length(List.filter(fun(w:B.write)->w.writer=0x9bba)plan.journal)=(if drain then 2 else 0))"state-driven fixed C5/E4 child CALL";
     if drain && selector=5 then require(plan.state.a=0&&plan.state.h=0xae&&plan.state.l=6&&plan.state.sign=((count+255)land 255>=128)&&plan.state.zero=(count=1))"final DCR channels"
    )[7,0,9;5,0,9;5,1,1;4,1,0]
   );
   if offset=0x73d0 then(
    List.iter(fun(value,carry)->
     let staged=altered[0xadaa,value;0xadc4,0xfe;0xadab,0x91;0xadb2,0x92]in
     let staged={staged with state={state with carry}}in let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let reset=value land 1<>0 in
     require(List.map(fun(w:B.write)->w.address)(List.filter(fun(w:B.write)->w.writer=0x95f4)plan.journal)=(if reset then List.init 8(fun i->0xadab+i)else[]))"independent eight-byte reset destinations";
     require(plan.state.sp=state.sp+2)"reset stack ABI";
     if reset then require(Bytes.sub result.memory 0xadab 8=Bytes.make 8 '\000')"ordered reset byte contents";
     if reset then require(plan.state.a=7&&plan.state.b=0xad&&plan.state.c=0xab&&plan.state.h=0xad&&plan.state.l=0xc4&&plan.state.carry)"reset final CMP channels"
     else require(plan.state.a=((value lsr 1)lor(if carry then 128 else 0))&&not plan.state.carry&&plan.state.sign=state.sign&&plan.state.zero=state.zero&&plan.state.parity=state.parity&&plan.state.auxiliary_carry=state.auxiliary_carry)"reset clear RAR preserves NZPA"
    )[0,false;2,true;3,false;0x81,true]
   );
   if offset=0x1272 then(
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x1d05,0]));
    (* Synthetic current indices drive padding; no oracle or live mutation. *)
    List.iter(fun(index,bits)->let p=prepare bridge offset ~call ~origin:o(altered[0x1d8a,index;0x1d8b,bits])in
     let n=List.length(List.filter(fun(w:B.write)->w.writer=0x1269)p.journal)in
     require(n=(if index=0&&bits=0 then 0 else(128-index)*8-bits))"state-driven padding termination") [0,0;127,7;127,1;1,0]);
   );
   if run_negatives && List.mem offset[0x11c3;0x11e5;0x1207]then(
    let cache,prefix=List.assoc offset[0x11c3,(0x20b9,0);0x11e5,(0x20bb,0x40);0x1207,(0x20bd,0x80)]in
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x2155,cache land 255;0x2156,cache lsr 8]));
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc+9,prefix lxor 0x40]));
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[state.pc+1,0xb6]));
    List.iter(fun(index,bits,value)->
     let staged=altered[0x1d8a,index;0x1d8b,bits;cache,0xfe;cache+1,0xfd]in
     let staged={staged with state={state with b=value lsr 8;c=value land 255}}in
     let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let buffer=Bytes.sub ram 0x1d0a 128 and cursor=ref index and bit=ref bits and records=ref[]in
     for n=0 to 17 do
      let incoming=if n<2 then(prefix lsr(7-n))land 1 else if n<10 then(value lsr(9-n))land 1 else(value lsr(25-n))land 1 in
      let old=Char.code(Bytes.get buffer !cursor)in Bytes.set buffer !cursor(Char.chr(((old lsl 1)lor incoming)land 255));
      incr bit;if !bit=8 then(bit:=0;incr cursor;if !cursor=128 then(records:=Bytes.copy buffer::!records;cursor:=0))
     done;
     require(Bytes.sub result.memory 0x1d0a 128=buffer)"independent tagged bit stream";
     require(Char.code(Bytes.get result.memory 0x1d8a)= !cursor&&Char.code(Bytes.get result.memory 0x1d8b)= !bit)"wrapping cursor";
     require(Char.code(Bytes.get result.memory cache)=value land 255&&Char.code(Bytes.get result.memory(cache+1))=value lsr 8)"word cache provenance";
     let actual=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record r->Some r.data|_->None)s.events)result.services in
     require(actual=List.rev !records)"synthetic boundary record bytes";
     require(List.map(fun(s:Runner.host_service)->s.call_state.c)result.services=(if !records=[]then[]else[26;21]))"synthetic flush service chronology"
    )[1,0,0x0001;1,0,0x0100;127,7,0xa55a]);
   if run_negatives && offset>=0x2200 then(
    if List.mem offset[0x746f;0x74c7;0x7510;0x756d;0x75a7;0x75ce;0x7619]then rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x201d,1]));
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x9745,0]));
    let cache=if offset=0x7701 then 0xadea else if offset=0x7434 then 0xadc6 else if offset=0x7630 then 0xaddc else 0xade0 in
    rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x2155,cache land 255;0x2156,cache lsr 8]));
    if List.mem offset[0x8225;0x8248]then(
    List.iter(fun edits->rejects(fun()->prepare bridge offset ~call ~origin:o(altered edits)))[[0xae05,1];[0xae04,1];[0x201c,1];[0x201d,1];[0x1c2c,0xff;0x1c2d,0xff]];
    let pointer=if offset=0x8225 then(state.d lsl 8)lor state.e else(state.b lsl 8)lor state.c in
    List.iter(fun(tag,flag)->
     let staged=altered[0xadaa,flag;0xadc4,0xfe;0xadab,0x91;0xadb2,0x92;0x1c2c,0;0x1c2d,0;0x1d8a,127;0x1d8b,7]in
     let staged=if offset=0x8225 then{staged with state={state with c=tag}}else staged in
     let plan=prepare bridge offset ~call ~origin:o staged in
     let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
     let actual_tag=if offset=0x8248 then 0xc4 else tag in
     require(Char.code(Bytes.get result.memory 0xae61)=actual_tag&&Char.code(Bytes.get result.memory 0xae62)=pointer land 255&&Char.code(Bytes.get result.memory 0xae63)=pointer lsr 8)"saved tag/pointer provenance";
     require(Char.code(Bytes.get result.memory 0xadd4)=(if actual_tag=0xc2 then 1 else 9))"canonical C2/09 normalization";
     require(Char.code(Bytes.get result.memory 0xadaa)=(if flag land 1<>0 then 0 else flag))"bit-driven preparation flag lifetime";
     require(List.length(List.filter(fun(w:B.write)->w.writer=0x95f4)plan.journal)=(if flag land 1<>0 then 8 else 0))"state-driven indexed clear";
     require(List.length(List.filter(fun(w:B.write)->w.writer=0x999c)plan.journal)>=1)"canonical pointed generation composed"
    )[0xc2,0;0xc3,3;0xc4,2];
    List.iter(fun pointer->let bad_state=if offset=0x8225 then{state with d=pointer lsr 8;e=pointer land 255}else{state with b=pointer lsr 8;c=pointer land 255}in rejects(fun()->prepare bridge offset ~call ~origin:o{boundary with state=bad_state}))[0xae61;0x1d0a;state.sp]
   );
   if offset=0x7701 then(
     List.iter(fun edits->rejects(fun()->prepare bridge offset ~call ~origin:o(altered edits)))[[0x201c,1];[0x201d,1];[0x1c2c,0xff;0x1c2d,0xff]];
     List.iter(fun pointer->rejects(fun()->prepare bridge offset ~call ~origin:o{boundary with state={state with b=pointer lsr 8;c=pointer land 255}}))[0xadea;0x1d0a;state.sp;0xfffd];
     let pointer=(state.b lsl 8)lor state.c in
     List.iter(fun(field,index,bit,position,modes)->
      let edits=List.mapi(fun i v->pointer+i,v)field@[0x1d8a,index;0x1d8b,bit;0x1c2c,position land 255;0x1c2d,position lsr 8;0x201c,fst modes;0x201d,snd modes]in
      let staged=altered edits in let plan=prepare bridge offset ~call ~origin:o staged in
      let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
      let rec last i=if i>0&&List.nth field i=0x20 then last(i-1)else i in
      let end_index=last 4 in let width=end_index+2 in
      let bits_of value count=List.init count(fun i->(value lsr(7-i))land 1)in
      let incoming=0::bits_of 0 8@(0::bits_of 0 8)@bits_of 0x8c 7@bits_of 0x40 2@bits_of(position land 255)8@bits_of(position lsr 8)8@bits_of(width lsl 5)3@bits_of 0x3f 8@List.concat_map(fun v->bits_of v 8)(List.filteri(fun i _->i<=end_index)field)in
      let buffer=Bytes.sub ram 0x1d0a 128 and cursor=ref index and used=ref bit and records=ref[]in
      List.iter(fun value->let old=Char.code(Bytes.get buffer !cursor)in Bytes.set buffer !cursor(Char.chr(((old lsl 1)lor value)land 255));incr used;if !used=8 then(used:=0;incr cursor;if !cursor=128 then(records:=Bytes.copy buffer::!records;cursor:=0)))incoming;
      require(Bytes.sub result.memory 0x1d0a 128=buffer)"independent pointer field bit stream";
      require(Char.code(Bytes.get result.memory 0xadee)=width&&Char.code(Bytes.get result.memory 0xadec)=end_index+1)"derived trim length/index termination";
      require(Char.code(Bytes.get result.memory 0xaded)=List.nth field end_index)"last pointed-byte publication";
      require(List.map(fun(w:B.write)->w.value)(List.filter(fun(w:B.write)->w.writer=0x9946)plan.journal)=List.init(4-end_index)(fun i->3-i))"state-driven trim retries";
      require(List.length(List.filter(fun(w:B.write)->w.writer=0x999c)plan.journal)=end_index+1)"state-driven byte loop";
      require(Char.code(Bytes.get result.memory 0x1d8a)= !cursor&&Char.code(Bytes.get result.memory 0x1d8b)= !used)"pointer wrapping output cursor";
      let actual=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record r->Some r.data|_->None)s.events)result.services in require(actual=List.rev !records)"pointer synthetic record chronology"
     )[[0x41;0x42;0x43;0x44;0x45],1,0,0,(0,0);[0x41;0x42;0x43;0x44;0x20],1,0,0x1234,(0,0);[0x41;0x42;0x20;0x20;0x20],1,0,0,(2,4);[0x20;0x20;0x20;0x20;0x20],127,7,0xfffd,(0,0);[0x41;0x42;0x43;0x44;0x21],1,0,0,(0,0);[0x41;0x42;0x43;0x44;0x1f],1,0,0,(0,0)]);
    if List.mem offset[0x7557;0x756d;0x75a7;0x75ce;0x75f1;0x7619]then(
     rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x1c2c,0xff;0x1c2d,0xff]));
     List.iter(fun(index,bits,value,field)->
      let staged=altered[0x1d8a,index;0x1d8b,bits;0x1c2c,0;0x1c2d,0]in
      let staged={staged with state={state with b=value lsr 8;c=value land 255;e=field}}in
      let plan=prepare bridge offset ~call ~origin:o staged in
      let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
      let byte=if offset=0x756d then (value land 255)lor(if value land 255=0xc2&&field=9 then 1 else field)
       else if offset=0x75ce then(value land 255)lor((field lsl 3)land 255)else value land 255 in
      let bytes=if List.mem offset[0x75f1;0x7619]then[value land 255;value lsr 8]else[byte]in
      let incoming=List.concat_map(fun v->0::List.init 8(fun i->(v lsr(7-i))land 1))bytes in
      let buffer=Bytes.sub ram 0x1d0a 128 and cursor=ref index and bit=ref bits and records=ref[]in
      List.iter(fun value->let old=Char.code(Bytes.get buffer !cursor)in Bytes.set buffer !cursor(Char.chr(((old lsl 1)lor value)land 255));incr bit;if !bit=8 then(bit:=0;incr cursor;if !cursor=128 then(records:=Bytes.copy buffer::!records;cursor:=0)))incoming;
      require(Bytes.sub result.memory 0x1d0a 128=buffer)"independent compact field bit stream";
      require(Char.code(Bytes.get result.memory 0x1d8a)= !cursor&&Char.code(Bytes.get result.memory 0x1d8b)= !bit)"compact wrapping cursor";
      let actual=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record r->Some r.data|_->None)s.events)result.services in
      require(actual=List.rev !records)"compact synthetic record chronology";
      require(Char.code(Bytes.get result.memory 0x1c2c)=List.length bytes&&Char.code(Bytes.get result.memory 0x1c2d)=0)"compact position law"
     )[1,0,0,0;1,0,0x0080,1;1,0,0x0100,8;127,7,0xa5c2,9;1,0,0xc2,8;1,0,0xc3,9]);
    if List.mem offset[0x7434;0x7630;0x765e]then(
     List.iter(fun(index,bits,value)->
      let staged=altered[0x1d8a,index;0x1d8b,bits;0x1c2c,0;0x1c2d,0]in
      let staged={staged with state={state with b=value lsr 8;c=value land 255}}in
      let plan=prepare bridge offset ~call ~origin:o staged in
      let result=match staged.preview_host_program plan.program with Ok r->r|Error e->failwith e in
      let tag=if offset=0x765e then 0x80 else 0x40 in
      let incoming=if offset=0x7434 then List.init 7(fun i->(0x96 lsr(7-i))land 1)else[1]in
      let incoming=incoming@List.init 2(fun i->(tag lsr(7-i))land 1)@List.init 8(fun i->(value lsr(7-i))land 1)@List.init 8(fun i->(value lsr(15-i))land 1)in
      let buffer=Bytes.sub ram 0x1d0a 128 and cursor=ref index and bit=ref bits and expected=ref[]in
      List.iter(fun b->let old=Char.code(Bytes.get buffer !cursor)in Bytes.set buffer !cursor(Char.chr(((old lsl 1)lor b)land 255));incr bit;
       if !bit=8 then(bit:=0;incr cursor;if !cursor=128 then(expected:=Bytes.copy buffer::!expected;cursor:=0)))incoming;
      require(Bytes.sub result.memory 0x1d0a 128=buffer)"independent adapter bit stream";
      require(Char.code(Bytes.get result.memory 0x1d8a)= !cursor&&Char.code(Bytes.get result.memory 0x1d8b)= !bit)"adapter cursor";
      let actual=List.concat_map(fun(s:Runner.host_service)->List.filter_map(function Cpm.Bdos.Write_record r->Some r.data|_->None)s.events)result.services in
      require(actual=List.rev !expected)"adapter synthetic flush record";
      let position=Char.code(Bytes.get result.memory 0x1c2c)lor(Char.code(Bytes.get result.memory 0x1c2d)lsl 8)in
      require(position=(if offset=0x7434 then value else 2))"adapter publication vs position policy"
     )[1,0,1;1,0,0x100;127,7,0xa55a]);
    if List.mem offset[0x7630;0x765e;0x7550;0x753c]then(
     rejects(fun()->prepare bridge offset ~call ~origin:o(altered[0x1c2c,0xff;0x1c2d,0xff]));
     List.iter(fun value->let plan=prepare bridge offset ~call ~origin:o(altered[0x1c2c,value land 255;0x1c2d,value lsr 8])in
      let count=if offset=0x753c then 1 else 2 in
      require(plan.state.a lor plan.state.l<>0)"position nonzero predicate";
      let publications=List.filter(fun(w:B.write)->w.writer=0x9740)plan.journal in
      require(List.map(fun(w:B.write)->w.value)publications=List.concat_map(fun n->let x=(value+n)land 65535 in[x land 255;x lsr 8])(List.init count(fun i->i+1)))"fresh increment publications"
     )[0;0xff;0x1234]);
   );
   require(boundary.copy_memory()=ram&&boundary.dma=dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())files)"rejection leaked live state";
   let p=prepare bridge offset ~call ~origin:o boundary in
   let preview=match boundary.preview_host_program p.program with Ok r->r|Error e->failwith e in
   root_records:=[];service_index:=0;active:=Some(step_index,call,state,ram,files,dma,p,preview,ref[],Hashtbl.create 128,ref[]))in
 match Experiment.run ~analysis:Experiment.Execution ~on_guest_step ~on_before_instruction ~on_bdos_record input with
 |Error _->failwith"historical output experiment"|Ok historical->require(!active=None)"missing output return";Ok{Q.cases=List.rev !cases;pending=[];historical;snapshots= !snapshots;records=List.rev !records;input_digest=Experiment.sha256_hex(Marshal.to_bytes input[])}

let controller ?(offset=0x1272) ?(exclude_entry_steps=[]) v input=
 require(v.pending=[])"cannot enable an unfinished logical proof";
 let first,last=B.bounds(output_operation offset) in
 require(v.input_digest=Experiment.sha256_hex(Marshal.to_bytes input[]))"source/input proof mismatch";
 let exclusions=List.sort_uniq compare exclude_entry_steps in
 require(List.length exclusions=List.length exclude_entry_steps&&List.for_all(fun n->List.exists(fun c->c.entry_step=n)(cases v))exclusions)"invalid exclusions";
 let selected=List.filter(fun c->not(List.mem c.entry_step exclusions))(cases v) in
 let bridge=B.create_with_images ~pli_com:input.Experiment.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let remaining=ref selected and pending=ref None in
 let prepare previous origin (boundary:Runner.instruction_boundary)=
  let c=match !remaining with q::_->q|[]->failwith"Additional acquisition parent root"in
  let s=List.assoc c.entry_step v.snapshots in
  require(boundary.dma=c.entry_dma&&Cpm.Filesystem.equal(boundary.copy_filesystem())s.entry_files)"entry service_result state proof";
  let call=B.verify_call bridge (output_operation offset) previous ~entry:boundary.state in
  let p=prepare bridge offset ~call ~origin boundary in
  require(p.journal=c.prepared.journal)"ordered compatibility/last-writer proof mismatch";
  let validate(r:Runner.host_program_result)=
   match p.program.validate r with Error _ as e->e|Ok()->
   if r.memory<>s.post_memory||r.dma<>c.post_dma||r.services<>c.services
    ||not(Cpm.Filesystem.equal r.filesystem s.post_files)then Error"root service_result/post-state proof mismatch"else Ok()in
  let program={p.program with validate}in
  let preview=match boundary.preview_host_program program with Ok q->q|Error e->failwith e in
  pending:=Some program;remaining:=List.tl !remaining;
  {Native_dispatch.state=p.state;memory=preview.memory;logical_writes=p.logical_writes;compatibility_writes=compatibility_writes p}in
 let oracles=List.map(fun c->let s=List.assoc c.entry_step v.snapshots in
  {Native_dispatch.input=c.input;output=c.output;entry_memory=s.entry_memory;post_memory=s.post_memory;
   logical_digest=Native_dispatch.write_digest c.prepared.logical_writes})selected in
 let t=Native_dispatch.create ~image:(image_name offset) ~entry_pc:(first+runtime_base offset) ~end_pc:(last+runtime_base offset) ~oracles ~records:v.records ~prepare in
 Native_dispatch.with_host_program t(fun _ _->let p=Option.get !pending in pending:=None;p)
let compare_external v (r:Experiment.result)=
 require(Cpm.Filesystem.equal r.filesystem v.historical.filesystem)"final filesystem";
 let event(e:Experiment.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range in
 require(List.map event r.file_events=List.map event v.historical.file_events)"file event order";
 require(r.console=v.historical.console)"complete console chronology";
 require(r.int_bytes=v.historical.int_bytes&&r.rel_bytes=v.historical.rel_bytes)"INT/REL identity"
let run v input controllers=match Native_dispatch.run input controllers with Error _ as e->e|Ok(_,r)as q->compare_external v r;q
let single ?(offset=0x1272) v input=run v input[controller ~offset v input]
