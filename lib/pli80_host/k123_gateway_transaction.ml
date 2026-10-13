(** Proof-only scoped gateway transaction. The installed k23 controller does not
    reference this module. Eligibility executes the same preparation on a copy;
    an eligible preparation error is never caught as a guest fallback. *)
module Q=K123_child_7d05_front
module R=Recursive_mapped
module H=Acquisition_parent
module F=Acquisition_family
let prepare ?(gateway_read=(fun _ _->())) memory ~pli2 ~pli_com ~call_site ~(entry:Q.state) ~observe =
 let need c s=if not c then invalid_arg("k123 gateway: "^s)in
 need(entry.pc=0x41b5 && entry.sp>=0xb220 && entry.sp<=0xfffc)"entry/stack";
 let staged=State.of_bytes(State.copy memory) in
 let immutable a b=for off=a to b-1 do
  need(State.read staged(off+0x2200)=Char.code(Bytes.get pli2 off))"code identity"
 done in
 List.iter(fun(a,b)->immutable a b)[0x1fb5,0x20eb;0x1dff,0x1fb5;0x047d,0x0493;0x0992,0x09b8;0x04a9,0x04c0];
 need(call_site>=0x2200 && call_site+3<0xaa00)"caller image";
 need(State.read staged call_site=0xcd && State.word staged(call_site+1)=0x41b5
      && State.word staged entry.sp=call_site+3)"original hardware CALL word";
 for i=0 to 2 do need(State.read staged(call_site+i)=Char.code(Bytes.get pli2(call_site-0x2200+i)))"caller code" done;
 need(State.read staged 0x202e land 1=0)"trace gate";
 let sp=ref entry.sp and frames=ref [] in
 let write a v=State.write staged a v;observe(Q.Write(a,v)) in
 let word a=State.word staged a in
 let returned_word a=let lo=State.read staged a in gateway_read a lo;
  let hi=State.read staged(a+1)in gateway_read(a+1)hi;lo lor(hi lsl 8)in
 let push v=write(!sp-1)(v lsr 8);write(!sp-2)(v land 255);sp:= !sp-2 in
 let compatibility=function
 |H.Enter(site,target)->
   need(State.read staged site=0xcd && word(site+1)=target)"CALL bytes";
   frames:=(!sp,site+3)::!frames;push(site+3)
 |H.Leave->(match !frames with
   |(before,pc)::rest->need(!sp=before-2 && word !sp=pc)"child RET ownership";
      ignore(returned_word !sp);sp:= !sp+2;frames:=rest
   |[]->invalid_arg"k123 gateway unmatched child")
 |H.Push(site,v)->need(List.mem(State.read staged site)[0xc5;0xd5;0xe5;0xf5])"PUSH bytes";push v
 |H.Pop->sp:= !sp+2
 |_->invalid_arg"k123 gateway unexpected compatibility operation" in
 let impossible()=invalid_arg"k123 gateway unsupported descendant"in
 let handler (q:R.returned)=
  let h=K123_handler_complete.run staged ~pli2 ~pli_com
   ~entry:{Q.pc=0x476e;sp= !sp;a=q.a;bc=q.bc;de=q.de;hl=q.hl;flags=q.flags} ~observe in
  need(h.pc=0x42b4 && h.sp= !sp+2)"software RET";
  sp:=h.sp;{R.a=h.a;bc=h.bc;de=h.de;hl=h.hl;flags=h.flags} in
 let logical:R.returned={a=entry.a;bc=entry.bc;de=entry.de;hl=entry.hl;flags=entry.flags}in
 (* A separate read-only lookup restricts this module to k123. It does not
    replace the gateway's real, scratch-writing +047D execution. *)
 let probe=State.of_bytes(State.copy staged) in
 let k=F.run(F.Pli2_output 0x047d)probe ~entry:logical
  ~write:(fun ~site:_ ~address:_ ~value:_->())~compatibility:(fun _->impossible())
  ~adjust:(fun ~site:_ ~delta:_->impossible())~sp:(fun()->entry.sp)
  ~guard_field:(fun _ _->impossible())~native:(fun ~site:_ ~target:_ _->impossible())
  ~follow_spine:false ~software:(fun ~site:_ ~consumed:_->impossible())in
 need(k.returned.a=123)"canonical index";
 let r=F.run ~read_access:gateway_read ~k123_handler:handler(F.Pli2_output 0x1fb5)staged ~entry:logical
  ~write:(fun ~site:_ ~address ~value->observe(Q.Write(address,value)))~compatibility
  ~adjust:(fun ~site ~delta->need(List.mem(site,delta)[0x41b9,-11;0x41bc,1;0x42e9,12])"SP operation";sp:= !sp+delta)
  ~sp:(fun()-> !sp)~guard_field:(fun _ _->impossible())~native:(fun ~site:_ ~target:_ _->impossible())
  ~follow_spine:false ~software:(fun ~site:_ ~consumed:_->impossible())in
 need(!sp=entry.sp && !frames=[])"outer frame restoration";
 let pc=returned_word !sp in need(pc=State.word memory entry.sp)"original hardware continuation";
 let q=r.returned in
 staged,{Q.pc;sp= !sp+2;a=q.a;bc=q.bc;de=q.de;hl=q.hl;flags=q.flags}
(* Only documented eligibility restrictions may decline. Unexpected canonical
   descendants, frame imbalance and computed continuation failures propagate,
   including during the read-only probe. No blanket exception-to-fallback rule. *)
let scope_rejections = [
 "k123 gateway: entry/stack";"k123 gateway: caller image";
 "k123 gateway: original hardware CALL word";"k123 gateway: caller code";
 "k123 gateway: code identity";"k123 gateway: trace gate";
 "k123 gateway: canonical index";
 "Acquisition_family: 1FB5 descriptor table scope";
 "Acquisition_family: 1FB5 candidate descriptor scope";
 "Acquisition_family: 1FB5 selected handler table scope";
 "Acquisition_family: 1FB5 fallback pointer domain";
 "Acquisition_family: 1DFF descriptor-family scope";
 "k123 generation bounded successful output";
 "k123 +75CE: unsupported output state";"k123 +73A7: inherited output scope";
 "k123 +785C: pointer, output or alias scope";"k123 +77CC: active pointer/stack alias";
 "k123 generation sentinel alias";"k123 generation pointer/stack alias";
 "k123 handler immutable code";"k123 +247B prefix immutable code";
 "k123 +247B immutable suffix";"k123 generation immutable code";
 "k123 generation resident code";"k123 +247B resident code";
 "k123 +247B unsupported initial predicate route";
 "k123 +247B unsupported zero difference route";
 "k123 +247B nonzero +83DC route unsupported"
]
let eligible memory ~pli2 ~pli_com ~call_site ~entry =
 match prepare memory ~pli2 ~pli_com ~call_site ~entry ~observe:(fun _->()) with
 |_->true
 |exception Invalid_argument text when List.mem text scope_rejections->false
