[@@@warning "-4-40-41-42"]
module D=Pli80.Native_dispatch
module E=Pli80.Experiment
let need b s=if not b then failwith s
let fails f=match f()with exception Failure _->()|_->failwith"defect silently accepted"
let input mixed=
 let com=Bytes.make 0x41 '\000'in
 let put off raw=Bytes.blit_string raw 0 com off(String.length raw)in
 put 0 "\x06\x03\x3e\x01\xcd\x30\x01\x05\xca\x00\x00";
 put 11(if mixed then"\xee\x02"else"\x3e\x01");put 13 "\xc3\x04\x01";
 put 0x30 "\xfe\x00\xca\x3a\x01\x3c\xc9";put 0x3a "\x3e\x01\xcd\x30\x01\xc9";
 {E.pli_com=com;pli0_ovl=Bytes.empty;pli1_ovl=Bytes.empty;pli2_ovl=Bytes.empty;source_name="TEST.PLI";source_bytes=Bytes.of_string"END;";module_name="TEST";command_tail=Bytes.empty;max_steps=1000}
let capture inp=
 let stack=ref[]and done_=ref[]and ordinal=ref 0 in
 let on_before_instruction ~origin:_ ~step_index:_ (b:Runner.instruction_boundary)=
  (match !stack with (n,s,m)::rest when b.state.sp=s.Runner.sp+2 && b.state.pc=(Char.code(Bytes.get m s.sp)lor(Char.code(Bytes.get m(s.sp+1))lsl 8))->
    done_:=(n,{D.input=s;output=b.state;entry_memory=m;post_memory=b.copy_memory();logical_digest=D.write_digest[]})::!done_;stack:=rest|_->());
  if b.state.pc=0x130 then(incr ordinal;stack:=(!ordinal,b.state,b.copy_memory())::!stack)in
 let r=match E.run ~analysis:Execution ~on_before_instruction inp with Ok r->r|_->failwith"fixture reference"in
 need(!stack=[])"fixture frames";List.map snd(List.sort(fun(a,_)(b,_)->compare a b)!done_),r
let prepare _ _ (b:Runner.instruction_boundary)=
 let s=b.state and m=b.copy_memory()in let pc=Char.code(Bytes.get m s.sp)lor(Char.code(Bytes.get m(s.sp+1))lsl 8)in
 need(s.a=1)"unsupported fixture preparation";
 {D.state={s with a=2;pc;sp=s.sp+2;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false};memory=m;logical_writes=[];compatibility_writes=[]}
let controller ?probe ?(prep=prepare) os=
 let t=D.create ~image:"PLI.COM"~entry_pc:0x130 ~end_pc:0x140 ~oracles:os ~records:[] ~prepare:prep in
 match probe with None->t|Some fn->D.with_partial_scope t fn
let eligible _ _ (b:Runner.instruction_boundary)=if b.state.a=1 then D.Eligible else Inapplicable
let run inp t=match D.run inp[t]with Ok q->q|_->failwith"fixture mixed run"
let ()=
 let inp=input true in let all,reference=capture inp in
 let os=List.filter(fun(o:D.oracle)->o.input.a=1)all in
 need(List.length all=5&&List.length os=3)"interleaved/nested entries";
 let t=controller ~probe:eligible os in let counts,result=run inp t in
 need(counts=[3]&&D.declined_count t=2)"partial oracle/transition accounting";
 need(result.run.termination=reference.run.termination&&Cpm.Filesystem.equal result.filesystem reference.filesystem)"fixture external state";
 fails(fun()->run inp(controller os));
 fails(fun()->run inp(controller ~probe:eligible(List.rev os)));
 fails(fun()->run inp(controller ~probe:(fun _ _ _->failwith"invalid probe")os));
 fails(fun()->run inp(controller ~probe:eligible ~prep:(fun _ _ _->failwith"late native failure")os));
 let first=ref true in
 let retry=controller ~probe:eligible ~prep:(fun p o b->if !first then(first:=false;invalid_arg"eligible preparation invariant");prepare p o b)os in
 (match run inp retry with exception Invalid_argument "eligible preparation invariant"->()|_->failwith"eligible invariant swallowed");
 let counts,_=run inp retry in need(counts=[3])"failed preparation consumed an oracle or committed state";
 fails(fun()->run inp(controller ~probe:eligible ~prep:(fun p o b->let q=prepare p o b in {q with state={q.state with a=3}})os));
 fails(fun()->run inp(controller ~probe:(fun _ _ _->D.Inapplicable)os));
 let strict=input false in let os,_=capture strict in
 let counts,_=run strict(controller os)in need(counts=[3])"default complete replacement changed";
 print_endline"partial controller: interleaved/nested guest frames; pure applicability; strict default; invalid preparation/oracles fail closed"

(* Direct real k23 probe checks; all byte changes are copied synthetic inputs. *)
let ()=match Sys.getenv_opt "RUNES_HOST_IMAGES"with None->()|Some images->
 let read name=let c=open_in_bin(Filename.concat images name)in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)in
 let com=read"PLI.COM"and p0=read"PLI0.OVL"and p1=read"PLI1.OVL"and p2=read"PLI2.OVL"in
 let module B=Pli80.Acquisition_family_bridge in
 let bridge=B.create_with_images ~pli_com:com ~pli0:p0 ~pli1:p1 ~pli2:p2 in
 let ram=Bytes.make 65536 '\000'in Bytes.blit com 0 ram 0x100(Bytes.length com);Bytes.blit p2 0 ram 0x2200(Bytes.length p2);
 let put a v=Bytes.set ram a(Char.chr v)in
 let s:Runner.state_snapshot={a=0;b=0;c=5;d=0;e=0;h=0;l=0;pc=0x41b5;sp=0xff80;sign=false;zero=false;auxiliary_carry=false;parity=false;carry=false}in
 put s.sp 0x4c;put(s.sp+1)0x43;put(0xaab0+5)200;put(0xa609+200)23;
 let fetched=Bytes.sub p2 0x2149 3 in need(fetched=Bytes.of_string"\xcd\xb5\x41")"natural historical CALL identity";
 let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok q->q|_->assert false in
 let before={s with pc=0x4349;sp=s.sp+2}in
 let step=I8080.Step.create ~source:Memory ~pc_before:before.pc ~pc_after:s.pc ~decoded ~fetched_bytes:fetched
  ~memory_accesses:[Write{address=s.sp+1;value=0x43};Write{address=s.sp;value=0x4c}]~control_flow:(Call{target=s.pc;taken=true})in
 let previous:D.previous={origin=B.origin"PLI2.OVL"0x2149;before;after=s;step}in
 let files=Cpm.Filesystem.create()in
 let boundary:Runner.instruction_boundary={state=s;read_memory=(fun a->Char.code(Bytes.get ram a));copy_memory=(fun()->Bytes.copy ram);copy_filesystem=(fun()->Cpm.Filesystem.copy files);dma=128;preview_host_program=(fun _->Error"fixture preview forbidden")}in
 let probe()=B.k23_applicability bridge previous ~origin:(B.origin"PLI2.OVL"0x1fb5)boundary in
 let old=Bytes.copy ram in need(probe()=D.Eligible&&ram=old)"read-only canonical lookup eligibility";
 put(0xa609+200)24;need(probe()=D.Inapplicable)"unsupported actual mapped k";put(0xa609+200)23;
 put 0x202e 1;need(probe()=D.Inapplicable)"trace domain decline";put 0x202e 2;need(probe()=D.Eligible)"actual trace bit0";put 0x202e 0;
 let original=Char.code(Bytes.get ram 0x3c4f)in put 0x3c4f 0;
 need(probe()=D.Eligible)"coarse k23 claim must undergo full preparation";
 let call=B.verify_call bridge(Pli2_output 0x1fb5)previous ~entry:s in
 (match B.prepare bridge(Pli2_output 0x1fb5)~call ~origin:(B.origin"PLI2.OVL"0x1fb5)boundary with
 |_->failwith"invalid eligible descriptor accepted"
 |exception Invalid_argument message->need(message="Acquisition_family: 1FB5 descriptor table scope")"eligible failure improperly classified");
 put 0x3c4f original;
 put 0x42af 0;(match probe()with exception Invalid_argument _->()|_->failwith"software writer code corruption declined silently");
 print_endline"real k23 probe: actual lookup/trace domain, immutable software writer, eligible late descriptor failure"
