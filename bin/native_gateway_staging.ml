[@@@warning "-4-40-41-42"]
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_resident_output
module Q=Pli80.Native_recursive_parent
module D=Pli80.Native_dispatch
module E=Pli80.Experiment
let need b s=if not b then failwith("Pass105: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array f xs="["^String.concat","(List.map f xs)^"]"
let sha=E.sha256_hex
let state(s:Runner.state_snapshot)=
 let flags=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor
  (if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 array string_of_int[s.pc;s.sp;s.a;s.b*256+s.c;s.d*256+s.e;s.h*256+s.l;flags]
let bdos_functions r=
 Analysis.Execution_map.bdos_sites(Option.get r.E.execution_map)
 |>List.map(fun(q:Analysis.Execution_map.bdos_site)->q.function_number,q.count)
let aggregate xs=
 let t=Hashtbl.create 16 in List.iter(fun(k,n)->Hashtbl.replace t k(n+Option.value ~default:0(Hashtbl.find_opt t k)))xs;
 Hashtbl.fold(fun k n xs->(k,n)::xs)t[]|>List.sort compare
let compare_results v r=
 N.compare_external v r;
 need(r.E.run.termination=v.Q.historical.run.termination)"termination";
 (* Full root equality, identical guest execution between accepted roots, and
    deterministic guest suffix establish final CPU equality by induction. *)
 need(r.console_messages |> List.map(fun(q:Pli80.Console_capture.message)->q.text)=
      (v.historical.console_messages |> List.map(fun q->q.Pli80.Console_capture.text)))"compiler messages";
 let native=List.concat_map(fun(c:N.case)->List.map(fun(s:Runner.host_service)->s.call_state.c,1)c.services)(N.cases v)in
 need(aggregate(bdos_functions r@native)=aggregate(bdos_functions v.historical))"guest/native BDOS function totals";
 need(r.run.host_bdos_services=List.length native)"committed native service count"

let input images name=
 let image n=read(Filename.concat images n)in
 let source=let p="examples/pli80/"^name^".PLI"in read(if Sys.file_exists p then p else Filename.concat images(name^".PLI"))in
 {E.pli_com=image"PLI.COM";pli0_ovl=image"PLI0.OVL";pli1_ovl=image"PLI1.OVL";pli2_ovl=image"PLI2.OVL";
  source_name=name^".PLI";source_bytes=E.prepare_source ~normalize:true source;module_name=name;command_tail=Bytes.of_string(" "^name);max_steps=10_000_000}
let preview ram files dma (p:Runner.host_program)=
 let memory=Bytes.copy ram in
 List.iter(function Runner.Memory_write(a,v)->Bytes.set memory a(Char.chr v)|Dispatch_bdos _->failwith"fixture service outside domain")p.effects;
 let r:Runner.host_program_result={memory;filesystem=Cpm.Filesystem.copy files;dma;services=[]}in
 match p.validate r with Ok()->Ok r|Error _ as e->e
let fixture input (v:N.result)(c:N.case) =
 let snap=List.assoc c.entry_step v.snapshots in
 let site=c.input.pc+(int_of_string("0x"^String.sub c.caller (String.index c.caller '+'+1)4)-0x1fb5)in
 let make ram (state:Runner.state_snapshot) =
  let before={state with Runner.pc=site;sp=state.sp+2} in
  let fetched=Bytes.sub input.E.pli2_ovl(site-0x2200)3 in
  let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok q->q|_->failwith"CALL decode"in
  let step=I8080.Step.create ~source:Memory ~pc_before:site ~pc_after:state.pc ~decoded ~fetched_bytes:fetched
   ~memory_accesses:[Write{address=state.sp+1;value=(site+3)lsr 8};Write{address=state.sp;value=(site+3)land 255}]
   ~control_flow:(Call{target=0x41b5;taken=true})in
  let previous:D.previous={origin=B.origin"PLI2.OVL"(site-0x2200);before;after=state;step}in
  let boundary:Runner.instruction_boundary={state;read_memory=(fun a->Char.code(Bytes.get ram a));copy_memory=(fun()->Bytes.copy ram);
   copy_filesystem=(fun()->Cpm.Filesystem.copy snap.entry_files);dma=c.entry_dma;
   preview_host_program=preview ram snap.entry_files c.entry_dma}in previous,boundary in
 make,snap.entry_memory
let origin=B.origin "PLI2.OVL" 0x1fb5
let bridge inp=B.create_with_images ~pli_com:inp.E.pli_com ~pli0:inp.pli0_ovl ~pli1:inp.pli1_ovl ~pli2:inp.pli2_ovl
let timed f=let start=Unix.gettimeofday()in let value=f()in value,Unix.gettimeofday()-.start
let get=function Ok q->q|Error _->failwith"experiment"
let median xs=List.nth(List.sort compare xs)(List.length xs/2)
let sample_json xs=Printf.sprintf"{\"samples\":%s,\"median\":%.6f,\"min\":%.6f,\"max\":%.6f}"(array(Printf.sprintf"%.6f")xs)(median xs)(List.fold_left min infinity xs)(List.fold_left max neg_infinity xs)
let negatives inp (v:N.result)=
 let b=bridge inp and results=ref[]in
 List.iter(fun(c:N.case)->if c.route="k33"||c.route="k216"then(
  let make,seed=fixture inp v c in let ram=Bytes.copy seed in let prev,view=make ram c.input in
  let old=B.gateway_route b prev ~origin view in
  let choose ()=N.stage_gateway_after_existing ~k33:true ~k216:true b prev ~origin view old in
  let binding=choose()in need(binding.route=c.route&&binding.staged<>None)"staged selected domain";
  let p=N.prepare_gateway binding b prev ~origin view in
  let call=B.verify_call b(B.Pli2_output 0x1fb5)prev ~entry:view.state in
  let original=N.prepare_selection c.route b ~call ~origin view in
  need(p.state=original.state&&p.journal=original.journal&&p.logical_writes=original.logical_writes&&p.program.effects=original.program.effects)"same computed ordered program";
  need((choose()).staged<>None&&ram=seed)"repeated assessment/live purity";
  let reject label previous origin boundary=
   let before=Bytes.copy ram in
   (match N.prepare_gateway binding b previous ~origin boundary with exception Failure _|exception Invalid_argument _->()|_->failwith(label^" cached despite changed entry"));
   need(ram=before)(label^" mutation");results:=label::!results in
  Bytes.set ram 0x80(Char.chr(Char.code(Bytes.get ram 0x80)lxor 1));reject "changed full RAM" prev origin view;
  Bytes.blit seed 0 ram 0 65536;
  reject "changed PC" prev origin {view with state={view.state with pc=view.state.pc+1}};
  reject "changed SP" prev origin {view with state={view.state with sp=view.state.sp+2}};
  reject "changed flags" prev origin {view with state={view.state with carry=not view.state.carry}};
  reject "changed DMA" prev origin {view with dma=view.dma lxor 128};
  let fs=view.copy_filesystem()in ignore(Cpm.Filesystem.add_file fs ~name:"ALTER.TXT"(Bytes.of_string"x"));
  reject "changed filesystem" prev origin {view with copy_filesystem=(fun()->Cpm.Filesystem.copy fs)};
  reject "changed ancestry" {prev with before={prev.before with pc=prev.before.pc+1}} origin view;
  reject "changed image" prev (B.origin"PLI1.OVL"0x1fb5) view;
  let broken={view with Runner.preview_host_program=(fun _->Error"transient final preview failure")}in
  need(broken.preview_host_program p.program=Error"transient final preview failure"&&ram=seed)"failed staged preview mutation";
  need((get(view.preview_host_program(N.prepare_gateway binding b prev ~origin view).program)).memory=(List.assoc c.entry_step v.snapshots).post_memory)"same-boundary retry";
  results:="same-boundary staged recovery"::!results;
  let edits=["hardware continuation",c.input.sp,0;"descriptor",(if c.route="k33"then 0x3c63 else 0x3dd1),0;
   "predicate",(if c.route="k33"then 0x57d8 else 0x871a),0xfa;
   "late child",(if c.route="k33"then 0x61fd else 0x8f47),0]in
  List.iter(fun(label,address,value)->
   Bytes.set ram address(Char.chr value);
   let outcome f=try f()with Invalid_argument text->"Invalid_argument:"^text|Failure text->"Failure:"^text in
   let control=outcome(fun()->N.gateway_selection ~k33:true ~k216:true b prev ~origin view)in
   let actual=outcome(fun()->(choose()).route)in
   need(actual=control)(label^" failure class/message changed");
   Bytes.blit seed 0 ram 0 65536;need((choose()).route=c.route)"negative retry";
   results:=label::!results)edits
 ))(N.cases v);array(Printf.sprintf"%S")(List.rev !results)
let oracle_failures inp (v:N.result)=
 let labels=ref[]in
 let test label cases=
  let last=ref None in
  let bad={v with Q.cases=cases}in
  let ctl=N.controller ~k123:true ~k33:true ~k216:true ~offset:0x1fb5 ~observe_selection:(fun route b->if route<>"guest"then last:=Some(b,b.Runner.copy_memory(),b.copy_filesystem(),b.dma))bad inp in
  (match N.run v inp[ctl]with exception Invalid_argument _|exception Failure _->()|_->failwith(label^" accepted"));
  let b,ram,files,dma=Option.get !last in
  need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal files(b.copy_filesystem()))"oracle failure live mutation";
  labels:=label::!labels in
 let cs=N.cases v in
 test "missing oracle" [];
 test "incorrect oracle" (List.mapi(fun i(c:N.case)->if i=0 then {c with input={c.input with a=c.input.a lxor 1}}else c)cs);
 if List.length cs>1 then test "reordered oracles"(List.rev cs);
 array(Printf.sprintf"%S")(List.rev !labels)
(* Root-view timing only, no persistent runtime instrumentation. Nested internal
   copies are not all exposed by these boundary callbacks; report inclusive times. *)
let profile inp (v:N.result)=
 let b=bridge inp in
 array Fun.id(List.filter_map(fun(c:N.case)->if c.route<>"k33"&&c.route<>"k216"then None else
  let make,seed=fixture inp v c in let prev,view=make seed c.input in
  let previews=ref 0. and ram_copies=ref 0. and fs_copies=ref 0. in
  let track bucket f=let q,t=timed f in bucket:= !bucket+.t;q in
  let view={view with Runner.copy_memory=(fun()->track ram_copies view.copy_memory);
   copy_filesystem=(fun()->track fs_copies view.copy_filesystem);
   preview_host_program=(fun p->track previews(fun()->view.preview_host_program p))}in
  let old=B.gateway_route b prev ~origin view in
  let choice,tprobe=timed(fun()->N.stage_gateway_after_existing ~k33:true ~k216:true b prev ~origin view old)in
  let _,thandoff=timed(fun()->N.prepare_gateway choice b prev ~origin view)in
  let call=B.verify_call b(B.Pli2_output 0x1fb5)prev ~entry:view.state in
  let p,tprepare=timed(fun()->N.prepare_selection c.route b ~call ~origin view)in
  let _,tfinal=timed(fun()->get(view.preview_host_program p.program))in
  let _,tdigest=timed(fun()->D.write_digest p.logical_writes)in
  Some(Printf.sprintf"{\"route\":%S,\"assessment_seconds\":%.6f,\"fresh_prepare_seconds\":%.6f,\"cached_handoff_seconds\":%.6f,\"final_preview_seconds\":%.6f,\"logical_digest_seconds\":%.6f,\"inclusive_preview_seconds\":%.6f,\"exposed_RAM_copy_seconds\":%.6f,\"exposed_FS_copy_seconds\":%.6f}"c.route tprobe tprepare thandoff tfinal tdigest !previews !ram_copies !fs_copies))(N.cases v))
let declined_profile inp chronology =
 let b=bridge inp and count=ref 0 and first=ref None and t33=ref 0. and t216=ref 0. in
 List.iter(fun(route,(state:Runner.state_snapshot),captured,files,dma)->if route="guest"then(
  let ram=Bytes.copy captured in
  let word a=Char.code(Bytes.get ram a)lor(Char.code(Bytes.get ram(a+1))lsl 8)in
  let site=word state.sp-3 in
  let before={state with Runner.pc=site;sp=state.sp+2}in
  let fetched=Bytes.sub inp.E.pli2_ovl(site-0x2200)3 in
  let decoded=match I8080.Decode.decode fetched ~offset:0 with Ok q->q|_->failwith"declined CALL"in
  let step=I8080.Step.create ~source:Memory ~pc_before:site ~pc_after:state.pc ~decoded ~fetched_bytes:fetched
   ~memory_accesses:[Write{address=state.sp+1;value=(site+3)lsr 8};Write{address=state.sp;value=(site+3)land 255}]
   ~control_flow:(Call{target=0x41b5;taken=true})in
  let previous:D.previous={origin=B.origin"PLI2.OVL"(site-0x2200);before;after=state;step}in
  let view:Runner.instruction_boundary={state;read_memory=(fun a->Char.code(Bytes.get ram a));copy_memory=(fun()->Bytes.copy ram);
   copy_filesystem=(fun()->Cpm.Filesystem.copy files);dma;preview_host_program=preview ram files dma}in
  let eligible33,t=timed(fun()->Pli80.Scanned_gateway_dependencies.eligible33 b ~call_site:site view)in
  let eligible216,u=timed(fun()->Pli80.K216_gateway_transaction.eligible b ~call_site:site view)in
  need(not eligible33&&not eligible216&&ram=captured)"declined probe domain/purity";
  t33:= !t33+.t;t216:= !t216+.u;incr count;
  if !first=None then(
   (* A cheap index rejection would hide this existing before-index failure. *)
   Bytes.set ram 0x1372(Char.chr(Char.code(Bytes.get ram 0x1372)lxor 1));
   let outcome f=try f()with Invalid_argument s->"error:"^s|Failure s->"error:"^s in
   let original=outcome(fun()->N.gateway_selection ~k33:true ~k216:true b previous ~origin view)in
   let candidate=outcome(fun()->(N.stage_gateway_after_existing ~k33:true ~k216:true b previous ~origin view B.Guest).route)in
   need(candidate=original)"unrelated index canonical failure changed";
   if String.starts_with ~prefix:"error:" original then first:=Some original
  )
 ))chronology;
 need(!first<>None)"missing natural rejected-index code-error discriminant";
 Printf.sprintf"{\"declined_invocations\":%d,\"failed_k33_probe_seconds\":%.6f,\"failed_k216_probe_seconds\":%.6f,\"pre_index_error_preserved\":%S}" !count !t33 !t216(Option.get !first)
let ()=
 let images=ref""and out=ref""and repeats=ref 5 and only=ref""in
 Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string out,"JSON";"--repeats",Arg.Set_int repeats,"odd number of paired samples";"--source",Arg.Set_string only,"source"]ignore"Pass105 bounded staging comparison";
 need(!repeats>=3 && !repeats mod 2=1)"at least three odd paired repeats";
 let sources=List.map(fun name->
  Printf.printf"START %s staging\n%!"name;
  let inp=input !images name and reference=ref None in
  let v=get(N.shadow ~k123:true ~k33:true ~k216:true ~offset:0x1fb5 ~run_negatives:false ~observe_gateway:(fun _ b->reference:=Some b)inp)in
  let control_chronology=ref None and finals=ref None in
  let check reuse detailed=
   let live=ref None and chronology=ref[]in
   let ctl,construct=timed(fun()->N.controller ~reuse_staging:reuse ~k123:true ~k33:true ~k216:true ~offset:0x1fb5 ~observe_selection:(fun route b->live:=Some b;if detailed then chronology:=(route,b.Runner.state,b.copy_memory(),b.copy_filesystem(),b.dma)::!chronology)v inp)in
   let (counts,r),seconds=timed(fun()->get(N.run v inp[ctl]))in compare_results v r;
   need(counts=[List.length(N.cases v)]&&r.run.steps=v.historical.run.steps-List.fold_left(fun n(c:N.case)->n+c.return_step-c.entry_step+1)0(N.cases v))"unchanged guest/host counts";
   let ram=(Option.get !live).Runner.copy_memory()in need(ram=(Option.get !reference).Runner.copy_memory())"final full RAM";
   if detailed then(
    let xs=List.rev !chronology in
    match !control_chronology with None->control_chronology:=Some xs|Some ys->
     need(List.length xs=List.length ys)"accepted/declined chronology length";
     List.iter2(fun(route,s,ram,fs,dma)(route',s',ram',fs',dma')->need(route=route'&&s=s'&&ram=ram'&&dma=dma'&&Cpm.Filesystem.equal fs fs')"complete eligibility chronology")xs ys);
   let identity=r.run.steps,r.run.host_transitions,D.declined_count ctl,sha ram,sha(Option.get r.rel_bytes)in
   (match !finals with None->finals:=Some identity|Some x->need(x=identity)"repeated native identity");
   seconds,construct in
  ignore(check false true);ignore(check true true);
  let before=ref[]and after=ref[]and construction=ref[]in
  for i=0 to !repeats-1 do
   let run reuse=let t,c=check reuse false in construction:=c::!construction;if reuse then after:=t::!after else before:=t::!before in
   if i mod 2=0 then(run false;run true)else(run true;run false)
  done;
  let steps,hosts,declined,ram,rel=Option.get !finals in
  let roots=array(fun(c:N.case)->Printf.sprintf"{\"route\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"ordered_writes_sha256\":%S,\"writes\":%d}"c.route c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256(D.write_digest(List.map(fun(w:B.write)->w.address,w.value)c.prepared.journal))(List.length c.prepared.journal))(N.cases v)in
  let profile=profile inp v and rejects=negatives inp v in
  let declines=declined_profile inp(Option.get !control_chronology)in
  let errors=oracle_failures inp v in
  Printf.printf"DONE %s %.6f -> %.6f guest=%d host=%d declined=%d\n%!"name(median !before)(median !after)steps hosts declined;
  Printf.sprintf"{\"source\":%S,\"control\":%s,\"optimized\":%s,\"controller_construction\":%s,\"guest\":%d,\"host\":%d,\"declined\":%d,\"final_RAM_sha256\":%S,\"REL_sha256\":%S,\"roots\":%s,\"profile\":%s,\"declined_profile\":%s,\"context_negatives\":%s,\"oracle_negatives\":%s,\"all_equivalence\":true}"name(sample_json(List.rev !before))(sample_json(List.rev !after))(sample_json !construction)steps hosts declined ram rel roots profile declines rejects errors
 )(if !only=""then["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]else[!only])in
 let f=open_out !out in Fun.protect ~finally:(fun()->close_out f)(fun()->Printf.fprintf f"{\"all_passed\":true,\"repeats\":%d,\"sources\":%s}\n" !repeats(array Fun.id sources))
