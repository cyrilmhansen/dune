[@@@warning "-4-40-41-42"]
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_resident_output
module Q=Pli80.Native_recursive_parent
module D=Pli80.Native_dispatch
module E=Pli80.Experiment
let need b s=if not b then failwith("Pass103: "^s)
let read p=let c=open_in_bin p in Fun.protect ~finally:(fun()->close_in c)(fun()->let b=Bytes.create(in_channel_length c)in really_input c b 0(Bytes.length b);b)
let array f xs="["^String.concat","(List.map f xs)^"]"
let sha=E.sha256_hex
let state(s:Runner.state_snapshot)=
 let flags=2 lor(if s.sign then 128 else 0)lor(if s.zero then 64 else 0)lor
  (if s.auxiliary_carry then 16 else 0)lor(if s.parity then 4 else 0)lor(if s.carry then 1 else 0)in
 array string_of_int[s.pc;s.sp;s.a;s.b*256+s.c;s.d*256+s.e;s.h*256+s.l;flags]
let file_event(e:E.file_event)=e.operation,e.file,e.succeeded,e.logical_record,e.byte_range
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
let negatives inp (v:N.result)=
 let b=bridge inp and results=ref[] in
 List.iter(fun(c:N.case)->if c.route="k33"then(
  let make,seed=fixture inp v c in
  let test label edits state expected=
   let ram=Bytes.copy seed in List.iter(fun(a,x)->Bytes.set ram a(Char.chr x))edits;
   let prev,view=make ram state in let before=Bytes.copy ram in
   let actual=try N.gateway_selection ~k33:true b prev ~origin view with Invalid_argument _|Failure _->"error" in
   need(actual=expected)(label^" got "^actual);need(ram=before)(label^" mutated live RAM");
   results:=label::!results in
  test "positive" [] c.input "k33";
  test "descriptor" [0x3c21+66,0] c.input "guest";
  test "handler" [0x3ddd+66,0] c.input "guest";
  test "predicate" [0x57d8,0xed] c.input "guest";
  test "trace" [0x202e,1] c.input "guest";
  test "hardware continuation" [c.input.sp,0] c.input "guest";
  test "gateway code propagates" [0x41b5,0] c.input "error";
  test "late handler code propagates" [0x61fd,0] c.input "error";
  test "stack collision propagates" [] {c.input with sp=0xad15} "error";
  let ram=Bytes.copy seed in let prev,view=make ram c.input in
  need(N.gateway_selection ~k33:true b prev ~origin view="k33")"eligible";
  let call=B.verify_call b(B.Pli2_output 0x1fb5)prev ~entry:view.state in
  Bytes.set ram 0x61fd '\000';let before=Bytes.copy ram in
  (match N.prepare_selection "k33" b ~call ~origin view with
   |exception Invalid_argument _|exception Failure _->()|_->failwith"late preparation accepted");
  need(ram=before)"eligible failure mutated RAM";
  Bytes.blit seed 0 ram 0 65536;
  need((N.prepare_selection "k33" b ~call ~origin view).state=c.output)"same boundary retry";
  results:="eligible failure/retry"::!results
 ))(N.cases v);
 array(Printf.sprintf"%S")(List.rev !results)
let failures inp (v:N.result)=
 let results=ref[] in
 List.iter(fun(c:N.case)->if c.route="k33"then(
  let change fn={v with Q.cases=List.map(fun(x:N.case)->if x.entry_step=c.entry_step then fn x else x)(N.cases v)}in
  let fail label bad=
   let last=ref None in
   let ctl=N.controller ~k123:true ~k33:true ~offset:0x1fb5 ~observe_selection:(fun route b->if route<>"guest" then last:=Some(b,b.Runner.copy_memory(),b.copy_filesystem(),b.dma)) bad inp in
   (match N.run v inp[ctl]with exception Invalid_argument _|exception Failure _->()|_->failwith(label^" accepted"));
   let b,ram,fs,dma=Option.get !last in
   need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())fs)(label^" live commit");results:=label::!results in
  fail "missing new oracle" {v with Q.cases=List.filter(fun(x:N.case)->x.entry_step<>c.entry_step)(N.cases v)};
  fail "wrong new input"(change(fun c->{c with input={c.input with a=c.input.a lxor 1}}));
  fail "wrong new post-state"(change(fun c->{c with output={c.output with carry=not c.output.carry}}));
  fail "eligible new journal error"(change(fun c->{c with prepared={c.prepared with journal=List.tl c.prepared.journal}}));
  let _,r=match N.run v inp[N.controller ~k123:true ~k33:true ~offset:0x1fb5 v inp]with Ok q->q|_->failwith"recovery"in compare_results v r;
  results:="fresh controller recovery"::!results
 ))(N.cases v);array(Printf.sprintf"%S")(List.rev !results)
let timed fn=let start=Unix.gettimeofday()in let q=fn()in q,Unix.gettimeofday()-.start
let get=function Ok q->q|Error _->failwith"experiment error"
let ()=
 let images=ref""and out=ref""and only=ref""in
 Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string out,"output";"--source",Arg.Set_string only,"source"]ignore"Single-controller scoped installation";
 let sources=List.map(fun name->
  Printf.printf"START %s installed scanned gateway\n%!"name;
  let inp=input !images name in
  let concrete,tguest=timed(fun()->get(E.run ~analysis:Execution inp))in
  let baseline,tacquire_old=timed(fun()->get(N.shadow ~k123:true ~offset:0x1fb5 ~run_negatives:false inp))in
  let reference=ref None in
  let v,tacquire=timed(fun()->get(N.shadow ~k123:true ~k33:true ~offset:0x1fb5 ~run_negatives:false ~observe_gateway:(fun _ b->reference:=Some b) inp))in
  need(concrete.run.steps=v.historical.run.steps)"concrete reference counters";
  let old=N.controller ~k123:true ~offset:0x1fb5 baseline inp in
  let (_,before),told=timed(fun()->get(N.run baseline inp[old]))in compare_results baseline before;
  let live=ref None and order=ref[]in
  let ctl=N.controller ~k123:true ~k33:true ~offset:0x1fb5 ~observe_selection:(fun route b->live:=Some b;if route<>"guest"then order:=(route,sha(b.Runner.copy_memory()))::!order) v inp in
  let (counts,after),tnative=timed(fun()->get(N.run v inp[ctl]))in compare_results v after;
  need(counts=[List.length(N.cases v)])"native count";
  need(List.rev !order=List.map(fun(c:N.case)->c.route,c.entry_memory_sha256)(N.cases v))"chronological oracle order";
  need((Option.get !live).Runner.copy_memory()=(Option.get !reference).Runner.copy_memory())"final full RAM";
  let absorbed=List.filter_map(fun(c:N.case)->
   match List.find_opt(fun(p:N.case)->p.entry_step=c.entry_step)(N.cases v)with
   |Some p->need(c.input=p.input&&c.output=p.output&&c.entry_memory_sha256=p.entry_memory_sha256&&c.post_memory_sha256=p.post_memory_sha256&&c.prepared.journal=p.prepared.journal)"old domain changed";None
   |None->let p=List.find(fun(p:N.case)->p.entry_step<c.entry_step&&p.return_step>c.return_step)(N.cases v)in
    Some(Printf.sprintf"{\"route\":%S,\"entry_step\":%d,\"absorbed_by\":%S,\"parent_entry_step\":%d}"c.route c.entry_step p.route p.entry_step))(N.cases baseline)in
  let roots=array(fun(c:N.case)->Printf.sprintf"{\"route\":%S,\"entry_step\":%d,\"return_step\":%d,\"input\":%s,\"output\":%s,\"entry_RAM_sha256\":%S,\"post_RAM_sha256\":%S,\"ordered_writes_sha256\":%S,\"writes\":%d}"c.route c.entry_step c.return_step(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256(D.write_digest(List.map(fun(w:B.write)->w.address,w.value)c.prepared.journal))(List.length c.prepared.journal))(N.cases v)in
  let count route=List.length(List.filter(fun(c:N.case)->c.route=route)(N.cases v))in
  let negative=negatives inp v and failure=failures inp v in
  Printf.printf"DONE %s roots=%d declined=%d guest=%d -> %d\n%!"name after.run.host_transitions(D.declined_count ctl)before.run.steps after.run.steps;
  Printf.sprintf"{\"source\":%S,\"concrete_guest\":%d,\"pass87_guest\":%d,\"installed_guest\":%d,\"pass87_host\":%d,\"installed_host\":%d,\"k23\":%d,\"k123\":%d,\"k33\":%d,\"declined\":%d,\"concrete_seconds\":%.6f,\"pass87_seconds\":%.6f,\"installed_seconds\":%.6f,\"oracle_acquisition_seconds\":%.6f,\"pass87_acquisition_seconds\":%.6f,\"REL_sha256\":%S,\"INT_sha256\":%s,\"final_RAM_sha256\":%S,\"roots\":%s,\"absorbed_roots\":%s,\"negatives\":%s,\"failures\":%s,\"full_equivalence\":true,\"ordered_oracle_exhaustion\":true}"name concrete.run.steps before.run.steps after.run.steps before.run.host_transitions after.run.host_transitions(count"k23")(count"k123")(count"k33")(D.declined_count ctl)tguest told tnative tacquire tacquire_old(sha(Option.get after.rel_bytes))(match after.int_bytes with None->"null"|Some b->Printf.sprintf"%S"(sha b))(sha((Option.get !live).copy_memory()))roots(array Fun.id absorbed)negative failure
 )(if !only=""then["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]else[!only])in
 let f=open_out !out in Fun.protect ~finally:(fun()->close_out f)(fun()->Printf.fprintf f"{\"all_passed\":true,\"sources\":%s}\n"(array Fun.id sources))
