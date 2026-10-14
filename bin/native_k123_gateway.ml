[@@@warning "-4-40-41-42"]
module B=Pli80.Acquisition_family_bridge
module N=Pli80.Native_resident_output
module Q=Pli80.Native_recursive_parent
module D=Pli80.Native_dispatch
module E=Pli80.Experiment
let need b s=if not b then failwith("Pass87: "^s)
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
let negatives input (v:N.result)=
 let k23=List.find(fun(c:N.case)->c.route="k23")(N.cases v)in
 let old_make,old_seed=fixture input v k23 in
 let c=List.find(fun(c:N.case)->c.route="k123")(N.cases v)in
 let make,seed=fixture input v c in
 let o=B.origin"PLI2.OVL"0x1fb5 in
 let bridge=B.create_with_images ~pli_com:input.E.pli_com ~pli0:input.pli0_ovl ~pli1:input.pli1_ovl ~pli2:input.pli2_ovl in
 let old_ram=Bytes.copy old_seed in Bytes.set old_ram 0x3c4f '\000';
 let old_p,old_b=old_make old_ram k23.input in
 need(B.gateway_route bridge old_p ~origin:o old_b=B.K23)"k23 eligibility weakened";
 let old_call=B.verify_call bridge(B.Pli2_output 0x1fb5)old_p ~entry:old_b.state in
 (match B.prepare bridge(B.Pli2_output 0x1fb5) ~call:old_call ~origin:o old_b with
  |exception Invalid_argument _->()|_->failwith"k23 proof failure became k123/fallback");
 let results=ref[]in
 let check label alter =
  let ram=Bytes.copy seed in let state=alter ram c.input in let p,b=make ram state in
  let before=Bytes.copy ram in
  need(B.gateway_route bridge p ~origin:o b=B.Guest)label;
  need(ram=before)(label^" mutated state");results:=label::!results in
 let byte label a value=check label(fun ram q->Bytes.set ram a(Char.chr value);q)in
 check "unsupported index"(fun _ q->{q with c=0});
 byte "k123 descriptor" (0x3c21+246) 0;
 byte "k123 handler" (0x3ddd+246) 0;
 byte "predicate token" 0x3bf7 0xed;
 byte "trace gate" 0x202e 1;
 byte "output error" 0x2029 1;
 byte "output bit" 0x1d8b 8;
 byte "output record" 0x1c2c 0;
 check "scratch pointer alias"(fun ram q->Bytes.set ram 0x2155 '\021';Bytes.set ram 0x2156 '\173';q);
 let errors=ref[]in
 let error label mutate =
  let ram=Bytes.copy seed in let state=mutate ram c.input in
  let p,b=make ram state in let before=Bytes.copy ram in
  (match B.gateway_route bridge p ~origin:o b with exception Invalid_argument _->()|_->failwith(label^" error declined"));
  need(ram=before)(label^" mutation");errors:=label::!errors in
 error "invalid gateway code"(fun ram q->Bytes.set ram 0x41b5 '\000';q);
 byte "invalid CALL word" c.input.sp 0;
 error "stack scratch ABI"(fun _ q->{q with sp=0xad15});
 error "unexpected predicate proof"(fun ram q->for i=0 to 255 do Bytes.set ram(0xa6cf+i)'\255' done;q);
 let ram=Bytes.copy seed in let p,b=make ram c.input in
 need(B.gateway_route bridge p ~origin:o b=B.K123)"eligible fixture";
 let call=B.verify_call bridge(B.Pli2_output 0x1fb5)p ~entry:b.state in
 Bytes.set ram 0x476e '\000';let before=Bytes.copy ram in
 (match B.prepare_k123 bridge ~call ~origin:o b with exception Invalid_argument _->()|_->failwith"eligible late failure swallowed");
 need(ram=before)"late failure mutation";
 Bytes.blit seed 0 ram 0 65536;
 let recovered=B.prepare_k123 bridge ~call ~origin:o b in
 need(recovered.state=c.output)"same-boundary preparation recovery";
 array(Printf.sprintf"%S")(List.rev !results),array(Printf.sprintf"%S")(List.rev !errors)
let controller_failures input (v:N.result)=
 let results=ref[]in
 let first=List.hd(N.cases v)in
 let fail label bad=
  let last=ref None in
  let controller=N.controller ~observe_gateway:(fun route b->
    if route<>B.Guest then last:=Some(b,b.Runner.copy_memory(),b.copy_filesystem(),b.dma))
   ~k123:true ~offset:0x1fb5 bad input in
  (match N.run v input[controller]with exception Failure _|exception Invalid_argument _->()
    |_->failwith(label^" accepted bad oracle"));
  let b,ram,files,dma=Option.get !last in
  need(b.copy_memory()=ram&&b.dma=dma&&Cpm.Filesystem.equal(b.copy_filesystem())files)(label^" live transition");
  results:=label::!results in
 let change fn={v with Q.cases=List.map(fun(c:N.case)->if c.entry_step=first.entry_step then fn c else c)(N.cases v)}in
 fail "missing eligible oracle" {v with Q.cases=[]};
 fail "wrong expected input"(change(fun c->{c with input={c.input with a=c.input.a lxor 1}}));
 fail "wrong expected post-state"(change(fun c->{c with output={c.output with carry=not c.output.carry}}));
 let k123=List.find(fun(c:N.case)->c.route="k123")(N.cases v)in
 let change_k123 fn={v with Q.cases=List.map(fun(c:N.case)->if c.entry_step=k123.entry_step then fn c else c)(N.cases v)}in
 fail "omitted k123 oracle" {v with Q.cases=List.filter(fun(c:N.case)->c.entry_step<>k123.entry_step)(N.cases v)};
 fail "wrong k123 post-state"(change_k123(fun c->{c with output={c.output with carry=not c.output.carry}}));
 fail "eligible k123 preparation journal failure"(change_k123(fun c->let p=c.prepared in
   {c with prepared={p with journal=List.tl p.journal}}));
 fail "eligible preparation journal failure"(change(fun c->let p=c.prepared in
   {c with prepared={p with journal=List.tl p.journal}}));
 (* Recovery uses a fresh controller after an aborted full run: declined guest
    frames from an aborted experiment are not a restart/reset API. Same-boundary
    preparation retry and the existing partial controller retry fixture cover
    the original controller's narrower retry contract. *)
 let _,recovered=match N.run v input[N.controller ~k123:true ~offset:0x1fb5 v input]with
   Ok q->q|_->failwith"fresh controller recovery"in compare_results v recovered;
 array(Printf.sprintf"%S")(List.rev !results)
let ()=
 let images=ref""and out=ref""and only=ref""in
 Arg.parse["--images",Arg.Set_string images,"images";"--output",Arg.Set_string out,"ignored result";"--source",Arg.Set_string only,"optional focused source"]ignore"Pass87 one combined gateway controller";
 let sources=ref[]in
 List.iter(fun name->
  let inp=input !images name in
  Printf.printf"START %s combined gateway\n%!"name;
  let reference_live=ref None in
  let v=match N.shadow ~observe_gateway:(fun _ b->reference_live:=Some b) ~k123:true ~offset:0x1fb5 ~run_negatives:false inp with Ok q->q|_->failwith"independent mixed root shadows"in
  let legacy={v with Q.cases=List.filter(fun(c:N.case)->c.route="k23")(N.cases v)}in
  let k23=List.length(N.cases legacy)and k123=List.length(List.filter(fun(c:N.case)->c.route="k123")(N.cases v))in
  let old=N.controller ~offset:0x1fb5 legacy inp in
  let _,before=match N.run v inp[old]with Ok q->q|_->failwith"legacy execution"in compare_results v before;
  let live=ref None and order=ref[]in
  let controller=N.controller ~observe_gateway:(fun route b->
   live:=Some b;
   match route with B.Guest->()|K23|K123->
    let name=if route=B.K23 then "k23"else "k123"in
    order:=(name,sha(b.Runner.copy_memory()))::!order) ~k123:true ~offset:0x1fb5 v inp in
  let counts,after=match N.run v inp[controller]with Ok q->q|_->failwith"combined execution"in compare_results v after;
  need(counts=[k23+k123])"balanced mixed dispatch";
  need(List.rev !order=List.map(fun(c:N.case)->c.route,c.entry_memory_sha256)(N.cases v))"chronological single oracle";
  let final_ram=(Option.get !live).Runner.copy_memory()in
  need(final_ram=(Option.get !reference_live).Runner.copy_memory())"final full RAM";
  let final_memory=sha final_ram in
  let rel=sha(Option.get after.rel_bytes)in
  let rejects,errors=if k123>0 then negatives inp v else "[]","[]"in
  let failures=if k123>0 then controller_failures inp v else "[]"in
  let legacy_journal js=sha(Bytes.of_string("["^String.concat ", "(List.map(fun(w:B.write)->Printf.sprintf"[%d, %d, %d, %d, %S]"w.address w.value w.writer w.depth w.kind)js)^"]"))in
  let roots=array(fun(c:N.case)->Printf.sprintf"{\"route\":%S,\"input\":%s,\"output\":%s,\"input_sha256\":%S,\"post_sha256\":%S,\"writes_sha256\":%S,\"legacy_journal_sha256\":%S,\"entry_step\":%d,\"return_step\":%d}"c.route(state c.input)(state c.output)c.entry_memory_sha256 c.post_memory_sha256(D.write_digest(List.map(fun(w:B.write)->w.address,w.value)c.prepared.journal))(legacy_journal c.prepared.journal)c.entry_step c.return_step)(N.cases v)in
  sources:=Printf.sprintf"{\"source\":%S,\"k23\":%d,\"k123\":%d,\"declined\":%d,\"guest_reference\":%d,\"k23_guest\":%d,\"combined_guest\":%d,\"k23_host\":%d,\"combined_host\":%d,\"host_BDOS_services\":%d,\"REL_sha256\":%S,\"final_RAM_sha256\":%S,\"roots\":%s,\"rejections\":%s,\"errors\":%s,\"controller_failures\":%s,\"full_equivalence\":true,\"single_oracle_order_verified\":true}"name k23 k123(D.declined_count controller)v.historical.run.steps before.run.steps after.run.steps before.run.host_transitions after.run.host_transitions after.run.host_bdos_services rel final_memory roots rejects errors failures::!sources;
  Printf.printf"DONE %s k23=%d k123=%d guest=%d instructions=%d->%d\n%!"name k23 k123(D.declined_count controller)before.run.steps after.run.steps
 ) (if !only=""then["MINIMAL";"FIZZBUZ";"PICTURE";"FACTOR";"OPTIMIST"]else[!only]);
 let c=open_out !out in Fun.protect ~finally:(fun()->close_out c)(fun()->Printf.fprintf c"{\"sources\":%s,\"all_passed\":true,\"one_controller\":true,\"register_vector\":[\"PC\",\"SP\",\"A\",\"BC\",\"DE\",\"HL\",\"PSW\"]}\n"(array Fun.id(List.rev !sources)))
