[@@@warning "-4-40-41-42"]
type t = { code : (int * bytes) list; residues : (int * int) list }
type prepared = {
  result : Pli80_host.Packed_scan.result; memory : bytes;
  state : Runner.state_snapshot; compatibility_writes : (int * int) list;
}
let require yes message = if not yes then invalid_arg ("7BBF bridge: "^message)
let create ~pli_com ~pli1 =
  require (Experiment.sha256_hex pli_com="c6d9c7b697b8909e7ff7326f25bf870d0e9f52b6444fe517c2484742a23bcd80") "incorrect resident image identity";
  require (Experiment.sha256_hex pli1="1ed6d00f423ffb55ab4ea9a49c33a72617b7ccc5ead5ecdcb5bbf1733214e564") "incorrect PLI1 image identity";
  let word b a = Char.code(Bytes.get b a) lor (Char.code(Bytes.get b (a+1)) lsl 8) in
  (* The last CALL writer at each depth is fixed by the established local
     control flow:82C9 before POP D,1A2C after POP D,7B2E after POP B.
     Return bytes are derived from verified CALL sites, never from an oracle. *)
  let residues=List.map(fun (depth,site,target)->
    require (Char.code(Bytes.get pli1 site)=0xcd && word pli1 (site+1)=target)
      "residue CALL encoding";
    depth,0x2200+site+3) [6,0x7bf3,0xa4c9;4,0x7bf7,0x1b2c;2,0x7c14,0x9d2e] in
  let code=(0x1b2c,Bytes.sub pli_com 0x1a2c 7)::
    List.map(fun (a,b)->0x2200+a,Bytes.sub pli1 a (b-a))
      [0x7bbf,0x7c1b;0x7a79,0x7a93;0x82e1,0x82ea;0x82bb,0x82c6;
       0x82c9,0x82d0;0x7b2e,0x7b49;0x7c37,0x7c3b] in
  {code;residues}

let verify_call ~(before:Runner.state_snapshot) ~(after:Runner.state_snapshot) step ~(entry:Runner.state_snapshot) =
  require (I8080.Step.pc_before step=0x9e37 && I8080.Step.pc_after step=0x9dbf
           && I8080.Step.control_flow step=I8080.Step.Call{target=0x9dbf;taken=true})
    "entry lacks actual caller CALL ancestry";
  require (after=entry && before.sp=(entry.sp+2)land 65535) "CALL register/SP ancestry";
  let writes=List.filter_map(function I8080.Step.Write q->Some(q.address,q.value)|_->None)(I8080.Step.memory_accesses step) in
  require (List.sort compare writes=List.sort compare [entry.sp,0x3a;(entry.sp+1)land 65535,0x9e]) "original CALL slot writer"

let prepare t ~origin ~state ~memory =
  require (state.Runner.pc=0x9dbf) "unexpected entry PC";
  require (match origin with Analysis.Execution_map.Image_byte{image;offset}->
    image.name="PLI1.OVL" && image.drive=0 && image.user=0 && offset=0x7bbf|_->false)
    "incorrect canonical boundary identity";
  List.iter Pli80_host.U8.check [state.a;state.b;state.c;state.d;state.e;state.h;state.l];
  Pli80_host.U16.check state.sp;
  let m=Pli80_host.State.of_bytes memory in
  List.iter(fun (address,code)->
    require (Bytes.sub memory address (Bytes.length code)=code) "changed historical boundary/helper code") t.code;
  require (Pli80_host.State.word m state.sp=0x9e3a) "incorrect continuation identity";
  let protected=List.init 8(fun i->Pli80_host.U16.wrap(state.sp-6+i)) in
  require (not(List.exists(fun a->List.exists(fun (base,b)->a>=base && a<base+Bytes.length b)t.code)protected)) "stack/code alias overlap";
  let result=Pli80_host.Packed_scan.run m ~position:state.c ~protected in
  let compatibility_writes=List.concat_map(fun(depth,value)->
    let a=Pli80_host.U16.wrap(state.sp-depth) in
    [a,value land 255;Pli80_host.U16.wrap(a+1),value lsr 8])t.residues in
  List.iter(fun(a,v)->Pli80_host.State.write m a v)compatibility_writes;
  (* Last ANA joins the FF/00 equality and positive masks; RAR retains
     NZPA and the final helper DAD clears CY. AC is operand-bit3 OR,
     including the counter-zero AND top-bit-change exit where AC is clear. *)
  let state={Runner.a=result.counter;b=0;c=result.fresh_index;
    d=result.publication_word lsr 8;e=result.publication_word land 255;
    h=result.auxiliary_address lsr 8;l=result.auxiliary_address land 255;
    sp=Pli80_host.U16.wrap(state.sp+2);pc=0x9e3a;
    sign=false;zero=true;parity=true;carry=false;
    auxiliary_carry=(result.positive_mask lor result.equality_mask)land 8<>0} in
  {result;memory=Pli80_host.State.copy m;state;compatibility_writes}
