module F = Fixed_binary_mod
(* Test-only bypass of the abstract OCaml input type to exercise the C guard. *)
external raw_execute : int -> int -> bool -> int = "runes_mir_mod_positive"
let need b = if not b then failwith "Pass112 semantic differential failed"
let () =
  let canary=Bytes.of_string "unchanged OCaml-owned state" in
  let original=Bytes.copy canary and visible_state=ref 73 in
  let cases=List.concat_map(fun b->
    let around n=[n-1;n;n+1]in
    let numerators=List.init 17 Fun.id @ around b @ around(2*b) @ around(7*b)
                   @ [32760;32761;32762;32763;32764;32765;32766;32767]in
    List.map(fun a->a,b)(List.sort_uniq compare(List.filter(fun a->a>=0&&a<=32767)numerators))) [15;3;5] in
  let rows=List.map(fun(a,b)->
    let q,expected=Reference.quotient_and_remainder a b in
    let input=F.of_int a and divisor=F.divisor_of_int b in
    let interp=F.to_int(F.modulo F.Interpreter input divisor)in
    let jit=F.to_int(F.modulo F.Jit input divisor)in
    need(interp=expected && jit=expected);
    need(F.to_int input=a && canary=original && !visible_state=73);
    a,b,q,expected,interp,jit)cases in
  let predicates=List.concat_map(fun i->List.map(fun b->
    let expected=Reference.is_multiple i b in
    let _,_,_,_,interp,jit=List.find(fun(a,d,_,_,_,_)->a=i&&d=b)rows in
    need((interp=0)=expected && (jit=0)=expected);
    i,b,expected,interp=0,jit=0)[15;3;5])(List.init 15(fun n->n+1)) in
  let rejected_ml=ref 0 and rejected_c=ref 0 in
  let rejects f counter =
    (try f();failwith "unsupported input accepted"with Invalid_argument _->incr counter);
    need(canary=original && !visible_state=73)in
  List.iter(fun n->rejects(fun()->ignore(F.of_int n))rejected_ml)[min_int;-32768;-1;32768;max_int];
  List.iter(fun b->rejects(fun()->ignore(F.divisor_of_int b))rejected_ml)[min_int;-15;-1;0;1;2;4;7;32768;max_int];
  let bad=[min_int,3;-32768,3;-1,15;32768,3;max_int,5;0,0;15,0;
           15,(-3);15,1;15,2;15,4;15,7;15,32768;15,max_int;15,min_int]in
  List.iter(fun(a,b)->List.iter(fun jit->
    rejects(fun()->ignore(raw_execute a b jit))rejected_c)[false;true])bad;
  let recovery=List.map(fun e->F.to_int(F.modulo e(F.of_int 32767)F.Fifteen)) [F.Interpreter;F.Jit]in
  need(recovery=[7;7]);need(canary=original && !visible_state=73);
  Printf.printf "{\"all_passed\":true,\"historical_runtime_MOD_observed\":false,\"host_representation\":\"MIR i64 / C int64_t\",\"engines\":[\"MIR_interp_arr\",\"MIR_gen\"],\"JIT_optimization_level\":0,\"accepted_cases_per_engine\":%d,\"additional_recovery_calls_per_engine\":1,\"OCaml_rejections\":%d,\"C_rejections_both_engines\":%d,\"input_state_unchanged\":true,\"case_columns\":[\"a\",\"b\",\"floor_quotient\",\"reference\",\"interpreter\",\"JIT\"],\"cases\":[%s],\"predicate_columns\":[\"i\",\"divisor\",\"reference\",\"interpreter\",\"JIT\"],\"FIZZBUZ_predicates\":[%s]}\n"
    (List.length rows) !rejected_ml !rejected_c
    (String.concat","(List.map(fun(a,b,q,r,x,y)->Printf.sprintf"[%d,%d,%d,%d,%d,%d]"a b q r x y)rows))
    (String.concat","(List.map(fun(i,b,r,x,y)->Printf.sprintf"[%d,%d,%b,%b,%b]"i b r x y)predicates))
