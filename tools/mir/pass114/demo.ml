module A = Arithmetic
external raw_execute : int -> int -> bool -> int = "runes_mir_arithmetic"
let need b = if not b then failwith "Pass114 differential failure"
let () =
  let canary=Bytes.of_string "OCaml input remains unchanged" in
  let saved=Bytes.copy canary and visible=ref 73 in
  let cases=[17,25;17,16;17,17;0,0;-10,25;-10,-25;10,-25;-1,0;
             0,50;0,51;0,-32768;0,32767;16383,1;-16384,0;
             16383,-32768;-16384,32767;1,-32768;25,0;26,0] in
  let rows=List.map(fun(a,b)->
    let r=Reference.evaluate a b in
    let input=A.make ~a ~b in
    let interp=A.evaluate A.Interpreter input and jit=A.evaluate A.Jit input in
    need(interp=r.final && jit=r.final);
    need(canary=saved && !visible=73);
    a,b,r,interp,jit)cases in
  let invalid=[min_int,0;max_int,0;0,min_int;0,max_int;-32769,0;32768,0;
               0,-32769;0,32768;16384,-32768;-16385,32767;16383,2;-16384,-1]in
  let rejects_ml=ref 0 and rejects_c=ref 0 and recovery=ref []in
  let recover label =
    List.iter(fun(engine,name)->
      let actual=A.evaluate engine(A.make ~a:17 ~b:25)in need(actual=58);
      need(canary=saved && !visible=73);
      recovery:=(label,name,actual)::!recovery)[A.Interpreter,"interpreter";A.Jit,"JIT"] in
  let reject label f counter =
    (try f();failwith "invalid input accepted" with Invalid_argument _->incr counter);
    need(canary=saved && !visible=73);recover label in
  List.iter(fun(a,b)->
    reject(Printf.sprintf"OCaml %d %d"a b)(fun()->ignore(A.make ~a ~b))rejects_ml;
    List.iter(fun jit->reject(Printf.sprintf"C %d %d %b"a b jit)
      (fun()->ignore(raw_execute a b jit))rejects_c)[false;true])invalid;
  Printf.printf "{\"all_passed\":true,\"historical_runtime_observed\":false,\"engines\":[\"MIR_interp_arr\",\"MIR_gen\"],\"JIT_optimization_level\":0,\"case_columns\":[\"a\",\"b\",\"product\",\"before_IF\",\"take_then\",\"reference_final\",\"interpreter\",\"JIT\"],\"cases\":[%s],\"OCaml_rejections\":%d,\"C_rejections_both_engines\":%d,\"input_state_unchanged\":true,\"recovery_columns\":[\"after\",\"engine\",\"actual\"],\"recoveries\":[%s]}\n"
    (String.concat","(List.map(fun(a,b,r,x,y)->Printf.sprintf"[%d,%d,%d,%d,%b,%d,%d,%d]"
      a b r.Reference.product r.before_if r.take_then r.final x y)rows)) !rejects_ml !rejects_c
    (String.concat","(List.map(fun(label,engine,r)->Printf.sprintf"[\"%s\",\"%s\",%d]"label engine r)(List.rev !recovery)))
