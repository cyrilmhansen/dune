open I8080

let cases = ref 0
let bit b = if b then 1 else 0
let parity n =
  let count = ref 0 in
  for i = 0 to 7 do
    if n / (1 lsl i) mod 2 = 1 then incr count
  done;
  !count mod 2 = 0

let psw value ac cy =
  2 + (128 * bit (value >= 128)) + (64 * bit (value = 0))
  + (16 * bit ac) + (4 * bit (parity value)) + bit cy

(* Reference addition/subtraction is a bit-by-bit ripple circuit, not the
   production byte arithmetic / complemented-addition formula. *)
let arithmetic ~subtract a b carry =
  let propagated = ref carry in
  let nibble = ref false in
  let value = ref 0 in
  for i = 0 to 7 do
    let x = a / (1 lsl i) mod 2 and y = b / (1 lsl i) mod 2 in
    let digit = if subtract then x - y - bit !propagated
      else x + y + bit !propagated in
    value := !value + ((digit + 2) mod 2 * (1 lsl i));
    propagated := if subtract then digit < 0 else digit >= 2;
    if i = 3 then nibble := !propagated
  done;
  (!value, psw !value (if subtract then not !nibble else !nibble) !propagated)

let logical operation a b =
  let value = ref 0 in
  for i = 0 to 7 do
    let x = a / (1 lsl i) mod 2 = 1 and y = b / (1 lsl i) mod 2 = 1 in
    let set = match operation with 4 -> x && y | 5 -> x <> y | _ -> x || y in
    if set then value := !value + (1 lsl i)
  done;
  (!value, psw !value (operation = 4 && (a / 8 mod 2 = 1 || b / 8 mod 2 = 1)) false)

let expected operation a b carry =
  match operation with
  | 0 -> arithmetic ~subtract:false a b false
  | 1 -> arithmetic ~subtract:false a b carry
  | 2 | 7 -> arithmetic ~subtract:true a b false
  | 3 -> arithmetic ~subtract:true a b carry
  | _ -> logical operation a b

(* Intel's successive corrections, retaining a ninth bit between stages. *)
let decimal a ac cy =
  let low = if a mod 16 > 9 || ac then 6 else 0 in
  let intermediate = a + low in
  let final = intermediate + (if intermediate / 16 > 9 || cy then 96 else 0) in
  let value = final mod 256 in
  (value, psw value (a mod 16 + low >= 16) (cy || final >= 256))

let actual_psw (r : Alu.result8) =
  let open Alu in
  2 + 128 * bit r.status.szp.sign + 64 * bit r.status.szp.zero
  + 16 * bit r.status.auxiliary_carry + 4 * bit r.status.szp.parity + bit r.carry

let check_result label a b c (value, flags) (r : Alu.result8) =
  incr cases;
  if r.Alu.value <> value || actual_psw r <> flags then
    failwith (Printf.sprintf "%s A=%02X B=%02X carry=%b: got %02X/%02X expected %02X/%02X"
      label a b c r.Alu.value (actual_psw r) value flags)

let test_pure () =
  let open Alu in
  for a = 0 to 255 do
    let s = Alu.szp a in
    assert (s.sign = (a >= 128) && s.zero = (a = 0) && s.parity = parity a);
    incr cases;
    for b = 0 to 255 do
      check_result "ADD" a b false (expected 0 a b false) (Alu.add ~carry:false a b);
      check_result "SUB" a b false (expected 2 a b false) (Alu.subtract ~borrow:false a b);
      List.iter (fun carry ->
        check_result "ADC" a b carry (expected 1 a b carry) (Alu.add ~carry a b);
        check_result "SBB" a b carry (expected 3 a b carry) (Alu.subtract ~borrow:carry a b)
      ) [false; true];
      List.iter (fun (op, f) -> check_result "logic" a b false (logical op a b) (f a b))
        [4, Alu.logand; 5, Alu.logxor; 6, Alu.logor]
    done
  done;
  let reference = Buffer.create 2048 in
  for a = 0 to 255 do
    for ac = 0 to 1 do
      for cy = 0 to 1 do
        let r = Alu.daa ~auxiliary_carry:(ac = 1) ~carry:(cy = 1) a in
        check_result "DAA" a ac (cy = 1) (decimal a (ac = 1) (cy = 1)) r;
        Buffer.add_char reference (Char.chr r.value);
        Buffer.add_char reference (Char.chr (actual_psw r))
      done
    done
  done;
  (* Output from the pinned, separately compiled upstream C implementation.
     See docs/i8080-flags.md and reference/daa_superzazu.c. *)
  assert (Digest.to_hex (Digest.string (Buffer.contents reference)) =
          "deb0a1c2a7373b4578efc9139907abb0");
  List.iter (fun (a, ac, cy, value, flags) ->
    check_result "Intel/edge DAA" a (bit ac) cy (value, flags)
      (Alu.daa ~auxiliary_carry:ac ~carry:cy a))
    [0x9b,false,false,0x01,0x13; 0x1a,false,false,0x20,0x12;
     0xfa,false,false,0x60,0x17; 0x99,true,false,0x9f,0x86;
     0x00,true,false,0x06,0x06; 0x00,false,true,0x60,0x07];
  check_result "Intel SUB" 0x3e 0x3e false (0,0x56) (Alu.subtract ~borrow:false 0x3e 0x3e);
  check_result "Intel SUI" 9 1 false (8,0x12) (Alu.subtract ~borrow:false 9 1);
  check_result "Intel SBB" 4 2 true (1,0x12) (Alu.subtract ~borrow:true 4 2);
  check_result "no nibble borrow" 0 0 false (0,0x56) (Alu.subtract ~borrow:false 0 0);
  check_result "nibble borrow" 0x10 1 false (0x0f,0x06) (Alu.subtract ~borrow:false 0x10 1);
  check_result "ADD nibble" 15 1 false (16,0x12) (Alu.add ~carry:false 15 1);
  check_result "ADD byte" 255 1 false (0,0x57) (Alu.add ~carry:false 255 1);
  check_result "ADD sign" 127 1 false (128,0x92) (Alu.add ~carry:false 127 1);
  check_result "8080 ANA clear AC" 0 0 false (0,0x46) (Alu.logand 0 0);
  check_result "8080 ANA set AC" 8 0 false (0,0x56) (Alu.logand 8 0)

let memory = Memory.create ()
let state = State.create ()
let cpu = Cpu.create ~state ~bus:(Bus.create memory)
let getters = [|State.b; State.c; State.d; State.e; State.h; State.l; (fun _ -> Memory.read memory 0x2345); State.a|]
let setters = [|State.set_b; State.set_c; State.set_d; State.set_e; State.set_h; State.set_l;
  (fun _ value -> Memory.write memory 0x2345 value); State.set_a|]
let flag_byte n =
  2 + 128 * (n / 16 mod 2) + 64 * (n / 8 mod 2) + 16 * (n / 4 mod 2)
  + 4 * (n / 2 mod 2) + n mod 2

let prepare a flags =
  State.set_a state a;
  State.set_bc state 0x4567;
  State.set_de state 0x89ab;
  State.set_hl state 0x2345;
  State.set_sp state 0xfffe;
  State.set_pc state 0x100;
  Flags.restore_from_psw_byte (State.flags state) flags

let execute opcode immediate accesses =
  Memory.write memory 0x100 opcode;
  Option.iter (Memory.write memory 0x101) immediate;
  let before = List.map (fun get -> get state) [State.b;State.c;State.d;State.e;State.h;State.l;State.sp] in
  let step = match Cpu.step cpu with Ok step -> step | Error _ -> failwith "ALU instruction rejected" in
  let length = match immediate with None -> 1 | Some _ -> 2 in
  assert (State.pc state = 0x100 + length);
  assert (Step.pc_before step = 0x100 && Step.pc_after step = 0x100 + length);
  assert (Step.control_flow step = Step.Sequential);
  assert (Step.memory_accesses step = accesses);
  let bytes = match immediate with None -> [opcode] | Some b -> [opcode;b] in
  assert (Step.fetched_bytes step = Bytes.init length (fun i -> Char.chr (List.nth bytes i)));
  assert ((Step.decoded step).Decode.opcode = opcode);
  incr cases;
  before

let check_state (a, flags) =
  assert (State.a state = a);
  assert (Flags.to_psw_byte (State.flags state) = flags)

let unchanged before =
  assert (before = List.map (fun get -> get state) [State.b;State.c;State.d;State.e;State.h;State.l;State.sp])

let test_forms_and_cmp () =
  (* Every CMP operand pair through the actual CPU, not just Alu.subtract. *)
  for a = 0 to 255 do
    for b = 0 to 255 do
      prepare a 0xd7;
      State.set_b state b;
      unchanged (execute 0xb8 None []);
      let _, flags = expected 7 a b false in
      check_state (a, flags)
    done
  done;
  let values = [0;1;7;8;15;16;0x7f;0x80;0xfe;0xff] in
  for op = 0 to 7 do
    for source = 0 to 8 do
      List.iter (fun a -> List.iter (fun b ->
        for f = 0 to 31 do
          prepare a (flag_byte f);
          if source < 8 then setters.(source) state b;
          let initial_a = State.a state in
          let operand = if source < 8 then getters.(source) state else b in
          let opcode, immediate = if source = 8 then (0xc6 + 8 * op, Some b)
            else (0x80 + 8 * op + source, None) in
          let accesses = if source = 6 then [Step.Read {address=0x2345;value=b}] else [] in
          unchanged (execute opcode immediate accesses);
          if source = 6 then assert (Memory.read memory 0x2345 = b);
          let value, flags = expected op initial_a operand (f mod 2 = 1) in
          check_state ((if op = 7 then initial_a else value), flags)
        done
      ) values) values
    done
  done

let test_inr_dcr () =
  let open Alu in
  for destination = 0 to 7 do
    for value = 0 to 255 do
      for cy = 0 to 1 do
        List.iter (fun decrement ->
          prepare 0xa5 (0xd6 + cy);
          setters.(destination) state value;
          let next = (value + (if decrement then 255 else 1)) mod 256 in
          let ac = if decrement then value mod 16 <> 0 else value mod 16 = 15 in
          let pure_value, status = if decrement then Alu.decrement value else Alu.increment value in
          assert (pure_value = next);
          assert (status.auxiliary_carry = ac && status.szp.sign = (next >= 128)
                  && status.szp.zero = (next = 0) && status.szp.parity = parity next);
          let old_regs = Array.map (fun get -> get state) getters in
          let accesses = if destination = 6 then
            [Step.Read {address=0x2345;value}; Step.Write {address=0x2345;value=next}] else [] in
          ignore (execute (4 + destination * 8 + bit decrement) None accesses);
          Array.iteri (fun i get -> assert (get state = (if i = destination then next else old_regs.(i)))) getters;
          assert (State.sp state = 0xfffe);
          assert (Flags.to_psw_byte (State.flags state) = psw next ac (cy = 1));
          if destination = 6 then assert (State.hl state = 0x2345)
        ) [false;true]
      done
    done
  done

let test_unary () =
  for a = 0 to 255 do
    for f = 0 to 31 do
      let flags = flag_byte f in
      let cy = f mod 2 in
      List.iter (fun (opcode,value,carry) ->
        prepare a flags;
        unchanged (execute opcode None []);
        check_state (value, flags - cy + carry)
      ) [0x07,(2*a + a/128) mod 256,a/128;
         0x0f,a/2 + 128*(a mod 2),a mod 2;
         0x17,(2*a + cy) mod 256,a/128;
         0x1f,a/2 + 128*cy,a mod 2;
         0x2f,255-a,cy; 0x37,a,1; 0x3f,a,1-cy];
      prepare a flags;
      unchanged (execute 0x27 None []);
      check_state (decimal a (f / 4 mod 2 = 1) (cy = 1))
    done
  done

let test_dad () =
  let values = [0;1;0xf;0xff;0x100;0x1234;0x4321;0x7fff;0x8000;0xfffe;0xffff] in
  for pair = 0 to 3 do
    List.iter (fun hl -> List.iter (fun operand ->
      for f = 0 to 31 do
        prepare 0xa5 (flag_byte f);
        State.set_hl state hl;
        (match pair with 0 -> State.set_bc state operand | 1 -> State.set_de state operand
          | 2 -> () | _ -> State.set_sp state operand);
        let operand = if pair = 2 then hl else operand in
        let sum = hl + operand in
        assert (Alu.dad hl operand = (sum mod 65536, sum >= 65536));
        let before = execute (0x09 + pair * 16) None [] in
        assert (State.hl state = sum mod 65536);
        (* Exclude H/L, but preserve all other registers and SP. *)
        assert (List.filteri (fun i _ -> i <> 4 && i <> 5) before =
                [State.b state;State.c state;State.d state;State.e state;State.sp state]);
        check_state (0xa5, flag_byte f - f mod 2 + bit (sum >= 65536))
      done
    ) values) values
  done

let () =
  let start = Sys.time () in
  test_pure ();
  test_forms_and_cmp ();
  test_inr_dcr ();
  test_unary ();
  test_dad ();
  Printf.printf "ALU: %d cases, %.3fs CPU time\n" !cases (Sys.time () -. start)
