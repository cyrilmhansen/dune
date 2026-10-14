(* An OCaml caller of upstream MIR, not an independent intermediate representation.
   State = two disjoint eight-byte channels; logical publication order = A, B.
   Bytes are opaque unsigned values. Source 6 clears A and still transfers B. *)
external transfer : bytes -> int -> int -> bool -> bytes = "runes_mir_transfer"
let reference bank source destination =
  if Bytes.length bank <> 16 || source < 0 || source >= 8
     || destination < 0 || destination >= 8 then invalid_arg "unsupported transfer";
  let result = Bytes.make 18 '\000' in
  Bytes.blit bank 0 result 0 16;
  let a = if source = 6 then '\000' else Bytes.get bank source in
  let b = Bytes.get bank (8 + source) in
  Bytes.set result destination a; Bytes.set result (8 + destination) b;
  Bytes.set result 16 a; Bytes.set result 17 b;
  result
let hex bytes = String.concat "" (List.init (Bytes.length bytes)
  (fun i -> Printf.sprintf "%02x" (Char.code (Bytes.get bytes i))))
let unhex s =
  if String.length s mod 2 <> 0 then invalid_arg "hex";
  Bytes.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let need b = if not b then failwith "MIR/reference mismatch"
let () =
  let natural = ref 0 and cpu_source6 = ref 0 and synthetic = ref 0 in
  let check bank source destination expected =
    let original = Bytes.copy bank in
    let answer = reference bank source destination in
    Option.iter (fun e -> need (answer = e)) expected;
    List.iter (fun jit -> need (transfer bank source destination jit = answer);
      need (bank = original)) [false;true]
  in
  let channel = open_in Sys.argv.(1) in
  (try while true do
    match String.split_on_char ' ' (input_line channel) with
    | [kind;src;dst;bank;expected] -> check (unhex bank) (int_of_string src) (int_of_string dst)
      (Some (unhex expected));
      (match kind with "natural" -> incr natural | "deduced-source6" -> incr cpu_source6
       | _ -> failwith "invalid evidence classification")
    | _ -> failwith "bad independent CPU vector"
  done with End_of_file -> close_in channel);
  (* Every supported index pair, distinct and same-valued bytes, with self-copy.
     Synthetic coverage is not natural observation. *)
  for source=0 to 7 do for destination=0 to 7 do
    List.iter (fun bank -> check bank source destination None; incr synthetic)
      ([Bytes.init 16 (fun i -> Char.chr ((i*31+source*7) land 255)); Bytes.make 16 '\255']
       @ if source=6 then [Bytes.make 16 '\000'] else [])
  done done;
  let invalid = ref 0 in
  List.iter (fun (bank,src,dst) -> List.iter (fun jit ->
    let copy=Bytes.copy bank in
    (try ignore(transfer bank src dst jit); failwith "accepted unsupported input"
     with Invalid_argument _ -> incr invalid);
    need(bank=copy)) [false;true])
    [Bytes.make 15 '\000',0,0; Bytes.make 17 '\000',0,0;
     Bytes.make 16 '\000',-1,0; Bytes.make 16 '\000',8,0;
     Bytes.make 16 '\000',0,8; Bytes.make 16 '\000',0,-1];
  Printf.printf "{\"all_passed\":true,\"natural_cases\":%d,\"CPU_source6_synthetic_cases\":%d,\"synthetic_cases\":%d,\"negative_cases\":%d,\"engines\":[\"MIR_interp_arr\",\"MIR_gen\"],\"JIT_optimization_level\":0}\n"
    !natural !cpu_source6 !synthetic !invalid
