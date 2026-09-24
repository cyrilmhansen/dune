type encoding_status = Documented | Undocumented_alias | Uncertain of string

type opcode_info = { instruction_length : int; encoding_status : encoding_status }

type decoded = {
  opcode : int;
  instr : Instr.t;
  length : int;
  status : encoding_status;
}

type error =
  | Invalid_offset of int
  | Truncated of { opcode : int; required : int; available : int }

type operand = No_operand | Byte_operand of int | Word_operand of int

type spec = {
  byte_count : int;
  classification : encoding_status;
  build : operand -> Instr.t;
}

(* These aliases are historically reported 8080 behaviors, supplied as a
   work list for later confirmation. They have not been experimentally
   verified by this project; no additional apparent holes are inferred. *)
let is_reported_alias = function
  | 0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x30 | 0x38 | 0xcb | 0xd9 | 0xdd
  | 0xed | 0xfd -> true
  | _ -> false

let status_for opcode =
  if is_reported_alias opcode then Undocumented_alias else Documented

let make_spec opcode length build =
  { byte_count = length; classification = status_for opcode; build }

let fixed opcode instr =
  make_spec opcode 1 (function
    | No_operand -> instr
    | Byte_operand _ | Word_operand _ -> assert false)

let byte_immediate opcode build =
  make_spec opcode 2 (function
    | Byte_operand value -> build value
    | No_operand | Word_operand _ -> assert false)

let word_immediate opcode build =
  make_spec opcode 3 (function
    | Word_operand value -> build value
    | No_operand | Byte_operand _ -> assert false)

let register_of_code = function
  | 0 -> Instr.Register Instr.B
  | 1 -> Instr.Register Instr.C
  | 2 -> Instr.Register Instr.D
  | 3 -> Instr.Register Instr.E
  | 4 -> Instr.Register Instr.H
  | 5 -> Instr.Register Instr.L
  | 6 -> Instr.Memory_at_HL
  | 7 -> Instr.Register Instr.A
  | _ -> invalid_arg "Decode.register_of_code"

let pair_of_code = function
  | 0 -> Instr.BC
  | 1 -> Instr.DE
  | 2 -> Instr.HL
  | 3 -> Instr.SP
  | _ -> invalid_arg "Decode.pair_of_code"

let stack_pair_of_code = function
  | 0 -> Instr.Stack_BC
  | 1 -> Instr.Stack_DE
  | 2 -> Instr.Stack_HL
  | 3 -> Instr.PSW
  | _ -> invalid_arg "Decode.stack_pair_of_code"

let condition_of_code = function
  | 0 -> Instr.Not_zero
  | 1 -> Instr.Zero
  | 2 -> Instr.Not_carry
  | 3 -> Instr.Carry
  | 4 -> Instr.Parity_odd
  | 5 -> Instr.Parity_even
  | 6 -> Instr.Positive
  | 7 -> Instr.Minus
  | _ -> invalid_arg "Decode.condition_of_code"

let alu_operation_of_code = function
  | 0 -> Instr.Add
  | 1 -> Instr.Add_with_carry
  | 2 -> Instr.Subtract
  | 3 -> Instr.Subtract_with_borrow
  | 4 -> Instr.And
  | 5 -> Instr.Xor
  | 6 -> Instr.Or
  | 7 -> Instr.Compare
  | _ -> invalid_arg "Decode.alu_operation_of_code"

let lower_opcode opcode =
  match opcode land 7 with
  | 0 -> fixed opcode Instr.Nop
  | 1 ->
      if opcode land 0x0f = 0x01 then
        word_immediate opcode (fun value -> Instr.Lxi (pair_of_code (opcode lsr 4), value))
      else fixed opcode (Instr.Dad (pair_of_code (opcode lsr 4)))
  | 2 -> (
      match opcode with
      | 0x02 -> fixed opcode (Instr.Stax Instr.Indirect_BC)
      | 0x12 -> fixed opcode (Instr.Stax Instr.Indirect_DE)
      | 0x22 -> word_immediate opcode (fun address -> Instr.Shld address)
      | 0x32 -> word_immediate opcode (fun address -> Instr.Sta address)
      | 0x0a -> fixed opcode (Instr.Ldax Instr.Indirect_BC)
      | 0x1a -> fixed opcode (Instr.Ldax Instr.Indirect_DE)
      | 0x2a -> word_immediate opcode (fun address -> Instr.Lhld address)
      | 0x3a -> word_immediate opcode (fun address -> Instr.Lda address)
      | _ -> assert false)
  | 3 ->
      if opcode land 8 = 0 then fixed opcode (Instr.Inx (pair_of_code (opcode lsr 4)))
      else fixed opcode (Instr.Dcx (pair_of_code (opcode lsr 4)))
  | 4 -> fixed opcode (Instr.Inr (register_of_code ((opcode lsr 3) land 7)))
  | 5 -> fixed opcode (Instr.Dcr (register_of_code ((opcode lsr 3) land 7)))
  | 6 ->
      byte_immediate opcode (fun value -> Instr.Mvi (register_of_code ((opcode lsr 3) land 7), value))
  | 7 -> (
      match opcode lsr 3 with
      | 0 -> fixed opcode (Instr.Rotate Instr.Rotate_left)
      | 1 -> fixed opcode (Instr.Rotate Instr.Rotate_right)
      | 2 -> fixed opcode (Instr.Rotate Instr.Rotate_left_through_carry)
      | 3 -> fixed opcode (Instr.Rotate Instr.Rotate_right_through_carry)
      | 4 -> fixed opcode Instr.Daa
      | 5 -> fixed opcode Instr.Cma
      | 6 -> fixed opcode Instr.Stc
      | 7 -> fixed opcode Instr.Cmc
      | _ -> assert false)
  | _ -> assert false

let control_opcode opcode =
  let field = (opcode lsr 3) land 7 in
  match opcode land 7 with
  | 0 -> fixed opcode (Instr.Return (Some (condition_of_code field)))
  | 1 -> (
      match opcode with
      | 0xc1 | 0xd1 | 0xe1 | 0xf1 ->
          fixed opcode (Instr.Pop (stack_pair_of_code ((opcode lsr 4) land 3)))
      | 0xc9 | 0xd9 -> fixed opcode (Instr.Return None)
      | 0xe9 -> fixed opcode Instr.Pchl
      | 0xf9 -> fixed opcode Instr.Sphl
      | _ -> assert false)
  | 2 ->
      word_immediate opcode (fun address ->
          Instr.Jump (Some (condition_of_code field), address))
  | 3 -> (
      match opcode with
      | 0xc3 | 0xcb -> word_immediate opcode (fun address -> Instr.Jump (None, address))
      | 0xd3 -> byte_immediate opcode (fun port -> Instr.Output port)
      | 0xdb -> byte_immediate opcode (fun port -> Instr.Input port)
      | 0xe3 -> fixed opcode Instr.Xthl
      | 0xeb -> fixed opcode Instr.Xchg
      | 0xf3 -> fixed opcode Instr.Di
      | 0xfb -> fixed opcode Instr.Ei
      | _ -> assert false)
  | 4 ->
      word_immediate opcode (fun address ->
          Instr.Call (Some (condition_of_code field), address))
  | 5 -> (
      match opcode with
      | 0xcd | 0xdd | 0xed | 0xfd ->
          word_immediate opcode (fun address -> Instr.Call (None, address))
      | _ -> fixed opcode (Instr.Push (stack_pair_of_code ((opcode lsr 4) land 3))))
  | 6 ->
      byte_immediate opcode (fun value ->
          Instr.Alu_immediate (alu_operation_of_code field, value))
  | 7 -> fixed opcode (Instr.Rst field)
  | _ -> assert false

let spec_for_opcode opcode =
  let spec =
    if opcode < 0x40 then lower_opcode opcode
    else if opcode < 0x80 then
      if opcode = 0x76 then fixed opcode Instr.Hlt
      else
        fixed opcode
          (Instr.Mov
             (register_of_code ((opcode lsr 3) land 7), register_of_code (opcode land 7)))
    else if opcode < 0xc0 then
      fixed opcode
        (Instr.Alu
           (alu_operation_of_code ((opcode lsr 3) land 7), register_of_code (opcode land 7)))
    else control_opcode opcode
  in
  spec

let specs = Array.init 256 spec_for_opcode

let check_opcode opcode =
  if opcode < 0 || opcode > 0xff then invalid_arg "Decode.opcode_info"

let opcode_info opcode =
  check_opcode opcode;
  let spec = specs.(opcode) in
  { instruction_length = spec.byte_count; encoding_status = spec.classification }

let decode bytes ~offset =
  if offset < 0 || offset >= Bytes.length bytes then Error (Invalid_offset offset)
  else
    let opcode = Char.code (Bytes.get bytes offset) in
    let spec = specs.(opcode) in
    let available = Bytes.length bytes - offset in
    if available < spec.byte_count then
      Error (Truncated { opcode; required = spec.byte_count; available })
    else
      let operand =
        match spec.byte_count with
        | 1 -> No_operand
        | 2 -> Byte_operand (Char.code (Bytes.get bytes (offset + 1)))
        | 3 ->
            let low = Char.code (Bytes.get bytes (offset + 1)) in
            let high = Char.code (Bytes.get bytes (offset + 2)) in
            Word_operand (low lor (high lsl 8))
        | _ -> assert false
      in
      Ok
        {
          opcode;
          instr = spec.build operand;
          length = spec.byte_count;
          status = spec.classification;
        }
