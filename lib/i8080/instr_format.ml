open Instr

let reg = function
  | Instr.A -> "A" | B -> "B" | C -> "C" | D -> "D" | E -> "E"
  | H -> "H" | L -> "L"

let reg_or_mem = function
  | Instr.Register register -> reg register
  | Instr.Memory_at_HL -> "M"

let pair = function
  | Instr.BC -> "B" | DE -> "D" | HL -> "H" | SP -> "SP"

let stack_pair = function
  | Instr.Stack_BC -> "B" | Stack_DE -> "D" | Stack_HL -> "H" | PSW -> "PSW"

let byte n = Printf.sprintf "%02XH" (n land 0xff)
let word n = Printf.sprintf "%04XH" (n land 0xffff)
let operand name arg = name ^ " " ^ arg
let two_operands name first second = name ^ " " ^ first ^ "," ^ second

let condition = function
  | Instr.Not_zero -> "NZ" | Zero -> "Z" | Not_carry -> "NC" | Carry -> "C"
  | Parity_odd -> "PO" | Parity_even -> "PE" | Positive -> "P" | Minus -> "M"

let alu = function
  | Instr.Add -> "ADD" | Add_with_carry -> "ADC" | Subtract -> "SUB"
  | Subtract_with_borrow -> "SBB" | And -> "ANA" | Xor -> "XRA"
  | Or -> "ORA" | Compare -> "CMP"

let alu_immediate = function
  | Instr.Add -> "ADI" | Add_with_carry -> "ACI" | Subtract -> "SUI"
  | Subtract_with_borrow -> "SBI" | And -> "ANI" | Xor -> "XRI"
  | Or -> "ORI" | Compare -> "CPI"

let format = function
  | Instr.Nop -> "NOP"
  | Mov (destination, source) -> two_operands "MOV" (reg_or_mem destination) (reg_or_mem source)
  | Mvi (destination, value) -> two_operands "MVI" (reg_or_mem destination) (byte value)
  | Lxi (register_pair, value) -> two_operands "LXI" (pair register_pair) (word value)
  | Ldax Indirect_BC -> "LDAX B"
  | Ldax Indirect_DE -> "LDAX D"
  | Stax Indirect_BC -> "STAX B"
  | Stax Indirect_DE -> "STAX D"
  | Lda address -> operand "LDA" (word address)
  | Sta address -> operand "STA" (word address)
  | Lhld address -> operand "LHLD" (word address)
  | Shld address -> operand "SHLD" (word address)
  | Inr target -> operand "INR" (reg_or_mem target)
  | Dcr target -> operand "DCR" (reg_or_mem target)
  | Inx register_pair -> operand "INX" (pair register_pair)
  | Dcx register_pair -> operand "DCX" (pair register_pair)
  | Dad register_pair -> operand "DAD" (pair register_pair)
  | Alu (operation, source) -> operand (alu operation) (reg_or_mem source)
  | Alu_immediate (operation, value) -> operand (alu_immediate operation) (byte value)
  | Rotate Rotate_left -> "RLC"
  | Rotate Rotate_right -> "RRC"
  | Rotate Rotate_left_through_carry -> "RAL"
  | Rotate Rotate_right_through_carry -> "RAR"
  | Daa -> "DAA" | Cma -> "CMA" | Stc -> "STC" | Cmc -> "CMC"
  | Push stack -> operand "PUSH" (stack_pair stack)
  | Pop stack -> operand "POP" (stack_pair stack)
  | Jump (None, address) -> operand "JMP" (word address)
  | Jump (Some cond, address) -> operand ("J" ^ condition cond) (word address)
  | Call (None, address) -> operand "CALL" (word address)
  | Call (Some cond, address) -> operand ("C" ^ condition cond) (word address)
  | Return None -> "RET"
  | Return (Some cond) -> "R" ^ condition cond
  | Rst number -> operand "RST" (string_of_int (number land 7))
  | Input port -> operand "IN" (byte port)
  | Output port -> operand "OUT" (byte port)
  | Xthl -> "XTHL" | Xchg -> "XCHG" | Pchl -> "PCHL" | Sphl -> "SPHL"
  | Ei -> "EI" | Di -> "DI" | Hlt -> "HLT"
