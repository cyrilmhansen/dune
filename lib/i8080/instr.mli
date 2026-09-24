(** Semantic representation of Intel 8080 instructions. This module describes
    instructions only; it does not execute them. *)

type register = A | B | C | D | E | H | L

type register_pair = BC | DE | HL | SP

type indirect_pair = Indirect_BC | Indirect_DE

type stack_pair = Stack_BC | Stack_DE | Stack_HL | PSW

type register_or_memory = Register of register | Memory_at_HL

type condition =
  | Not_zero
  | Zero
  | Not_carry
  | Carry
  | Parity_odd
  | Parity_even
  | Positive
  | Minus

type alu_operation =
  | Add
  | Add_with_carry
  | Subtract
  | Subtract_with_borrow
  | And
  | Xor
  | Or
  | Compare

type rotate = Rotate_left
  | Rotate_right
  | Rotate_left_through_carry
  | Rotate_right_through_carry

type t =
  | Nop
  | Mov of register_or_memory * register_or_memory
  | Mvi of register_or_memory * int
  | Lxi of register_pair * int
  | Ldax of indirect_pair
  | Stax of indirect_pair
  | Lda of int
  | Sta of int
  | Lhld of int
  | Shld of int
  | Inr of register_or_memory
  | Dcr of register_or_memory
  | Inx of register_pair
  | Dcx of register_pair
  | Dad of register_pair
  | Alu of alu_operation * register_or_memory
  | Alu_immediate of alu_operation * int
  | Rotate of rotate
  | Daa
  | Cma
  | Stc
  | Cmc
  | Push of stack_pair
  | Pop of stack_pair
  | Jump of condition option * int
  | Call of condition option * int
  | Return of condition option
  | Rst of int
  | Input of int
  | Output of int
  | Xthl
  | Xchg
  | Pchl
  | Sphl
  | Ei
  | Di
  | Hlt
