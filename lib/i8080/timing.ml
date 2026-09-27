let cost step =
  let instr = (Step.decoded step).Decode.instr in
  let memory_operand = function Instr.Memory_at_HL -> true | Instr.Register _ -> false in
  let open Instr in
  match instr with
  | Nop -> 4
  | Mov (destination, source) ->
      if memory_operand destination || memory_operand source then 7 else 5
  | Mvi (destination, _) -> if memory_operand destination then 10 else 7
  | Lxi _ -> 10
  | Ldax _ | Stax _ -> 7
  | Lda _ | Sta _ -> 13
  | Lhld _ | Shld _ -> 16
  | Inr operand | Dcr operand -> if memory_operand operand then 10 else 5
  | Inx _ | Dcx _ -> 5
  | Dad _ -> 10
  | Alu (_, operand) -> if memory_operand operand then 7 else 4
  | Alu_immediate _ -> 7
  | Rotate _ | Daa | Cma | Stc | Cmc -> 4
  | Push _ -> 11
  | Pop _ -> 10
  | Jump _ -> 10
  | Call (None, _) -> 17
  | Call (Some _, _) -> (
      match Step.control_flow step with
      | Step.Call { taken = true; _ } -> 17
      | Step.Call { taken = false; _ } -> 11
      | _ -> invalid_arg "I8080.Timing.cost: conditional CALL without CALL outcome")
  | Return None -> 10
  | Return (Some _) -> (
      match Step.control_flow step with
      | Step.Return { taken = true; _ } -> 11
      | Step.Return { taken = false; _ } -> 5
      | _ -> invalid_arg "I8080.Timing.cost: conditional RET without RET outcome")
  | Rst _ -> 11
  | Input _ | Output _ -> 10
  | Xthl -> 18
  | Xchg -> 4
  | Pchl | Sphl -> 5
  | Ei | Di -> 4
  | Hlt -> 7
