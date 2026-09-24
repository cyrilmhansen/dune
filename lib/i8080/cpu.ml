type t = { state : State.t; bus : Bus.t }

type error =
  | Decode_error of Decode.error
  | Unsupported_instruction of Decode.decoded

let create ~state ~bus = { state; bus }

let wrap_address address = address land 0xffff

let fetch_instruction cpu pc =
  let opcode = Bus.read_memory cpu.bus ~address:pc in
  let info = Decode.opcode_info opcode in
  let instruction_length = info.Decode.instruction_length in
  let bytes = Bytes.create instruction_length in
  Bytes.set bytes 0 (Char.chr opcode);
  for index = 1 to instruction_length - 1 do
    let address = wrap_address (pc + index) in
    let byte = Bus.read_memory cpu.bus ~address in
    Bytes.set bytes index (Char.chr byte)
  done;
  match Decode.decode bytes ~offset:0 with
  | Ok decoded -> Ok (decoded, bytes)
  | Error error -> Error (Decode_error error)

let set_register state register value =
  match register with
  | Instr.A -> State.set_a state value
  | Instr.B -> State.set_b state value
  | Instr.C -> State.set_c state value
  | Instr.D -> State.set_d state value
  | Instr.E -> State.set_e state value
  | Instr.H -> State.set_h state value
  | Instr.L -> State.set_l state value

let set_pair state pair value =
  match pair with
  | Instr.BC -> State.set_bc state value
  | Instr.DE -> State.set_de state value
  | Instr.HL -> State.set_hl state value
  | Instr.SP -> State.set_sp state value

let finish cpu pc_before decoded fetched_bytes memory_accesses control_flow =
  Step.create ~pc_before ~pc_after:(State.pc cpu.state) ~decoded ~fetched_bytes
    ~memory_accesses ~control_flow

let step cpu =
  let state = cpu.state in
  let pc_before = State.pc state in
  match fetch_instruction cpu pc_before with
  | Error error -> Error error
  | Ok (decoded, fetched_bytes) ->
      let next_pc = wrap_address (pc_before + decoded.Decode.length) in
      let sequential () =
        State.set_pc state next_pc;
        Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
      in
      (match decoded.Decode.instr with
      | Instr.Nop -> sequential ()
      | Instr.Mvi (Instr.Register register, value) ->
          set_register state register value;
          State.set_pc state next_pc;
          Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
      | Instr.Mvi (Instr.Memory_at_HL, value) ->
          let address = State.hl state in
          Bus.write_memory cpu.bus ~address ~value;
          State.set_pc state next_pc;
          let accesses = [ Step.Write { address; value } ] in
          Ok (finish cpu pc_before decoded fetched_bytes accesses Step.Sequential)
      | Instr.Lxi (pair, value) ->
          set_pair state pair value;
          State.set_pc state next_pc;
          Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
      | Instr.Call (None, target) ->
          let return_address = next_pc in
          let old_sp = State.sp state in
          let high_address = wrap_address (old_sp - 1) in
          let low_address = wrap_address (old_sp - 2) in
          let high_byte = (return_address lsr 8) land 0xff in
          let low_byte = return_address land 0xff in
          Bus.write_memory cpu.bus ~address:high_address ~value:high_byte;
          Bus.write_memory cpu.bus ~address:low_address ~value:low_byte;
          State.set_sp state low_address;
          State.set_pc state target;
          let accesses =
            [
              Step.Write { address = high_address; value = high_byte };
              Step.Write { address = low_address; value = low_byte };
            ]
          in
          let flow = Step.Call { target; taken = true } in
          Ok (finish cpu pc_before decoded fetched_bytes accesses flow)
      | Instr.Return None ->
          let old_sp = State.sp state in
          let high_address = wrap_address (old_sp + 1) in
          let low_byte = Bus.read_memory cpu.bus ~address:old_sp in
          let high_byte = Bus.read_memory cpu.bus ~address:high_address in
          let target = low_byte lor (high_byte lsl 8) in
          let new_sp = wrap_address (old_sp + 2) in
          State.set_sp state new_sp;
          State.set_pc state target;
          let accesses =
            [
              Step.Read { address = old_sp; value = low_byte };
              Step.Read { address = high_address; value = high_byte };
            ]
          in
          let flow = Step.Return { target = Some target; taken = true } in
          Ok (finish cpu pc_before decoded fetched_bytes accesses flow)
      | Instr.Mov _
      | Instr.Ldax _
      | Instr.Stax _
      | Instr.Lda _
      | Instr.Sta _
      | Instr.Lhld _
      | Instr.Shld _
      | Instr.Inr _
      | Instr.Dcr _
      | Instr.Inx _
      | Instr.Dcx _
      | Instr.Dad _
      | Instr.Alu _
      | Instr.Alu_immediate _
      | Instr.Rotate _
      | Instr.Daa
      | Instr.Cma
      | Instr.Stc
      | Instr.Cmc
      | Instr.Push _
      | Instr.Pop _
      | Instr.Jump _
      | Instr.Call (Some _, _)
      | Instr.Return (Some _)
      | Instr.Rst _
      | Instr.Input _
      | Instr.Output _
      | Instr.Xthl
      | Instr.Xchg
      | Instr.Pchl
      | Instr.Sphl
      | Instr.Ei
      | Instr.Di
      | Instr.Hlt -> Error (Unsupported_instruction decoded))
