type t = { state : State.t; bus : Bus.t; mutable halted : bool }

type error =
  | Decode_error of Decode.error
  | Unsupported_instruction of Decode.decoded
  | Bus_io_error of Bus.io_error
  | Cpu_halted

let create ~state ~bus = { state; bus; halted = false }
let is_halted cpu = cpu.halted

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

let register_value state = function
  | Instr.A -> State.a state
  | Instr.B -> State.b state
  | Instr.C -> State.c state
  | Instr.D -> State.d state
  | Instr.E -> State.e state
  | Instr.H -> State.h state
  | Instr.L -> State.l state

let set_register state register value =
  match register with
  | Instr.A -> State.set_a state value
  | Instr.B -> State.set_b state value
  | Instr.C -> State.set_c state value
  | Instr.D -> State.set_d state value
  | Instr.E -> State.set_e state value
  | Instr.H -> State.set_h state value
  | Instr.L -> State.set_l state value

let pair_value state = function
  | Instr.BC -> State.bc state
  | Instr.DE -> State.de state
  | Instr.HL -> State.hl state
  | Instr.SP -> State.sp state

let set_pair state pair value =
  match pair with
  | Instr.BC -> State.set_bc state value
  | Instr.DE -> State.set_de state value
  | Instr.HL -> State.set_hl state value
  | Instr.SP -> State.set_sp state value

let read_register_or_memory cpu = function
  | Instr.Register register -> (register_value cpu.state register, [])
  | Instr.Memory_at_HL ->
      let address = State.hl cpu.state in
      let value = Bus.read_memory cpu.bus ~address in
      (value, [ Step.Read { address; value } ])

let write_register_or_memory cpu destination value =
  match destination with
  | Instr.Register register ->
      set_register cpu.state register value;
      []
  | Instr.Memory_at_HL ->
      let address = State.hl cpu.state in
      Bus.write_memory cpu.bus ~address ~value;
      [ Step.Write { address; value } ]

let read_memory cpu address =
  let address = wrap_address address in
  let value = Bus.read_memory cpu.bus ~address in
  (value, Step.Read { address; value })

let write_memory cpu address value =
  let address = wrap_address address in
  Bus.write_memory cpu.bus ~address ~value;
  Step.Write { address; value }

let push16 cpu value =
  let old_sp = State.sp cpu.state in
  let high_address = wrap_address (old_sp - 1) in
  let low_address = wrap_address (old_sp - 2) in
  let high_byte = (value lsr 8) land 0xff in
  let low_byte = value land 0xff in
  let high_write = write_memory cpu high_address high_byte in
  let low_write = write_memory cpu low_address low_byte in
  State.set_sp cpu.state low_address;
  [ high_write; low_write ]

let pop16 cpu =
  let old_sp = State.sp cpu.state in
  let high_address = wrap_address (old_sp + 1) in
  let low_byte, low_read = read_memory cpu old_sp in
  let high_byte, high_read = read_memory cpu high_address in
  State.set_sp cpu.state (wrap_address (old_sp + 2));
  (low_byte lor (high_byte lsl 8), [ low_read; high_read ])

let stack_pair_value state = function
  | Instr.Stack_BC -> State.bc state
  | Instr.Stack_DE -> State.de state
  | Instr.Stack_HL -> State.hl state
  | Instr.PSW -> (State.a state lsl 8) lor Flags.to_psw_byte (State.flags state)

let set_stack_pair state pair value =
  match pair with
  | Instr.Stack_BC -> State.set_bc state value
  | Instr.Stack_DE -> State.set_de state value
  | Instr.Stack_HL -> State.set_hl state value
  | Instr.PSW ->
      State.set_a state ((value lsr 8) land 0xff);
      Flags.restore_from_psw_byte (State.flags state) (value land 0xff)

let condition_holds state = function
  | Instr.Not_zero -> not (Flags.zero (State.flags state))
  | Instr.Zero -> Flags.zero (State.flags state)
  | Instr.Not_carry -> not (Flags.carry (State.flags state))
  | Instr.Carry -> Flags.carry (State.flags state)
  | Instr.Parity_odd -> not (Flags.parity (State.flags state))
  | Instr.Parity_even -> Flags.parity (State.flags state)
  | Instr.Positive -> not (Flags.sign (State.flags state))
  | Instr.Minus -> Flags.sign (State.flags state)

let finish cpu pc_before decoded fetched_bytes memory_accesses control_flow =
  Step.create ~pc_before ~pc_after:(State.pc cpu.state) ~decoded ~fetched_bytes
    ~memory_accesses ~control_flow

let step cpu =
  if cpu.halted then Error Cpu_halted
  else
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
            let accesses = write_register_or_memory cpu Instr.Memory_at_HL value in
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes accesses Step.Sequential)
        | Instr.Lxi (pair, value) ->
            set_pair state pair value;
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
        | Instr.Mov (destination, source) ->
            let value, reads = read_register_or_memory cpu source in
            let writes = write_register_or_memory cpu destination value in
            State.set_pc state next_pc;
            Ok
              (finish cpu pc_before decoded fetched_bytes (reads @ writes)
                 Step.Sequential)
        | Instr.Ldax pair ->
            let address =
              match pair with
              | Instr.Indirect_BC -> State.bc state
              | Instr.Indirect_DE -> State.de state
            in
            let value, access = read_memory cpu address in
            State.set_a state value;
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [ access ] Step.Sequential)
        | Instr.Stax pair ->
            let address =
              match pair with
              | Instr.Indirect_BC -> State.bc state
              | Instr.Indirect_DE -> State.de state
            in
            let access = write_memory cpu address (State.a state) in
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [ access ] Step.Sequential)
        | Instr.Lda address ->
            let value, access = read_memory cpu address in
            State.set_a state value;
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [ access ] Step.Sequential)
        | Instr.Sta address ->
            let access = write_memory cpu address (State.a state) in
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [ access ] Step.Sequential)
        | Instr.Lhld address ->
            let low, low_read = read_memory cpu address in
            let high, high_read = read_memory cpu (address + 1) in
            State.set_l state low;
            State.set_h state high;
            State.set_pc state next_pc;
            Ok
              (finish cpu pc_before decoded fetched_bytes [ low_read; high_read ]
                 Step.Sequential)
        | Instr.Shld address ->
            let low_write = write_memory cpu address (State.l state) in
            let high_write = write_memory cpu (address + 1) (State.h state) in
            State.set_pc state next_pc;
            Ok
              (finish cpu pc_before decoded fetched_bytes [ low_write; high_write ]
                 Step.Sequential)
        | Instr.Inx pair ->
            set_pair state pair (wrap_address (pair_value state pair + 1));
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
        | Instr.Dcx pair ->
            set_pair state pair (wrap_address (pair_value state pair - 1));
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
        | Instr.Push pair ->
            let accesses = push16 cpu (stack_pair_value state pair) in
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes accesses Step.Sequential)
        | Instr.Pop pair ->
            let value, accesses = pop16 cpu in
            set_stack_pair state pair value;
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes accesses Step.Sequential)
        | Instr.Call (condition, target) ->
            let taken =
              match condition with None -> true | Some condition -> condition_holds state condition
            in
            if not taken then (
              State.set_pc state next_pc;
              Ok
                (finish cpu pc_before decoded fetched_bytes []
                   (Step.Call { target; taken = false })))
            else
              let accesses = push16 cpu next_pc in
              State.set_pc state target;
              Ok
                (finish cpu pc_before decoded fetched_bytes accesses
                   (Step.Call { target; taken = true }))
        | Instr.Return condition ->
            let taken =
              match condition with None -> true | Some condition -> condition_holds state condition
            in
            if not taken then (
              State.set_pc state next_pc;
              Ok
                (finish cpu pc_before decoded fetched_bytes []
                   (Step.Return { target = None; taken = false })))
            else
              let target, accesses = pop16 cpu in
              State.set_pc state target;
              Ok
                (finish cpu pc_before decoded fetched_bytes accesses
                   (Step.Return { target = Some target; taken = true }))
        | Instr.Jump (condition, target) ->
            let taken =
              match condition with None -> true | Some condition -> condition_holds state condition
            in
            let pc_after = if taken then target else next_pc in
            State.set_pc state pc_after;
            Ok
              (finish cpu pc_before decoded fetched_bytes []
                 (Step.Jump { target; taken }))
        | Instr.Rst number ->
            let target = number * 8 in
            let accesses = push16 cpu next_pc in
            State.set_pc state target;
            Ok
              (finish cpu pc_before decoded fetched_bytes accesses (Step.Restart { target }))
        | Instr.Xchg ->
            let de = State.de state in
            let hl = State.hl state in
            State.set_de state hl;
            State.set_hl state de;
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
        | Instr.Xthl ->
            let old_sp = State.sp state in
            let high_address = wrap_address (old_sp + 1) in
            (* Observe both old stack bytes before replacing either one. *)
            let low, low_read = read_memory cpu old_sp in
            let high, high_read = read_memory cpu high_address in
            let low_write = write_memory cpu old_sp (State.l state) in
            let high_write = write_memory cpu high_address (State.h state) in
            State.set_l state low;
            State.set_h state high;
            State.set_pc state next_pc;
            Ok
              (finish cpu pc_before decoded fetched_bytes
                 [ low_read; high_read; low_write; high_write ] Step.Sequential)
        | Instr.Pchl ->
            let target = State.hl state in
            State.set_pc state target;
            Ok
              (finish cpu pc_before decoded fetched_bytes []
                 (Step.Jump { target; taken = true }))
        | Instr.Sphl ->
            State.set_sp state (State.hl state);
            State.set_pc state next_pc;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential)
        | Instr.Input port ->
            (match Bus.input cpu.bus ~port with
            | Error error -> Error (Bus_io_error error)
            | Ok value ->
                State.set_a state value;
                State.set_pc state next_pc;
                Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential))
        | Instr.Output port ->
            (match Bus.output cpu.bus ~port ~value:(State.a state) with
            | Error error -> Error (Bus_io_error error)
            | Ok () ->
                State.set_pc state next_pc;
                Ok (finish cpu pc_before decoded fetched_bytes [] Step.Sequential))
        | Instr.Hlt ->
            State.set_pc state next_pc;
            cpu.halted <- true;
            Ok (finish cpu pc_before decoded fetched_bytes [] Step.Halt)
        | Instr.Inr _
        | Instr.Dcr _
        | Instr.Dad _
        | Instr.Alu _
        | Instr.Alu_immediate _
        | Instr.Rotate _
        | Instr.Daa
        | Instr.Cma
        | Instr.Stc
        | Instr.Cmc
        | Instr.Ei
        | Instr.Di -> Error (Unsupported_instruction decoded))
