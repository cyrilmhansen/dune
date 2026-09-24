let test_writer_format_and_determinism () =
  let open Trace.Event in
  let write_run () =
    let output = Buffer.create 256 in
    let writer = Trace.Writer.create ~output:(Buffer.add_string output) in
    let emit event = Trace.Writer.write writer event in
    emit
      (Trace.Event.Cpu_step
         {
           step_index = 0;
           pc_before = 0x0000;
           pc_after = 0xffff;
           opcode = 0xff;
           encoding_status = Trace.Event.Undocumented_alias;
           instruction_bytes = "\xff";
           control_flow = Trace.Event.Call { target = 0xffff; taken = true };
           memory_accesses =
             [
               Trace.Event.Read { address = 0x0000; value = 0x00 };
               Trace.Event.Write { address = 0xffff; value = 0xff };
             ];
         });
    emit (Trace.Event.Bdos_call { step_index = 1; function_number = 9; de = 0xffff });
    emit
      (Trace.Event.Cpu_step
         {
           step_index = 1;
           pc_before = 0xffff;
           pc_after = 0x0000;
           opcode = 0xc9;
           encoding_status = Trace.Event.Uncertain;
           instruction_bytes = "\xc9";
           control_flow = Trace.Event.Return { target = None; taken = false };
           memory_accesses = [];
         });
    emit
      (Trace.Event.Termination
         { step_index = 2; reason = Trace.Event.Bdos_function 0 });
    Buffer.contents output
  in
  let expected =
    "AT8TRACE\t1\n"
    ^ "STEP\t0\t0000\tFFFF\tFF\tFF\tundocumented_alias\tcall:1:FFFF\n"
    ^ "MEMR\t0\t0000\t00\nMEMW\t0\tFFFF\tFF\n"
    ^ "BDOS\t1\t9\tFFFF\n"
    ^ "STEP\t1\tFFFF\t0000\tC9\tC9\tuncertain\treturn:0:none\n"
    ^ "TERM\t2\tbdos:0\n"
  in
  let first = write_run () in
  assert (first = expected);
  assert (write_run () = first)

let test_live_step_conversion () =
  let open Trace.Event in
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 (Bytes.of_string "\x08");
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  match I8080.Cpu.step cpu with
  | Error _ -> failwith "expected undocumented NOP alias to execute"
  | Ok live ->
      (match Trace.Event.cpu_step_of_live ~step_index:0 live with
      | Trace.Event.Cpu_step step ->
          assert (step.opcode = 0x08);
          assert (step.encoding_status = Trace.Event.Undocumented_alias);
          assert (step.instruction_bytes = "\x08")
      | Trace.Event.Bdos_call _ | Trace.Event.Termination _ ->
          failwith "live CPU step converted to non-step trace event")

let test_interrupt_step_rejected_by_v1 () =
  let memory = I8080.Memory.create () in
  I8080.Memory.load memory ~address:0x0100 (Bytes.of_string "\xfb\x00");
  let state = I8080.State.create () in
  I8080.State.set_pc state 0x0100;
  let cpu = I8080.Cpu.create ~state ~bus:(I8080.Bus.create memory) in
  (match I8080.Cpu.step cpu with
  | Ok _ -> ()
  | Error _ -> failwith "expected EI to execute");
  (match I8080.Cpu.step cpu with
  | Ok _ -> ()
  | Error _ -> failwith "expected EI's protected instruction to execute");
  match I8080.Cpu.step ~interrupt:(Bytes.of_string "\x00") cpu with
  | Error _ -> failwith "expected interrupt acknowledge instruction"
  | Ok live ->
      assert (I8080.Step.source live = I8080.Step.Interrupt_acknowledge);
      (match Trace.Event.cpu_step_of_live ~step_index:2 live with
      | exception Invalid_argument message ->
          assert
            (String.equal message
               "AT8TRACE v1 cannot represent interrupt-acknowledge instruction origin")
      | _ -> failwith "AT8TRACE v1 accepted an interrupt-origin step")

let () =
  test_writer_format_and_determinism ();
  test_live_step_conversion ();
  test_interrupt_step_rejected_by_v1 ()
