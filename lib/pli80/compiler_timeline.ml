[@@@warning "-40-42"]

type file_observation = Experiment.file_event

type event =
  | Execution_start of int
  | Image_first_execution of { step_index : int; image : string; runtime_pc : int; image_offset : int }
  | Console_message of Console_capture.message
  | File_operation of file_observation
  | Termination of { step_index : int; reason : Runner.termination }

type t = { total_steps : int; events : event list }

let step_index = function
  | Execution_start step_index | Image_first_execution {step_index;_}
  | Termination {step_index;_} -> step_index
  | Console_message message -> message.last_step
  | File_operation event -> event.step_index

let rank = function Execution_start _ -> 0 | Image_first_execution _ -> 1
  | File_operation _ -> 2 | Console_message _ -> 3 | Termination _ -> 4

let image_tie = function
  |Image_first_execution {image;_}->image
  |Execution_start _|Console_message _|File_operation _|Termination _->""

let of_experiment experiment =
  let events = ref [Execution_start 0; Termination {step_index=experiment.Experiment.run.steps;
    reason=experiment.run.termination}] in
  List.iter (fun message -> events := Console_message message :: !events) experiment.console_messages;
  List.iter (fun event -> events := File_operation event :: !events) experiment.file_events;
  (match experiment.execution_map with
   |None->()
   |Some map->List.iter (fun (summary:Analysis.Execution_map.image_summary)->
      Option.iter (fun (runtime_pc,image_offset,step_index)->
        events:=Image_first_execution {step_index;image=summary.image.name;runtime_pc;image_offset}::!events) summary.first_execution)
      (Analysis.Execution_map.image_summaries map));
  let events=List.sort (fun a b->let c=compare(step_index a)(step_index b) in
    if c<>0 then c else let c=compare(rank a)(rank b) in if c<>0 then c else
      String.compare (image_tie a) (image_tie b)) !events in
  {total_steps=experiment.run.steps;events}

let total_steps report = report.total_steps
let events report = report.events

let json_string text =
  let out=Buffer.create(String.length text+8) in
  Buffer.add_char out '"';
  String.iter(fun c->match c with
    |'"'->Buffer.add_string out "\\\""|'\\'->Buffer.add_string out "\\\\"
    |'\n'->Buffer.add_string out "\\n"|'\r'->Buffer.add_string out "\\r"|'\t'->Buffer.add_string out "\\t"
    |c when Char.code c<0x20->Buffer.add_string out(Printf.sprintf"\\u%04x"(Char.code c))
    |c->Buffer.add_char out c)text;
  Buffer.add_char out '"';Buffer.contents out

let operation_name = function
  |Experiment.Open->"OPEN"|Close->"CLOSE"|Make->"MAKE"|Delete->"DELETE"
  |Sequential_read->"READ_SEQUENTIAL"|Sequential_write->"WRITE_SEQUENTIAL"

let termination_name = function Runner.Warm_boot->"warm_boot"|Bdos_function n->"bdos_"^string_of_int n

let event_json = function
  |Execution_start step->Printf.sprintf"{\"step\":%d,\"kind\":\"execution_start\"}"step
  |Image_first_execution{step_index;image;runtime_pc;image_offset}->Printf.sprintf"{\"step\":%d,\"kind\":\"image_first_execution\",\"image\":%s,\"runtime_pc\":%d,\"image_offset\":%d}"
      step_index(json_string image)runtime_pc image_offset
  |Console_message message->Printf.sprintf"{\"step\":%d,\"kind\":\"console_message\",\"text\":%s,\"first_step\":%d,\"last_step\":%d}"
      message.last_step(json_string message.text)message.first_step message.last_step
  |File_operation event->
      let optional_int = function None->"null"|Some n->string_of_int n in
      let range = match event.byte_range with None->"null"|Some(first,last)->Printf.sprintf"{\"start\":%d,\"end_exclusive\":%d}"first last in
      Printf.sprintf"{\"step\":%d,\"kind\":\"file_operation\",\"operation\":%s,\"file\":{\"drive\":%d,\"user\":%d,\"name\":%s},\"succeeded\":%b,\"logical_record\":%s,\"byte_range\":%s}"
        event.step_index(json_string(operation_name event.operation))event.file.drive event.file.user
        (json_string event.file.name)event.succeeded(optional_int event.logical_record)range
  |Termination{step_index;reason}->Printf.sprintf"{\"step\":%d,\"kind\":\"termination\",\"reason\":%s}"
      step_index(json_string(termination_name reason))

let to_json_string report =
  let out=Buffer.create(256+List.length report.events*100) in
  Buffer.add_string out "RUNES_PLI80_FILE_TIMELINE 1\n{\"step_indexing\":\"zero-based; file operations are timestamped at BDOS dispatch, console characters at BDOS output callback\",\"total_steps\":";
  Buffer.add_string out(string_of_int report.total_steps);Buffer.add_string out ",\"events\":[";
  List.iteri(fun index event->if index>0 then Buffer.add_char out ',';Buffer.add_string out(event_json event))report.events;
  Buffer.add_string out "]}\n";Buffer.contents out
