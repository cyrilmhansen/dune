type event =
  | Execution_start of int
  | Image_first_execution of { step_index : int; image : string; runtime_pc : int; image_offset : int }
  | Console_message of Console_capture.message
  | File_operation of Experiment.file_event
  | Termination of { step_index : int; reason : Runner.termination }
type t

val of_experiment : Experiment.result -> t
val total_steps : t -> int
val events : t -> event list
val to_json_string : t -> string
