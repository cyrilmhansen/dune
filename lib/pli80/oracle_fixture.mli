type instruction = {
  address : int;
  bytes : bytes;
  mnemonic : string;
}

type t = {
  id : string;
  question : string option;
  toolchain : (string * string) list;
  toolchain_version : string;
  source : string;
  code_size : int;
  variable_size : int;
  maximum_stack : int;
  code_start : string;
  code_end_inclusive : string;
  data_range : string option;
  code_bytes : bytes;
  disassembly : instruction list;
  documented_expectation : string option;
  observations : string list;
  unresolved_questions : string list;
}

val load : string -> (t, string) result
(** [load fixture_directory] reads its preserved [manifest.json]. It does not
    execute tools or modify fixture files. *)

val to_text : t -> string
