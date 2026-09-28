type source_text = Cpm | Raw
type t = {
  oracle_fixture : string option;
  oracle_fixture_comparison : (string * string) option;
  full_evidence : bool;
  toolchain : string option;
  source : string option;
  output_dir : string option;
  module_name : string option;
  max_steps : int;
  analysis : Experiment.analysis;
  report : Experiment.report;
  source_text : source_text;
  selected_rel : int list;
  raw_slices : int list;
  structure : bool;
}

val usage : string
val parse : string list -> (t, string) Stdlib.result
