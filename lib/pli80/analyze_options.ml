type source_text = Cpm | Raw
type t = {
  oracle_fixture:string option;
  oracle_fixture_comparison:(string * string) option;
  full_evidence:bool;
  toolchain:string option; source:string option; output_dir:string option;
  module_name:string option; max_steps:int; analysis:Experiment.analysis;
  report:Experiment.report; source_text:source_text; selected_rel:int list;
  raw_slices:int list; structure:bool;
}

let usage = {|Usage:
  pli80-analyze --oracle-fixture DIR
  pli80-analyze --compare-oracle-fixtures DIR_A DIR_B [--full-evidence]
  pli80-analyze --toolchain DIR --source FILE --output-dir DIR [options]
  --oracle-fixture DIR      Display preserved PL/M oracle fixture evidence (read-only)
  --compare-oracle-fixtures DIR_A DIR_B  Compare two preserved PL/M fixtures (read-only)
  --full-evidence          Include full source, exact bytes, and manifest text in comparisons
  --module NAME             Override the CP/M module name (1..8 characters)
  --source-text cpm|raw     Normalize PL/I text to CRLF + one Ctrl-Z (default cpm)
  --analysis run|execution|data|path  Select live analysis (default run)
  --report none|summary|explorer   Select output reports (default summary)
  --select-rel OFFSET       Select explorer sink; repeatable (decimal or 0xHEX)
  --raw-slice OFFSET        Write exact slice JSON; repeatable, data/path only
  --structure               Collect routine transitions and observed blocks (requires execution analysis)
  --max-steps N             Positive instruction budget (default 10000000)
  --help                    Show this help

The command compiles PL/I through historical PLI.COM. It does not link or run the generated REL.|}

let positive_integer s=match int_of_string_opt s with Some n when n>0->Some n|_->None
let value_options=["--oracle-fixture";"--toolchain";"--source";"--output-dir";"--module";"--max-steps";"--analysis";"--report";"--source-text";"--select-rel";"--raw-slice"]

let parse args =
  let rec go options = function
    |[]->Ok options
    |"--help"::_->Error"help"
    |"--full-evidence"::rest->if options.full_evidence then Error "--full-evidence repeated" else go{options with full_evidence=true}rest
    |"--compare-oracle-fixtures"::[]->Error"--compare-oracle-fixtures requires two fixture directories"
    |"--compare-oracle-fixtures"::_first::[]->Error"--compare-oracle-fixtures requires two fixture directories"
    |"--compare-oracle-fixtures"::first::second::_rest when String.starts_with ~prefix:"--" first || String.starts_with ~prefix:"--" second -> Error "--compare-oracle-fixtures requires two fixture directories"
    |"--compare-oracle-fixtures"::first::second::rest->(match options.oracle_fixture_comparison with None->go{options with oracle_fixture_comparison=Some(first,second)}rest|Some _->Error"--compare-oracle-fixtures repeated")
    |flag::[] when List.mem flag value_options->Error("missing value after "^flag)
    |flag::value::_ when List.mem flag value_options && String.starts_with ~prefix:"--" value->Error("missing value after "^flag)
    |"--oracle-fixture"::value::rest->(match options.oracle_fixture with None->go{options with oracle_fixture=Some value}rest|Some _->Error"--oracle-fixture repeated")
    |"--toolchain"::value::rest->(match options.toolchain with None->go{options with toolchain=Some value}rest|Some _->Error"--toolchain repeated")
    |"--source"::value::rest->(match options.source with None->go{options with source=Some value}rest|Some _->Error"--source repeated")
    |"--output-dir"::value::rest->(match options.output_dir with None->go{options with output_dir=Some value}rest|Some _->Error"--output-dir repeated")
    |"--module"::value::rest->(match options.module_name with None->go{options with module_name=Some value}rest|Some _->Error"--module repeated")
    |"--max-steps"::value::rest->(match positive_integer value with None->Error"--max-steps must be a positive integer"|Some max_steps->go{options with max_steps}rest)
    |"--analysis"::value::rest->(match Experiment.parse_analysis value with Error e->Error e|Ok analysis->go{options with analysis}rest)
    |"--report"::value::rest->(match Experiment.parse_report value with Error e->Error e|Ok report->go{options with report}rest)
    |"--source-text"::"cpm"::rest->go{options with source_text=Cpm}rest
    |"--source-text"::"raw"::rest->go{options with source_text=Raw}rest
    |"--source-text"::_::_->Error"--source-text must be cpm or raw"
    |"--structure"::rest->if options.structure then Error "--structure repeated" else go{options with structure=true}rest
    |"--select-rel"::value::rest->(match Experiment.parse_offset value with Error e->Error e|Ok n->go{options with selected_rel=options.selected_rel@[n]}rest)
    |"--raw-slice"::value::rest->(match Experiment.parse_offset value with Error e->Error e|Ok n->go{options with raw_slices=(if List.mem n options.raw_slices then options.raw_slices else options.raw_slices@[n])}rest)
    |option::_->Error("unknown option "^option)
  in
  let parsed = go {oracle_fixture=None;oracle_fixture_comparison=None;full_evidence=false;toolchain=None;source=None;output_dir=None;module_name=None;max_steps=10_000_000;
    analysis=Experiment.Run;report=Experiment.Summary;source_text=Cpm;structure=false;selected_rel=[];raw_slices=[]} args
  in
  match parsed with
  | Error _ as error -> error
  | Ok options when options.oracle_fixture <> None || options.oracle_fixture_comparison <> None ->
      if options.oracle_fixture <> None && options.oracle_fixture_comparison <> None then Error "choose --oracle-fixture or --compare-oracle-fixtures"
      else if options.full_evidence && options.oracle_fixture_comparison = None then Error "--full-evidence requires --compare-oracle-fixtures"
      else if options.toolchain=None && options.source=None && options.output_dir=None && options.module_name=None
        && options.max_steps=10_000_000 && options.analysis=Experiment.Run && options.report=Experiment.Summary
        && options.source_text=Cpm && not options.structure && options.selected_rel=[] && options.raw_slices=[] then Ok options
      else Error "oracle fixture inspection cannot be combined with compiler-run options"
  | Ok options when options.full_evidence -> Error "--full-evidence requires --compare-oracle-fixtures"
  | Ok options -> Ok options
