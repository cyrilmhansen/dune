type source_text = Cpm | Raw
type t = {
  toolchain:string option; source:string option; output_dir:string option;
  module_name:string option; max_steps:int; analysis:Experiment.analysis;
  report:Experiment.report; source_text:source_text; selected_rel:int list;
  raw_slices:int list; structure:bool;
}

let usage = {|Usage: pli80-analyze --toolchain DIR --source FILE --output-dir DIR [options]
  --module NAME             Override the CP/M module name (1..8 characters)
  --source-text cpm|raw     Normalize PL/I text to CRLF + one Ctrl-Z (default cpm)
  --analysis run|execution|data|path  Select live analysis (default run)
  --report none|summary|explorer   Select output reports (default summary)
  --select-rel OFFSET       Select explorer sink; repeatable (decimal or 0xHEX)
  --raw-slice OFFSET        Write exact slice JSON; repeatable, data/path only
  --structure               Collect dynamic routine candidates/transitions (requires execution analysis)
  --max-steps N             Positive instruction budget (default 10000000)
  --help                    Show this help

The command compiles PL/I through historical PLI.COM. It does not link or run the generated REL.|}

let positive_integer s=match int_of_string_opt s with Some n when n>0->Some n|_->None
let value_options=["--toolchain";"--source";"--output-dir";"--module";"--max-steps";"--analysis";"--report";"--source-text";"--select-rel";"--raw-slice"]

let parse args =
  let rec go options = function
    |[]->Ok options
    |"--help"::_->Error"help"
    |flag::[] when List.mem flag value_options->Error("missing value after "^flag)
    |flag::value::_ when List.mem flag value_options && String.starts_with ~prefix:"--" value->Error("missing value after "^flag)
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
  go {toolchain=None;source=None;output_dir=None;module_name=None;max_steps=10_000_000;
    analysis=Experiment.Run;report=Experiment.Summary;source_text=Cpm;structure=false;selected_rel=[];raw_slices=[]} args
