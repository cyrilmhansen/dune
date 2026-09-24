let () =
  if Array.length Sys.argv > 1 && Sys.argv.(1) = "--help" then
    print_endline "Usage: pli80-run [options] PROGRAM.COM\n\nThe PL/I-80 execution environment is not implemented yet."
  else
    print_endline "pli80-run: the execution environment is not implemented yet."
