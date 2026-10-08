[@@@warning "-4-40-41-42"]
(* The established eight-byte frame is a reusable host operation; only its
   external transaction boundary is new. Child algorithms remain canonical. *)
include Native_recursive_parent
let operation=Pli80_host.Recursive_parent.Recursive_frame
let prepare_root ?observe bridge input ~call ~origin boundary=
 Native_recursive_parent.prepare_root ~operation ?observe bridge input ~call ~origin boundary
let shadow input=Native_recursive_parent.shadow ~operation input
let controller ?(exclude_entry_steps=[]) v input=
 Native_recursive_parent.controller ~operation ~exclude_entry_steps v input
let single v input=run v input[controller v input]
