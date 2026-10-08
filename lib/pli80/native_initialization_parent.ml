include Native_recursive_parent
let operation=Pli80_host.Recursive_parent.Initialization Pli80_host.Initialization_parent.Parent
let prepare_root ?observe bridge input ~call ~origin boundary=prepare_root ~operation ?observe bridge input ~call ~origin boundary
let shadow input=shadow ~operation input
let controller ?exclude_entry_steps v input=controller ~operation ?exclude_entry_steps v input
let single v input=run v input[controller v input]
