(** Bounded historical +7C1B composition. No decoder, CPU stepping, memoization,
    recursion guard, or snapshot-dependent path selection. *)
type flags = { sign:bool; zero:bool; auxiliary_carry:bool; parity:bool; carry:bool }
type inherited = { position:int; hl:int; de:int; sp:int }
type returned = { a:int; bc:int; de:int; hl:int; flags:flags }
type write = { address:int; value:int; writer:int; depth:int; phase:string }
type compatibility = Call of { site:int; sp:int; depth:int }
                   | Position_carrier of { sp:int; position:int; depth:int }
                   | Dispatch_carrier of { sp:int; mapped:int; depth:int }
type helper = Mapping of int * Mapped_lookup.mapped
            | Attribute of int * Mapped_lookup.attribute
            | Auxiliary_read of int * Auxiliary.access
            | Auxiliary_write of int * Auxiliary.access
            | Packed of int * Packed_scan.result
            | Balance of int * Balance_scan.result
type node = { entry:inherited; frame:int; depth:int; initial_frame:int list;
              mapped:int; path:string; children:node list; helpers:helper list;
              final_frame:int list; returned:returned; return_site:int }
type result = { tree:node; writes:write list }
val comparison : int -> int -> flags
val supported_special : first:int -> second:int -> int
val run : State.t -> entry:inherited -> compatibility:(compatibility -> unit) -> observe:(write -> unit) -> result
