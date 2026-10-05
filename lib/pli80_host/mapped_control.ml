(** Two complete historical AC73 operations; shared byte-addressed memory. *)
type access={position:int;index:int;address:int;value:int;discarded_high:int}
let guard protected addresses=
 List.iter U16.check protected;
 if List.exists(fun a->List.mem a protected)addresses then invalid_arg "Mapped_control: scratch/table/stack alias"
let put memory write phase address value=
 State.write memory address value;write {Mapped_lookup.address;value;phase}
let read memory ~position ~protected ~write=
 U8.check position;
 let map=0xaa1f+position in guard protected [0xae39;0xae3a;map];
 put memory write "control_read_position" 0xae39 position;
 let carrier=State.word memory 0xae39 in
 let index=State.read memory(0xaa1f+(carrier land 255))in
 let address=0xac73+index in guard(0xae39::0xae3a::map::protected)[address];
 {position;index;address;value=State.read memory address;discarded_high=carrier lsr 8}
let publish memory ~position ~value ~protected ~write=
 U8.check position;U8.check value;
 let map=0xaa1f+position in guard protected [0xae41;0xae42;map];
 guard(0xae41::0xae42::map::protected)[0xac73+State.read memory map];
 put memory write "control_value" 0xae42 value;
 put memory write "control_write_position" 0xae41 position;
 let carrier=State.word memory 0xae41 in
 let index=State.read memory(0xaa1f+(carrier land 255))in
 let address=0xac73+index in
 let value=State.read memory 0xae42 in
 put memory write "control_publication" address value;
 {position=carrier land 255;index;address;value;discarded_high=carrier lsr 8}
