(** Historical +7EC0 direct packed-table gate and +80B7 saved-input composition. *)
module R=Recursive_mapped
module S=State
type operation=Input_process|Range_process|Gate
type result={route:string;input:int;discarded_high:int;packed:int option;rotated:int option;fresh_input:int option;returned:R.returned}
let gate memory ~entry ~write ~call=
 let input=entry.R.bc land 255 in
 S.write memory 0xae57 input;write ~site:0x7ec3 ~address:0xae57 ~value:input;
 let pair=S.word memory 0xae57 in
 let address=U16.wrap(0x1b4b+(pair land 255))in
 let packed=S.read memory address in
 (* RLC publishes its old bit7 as carry; RAR consumes that carry. Neither
    operation changes NZPA/AC. Keep the intermediate rotated byte explicit. *)
 let carry=packed land 128<>0 in
 let rotated=U8.wrap(packed lsl 1)lor(if carry then 1 else 0)in
 let restored=(rotated lsr 1)lor(if carry then 128 else 0)in
 let flags={entry.flags with carry=rotated land 1<>0}in
 let q={entry with R.a=restored;bc=0x1b4b;hl=address;flags}in
 let returned=if flags.carry then call ~site:0x7ed3 ~operation:Range_process q else q in
 {route=(if flags.carry then "call"else "skip");input;discarded_high=pair lsr 8;packed=Some packed;rotated=Some rotated;fresh_input=None;returned}
let saved memory ~entry ~write ~call=
 let input=entry.R.bc land 255 in
 S.write memory 0xae6b input;write ~site:0x80ba ~address:0xae6b ~value:input;
 let pair=S.word memory 0xae6b in
 let q={entry with R.hl=pair;bc=(entry.bc land 0xff00)lor(pair land 255)}in
 let q=call ~site:0x80bf ~operation:Input_process q in
 let fresh=S.word memory 0xae6b in
 let q={q with R.hl=fresh;bc=(q.R.bc land 0xff00)lor(fresh land 255)}in
 let returned=call ~site:0x80c6 ~operation:Gate q in
 {route="saved";input;discarded_high=pair lsr 8;packed=None;rotated=None;fresh_input=Some(fresh land 255);returned}
