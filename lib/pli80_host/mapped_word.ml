type write = { address:int; value:int; phase:string }
type result = {position:int;discarded_ae39:int;index:int;offset:int;
 low_address:int;high_address:int;low:int;high:int;word:int}
let addresses state position =
 U8.check position;
 let map=U16.wrap(0xaa1f+position) in
 let index=State.read state map in
 let first=U16.wrap(0xab49+index) in
 let low=U16.wrap(first+index) in
 map,index,low,U16.wrap(low+1)
let lookup state ~position ~protected ~write =
 List.iter U16.check protected;
 let map,_,low,high=addresses state position in
 let accessed=[0xae38;0xae39;map;low;high]in
 if List.length(List.sort_uniq compare accessed)<>List.length accessed ||
    List.exists(fun a->List.mem a accessed)protected then invalid_arg "Mapped_word: declared alias overlap";
 State.write state 0xae38 position;
 write {address=0xae38;value=position;phase="mapped_word_position"};
 let pair=State.word state 0xae38 in
 let saved=pair land 255 and discarded_ae39=pair lsr 8 in
 let _,index,low_address,high_address=addresses state saved in
 let low=State.read state low_address in
 let high=State.read state high_address in
 {position=saved;discarded_ae39;index;offset=U16.wrap(index+index);
  low_address;high_address;low;high;word=low lor(high lsl 8)}

type publication={position:int;discarded_ae3f:int;index:int;first_address:int;
 low_address:int;high_address:int;low:int;high:int;word:int;old_word:int}
let publish state ~position ~value ~protected ~write ~save_destination =
 U8.check position;U16.check value;List.iter U16.check protected;
 let map,_,low,high=addresses state position in
 let accessed=[0xae3e;0xae3f;0xae40;map;low;high]in
 if List.length(List.sort_uniq compare accessed)<>List.length accessed ||
    List.exists(fun a->List.mem a accessed)protected then invalid_arg "Mapped_word.publish: declared alias overlap";
 let put phase address value=State.write state address value;write{address;value;phase}in
 put "mapped_word_value_high" 0xae40(value lsr 8);
 put "mapped_word_value_low" 0xae3f(value land 255);
 put "mapped_word_write_position" 0xae3e position;
 let pair=State.word state 0xae3e in
 let position=pair land 255 and discarded_ae3f=pair lsr 8 in
 (* Fresh map read followed by the two historical index additions. *)
 let index=State.read state(U16.wrap(0xaa1f+position))in
 let first_address=U16.wrap(0xab49+index)in
 let low_address=U16.wrap(first_address+index)in
 save_destination low_address;
 let word=State.word state 0xae3f in
 let low=word land 255 and high=word lsr 8 in
 let high_address=U16.wrap(low_address+1)in
 let old_word=State.word state low_address in
 put "mapped_word_publication_low" low_address low;
 put "mapped_word_publication_high" high_address high;
 {position;discarded_ae3f;index;first_address;low_address;high_address;low;high;word;old_word}
