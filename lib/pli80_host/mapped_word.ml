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
