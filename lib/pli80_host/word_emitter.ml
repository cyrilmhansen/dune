type selection={low_wrapper:bool;paired_word:int;neighbor:int;lookup:Mapped_word.result option;
 selected_word:int;emitted_byte:int;writes:Mapped_word.write list}
let low state ~protected ~emit =
 List.iter U16.check protected;
 if List.exists(fun a->List.mem a [0xae4f;0xae50;0xae52;0xae53])protected
 then invalid_arg "Word_emitter: cache/cursor alias";
 let paired_word=State.word state 0xae4f in
 let writes=ref []in
 let write w=writes:=w::!writes in
 let lookup=Mapped_word.lookup state ~position:(paired_word land 255)
  ~protected:(protected@[0xae4f;0xae50;0xae52;0xae53]) ~write in
 let put address value=State.write state address value;
  write {Mapped_word.address;value;phase="mapped_word_cache"}in
 put 0xae52 lookup.low;put 0xae53 lookup.high;
 let selection={low_wrapper=true;paired_word;neighbor=paired_word lsr 8;lookup=Some lookup;
 selected_word=lookup.word;emitted_byte=lookup.low;writes=List.rev !writes}in
 selection,emit state selection
let high state ~protected ~emit =
 List.iter U16.check protected;
 if List.exists(fun a->List.mem a [0xae52;0xae53])protected
 then invalid_arg "Word_emitter: cache alias";
 let paired_word=State.word state 0xae52 in
 let selection={low_wrapper=false;paired_word;neighbor=paired_word land 255;lookup=None;
 selected_word=paired_word;emitted_byte=paired_word lsr 8;writes=[]}in
 selection,emit state selection
