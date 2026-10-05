(** Bounded +7E5F; the four historical children retain their own algorithms. *)
type result={end_before:int;old_index:int;displaced:int;
 byte:Mapped_publication.publication;word:Mapped_word.publication;
 primary:Auxiliary.access;secondary:Auxiliary.access;returned_a:int;increment_before:int;end_after:int}
let supported_end n=U8.check n;if n>0x94 then invalid_arg "Range_publication: unsupported end>94"
let run memory ~input_c ~input_de ~protected ~write ~call ~save_destination =
 U8.check input_c;U16.check input_de;List.iter U16.check protected;
 let read=State.read memory in
 supported_end(read 0xae35);
 let parent=[0xae32;0xae33;0xae34;0xae35;0xae36;0xae54;0xae55;0xae56]in
 if List.exists(fun a->List.mem a protected)parent then invalid_arg "Range_publication: parent alias";
 let initial_access=parent@[0xaa1f+read 0xae35;0xaab4+read 0xae33]in
 if List.exists(fun a->List.mem a protected)initial_access then invalid_arg "Range_publication: initial map/table alias";
 let put site address value=State.write memory address value;write ~site ~address ~value in
 put 0x7e62 0xae56(input_de lsr 8);
 put 0x7e64 0xae55(input_de land 255);
 put 0x7e66 0xae54 input_c;
 supported_end(read 0xae35);
 let end_before=State.word memory 0xae35 land 255 in
 let old_index=read 0xae33 in
 put 0x7e7f (0xaa1f+end_before) old_index;
 let index=State.word memory 0xae33 land 255 in
 let displaced=read(0xaab4+index)in
 put 0x7e8a 0xae33 displaced;
 let protected=parent@protected in
 let emit phases (w:Mapped_lookup.write)=write ~site:(List.assoc w.phase phases)~address:w.address ~value:w.value in
 let position()=State.word memory 0xae35 land 255 in
 let p=position()in let value=State.word memory 0xae54 land 255 in
 call 0x7e95;
 let byte=Mapped_publication.publish memory ~position:p ~value ~protected
  ~write:(emit["mapped_write_value",0x7ad8;"mapped_write_position",0x7ada;"mapped_publication",0x7aee])in
 let p=position()in let value=State.word memory 0xae55 in
 call 0x7ea0;
 let word=Mapped_word.publish memory ~position:p ~value ~protected
  ~write:(fun(w:Mapped_word.write)->emit["mapped_word_value_high",0x7af3;"mapped_word_value_low",0x7af5;"mapped_word_write_position",0x7af7;"mapped_word_publication_low",0x7b0f;"mapped_word_publication_high",0x7b11]
   {Mapped_lookup.address=w.address;value=w.value;phase=w.phase})~save_destination in
 let p=position()in call 0x7ea9;
 let primary=Auxiliary.publish memory ~position:p ~value:0 ~protected
  ~write:(emit["auxiliary_value",0x7b31;"auxiliary_position",0x7b33;"auxiliary_publication",0x7b47])in
 let p=position()in call 0x7eb2;
 let secondary=Auxiliary.publish_secondary memory ~position:p ~value:0 ~protected
  ~write:(emit["secondary_auxiliary_value",0x7b4c;"secondary_auxiliary_write_position",0x7b4e;"secondary_auxiliary_publication",0x7b62])in
 let fresh_end=read 0xae35 in put 0x7eb8 0xae32 fresh_end;
 let increment_before=read 0xae35 in
 let end_after=U8.wrap(increment_before+1)in put 0x7ebe 0xae35 end_after;
 {end_before;old_index;displaced;byte;word;primary;secondary;returned_a=fresh_end;increment_before;end_after}
