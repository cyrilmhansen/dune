type iteration = {
  cursor : int; lookup : Mapped_lookup.attribute;
  balance_before : int; temporary_sum : int; balance_after : int;
  cursor_wrapped : bool;
}
type result = { start_cursor : int; stop_cursor : int;
  iterations : iteration list; writes : Mapped_lookup.write list }
let update_balance ~attribute ~balance =
  U8.check attribute;U8.check balance;
  let temporary_sum=U8.wrap(attribute+balance) in
  temporary_sum,U8.wrap(temporary_sum-1)
let run memory ~cursor ~protected =
  U8.check cursor;List.iter U16.check protected;
  if List.exists(fun a->List.mem a protected)[0xae36;0xae37;0xae38;0xae48;0xae49]
  then invalid_arg "Balance_scan: scratch/stack alias";
  let writes=ref [] and iterations=ref [] in
  let record w=writes:=w::!writes in
  let put phase address value=
    State.write memory address value;record {Mapped_lookup.address;value;phase} in
  put "cursor_initialization" 0xae48 cursor;
  put "balance_initialization" 0xae49 1;
  let rec loop () =
    (* +7B83 reads both cursor and adjacent balance; only the low byte
       becomes +7A63's argument. No flattened attribute(position) cache. *)
    let current_cursor=State.word memory 0xae48 land 255 in
    let lookup=Mapped_lookup.low_attribute memory ~position:current_cursor ~protected ~write:record in
    let balance_before=State.read memory 0xae49 in
    let temporary_sum,balance_after=update_balance ~attribute:lookup.low3 ~balance:balance_before in
    put "balance_publication" 0xae49 balance_after;
    let cursor_wrapped=balance_after<>0 && current_cursor=0 in
    iterations:={cursor=current_cursor;lookup;balance_before;temporary_sum;balance_after;cursor_wrapped}::!iterations;
    (* +7B93 CMP 0,balance; +7B94 JNC iff published balance is zero. *)
    if balance_after<>0 then (
      let fresh_cursor=State.read memory 0xae48 in
      put "cursor_decrement" 0xae48 (U8.wrap(fresh_cursor-1));loop ()) in
  loop ();
  let stop_cursor=State.read memory 0xae48 in
  {start_cursor=cursor;stop_cursor;iterations=List.rev !iterations;writes=List.rev !writes}
