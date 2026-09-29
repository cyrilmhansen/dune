type message = { text : string; first_step : int; last_step : int }

type t = {
  output : Buffer.t;
  mutable recent : (char * int) list;
  mutable messages_rev : message list;
}

let observed_messages = [
  "NO ERROR(S) IN PASS 1";
  "NO ERROR(S) IN PASS 2";
  "END  COMPILATION";
]

let max_message_length =
  List.fold_left (fun size text -> max size (String.length text)) 0 observed_messages

let create () = { output = Buffer.create 256; recent = []; messages_rev = [] }

let emit capture ~step_index character =
  Buffer.add_char capture.output character;
  capture.recent <- capture.recent @ [character, step_index];
  let excess = List.length capture.recent - max_message_length in
  if excess > 0 then capture.recent <- List.filteri (fun index _ -> index >= excess) capture.recent;
  List.iter (fun text ->
    let length = String.length text in
    if List.length capture.recent >= length then (
      let suffix = List.filteri (fun index _ -> index >= List.length capture.recent - length) capture.recent in
      if String.init length (fun index -> fst (List.nth suffix index)) = text then
        let first_step = snd (List.hd suffix) and last_step = snd (List.hd (List.rev suffix)) in
        capture.messages_rev <- {text; first_step; last_step} :: capture.messages_rev)) observed_messages

let text capture = Buffer.contents capture.output
let messages capture = List.rev capture.messages_rev
