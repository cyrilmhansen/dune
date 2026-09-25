[@@@warning "-40-41-42-69"]

type byte = {
  image_offset : int;
  virtual_offset : int;
  value : int option;
  dynamic_fetch_count : int;
  instruction_start_count : int;
  fetched : bool;
  instruction : Execution_map.instruction option;
}

type image = {
  id : Execution_map.image_id;
  virtual_base : int;
  span : int;
  bytes : byte array;
  known_byte_count : int;
  unique_fetched_byte_count : int;
  unique_fetched_percentage : float;
  dynamic_fetched_byte_count : int;
  unique_instruction_starts : int;
  total_instruction_executions : int;
  first_execution_step : int option;
  last_execution_step : int option;
  first_record_read_step : int option;
  last_record_read_step : int option;
}

type transition = {
  source_image : Execution_map.image_id;
  source_offset : int;
  source_virtual_offset : int;
  source_runtime_pc : int;
  kind : Execution_map.flow_kind;
  target_image : Execution_map.image_id;
  target_offset : int;
  target_virtual_offset : int;
  runtime_target : int;
  count : int;
}

type dynamic_edge = {
  source_image : Execution_map.image_id option;
  source_offset : int option;
  source_virtual_offset : int option;
  source_runtime_pc : int;
  kind : Execution_map.flow_kind;
  taken : bool option;
  target_image : Execution_map.image_id option;
  target_offset : int option;
  target_virtual_offset : int option;
  runtime_target : int option;
  count : int;
}

type bdos_site = {
  image : Execution_map.image_id option;
  offset : int option;
  virtual_offset : int option;
  runtime_pc : int option;
  function_number : int;
  count : int;
}

type t = {
  images : image list;
  virtual_span : int;
  execution_summary : Execution_map.summary;
  transitions : transition list;
  dynamic_edges : dynamic_edge list;
  bdos_sites : bdos_site list;
  hottest_instructions : (Execution_map.instruction * int) list;
}

type error = Missing_image of Execution_map.image_id

let images report = report.images
let virtual_span report = report.virtual_span
let execution_summary report = report.execution_summary
let transitions report = report.transitions
let dynamic_edges report = report.dynamic_edges
let bdos_sites report = report.bdos_sites
let hottest_instructions report = report.hottest_instructions

let heat_value ~maximum count =
  if maximum <= 0 || count <= 0 then 0.
  else min 1. (log (1. +. float_of_int count) /. log (1. +. float_of_int maximum))

let image_name (id : Execution_map.image_id) =
  Printf.sprintf "%c:%d:%s" (Char.chr (Char.code 'A' + id.drive)) id.user id.name

let span_of_summary (summary : Execution_map.image_summary) =
  match summary.known_size with
  | Some size -> size
  | None ->
      (match List.rev summary.observed_records with
      | [] -> 0
      | last :: _ -> (last + 1) * 128)

let take count values =
  let rec loop n = function _ when n = 0 -> [] | [] -> [] | x :: xs -> x :: loop (n - 1) xs in
  loop count values

let report_of_map ?(top_n = 25) map ~images:image_order =
  if top_n < 0 then invalid_arg "Execution_report.report_of_map: top_n";
  let rec get_summaries acc = function
    | [] -> Ok (List.rev acc)
    | id :: rest ->
        (match Execution_map.image_summary map ~image:id with
        | None -> Error (Missing_image id)
        | Some summary -> get_summaries ((id, summary) :: acc) rest)
  in
  match get_summaries [] image_order with
  | Error _ as error -> error
  | Ok summaries ->
      let bases = Hashtbl.create (List.length summaries) in
      let next_base = ref 0 in
      List.iter
        (fun (id, summary) ->
          Hashtbl.replace bases id !next_base;
          next_base := !next_base + span_of_summary summary)
        summaries;
      let instruction_starts = Hashtbl.create 4093 in
      List.iter
        (fun (entry : Execution_map.instruction) ->
          Hashtbl.replace instruction_starts (entry.image, entry.offset) entry)
        (Execution_map.instructions map);
      let images =
        List.map
          (fun (id, summary) ->
            let span = span_of_summary summary in
            let base = Hashtbl.find bases id in
            let bytes =
              Array.init span (fun offset ->
                  let dynamic_fetch_count = Execution_map.byte_fetch_count map ~image:id ~offset in
                  let instruction_start_count = Execution_map.instruction_start_count map ~image:id ~offset in
                  {
                    image_offset = offset;
                    virtual_offset = base + offset;
                    value = Execution_map.byte_at map ~image:id ~offset;
                    dynamic_fetch_count;
                    instruction_start_count;
                    fetched = dynamic_fetch_count > 0;
                    instruction = Hashtbl.find_opt instruction_starts (id, offset);
                  })
            in
            let known_byte_count = summary.known_byte_count in
            let unique_fetched_byte_count = summary.unique_fetched_byte_count in
            {
              id;
              virtual_base = base;
              span;
              bytes;
              known_byte_count;
              unique_fetched_byte_count;
              unique_fetched_percentage =
                if known_byte_count = 0 then 0.
                else 100. *. float_of_int unique_fetched_byte_count /. float_of_int known_byte_count;
              dynamic_fetched_byte_count = summary.fetched_byte_count;
              unique_instruction_starts = summary.unique_instruction_starts;
              total_instruction_executions = summary.total_instruction_executions;
              first_execution_step = Option.map (fun (_, _, step) -> step) summary.first_execution;
              last_execution_step = summary.last_execution_step;
              first_record_read_step = summary.first_record_read_step;
              last_record_read_step = summary.last_record_read_step;
            })
          summaries
      in
      let transitions =
        Execution_map.cross_image_transitions map
        |> List.filter_map (fun (edge : Execution_map.control_flow_observation) ->
               match edge.source, edge.target_origin, edge.runtime_target with
               | Execution_map.Image_instruction { image = source_image; offset = source_offset },
                 Some (Execution_map.Image_byte { image = target_image; offset = target_offset }),
                 Some runtime_target
                 when Hashtbl.mem bases source_image && Hashtbl.mem bases target_image ->
                   Some
                     {
                       source_image;
                       source_offset;
                       source_virtual_offset = Hashtbl.find bases source_image + source_offset;
                       source_runtime_pc = edge.source_pc;
                       kind = edge.kind;
                       target_image;
                       target_offset;
                       target_virtual_offset = Hashtbl.find bases target_image + target_offset;
                       runtime_target;
                       count = edge.count;
                     }
               | (Execution_map.Unknown_runtime | Execution_map.Mixed_or_unresolved
                 | Execution_map.Interrupt_acknowledge), _, _
               | _, (Some Execution_map.Unknown | None), _
               | _, Some (Execution_map.Image_byte _), None
               | Execution_map.Image_instruction _, Some (Execution_map.Image_byte _), Some _ -> None)
        |> List.sort (fun (a : transition) (b : transition) ->
               let by_count = compare b.count a.count in
               if by_count <> 0 then by_count
               else compare
                 (a.source_image, a.source_offset, a.target_image, a.target_offset, a.kind)
                 (b.source_image, b.source_offset, b.target_image, b.target_offset, b.kind))
        |> take top_n
      in
      let dynamic_edges =
        Execution_map.control_flow_observations map
        |> List.map (fun (edge : Execution_map.control_flow_observation) ->
               let source_image, source_offset, source_virtual_offset =
                 match edge.source with
                 | Execution_map.Image_instruction { image; offset } ->
                     Some image, Some offset,
                     Option.map (( + ) offset) (Hashtbl.find_opt bases image)
                 | Execution_map.Unknown_runtime | Execution_map.Mixed_or_unresolved
                 | Execution_map.Interrupt_acknowledge -> None, None, None
               in
               let target_image, target_offset, target_virtual_offset =
                 match edge.target_origin with
                 | Some (Execution_map.Image_byte { image; offset }) ->
                     Some image, Some offset,
                     Option.map (( + ) offset) (Hashtbl.find_opt bases image)
                 | Some Execution_map.Unknown | None -> None, None, None
               in
               { source_image; source_offset; source_virtual_offset;
                 source_runtime_pc = edge.source_pc; kind = edge.kind; taken = edge.taken;
                 target_image; target_offset; target_virtual_offset;
                 runtime_target = edge.runtime_target; count = edge.count })
      in
      let bdos_sites =
        Execution_map.bdos_sites map
        |> List.map (fun (site : Execution_map.bdos_site) ->
               let image, offset =
                 match site.source with
                 | Execution_map.Image_instruction { image; offset } -> Some image, Some offset
                 | Execution_map.Unknown_runtime | Execution_map.Mixed_or_unresolved
                 | Execution_map.Interrupt_acknowledge -> None, None
               in
               let virtual_offset =
                 match image, offset with
                 | Some image, Some offset -> Option.map (( + ) offset) (Hashtbl.find_opt bases image)
                 | _ -> None
               in
               { image; offset; virtual_offset; runtime_pc = site.source_pc;
                 function_number = site.function_number; count = site.count })
        |> List.sort (fun a b ->
               compare (a.image, a.offset, a.function_number) (b.image, b.offset, b.function_number))
      in
      let hottest_instructions =
        Execution_map.instructions map
        |> List.filter (fun (entry : Execution_map.instruction) -> Hashtbl.mem bases entry.image)
        |> List.sort (fun (a : Execution_map.instruction) (b : Execution_map.instruction) ->
               let by_count = compare b.execution_count a.execution_count in
               if by_count <> 0 then by_count
               else
                 let by_image = compare (Hashtbl.find bases a.image) (Hashtbl.find bases b.image) in
                 if by_image <> 0 then by_image else compare a.offset b.offset)
        |> take top_n
        |> List.filter_map (fun (entry : Execution_map.instruction) ->
               Option.map (fun base -> entry, base + entry.offset) (Hashtbl.find_opt bases entry.image))
      in
      Ok { images; virtual_span = !next_base; execution_summary = Execution_map.summary map;
           transitions; dynamic_edges; bdos_sites; hottest_instructions }

let json_escape text =
  let buffer = Buffer.create (String.length text + 8) in
  String.iter
    (fun character ->
      match character with
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\b' -> Buffer.add_string buffer "\\b"
      | '\012' -> Buffer.add_string buffer "\\f"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | '<' -> Buffer.add_string buffer "\\u003c"
      | '>' -> Buffer.add_string buffer "\\u003e"
      | '&' -> Buffer.add_string buffer "\\u0026"
      | character when Char.code character < 0x20 ->
          Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code character))
      | character -> Buffer.add_char buffer character)
    text;
  Buffer.contents buffer

let quote text = "\"" ^ json_escape text ^ "\""
let int_option = function None -> "null" | Some number -> string_of_int number
let hex_bytes bytes =
  let out = Buffer.create (Bytes.length bytes * 2) in
  Bytes.iter (fun byte -> Buffer.add_string out (Printf.sprintf "%02X" (Char.code byte))) bytes;
  Buffer.contents out

let flow_kind = function
  | Execution_map.Jump -> "jump"
  | Execution_map.Call -> "call"
  | Execution_map.Return -> "return"
  | Execution_map.Restart -> "restart"
  | Execution_map.Halt -> "halt"

let json_image_id id =
  Printf.sprintf "{\"drive\":%d,\"user\":%d,\"name\":%s}"
    id.Cpm.Filesystem.drive id.user (quote id.name)

let to_json_string report =
  let out = Buffer.create 4096 in
  let add = Buffer.add_string out in
  add "{\"schema\":\"RUNES_EXECUTION_MAP_REPORT 1\",\"virtual_span\":";
  add (string_of_int report.virtual_span);
  let counts = report.execution_summary in
  add ",\"execution_summary\":{\"total\":"; add (string_of_int counts.total_instruction_executions);
  add ",\"attributed\":"; add (string_of_int counts.attributed_instruction_executions);
  add ",\"unknown\":"; add (string_of_int counts.unknown_executions);
  add ",\"mixed_or_unresolved\":"; add (string_of_int counts.mixed_or_unresolved_executions);
  add ",\"interrupt_acknowledge\":"; add (string_of_int counts.interrupt_acknowledge_executions); add "}";
  add ",\"images\":[";
  List.iteri (fun image_index image ->
      if image_index > 0 then add ",";
      add "{\"id\":"; add (json_image_id image.id);
      add ",\"display_name\":"; add (quote (image_name image.id));
      add ",\"virtual_base\":"; add (string_of_int image.virtual_base);
      add ",\"span\":"; add (string_of_int image.span);
      add ",\"known_byte_count\":"; add (string_of_int image.known_byte_count);
      add ",\"unique_fetched_byte_count\":"; add (string_of_int image.unique_fetched_byte_count);
      add ",\"unique_fetched_percentage\":"; add (Printf.sprintf "%.6f" image.unique_fetched_percentage);
      add ",\"dynamic_fetched_byte_count\":"; add (string_of_int image.dynamic_fetched_byte_count);
      add ",\"unique_instruction_starts\":"; add (string_of_int image.unique_instruction_starts);
      add ",\"total_instruction_executions\":"; add (string_of_int image.total_instruction_executions);
      add ",\"first_execution_step\":"; add (int_option image.first_execution_step);
      add ",\"last_execution_step\":"; add (int_option image.last_execution_step);
      add ",\"first_record_read_step\":"; add (int_option image.first_record_read_step);
      add ",\"last_record_read_step\":"; add (int_option image.last_record_read_step);
      add ",\"bytes\":[";
      Array.iteri (fun offset byte ->
          if offset > 0 then add ",";
          add "["; add (int_option byte.value); add ",";
          add (string_of_int byte.dynamic_fetch_count); add ",";
          add (string_of_int byte.instruction_start_count); add ",";
          add (if byte.fetched then "true" else "false"); add "]") image.bytes;
      add "],\"instruction_starts\":[";
      let entries = Array.to_list image.bytes |> List.filter_map (fun byte -> Option.map (fun entry -> byte.image_offset, entry) byte.instruction) in
      List.iteri (fun index (offset, entry) ->
          if index > 0 then add ",";
          add "{\"offset\":"; add (string_of_int offset);
          add ",\"opcode\":"; add (string_of_int entry.Execution_map.opcode);
          add ",\"bytes_hex\":"; add (quote (hex_bytes entry.bytes));
          add ",\"count\":"; add (string_of_int entry.execution_count);
          add ",\"first_step\":"; add (string_of_int entry.first_step_index);
          add ",\"last_step\":"; add (string_of_int entry.last_step_index);
          add ",\"runtime_pcs\":[";
          List.iteri (fun i pc -> if i > 0 then add ","; add (string_of_int pc)) entry.runtime_pcs;
          add "]}") entries;
      add "]}") report.images;
  add "],\"transitions\":[";
  List.iteri (fun index (edge : transition) ->
      if index > 0 then add ",";
      add "{\"source_image\":"; add (json_image_id edge.source_image);
      add ",\"source_offset\":"; add (string_of_int edge.source_offset);
      add ",\"source_virtual_offset\":"; add (string_of_int edge.source_virtual_offset);
      add ",\"source_runtime_pc\":"; add (string_of_int edge.source_runtime_pc);
      add ",\"kind\":"; add (quote (flow_kind edge.kind));
      add ",\"target_image\":"; add (json_image_id edge.target_image);
      add ",\"target_offset\":"; add (string_of_int edge.target_offset);
      add ",\"target_virtual_offset\":"; add (string_of_int edge.target_virtual_offset);
      add ",\"runtime_target\":"; add (string_of_int edge.runtime_target);
      add ",\"count\":"; add (string_of_int edge.count); add "}") report.transitions;
  add "],\"dynamic_edges\":[";
  List.iteri (fun index edge ->
      if index > 0 then add ",";
      add "{\"source_image\":"; add (match edge.source_image with None -> "null" | Some id -> json_image_id id);
      add ",\"source_offset\":"; add (int_option edge.source_offset);
      add ",\"source_virtual_offset\":"; add (int_option edge.source_virtual_offset);
      add ",\"source_runtime_pc\":"; add (string_of_int edge.source_runtime_pc);
      add ",\"kind\":"; add (quote (flow_kind edge.kind));
      add ",\"taken\":"; add (match edge.taken with None -> "null" | Some true -> "true" | Some false -> "false");
      add ",\"target_image\":"; add (match edge.target_image with None -> "null" | Some id -> json_image_id id);
      add ",\"target_offset\":"; add (int_option edge.target_offset);
      add ",\"target_virtual_offset\":"; add (int_option edge.target_virtual_offset);
      add ",\"runtime_target\":"; add (int_option edge.runtime_target);
      add ",\"count\":"; add (string_of_int edge.count); add "}") report.dynamic_edges;
  add "],\"bdos_sites\":[";
  List.iteri (fun index site ->
      if index > 0 then add ",";
      add "{\"image\":"; add (match site.image with None -> "null" | Some id -> json_image_id id);
      add ",\"offset\":"; add (int_option site.offset);
      add ",\"virtual_offset\":"; add (int_option site.virtual_offset);
      add ",\"runtime_pc\":"; add (int_option site.runtime_pc);
      add ",\"function_number\":"; add (string_of_int site.function_number);
      add ",\"count\":"; add (string_of_int site.count); add "}") report.bdos_sites;
  add "],\"hottest_instructions\":[";
  List.iteri (fun index ((entry : Execution_map.instruction), virtual_offset) ->
      if index > 0 then add ",";
      add "{\"image\":"; add (json_image_id entry.Execution_map.image);
      add ",\"offset\":"; add (string_of_int entry.offset);
      add ",\"virtual_offset\":"; add (string_of_int virtual_offset);
      add ",\"runtime_pcs\":[";
      List.iteri (fun i pc -> if i > 0 then add ","; add (string_of_int pc)) entry.runtime_pcs;
      add "],\"bytes_hex\":"; add (quote (hex_bytes entry.bytes));
      add ",\"count\":"; add (string_of_int entry.execution_count);
      add ",\"first_step\":"; add (string_of_int entry.first_step_index);
      add ",\"last_step\":"; add (string_of_int entry.last_step_index); add "}") report.hottest_instructions;
  add "]}";
  Buffer.contents out

let write_json ~output report = output (to_json_string report)

let html_escape text =
  let out = Buffer.create (String.length text + 8) in
  String.iter (function
    | '&' -> Buffer.add_string out "&amp;"
    | '<' -> Buffer.add_string out "&lt;"
    | '>' -> Buffer.add_string out "&gt;"
    | '"' -> Buffer.add_string out "&quot;"
    | '\'' -> Buffer.add_string out "&#39;"
    | character -> Buffer.add_char out character) text;
  Buffer.contents out

let option_hex = function None -> "—" | Some number -> Printf.sprintf "%04Xh" number
let option_step = function None -> "—" | Some number -> string_of_int number

let to_html_string ?(row_width = 64) report =
  if row_width <= 0 then invalid_arg "Execution_report.to_html_string: row_width";
  let out = Buffer.create 8192 in
  let add = Buffer.add_string out in
  add "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Runes execution map</title>";
  add "<style>body{font:14px system-ui,sans-serif;margin:1.5rem;color:#172033}table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}th,td{padding:.35rem .5rem;border:1px solid #ccd3dc;text-align:left;font-variant-numeric:tabular-nums}th{background:#eef2f6;position:sticky;top:0}canvas{display:block;max-width:100%;border:1px solid #9aa5b1;image-rendering:pixelated}.heat{height:auto}.overview{height:90px}.timeline{height:170px}.image{margin:2rem 0}.tooltip{min-height:3.5rem;padding:.5rem;background:#f3f6f8;font:12px ui-monospace,monospace;white-space:pre-wrap}.muted{color:#4b5563}</style></head><body>";
  add "<h1>Execution Map v0</h1><p class=\"muted\">Not fetched does not mean dead code. Linear virtual offsets are an analysis coordinate, not a historical memory layout.</p><p>Coordinates are distinct: runtime PC, image/file offset, virtual offset and execution step index.</p>";
  add "<h2>Images</h2><table><thead><tr><th>Image</th><th>Virtual range</th><th>Span bytes</th><th>Known bytes</th><th>Unique fetched bytes</th><th>Known-byte coverage</th><th>Unique instruction starts</th><th>Instruction executions</th><th>Dynamic fetched-byte total</th><th>First / last step</th></tr></thead><tbody>";
  List.iter (fun image ->
      let name = html_escape (image_name image.id) in
      let range = if image.span = 0 then Printf.sprintf "%05Xh empty" image.virtual_base else Printf.sprintf "%05Xh–%05Xh" image.virtual_base (image.virtual_base + image.span - 1) in
      add "<tr><td>"; add name; add "</td><td>"; add range; add "</td><td>"; add (string_of_int image.span);
      add "</td><td>"; add (string_of_int image.known_byte_count); add "</td><td>"; add (string_of_int image.unique_fetched_byte_count);
      add "</td><td>"; add (Printf.sprintf "%.2f%%" image.unique_fetched_percentage); add "</td><td>"; add (string_of_int image.unique_instruction_starts);
      add "</td><td>"; add (string_of_int image.total_instruction_executions); add "</td><td>"; add (string_of_int image.dynamic_fetched_byte_count);
      add "</td><td>"; add (option_step image.first_execution_step); add " / "; add (option_step image.last_execution_step); add "</td></tr>") report.images;
  add "</tbody></table><h2>Linear program overview</h2><p class=\"muted\">Each bucket shows the maximum dynamic byte-fetch count among its bytes; outlines show image boundaries.</p><canvas id=\"overview\" class=\"overview\"></canvas><h2>Execution timeline</h2><p class=\"muted\">Dark bars: first-to-last execution. Teal bars: first-to-last successful BDOS record read when step indexes were supplied. These are observed ranges, not inferred passes.</p><canvas id=\"timeline\" class=\"timeline\"></canvas>";
  List.iteri (fun index image ->
      add "<section class=\"image\"><h2>"; add (html_escape (image_name image.id)); add "</h2><p>Virtual base ";
      add (Printf.sprintf "%05Xh" image.virtual_base); add "; image span "; add (string_of_int image.span);
      add " bytes; detail grid uses "; add (string_of_int row_width); add " bytes/row.</p><canvas class=\"heat\" data-image-index=\"";
      add (string_of_int index); add "\"></canvas><div class=\"tooltip\">Hover over a byte for details.</div></section>") report.images;
  add "<h2>Cross-image transitions (top 25)</h2><table><thead><tr><th>Source image</th><th>Source offset</th><th>Runtime PC</th><th>Flow</th><th>Target image</th><th>Target offset</th><th>Runtime target</th><th>Count</th></tr></thead><tbody>";
  List.iter (fun (edge : transition) ->
      add "<tr><td>"; add (html_escape (image_name edge.source_image)); add "</td><td>"; add (Printf.sprintf "%04Xh" edge.source_offset);
      add "</td><td>"; add (Printf.sprintf "%04Xh" edge.source_runtime_pc); add "</td><td>"; add (flow_kind edge.kind);
      add "</td><td>"; add (html_escape (image_name edge.target_image)); add "</td><td>"; add (Printf.sprintf "%04Xh" edge.target_offset);
      add "</td><td>"; add (Printf.sprintf "%04Xh" edge.runtime_target); add "</td><td>"; add (string_of_int edge.count); add "</td></tr>") report.transitions;
  add "</tbody></table><h2>BDOS sites</h2><table><thead><tr><th>Function</th><th>Image</th><th>Image offset</th><th>Runtime PC</th><th>Count</th></tr></thead><tbody>";
  List.iter (fun site ->
      add "<tr><td>"; add (string_of_int site.function_number); add "</td><td>";
      add (match site.image with None -> "Unknown" | Some id -> html_escape (image_name id));
      add "</td><td>"; add (option_hex site.offset); add "</td><td>"; add (option_hex site.runtime_pc);
      add "</td><td>"; add (string_of_int site.count); add "</td></tr>") report.bdos_sites;
  add "</tbody></table><h2>Hottest instruction starts (top 25)</h2><table><thead><tr><th>Image</th><th>Offset</th><th>Virtual offset</th><th>Runtime PC(s)</th><th>Bytes</th><th>Executions</th><th>First step</th><th>Last step</th></tr></thead><tbody>";
  List.iter (fun ((entry : Execution_map.instruction), virtual_offset) ->
      add "<tr><td>"; add (html_escape (image_name entry.image)); add "</td><td>"; add (Printf.sprintf "%04Xh" entry.offset);
      add "</td><td>"; add (Printf.sprintf "%05Xh" virtual_offset); add "</td><td>";
      List.iteri (fun i pc -> if i > 0 then add ", "; add (Printf.sprintf "%04Xh" pc)) entry.runtime_pcs;
      add "</td><td><code>"; add (hex_bytes entry.bytes); add "</code></td><td>"; add (string_of_int entry.execution_count);
      add "</td><td>"; add (string_of_int entry.first_step_index); add "</td><td>"; add (string_of_int entry.last_step_index); add "</td></tr>") report.hottest_instructions;
  add "</tbody></table><p class=\"muted\">Grey cells are unknown or known-but-unfetched. Fetched-byte heat uses log(1+count)/log(1+maximum); instruction starts have a dark outline.</p>";
  add "<script>const DATA="; add (to_json_string report); add ";const ROW_WIDTH="; add (string_of_int row_width); add ";";
  add "function color(n,max){if(!n)return '#d1d5db';const h=Math.min(1,Math.log1p(n)/Math.log1p(max||1));return `rgb(255,${Math.round(248-175*h)},${Math.round(205-190*h)})`}";
  add "function drawOverview(){const c=document.getElementById('overview'),x=c.getContext('2d'),w=Math.max(900,c.clientWidth),total=Math.max(1,DATA.virtual_span);c.width=w;c.height=90;let max=1;for(const im of DATA.images)for(const b of im.bytes)max=Math.max(max,b[1]);for(const im of DATA.images){if(!im.span)continue;const s=Math.floor(im.virtual_base/total*w),e=Math.floor((im.virtual_base+im.span)/total*w),n=Math.max(1,e-s);for(let k=0;k<n;k++){const a=Math.floor(k*im.span/n),z=Math.max(a+1,Math.floor((k+1)*im.span/n));let peak=0;for(let q=a;q<Math.min(z,im.span);q++)peak=Math.max(peak,im.bytes[q][1]);x.fillStyle=color(peak,max);x.fillRect(s+k,18,1,48)}x.strokeStyle='#111827';x.lineWidth=2;x.strokeRect(s,17,Math.max(1,e-s),50);x.fillStyle='#111827';x.font='11px sans-serif';x.fillText(im.display_name,s+3,78)}}";
  add "function drawGrid(canvas,im,max){const ctx=canvas.getContext('2d'),cell=12,rh=10,rows=Math.ceil(im.span/ROW_WIDTH);canvas.width=ROW_WIDTH*cell;canvas.height=Math.max(rh,rows*rh);ctx.fillStyle='#e5e7eb';ctx.fillRect(0,0,canvas.width,canvas.height);for(let i=0;i<im.span;i++){const b=im.bytes[i],x=i%ROW_WIDTH*cell,y=Math.floor(i/ROW_WIDTH)*rh;ctx.fillStyle=b[0]===null?'#e5e7eb':color(b[1],max);ctx.fillRect(x,y,cell,rh);if(b[2]>0){ctx.strokeStyle='#111827';ctx.lineWidth=1;ctx.strokeRect(x+.5,y+.5,cell-1,rh-1)}}canvas.addEventListener('mousemove',ev=>{const rect=canvas.getBoundingClientRect(),x=Math.floor((ev.clientX-rect.left)*canvas.width/rect.width),y=Math.floor((ev.clientY-rect.top)*canvas.height/rect.height),off=Math.floor(y/rh)*ROW_WIDTH+Math.floor(x/cell),tip=canvas.nextElementSibling;if(off<0||off>=im.span){tip.textContent='';return}const b=im.bytes[off],start=im.instruction_starts.find(v=>v.offset===off);let s=`${im.display_name}\\nimage offset ${off.toString(16).toUpperCase()}\\nvirtual offset ${(im.virtual_base+off).toString(16).toUpperCase()}\\nbyte ${b[0]===null?'unknown':b[0].toString(16).toUpperCase().padStart(2,'0')}\\ndynamic fetch count ${b[1]}\\ninstruction-start count ${b[2]}\\nfetched ${b[3]?'yes':'no'}`;if(start)s+=`\\ninstruction bytes ${start.bytes_hex}\\nruntime PC(s) ${start.runtime_pcs.map(v=>v.toString(16).toUpperCase()).join(', ')}\\nexecutions ${start.count}\\nfirst step ${start.first_step}\\nlast step ${start.last_step}`;tip.textContent=s})}";
  add "let maximum=1;for(const im of DATA.images)for(const b of im.bytes)maximum=Math.max(maximum,b[1]);drawOverview();const tl=document.getElementById('timeline'),tx=tl.getContext('2d');tl.width=Math.max(900,tl.clientWidth);tl.height=Math.max(100,DATA.images.length*40);let last=1;for(const im of DATA.images)last=Math.max(last,im.last_execution_step||0,im.last_record_read_step||0);DATA.images.forEach((im,i)=>{const y=i*40+8,a=im.first_execution_step===null?0:im.first_execution_step/last*tl.width,b=im.last_execution_step===null?a:im.last_execution_step/last*tl.width;tx.fillStyle='#334155';tx.fillRect(a,y,Math.max(2,b-a),12);if(im.first_record_read_step!==null){const la=im.first_record_read_step/last*tl.width,lb=(im.last_record_read_step||la)/last*tl.width;tx.fillStyle='#0f766e';tx.fillRect(la,y+14,Math.max(2,lb-la),8)}tx.fillStyle='#111827';tx.font='12px sans-serif';tx.fillText(im.display_name,4,y-1)});document.querySelectorAll('canvas.heat').forEach(c=>drawGrid(c,DATA.images[Number(c.dataset.imageIndex)],maximum));</script></body></html>";
  Buffer.contents out

let write_html ?(row_width = 64) ~output report = output (to_html_string ~row_width report)
