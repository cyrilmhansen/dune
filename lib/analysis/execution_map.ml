(* This module intentionally exposes similarly named fields for query records
   and keeps structurally compared hash keys; silence only the resulting
   record-label/unused-key diagnostics. *)
[@@@warning "-41-42-69"]

type image_id = Cpm.Filesystem.key

type origin = Unknown | Image_byte of { image : image_id; offset : int }

type instruction_origin =
  | Image_instruction of { image : image_id; offset : int }
  | Unknown_runtime
  | Mixed_or_unresolved
  | Interrupt_acknowledge

type flow_kind = Jump | Call | Return | Restart | Halt

type control_flow_observation = {
  source : instruction_origin;
  source_pc : int;
  kind : flow_kind;
  taken : bool option;
  runtime_target : int option;
  target_origin : origin option;
  count : int;
}

type edge_acc = { observation : control_flow_observation; mutable count : int }

type instruction_acc = {
  image : image_id;
  offset : int;
  mutable execution_count : int;
  mutable first_step_index : int;
  mutable last_step_index : int;
  runtime_pcs : (int, unit) Hashtbl.t;
  opcode : int;
  bytes : bytes;
}

type instruction = {
  image : image_id;
  offset : int;
  execution_count : int;
  first_step_index : int;
  last_step_index : int;
  runtime_pcs : int list;
  opcode : int;
  bytes : bytes;
}

type image_summary = {
  image : image_id;
  known_size : int option;
  known_byte_count : int;
  observed_records : int list;
  fetched_byte_count : int;
  unique_instruction_starts : int;
  total_instruction_executions : int;
  first_execution : (int * int * int) option;
  last_execution_step : int option;
}

type image_acc = {
  id : image_id;
  mutable known_size : int option;
  known_bytes : (int, int) Hashtbl.t;
  fetched_counts : (int, int) Hashtbl.t;
  observed_records : (int, unit) Hashtbl.t;
  mutable total_instruction_executions : int;
  mutable first_execution : (int * int * int) option;
  mutable last_execution_step : int option;
}

type edge_key = {
  source : instruction_origin;
  source_pc : int;
  kind : flow_kind;
  taken : bool option;
  runtime_target : int option;
  target_origin : origin option;
}

type bdos_key = {
  source : instruction_origin;
  source_pc : int option;
  function_number : int;
}

type bdos_site = {
  source : instruction_origin;
  source_pc : int option;
  function_number : int;
  count : int;
}

type bdos_site_acc = { site : bdos_site; mutable count : int }

type summary = {
  total_instruction_executions : int;
  attributed_instruction_executions : int;
  unknown_executions : int;
  mixed_or_unresolved_executions : int;
  interrupt_acknowledge_executions : int;
}

type error = Conflicting_instruction_bytes of { image : image_id; offset : int }
exception Analysis_error of error

type t = {
  origins : origin array;
  images : (image_id, image_acc) Hashtbl.t;
  instructions : ((image_id * int), instruction_acc) Hashtbl.t;
  edges : (edge_key, edge_acc) Hashtbl.t;
  sites : (bdos_key, bdos_site_acc) Hashtbl.t;
  mutable total_steps : int;
  mutable attributed_steps : int;
  mutable unknown_steps : int;
  mutable mixed_steps : int;
  mutable interrupt_steps : int;
  mutable last_step : (int * I8080.Step.t * instruction_origin) option;
}

let create () =
  {
    origins = Array.make I8080.Memory.size Unknown;
    images = Hashtbl.create 17;
    instructions = Hashtbl.create 4093;
    edges = Hashtbl.create 257;
    sites = Hashtbl.create 31;
    total_steps = 0;
    attributed_steps = 0;
    unknown_steps = 0;
    mixed_steps = 0;
    interrupt_steps = 0;
    last_step = None;
  }

let image_id ~drive ~user ~filename =
  Cpm.Filesystem.key_of_name ~drive ~user ~name:filename

let image_acc map image =
  match Hashtbl.find_opt map.images image with
  | Some acc -> acc
  | None ->
      let acc : image_acc =
        {
          id = image;
          known_size = None;
          known_bytes = Hashtbl.create 257;
          fetched_counts = Hashtbl.create 257;
          observed_records = Hashtbl.create 17;
          total_instruction_executions = 0;
          first_execution = None;
          last_execution_step = None;
        }
      in
      Hashtbl.add map.images image acc;
      acc

let seed_image map ~image ~runtime_base bytes =
  if runtime_base < 0 || runtime_base >= I8080.Memory.size then
    Error "Execution_map.seed_image: runtime base must be a 16-bit address"
  else if Bytes.length bytes > I8080.Memory.size then
    Error "Execution_map.seed_image: image exceeds the 64 KiB address space"
  else (
    let image_acc = image_acc map image in
    Array.iteri
      (fun address -> function
        | Image_byte { image = origin_image; _ } when origin_image = image ->
            map.origins.(address) <- Unknown
        | Unknown | Image_byte _ -> ())
      map.origins;
    Hashtbl.clear image_acc.known_bytes;
    image_acc.known_size <- Some (Bytes.length bytes);
    for offset = 0 to Bytes.length bytes - 1 do
      let value = Char.code (Bytes.get bytes offset) in
      Hashtbl.replace image_acc.known_bytes offset value;
      map.origins.((runtime_base + offset) land 0xffff) <- Image_byte { image; offset }
    done;
    Ok ())

let origin_at map address =
  if address < 0 || address >= I8080.Memory.size then invalid_arg "Execution_map.origin_at";
  map.origins.(address)

let byte_at map ~image ~offset =
  Option.map (fun byte -> byte land 0xff)
    (Option.bind (Hashtbl.find_opt map.images image) (fun acc -> Hashtbl.find_opt acc.known_bytes offset))

let byte_fetch_count map ~image ~offset =
  Option.value
    (Option.bind (Hashtbl.find_opt map.images image) (fun acc -> Hashtbl.find_opt acc.fetched_counts offset))
    ~default:0

let increment table key =
  Hashtbl.replace table key (1 + Option.value (Hashtbl.find_opt table key) ~default:0)

let origin_of_step map step =
  match I8080.Step.source step with
  | I8080.Step.Interrupt_acknowledge -> Interrupt_acknowledge
  | I8080.Step.Memory ->
      let bytes = I8080.Step.fetched_bytes step in
      let first = origin_at map (I8080.Step.pc_before step) in
      (match first with
      | Unknown ->
          if Bytes.length bytes > 0
             && List.for_all
                  (fun index -> origin_at map ((I8080.Step.pc_before step + index) land 0xffff) = Unknown)
                  (List.init (Bytes.length bytes) Fun.id)
          then Unknown_runtime else Mixed_or_unresolved
      | Image_byte { image; offset } ->
          let coherent = ref true in
          for index = 0 to Bytes.length bytes - 1 do
            if origin_at map ((I8080.Step.pc_before step + index) land 0xffff)
               <> Image_byte { image; offset = offset + index }
            then coherent := false
          done;
          if !coherent then Image_instruction { image; offset }
          else Mixed_or_unresolved)

let edge_of_step step source map : control_flow_observation option =
  let pc_after = I8080.Step.pc_after step in
  let target_of ?(taken = true) encoded_target =
    let runtime_target = if taken then encoded_target else pc_after in
    (Some runtime_target, Some (origin_at map runtime_target))
  in
  let control = I8080.Step.control_flow step in
  let kind, taken, target =
    match control with
    | I8080.Step.Sequential -> None, None, None
    | I8080.Step.Jump { target; taken } ->
        let runtime_target, target_origin = target_of ~taken target in
        Some Jump, Some taken, Some (runtime_target, target_origin)
    | I8080.Step.Call { target; taken } ->
        let runtime_target, target_origin = target_of ~taken target in
        Some Call, Some taken, Some (runtime_target, target_origin)
    | I8080.Step.Return { taken; _ } ->
        Some Return, Some taken, Some (Some pc_after, Some (origin_at map pc_after))
    | I8080.Step.Restart { target } ->
        let runtime_target, target_origin = target_of target in
        Some Restart, Some true, Some (runtime_target, target_origin)
    | I8080.Step.Halt -> Some Halt, None, None
  in
  match kind with
  | None -> None
  | Some kind ->
      let runtime_target, target_origin =
        match target with None -> None, None | Some (target, origin) -> target, origin
      in
      Some
        ({
          source;
          source_pc = I8080.Step.pc_before step;
          kind;
          taken;
          runtime_target;
          target_origin;
          count = 1;
        } : control_flow_observation)

let add_edge map (observation : control_flow_observation) =
  let key : edge_key =
    {
      source = observation.source;
      source_pc = observation.source_pc;
      kind = observation.kind;
      taken = observation.taken;
      runtime_target = observation.runtime_target;
      target_origin = observation.target_origin;
    }
  in
  match Hashtbl.find_opt map.edges key with
  | Some (existing : edge_acc) -> existing.count <- existing.count + 1
  | None -> Hashtbl.add map.edges key { observation; count = 1 }

let observe_step map ~step_index step =
  let instruction_origin = origin_of_step map step in
  let fetched = I8080.Step.fetched_bytes step in
  let conflict =
    match instruction_origin with
    | Image_instruction { image; offset } ->
        (match Hashtbl.find_opt map.instructions (image, offset) with
        | Some existing when not (Bytes.equal existing.bytes fetched) ->
            Some (Conflicting_instruction_bytes { image; offset })
        | _ -> None)
    | Unknown_runtime | Mixed_or_unresolved | Interrupt_acknowledge -> None
  in
  match conflict with
  | Some error -> Error error
  | None ->
  (match instruction_origin with
  | Image_instruction { image; offset } ->
      let image_acc = image_acc map image in
      let key = image, offset in
      let opcode = (I8080.Step.decoded step).I8080.Decode.opcode in
      (match Hashtbl.find_opt map.instructions key with
      | Some _ -> ()
      | None ->
          let entry : instruction_acc =
            {
              image;
              offset;
              execution_count = 0;
              first_step_index = step_index;
              last_step_index = step_index;
              runtime_pcs = Hashtbl.create 3;
              opcode;
              bytes = Bytes.copy fetched;
            }
          in
          Hashtbl.add map.instructions key entry);
      let entry = Hashtbl.find map.instructions key in
      entry.execution_count <- entry.execution_count + 1;
      entry.last_step_index <- step_index;
      Hashtbl.replace entry.runtime_pcs (I8080.Step.pc_before step) ();
      image_acc.total_instruction_executions <- image_acc.total_instruction_executions + 1;
      if image_acc.first_execution = None then
        image_acc.first_execution <- Some (I8080.Step.pc_before step, offset, step_index);
      image_acc.last_execution_step <- Some step_index;
      map.attributed_steps <- map.attributed_steps + 1
  | Unknown_runtime -> map.unknown_steps <- map.unknown_steps + 1
  | Mixed_or_unresolved -> map.mixed_steps <- map.mixed_steps + 1
  | Interrupt_acknowledge -> map.interrupt_steps <- map.interrupt_steps + 1);
  (match I8080.Step.source step with
  | I8080.Step.Interrupt_acknowledge -> ()
  | I8080.Step.Memory ->
      for index = 0 to Bytes.length fetched - 1 do
        let address = (I8080.Step.pc_before step + index) land 0xffff in
        match origin_at map address with
        | Unknown -> ()
        | Image_byte { image; offset } ->
            let acc = image_acc map image in
            increment acc.fetched_counts offset
      done);
  (* Attribute before writes: fetched instruction bytes existed at fetch time. *)
  let writes =
    List.filter_map
      (function
        | I8080.Step.Write { address; _ } -> Some (address land 0xffff)
        | I8080.Step.Read _ -> None)
      (I8080.Step.memory_accesses step)
  in
  List.iter (fun address -> map.origins.(address) <- Unknown) writes;
  (match edge_of_step step instruction_origin map with
  | None -> ()
  | Some edge -> add_edge map edge);
  map.total_steps <- map.total_steps + 1;
  map.last_step <- Some (step_index, step, instruction_origin);
  Ok ()

let observe_bdos_event map = function
  | Cpm.Bdos.Read_record { file; logical_record; dma; data } ->
      let acc = image_acc map file in
      Hashtbl.replace acc.observed_records logical_record ();
      for index = 0 to Bytes.length data - 1 do
        let offset = logical_record * 128 + index in
        Hashtbl.replace acc.known_bytes offset (Char.code (Bytes.get data index));
        map.origins.((dma + index) land 0xffff) <- Image_byte { image = file; offset }
      done;
  | Cpm.Bdos.Write_record { file; logical_record; data; _ } ->
      let acc = image_acc map file in
      Hashtbl.replace acc.observed_records logical_record ();
      for index = 0 to Bytes.length data - 1 do
        let offset = logical_record * 128 + index in
        Hashtbl.replace acc.known_bytes offset (Char.code (Bytes.get data index))
      done

let observe_runner_event map = function
  | Runner.Step step ->
      let step_index =
        match map.last_step with None -> 0 | Some (previous, _, _) -> previous + 1
      in
      (match observe_step map ~step_index step with
      | Ok () -> ()
      | Error error -> raise (Analysis_error error))
  | Runner.Bdos_call { step_index; function_number; _ } ->
      let source, source_pc =
        match map.last_step with
        | Some (last_index, step, origin)
          when last_index + 1 = step_index
               && I8080.Step.pc_after step = 0x0005
               && I8080.Step.control_flow step <> I8080.Step.Sequential ->
            origin, Some (I8080.Step.pc_before step)
        | _ -> Unknown_runtime, None
      in
      let key = { source; source_pc; function_number } in
      (match Hashtbl.find_opt map.sites key with
      | Some site -> site.count <- site.count + 1
      | None ->
          let site = { source; source_pc; function_number; count = 1 } in
          Hashtbl.add map.sites key { site; count = 1 })
  | Runner.Termination _ -> ()

let instruction_start_count map ~image ~offset =
  Option.fold ~none:0 ~some:(fun (entry : instruction_acc) -> entry.execution_count)
    (Hashtbl.find_opt map.instructions (image, offset))

let compare_image = compare
let images map = Hashtbl.fold (fun image _ acc -> image :: acc) map.images [] |> List.sort compare_image

let counts_total table = Hashtbl.fold (fun _ count total -> count + total) table 0
let image_instruction_entries map image =
  Hashtbl.fold
    (fun (entry_image, _) entry acc -> if entry_image = image then entry :: acc else acc)
    map.instructions []

let summary_for_image map (acc : image_acc) : image_summary =
  let entries = image_instruction_entries map acc.id in
  {
    image = acc.id;
    known_size = acc.known_size;
    known_byte_count = Hashtbl.length acc.known_bytes;
    observed_records = Hashtbl.fold (fun record () records -> record :: records) acc.observed_records [] |> List.sort compare;
    fetched_byte_count = counts_total acc.fetched_counts;
    unique_instruction_starts = List.length entries;
    total_instruction_executions = acc.total_instruction_executions;
    first_execution = acc.first_execution;
    last_execution_step = acc.last_execution_step;
  }

let image_summary map ~image =
  Option.map (summary_for_image map) (Hashtbl.find_opt map.images image)

let image_summaries map =
  Hashtbl.fold (fun _ (acc : image_acc) result -> summary_for_image map acc :: result) map.images []
  |> List.sort (fun (a : image_summary) (b : image_summary) -> compare_image a.image b.image)

let instruction_of_acc (acc : instruction_acc) : instruction =
  {
    image = acc.image;
    offset = acc.offset;
    execution_count = acc.execution_count;
    first_step_index = acc.first_step_index;
    last_step_index = acc.last_step_index;
    runtime_pcs = Hashtbl.fold (fun pc () pcs -> pc :: pcs) acc.runtime_pcs [] |> List.sort compare;
    opcode = acc.opcode;
    bytes = Bytes.copy acc.bytes;
  }

let instructions map =
  Hashtbl.fold (fun _ (acc : instruction_acc) result -> instruction_of_acc acc :: result) map.instructions []
  |> List.sort (fun (a : instruction) (b : instruction) ->
         let by_image = compare_image a.image b.image in
         if by_image <> 0 then by_image else compare a.offset b.offset)

let hot_instructions map ~limit =
  if limit < 0 then invalid_arg "Execution_map.hot_instructions";
  instructions map
  |> List.sort (fun a b ->
         let by_count = compare b.execution_count a.execution_count in
         if by_count <> 0 then by_count
         else let by_image = compare_image a.image b.image in
           if by_image <> 0 then by_image else compare a.offset b.offset)
  |> fun entries ->
  let rec take remaining = function
    | _ when remaining = 0 -> []
    | [] -> []
    | entry :: rest -> entry :: take (remaining - 1) rest
  in
  take limit entries

let control_flow_observations map =
  Hashtbl.fold
    (fun _ acc result -> { acc.observation with count = acc.count } :: result)
    map.edges []
  |> List.sort compare

let cross_image_transitions map =
  control_flow_observations map
  |> List.filter (fun (edge : control_flow_observation) ->
       match edge.source, edge.target_origin with
       | Image_instruction { image = source_image; _ },
         Some (Image_byte { image = target_image; _ }) ->
           source_image <> target_image
       | _ -> false)

let bdos_sites map =
  Hashtbl.fold (fun _ acc result -> { acc.site with count = acc.count } :: result) map.sites []
  |> List.sort compare

let summary map =
  {
    total_instruction_executions = map.total_steps;
    attributed_instruction_executions = map.attributed_steps;
    unknown_executions = map.unknown_steps;
    mixed_or_unresolved_executions = map.mixed_steps;
    interrupt_acknowledge_executions = map.interrupt_steps;
  }
