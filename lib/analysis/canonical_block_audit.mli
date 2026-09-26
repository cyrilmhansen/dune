type start_status = All_owners | Some_owners | No_owners

type owner_block = {
  routine_id : int;
  block_id : int;
  start_offset : int option;
  end_offset : int option;
  canonical_image_span : bool;
}

type shared_coordinate = {
  image : Execution_map.image_id;
  offset : int;
  routine_ids : int list;
  instruction_record_count : int;
  bytes_agree : bool;
  decoded_agree : bool;
  block_start_status : start_status;
  owner_blocks : (int * owner_block list) list;
  boundaries_identical : bool;
}

type candidate_block = {
  image : Execution_map.image_id;
  start_offset : int;
  end_offset : int;
}

type routine_detail = {
  routine_id : int;
  owner_qualified_image_instruction_records : int;
  shared_coordinates : int;
  boundary_conflicts : int;
  implicated_blocks : int;
  examples : shared_coordinate list;
}

type summary = {
  canonical_instruction_coordinates : int;
  owner_qualified_image_instruction_records : int;
  duplicated_owner_qualified_instruction_records : int;
  multi_owner_instruction_coordinates : int;
  byte_disagreement_coordinates : int;
  decoded_disagreement_coordinates : int;
  block_start_all_owners : int;
  block_start_some_owners : int;
  block_start_no_owners : int;
  boundary_conflict_count : int;
  current_owner_qualified_blocks : int;
  current_canonical_image_blocks : int;
  candidate_canonical_blocks : int;
  estimated_block_deduplication : int;
}

type report

val analyze : Dynamic_blocks.report -> report
val summary : report -> summary
val shared_coordinates : report -> shared_coordinate list
val candidate_blocks : report -> candidate_block list
val routine_details : ?routine_ids:int list -> report -> routine_detail list
val to_json_string : report -> string
val to_text : ?routine_ids:int list -> report -> string
