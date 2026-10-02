#!/usr/bin/env python3
"""Bounded MINIMAL evidence join; no decoding, discovery or semantic promotion."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from check_minimal_pass_2 import coord, require
from check_minimal_pass_3 import gather, validate as validate_pass_3
from minimal_baseline import digest, load, ranges, status_at
from evidence_packet_local import call_contract, dependency_chain, derive_local, navigation_effects, preserved_address, validate_local

ROOT = Path(__file__).resolve().parents[2]
TARGET = "PLI0.OVL+24BC"


def stable(origin, images):
    if origin is None:
        return None
    image = images[origin["image"]["name"]]
    return {"image": image["name"], "image_sha256": image["sha256"],
            "offset": origin["offset"]}


def verify_return(call, ret, relation):
    require(relation["frame"]["call_step"] == call["step_index"]
            and relation["step_index"] == ret["step_index"]
            and ret["pc_after"] == call["call_return_address"]
            and ret["sp_before"] == call["sp_after"]
            and ret["sp_after"] == (call["sp_after"] + 2) & 65535
            and {q["address"]: q["value"] for q in ret["reads"]}
            == {q["address"]: q["new_value"] for q in call["writes"]},
            f"CALL {call['step_index']}: original hardware slot mismatch")


def role_matches(address, roles):
    # Unknown-length roles match only the established base byte. Never infer
    # table bounds or make roles global merely because addresses coincide.
    return [{"role_id": r["id"], "role": r["name"], "address": address,
             "role_byte_offset": address - r["runtime_address"],
             "join_evidence": "DEDUCED",
             "role_evidence": "ACCUMULATED KNOWLEDGE",
             "raw_address_retained": True}
            for r in roles if r["runtime_address"] <= address
            < r["runtime_address"] + (r["width"] or 1)]


def access_rows(accesses, frame, frame_bytes, roles):
    rows = []
    for q in accesses:
        row = dict(q, width=1, joined_roles=role_matches(q["address"], roles))
        delta = (q["address"] - frame) & 65535
        signed = delta if delta < 32768 else delta - 65536
        # Only local storage, original return word and the observed below-frame
        # stack region get a frame presentation; other addresses stay numeric.
        if -4 <= signed < frame_bytes + 2:
            row["deduced_frame_relation"] = {
                "F": frame, "offset": signed,
                "expression": f"F{signed:+d}", "evidence": "DEDUCED",
                "address": q["address"]}
        rows.append(row)
    return rows


def first_written_slots(ws, frame, frame_bytes):
    slots = {}
    for w in ws:
        for q in w["writes"]:
            delta = (q["address"] - frame) & 65535
            if delta < frame_bytes:
                slots.setdefault(delta, {"value": q["new_value"],
                                         "producer_step": w["step_index"]})
    return slots


def path_signature(r, frame_bytes, class_slots):
    ws = r["own_witnesses"]
    frame = (r["entry"]["before"]["sp"] - frame_bytes) & 65535
    slots = first_written_slots(ws, frame, frame_bytes)
    return (r["entry"]["before"]["c"],
            tuple((n, slots.get(n, {}).get("value")) for n in class_slots),
            tuple((coord(w["origin"]), w["control"]["kind"],
                   w["control"].get("taken", True), coord(w.get("target_origin")))
                  for w in ws if w["control"]["kind"] != "sequential"))


def edge_kind(w):
    c = w["control"]
    if c["kind"] == "call" and c.get("taken", True):
        return "call-return-continuation"
    if "taken" in c and not c["taken"]:
        return "branch-fallthrough"
    if c["kind"] == "jump":
        return "branch-taken"
    return c["kind"]


def immediate_predicate_producer(branch, previous, instructions, steps):
    """Only the immediately preceding recorded instruction; no data-flow walk."""
    if previous is None:
        return None
    condition = instructions[branch]["decoded"].split()[0][1:]
    flag = {"NZ": "zero", "Z": "zero", "NC": "carry", "C": "carry",
            "PO": "parity", "PE": "parity", "P": "sign", "M": "sign"}.get(condition)
    mnemonic = instructions[steps[str(previous)]["coordinate"]]["decoded"].split()[0]
    all_flags = {"ADD", "ADC", "ADI", "ACI", "SUB", "SBB", "SUI", "SBI", "ANA", "ANI",
                 "XRA", "XRI", "ORA", "ORI", "CMP", "CPI", "DAA"}
    changes_flag = mnemonic in all_flags or (flag != "carry" and mnemonic in ("INR", "DCR"))
    changes_flag |= flag == "carry" and mnemonic in ("RAR", "RAL", "RRC", "RLC", "DAD", "STC", "CMC")
    return previous if flag is not None and changes_flag else None


def build(capture, images_dir, entry=TARGET, frame_bytes=18, class_slots=(9, 10)):
    annotation = ROOT / "research/annotated-assembly"
    manifest = load(annotation / "manifest.json")
    images = {i["name"]: i for i in manifest["images"]}
    originals = {}
    for name, image in images.items():
        path = images_dir / name
        require(digest(path) == image["sha256"], f"Historical image hash mismatch: {name}")
        originals[name] = path.read_bytes()
    catalog = {p["id"]: p for p in load(annotation / "procedures.json")["procedures"]}
    require(entry in catalog, "Entry must cite an existing ProcedureHypothesis")
    procedure = catalog[entry]
    all_roles = load(annotation / "data-roles.json")["roles"]
    selected_roles = [r for r in all_roles
                      if r["id"] in procedure["data_role_ids"]]
    require(all(r["image_sha256"] == images[r["image"]]["sha256"]
                for r in selected_roles), "Role image identity mismatch")
    index = load(capture / "event-witnesses.json")
    require(index["run_id"].startswith("MINIMAL:"), "Only existing MINIMAL evidence is in scope")
    canonical = load(capture / "canonical-code-blocks.json")
    facts = {coord({"image": i["image"], "offset": i["offset"]}): i
             for i in canonical["instructions"]}
    records = sorted(gather(capture, {entry: (procedure["start_offset"], procedure["end_offset"])},
                            include_nested_returns=True)[entry],
                     key=lambda r: r["call"]["step_index"])
    require(len(records) == procedure["observed_paths"]["invocations_by_run"]["MINIMAL"],
            "Invocation count disagrees with catalog")
    local_counts = Counter(coord(w["origin"]) for r in records for w in r["own_witnesses"])
    require(all(local_counts[k] == facts[k]["execution_count"] for k in local_counts),
            "Local projection does not account for canonical coordinate counts")
    offsets = {w["origin"]["offset"] for r in records for w in r["own_witnesses"]}
    blocks, block_for = [], {}
    for source in canonical["blocks"]:
        selected = [o for o in source["instruction_offsets"] if o in offsets]
        if source["image"]["name"] != procedure["image"] or not selected:
            continue
        require(selected == source["instruction_offsets"], "Selected evidence cuts a source block")
        block = {"derived_id": f"B{len(blocks):03d}",
                 "stable_instruction_range": {"image": procedure["image"],
                     "image_sha256": procedure["image_sha256"],
                     "start_offset": source["start_offset"], "end_offset": source["end_offset"]},
                 "instructions": [f"{procedure['image']}+{o:04X}" for o in selected],
                 "observed": {"executions": [], "predecessors": [], "successors": [],
                              "reads": [], "writes": [], "branches": [], "calls": []},
                 "joined_roles": [], "joined_callee_contracts": [],
                 "deduced_mechanical_relations": [], "unresolved": []}
        blocks.append(block)
        for o in selected:
            require(o not in block_for, "Overlapping block presentation")
            block_for[o] = block
    require(set(block_for) == offsets, "Missing block presentation")

    instructions, steps, calls, branches, invocations = {}, {}, {}, {}, []
    callee_keys, gaps = set(), []
    memberships = defaultdict(list)
    edges = defaultdict(list)
    branch_samples = defaultdict(list)
    call_samples = defaultdict(list)
    local_writes_then_reads = []
    unresolved_reads = defaultdict(list)

    def add_instruction(w):
        key = coord(w["origin"])
        require(key is not None, "Packet boundary has unresolved historical origin")
        name, offset = w["origin"]["image"]["name"], w["origin"]["offset"]
        image = images[name]
        raw = bytes.fromhex(w["bytes"])
        require(originals[name][offset:offset + len(raw)] == raw
                and image["runtime_base"] + offset == w["pc"],
                f"Instruction bytes/runtime mismatch: {key}")
        fact = facts[key]
        require(fact["bytes"] == w["bytes"] and fact["decoded"] == w["disassembly"],
                f"Canonical instruction mismatch: {key}")
        instructions[key] = {"coordinate": stable(w["origin"], images),
                             "runtime_pc": w["pc"], "bytes": w["bytes"],
                             "decoded": fact["decoded"],
                             "annotation_status": status_at(image, offset),
                             "source_execution_count": fact["execution_count"],
                             "local_execution_count": local_counts[key],
                             "source_first_step": fact["first_step"],
                             "source_last_step": fact["last_step"]}
        return key

    def add_step(w, invocation, frame, scope):
        n = w["step_index"]
        key = add_instruction(w)
        destination = coord(w.get("target_origin"))
        if destination is not None:
            target = w["target_origin"]
            image = images[target["image"]["name"]]
            require(0 <= target["offset"] < image["length"]
                    and image["runtime_base"] + target["offset"] == w["control"]["target"],
                    "Transfer target identity/runtime mismatch")
            if destination in facts:
                fact = facts[destination]
                add_instruction(dict(w, origin=target, pc=w["control"]["target"],
                                     bytes=fact["bytes"], disassembly=fact["decoded"]))
        # A recursive child's RET may first appear as its parent's boundary.
        # Its local ownership/frame annotation wins when that child is projected.
        if str(n) not in steps or (scope == "local" and steps[str(n)]["scope"] != "local"):
            steps[str(n)] = {"coordinate": key, "invocation": invocation, "scope": scope,
                             "before": w["before"], "after": w["after"],
                             "control": w["control"], "pc_after": w["pc_after"],
                             "target": stable(w.get("target_origin"), images),
                             "target_coordinate_kind": "observed-instruction" if destination in facts
                                 else "unobserved-transfer-coordinate" if destination else None,
                             "reads": access_rows(w["reads"], frame, frame_bytes, selected_roles)
                                 if scope == "local" else [dict(q, width=1) for q in w["reads"]],
                             "writes": access_rows(w["writes"], frame, frame_bytes, selected_roles)
                                 if scope == "local" else [dict(q, width=1) for q in w["writes"]]}
            mnemonic = w["disassembly"].split()[0]
            steps[str(n)]["deduced_word_accesses"] = [
                {"access_kind": kind, "width": 2, "byte_accesses": [0, 1],
                 "evidence": "DEDUCED", "basis": f"8080 {mnemonic}; byte order retained in accesses"}
                for kind in ("reads", "writes") if len(w[kind]) == 2
                and mnemonic in ("LHLD", "SHLD", "PUSH", "POP", "CALL", "RET", "XTHL")]
        return n

    for r in records:
        if entry == TARGET and frame_bytes == 18:
            validate_pass_3(r)  # Reuse the existing frame/projection proof unchanged.
        ws, call, ret = r["own_witnesses"], r["call"], r["ret"]
        n = call["step_index"]
        verify_return(call, ret, r["relation"])
        require(all(w["origin"]["image"]["name"] == procedure["image"]
                    and procedure["start_offset"] <= w["origin"]["offset"] < procedure["end_offset"]
                    for w in ws), "Local projection escapes the accumulated extent")
        frame = (r["entry"]["before"]["sp"] - frame_bytes) & 65535
        require(any(w["sp_after"] == frame for w in ws)
                and ret["sp_before"] == r["entry"]["sp_before"],
                "Frame base is inconsistent with observed SP")
        slots = first_written_slots(ws, frame, frame_bytes)
        signature = path_signature(r, frame_bytes, class_slots)
        memberships[signature].append(n)
        add_step(call, n, frame, "caller-boundary")
        visits, local_steps, nested_steps = [], [], []
        segment = None
        writers = {}  # Retain only explicitly supported caller storage across calls.
        writer_calls = {}
        prior = None
        for w in ws:
            step = add_step(w, n, frame, "local")
            local_steps.append(step)
            block = block_for[w["origin"]["offset"]]
            if segment is None or segment["block"] != block["derived_id"]:
                segment = {"block": block["derived_id"], "invocation": n,
                           "entry_step": step, "exit_step": step, "steps": []}
                visits.append(segment)
                block["observed"]["executions"].append(segment)
            segment["exit_step"] = step
            segment["steps"].append(step)
            for kind in ("reads", "writes"):
                if w[kind]:
                    block["observed"][kind].append(step)
            for i, q in enumerate(w["reads"]):
                if q["address"] in writers:
                    producer, value = writers[q["address"]]
                    require(value == q["value"], "Local last-write/read mismatch")
                    relation = {"kind": "local-write-then-read", "invocation": n,
                                "address": q["address"], "value": value,
                                "writer_step": producer, "reader_step": step, "reader_access": i,
                                "preserved_across_calls": writer_calls.get(q["address"], [])}
                    local_writes_then_reads.append(relation)
                    block["deduced_mechanical_relations"].append(len(local_writes_then_reads) - 1)
                else:
                    unresolved_reads[coord(w["origin"])].append({"step": step, "access": i})
            for q in w["writes"]:
                writers[q["address"]] = (step, q["new_value"])
                writer_calls[q["address"]] = []
            control = w["control"]
            if control["kind"] in ("jump", "return", "call") and "taken" in control:
                branch_samples[coord(w["origin"])].append({
                    "invocation": n, "step": step, "taken": control["taken"],
                    "predicate_state_step": step,
                    "immediate_predecessor_step": prior,
                    "predicate_producer": immediate_predicate_producer(coord(w["origin"]), prior, instructions, steps),
                    "predicate_producer_evidence": "DEDUCED from immediate 8080 instruction flag effects"})
            if control["kind"] == "call" and control.get("taken", True):
                nested = r["nested_returns"][step]
                verify_return(w, nested["ret"], nested["relation"])
                target = coord(w.get("target_origin"))
                require(target in facts, "Callee target lacks an observed stable coordinate")
                return_step = add_step(nested["ret"], n, frame, "callee-return-boundary")
                callee_roles = [role for role in all_roles
                                if target in catalog and role["id"] in catalog[target]["data_role_ids"]]
                effects = [{"step": q["step_index"], "coordinate": add_instruction(q),
                            "reads": [dict(a, width=1, joined_roles=role_matches(a["address"], callee_roles)) for a in q["reads"]],
                            "writes": [dict(a, width=1, joined_roles=role_matches(a["address"], callee_roles)) for a in q["writes"]]}
                           for q in nested["memory_witnesses"]]
                if target in catalog:
                    callee_keys.add(target)
                calls[str(step)] = {"invocation": n, "callsite": coord(w["origin"]),
                                    "target": target, "pre_call_state_step": step,
                                    "post_return_state_step": return_step,
                                    "hardware_return_proof": nested["relation"],
                                    "contract_ref": f"research/annotated-assembly/procedures.json#id={target}" if target in catalog else None,
                                    "callee_completeness": catalog[target]["completeness"] if target in catalog else None,
                                    "contract_presentation": call_contract(catalog.get(target), entry, target, nested["memory_witnesses"], catalog),
                                    "unresolved_opaque": target not in catalog or catalog[target]["completeness"]["contract"] != "complete",
                                    "recursive_child_invocation": step if target == entry else None,
                                    "callee_memory_effects": {"scope": "callee subtree, including descendants; separate from parent-local blocks",
                                                             "guest_instruction_accesses": effects,
                                                             "host_effects": "not joined in V0"}}
                nested_steps.append(step)
                block["observed"]["calls"].append(step)
                call_samples[(coord(w["origin"]), target)].append(step)
                writers = {a: v for a, v in writers.items()
                           if preserved_address(calls[str(step)], a, frame, frame_bytes, steps)}
                writer_calls = {a: writer_calls.get(a, []) + [step] for a in writers}
                prior = return_step
            else:
                prior = step
            if control["kind"] != "sequential":
                segment = None
        for left, right in zip(visits, visits[1:]):
            last = next(w for w in ws if w["step_index"] == left["exit_step"])
            edges[(left["block"], right["block"], edge_kind(last))].append({
                "invocation": n, "source_step": left["exit_step"], "target_step": right["entry_step"]})
        invocations.append({"call_step": n, "caller": coord(call["origin"]),
                            "entry_step": ws[0]["step_index"], "return_step": ret["step_index"],
                            "entry_sp": r["entry"]["before"]["sp"], "F": frame,
                            "frame_relation": {"evidence": "DEDUCED", "bytes": frame_bytes,
                                               "source": "existing +24BC frame contract" if entry == TARGET else "explicit --frame-bytes hypothesis"},
                            "hardware_return_proof": r["relation"],
                            "first_written_local_bytes": slots, "local_steps": local_steps,
                            "block_visits": [{k: v for k, v in s.items() if k != "steps"} for s in visits],
                            "nested_calls": nested_steps})

    classes = []
    for i, (signature, members) in enumerate(sorted(memberships.items())):
        mode, slot_values, transfers = signature
        cls = {"derived_id": f"C{i:02d}", "count": len(members),
               "distinguishing_observed_conditions": {"entry_C": mode,
                   "first_written_local_bytes": [{"F_offset": o, "value": v} for o, v in slot_values],
                   "ordered_transfers": [{"coordinate": c, "kind": k, "taken": t, "target": d}
                                         for c, k, t, d in transfers]},
               "representative_invocations": members[:2], "invocations": members,
               "data_flow": "Every member retains its own inputs, outputs, block states, memory effects and nested calls in invocations/steps/calls; class membership asserts the same observed path, not value equivalence."}
        classes.append(cls)
        for invocation in invocations:
            if invocation["call_step"] in members:
                invocation["class"] = cls["derived_id"]
    class_for = {r["call_step"]: r["class"] for r in invocations}
    by_id = {b["derived_id"]: b for b in blocks}
    for (source, target, kind), samples in sorted(edges.items()):
        row = {"source": source, "target": target, "kind": kind, "count": len(samples),
               "first_step": min(s["source_step"] for s in samples),
               "last_step": max(s["source_step"] for s in samples),
               "observations": samples}
        by_id[source]["observed"]["successors"].append(row)
        by_id[target]["observed"]["predecessors"].append(row)
    for key, samples in sorted(branch_samples.items()):
        branches[key] = {"coordinate": instructions[key]["coordinate"],
                         "outcomes": [{"taken": outcome, "count": sum(s["taken"] == outcome for s in samples),
                                       "classes": dict(sorted(Counter(class_for[s["invocation"]] for s in samples
                                                                       if s["taken"] == outcome).items()))}
                                      for outcome in (False, True)],
                         "observations": samples}
        offset = instructions[key]["coordinate"]["offset"]
        block_for[offset]["observed"]["branches"].append(key)
        mnemonic = instructions[key]["decoded"].split()[0]
        conditional = mnemonic not in ("JMP", "RET", "CALL")
        if conditional and len({s["taken"] for s in samples}) == 1:
            gaps.append(f"{key} ({mnemonic}) has only {'taken' if samples[0]['taken'] else 'fallthrough'} observations.")
        if any(s["predicate_producer"] is None for s in samples) and conditional:
            block_for[offset]["unresolved"].append(f"{key}: no immediate predicate producer; see per-occurrence local_dependencies for the bounded chain or explicit stop.")
    callsites = []
    for (site, target), samples in sorted(call_samples.items()):
        row = {"callsite": site, "target": target, "invocation_count": len(samples),
               "representative_call_steps": samples[:2], "call_steps": samples,
               "contract_ref": calls[str(samples[0])]["contract_ref"],
               "callee_completeness": calls[str(samples[0])]["callee_completeness"],
               "unresolved_opaque": calls[str(samples[0])]["unresolved_opaque"]}
        callsites.append(row)
        block = block_for[instructions[site]["coordinate"]["offset"]]
        block["joined_callee_contracts"].append(row)
        if row["unresolved_opaque"]:
            block["unresolved"].append(f"{target}: {'no catalog contract' if row['contract_ref'] is None else 'catalog contract is partial'}.")
    for target in sorted({c["target"] for c in calls.values() if c["unresolved_opaque"]}):
        gaps.append(f"Helper {target} has {'no catalog contract' if target not in catalog else 'a partial catalog contract'}.")
    for block in blocks:
        observed = block["observed"]
        observed["execution_count"] = len(observed["executions"])
        observed["instruction_occurrences"] = sum(len(s["steps"]) for s in observed["executions"])
        observed["invocation_classes"] = dict(sorted(Counter(class_for[s["invocation"]]
                                                               for s in observed["executions"]).items()))
        observed["entry_states"] = [s["entry_step"] for s in observed["executions"]]
        observed["exit_states"] = [s["exit_step"] for s in observed["executions"]]
        observed["entry_call_steps"] = [r["call_step"] for r in invocations
                                         if r["entry_step"] in observed["entry_states"]]
        observed["return_steps"] = [r["return_step"] for r in invocations
                                     if r["return_step"] in observed["exit_states"]]
        joined = defaultdict(set)
        for kind in ("reads", "writes"):
            for step in observed[kind]:
                for q in steps[str(step)][kind]:
                    for role in q["joined_roles"]:
                        joined[(role["role_id"], q["address"])].add(step)
        block["joined_roles"] = [{"role_id": role, "address": address,
                                  "raw_address_retained": True, "access_steps": sorted(refs)}
                                 for (role, address), refs in sorted(joined.items())]
    unobserved = set(range(procedure["start_offset"], procedure["end_offset"]))
    for key in local_counts:
        i = instructions[key]
        o = i["coordinate"]["offset"]
        unobserved.difference_update(range(o, o + len(bytes.fromhex(i["bytes"]))))
    gaps.extend(["No full memory snapshot at entry: bytes without an observed access remain unavailable.",
                 "Callee subtree guest accesses are separate from local footprints; host-side effects are not joined in V0.",
                 "General provenance is not joined; local links cross calls only under explicit supported preservation clauses.",
                 "Overwritten memory values are null in source witnesses.",
                 "Unobserved paths have no concrete states or outcome counts; accumulated unresolved paths remain in the catalog entry."])
    gaps.append(f"{sum(len(v) for v in unresolved_reads.values())} parent-local read accesses have no joined earlier local writer under supported call preservation; producer identity outside that projection is unresolved.")
    sources = [Path(__file__), Path(__file__).with_name("evidence_packet_local.py")]
    sources += [annotation / n for n in ("manifest.json", "procedures.json", "data-roles.json")]
    sources += [capture / n for n in ("event-witnesses.json", "canonical-code-blocks.json", "dynamic-blocks.json", "run-summary.json")]
    sources += [capture / "event-witnesses/chunks" / f"{c['id']:06d}.json" for c in index["chunks"]]
    packet = {"experiment": "PROCEDURE_EVIDENCE_PACKET_V0_1", "baseline_commit": "b8c6b47",
              "run_id": index["run_id"], "entry": entry,
              "identity_rule": "Instruction keys abbreviate exact image SHA-256 + file offset resolved in instructions. Derived block/class IDs are packet-local presentation only.",
              "reference_guide": "steps is keyed by chronological step. State references use before for entries/pre-call/predicates and after for exits/post-return. A CALL block exits before callee execution; its joined call provides the post-return state. Reads/writes are ordered byte accesses; raw numeric addresses and values are always retained. Calls and invocations are keyed/referenced by CALL step. Unobserved transfer coordinates assert no decoded instruction entry.",
              "class_rule": "entry C + selected first-written frame bytes + complete ordered local transfers. No semantic labels or independent value sets. All member executions remain distinct.",
              "sources": [{"path": str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p),
                           "sha256": digest(p)} for p in sources],
              "accumulated_knowledge": {"evidence": "ACCUMULATED KNOWLEDGE",
                  "source": "research/annotated-assembly/procedures.json", "procedure": procedure,
                  "callees": {k: catalog[k] for k in sorted(callee_keys) if k != entry},
                  "roles": [role for role in all_roles
                            if role["id"] in {rid for k in callee_keys | {entry}
                                             for rid in catalog[k]["data_role_ids"]}]},
              "instructions": dict(sorted(instructions.items())), "blocks": blocks,
              "invocation_classes": classes, "invocations": invocations,
              "steps": dict(sorted(steps.items(), key=lambda pair: int(pair[0]))),
              "branches": branches, "calls": calls, "callsites": callsites,
              "deduced": {"local_write_read_relations": local_writes_then_reads},
              "provenance": "not joined in V0",
              "evidence_gaps": {"facts": gaps, "unobserved_extent_byte_ranges": ranges(unobserved),
                  "reads_without_joined_local_writer": dict(sorted(unresolved_reads.items())),
                  "read_gap_scope": "No surviving supported parent-local writer; unspecified call state is unresolved. No assertion about producers outside this projection."},
              "quality_checks": {"invocations": len(records), "local_instruction_occurrences": sum(local_counts.values()),
                  "local_instruction_coordinates": len(local_counts), "derived_blocks": len(blocks),
                  "invocation_path_classes": len(classes), "recursive_children": sum(c["target"] == entry for c in calls.values())}}
    derive_local(packet)
    navigation_effects(packet)
    validate_packet(packet, canonical, load(capture / "dynamic-blocks.json"), records, catalog)
    return packet


def validate_packet(packet, canonical, dynamic, records, catalog):
    """Independent source counters plus structural checks; fail closed on gaps."""
    facts = {coord({"image": i["image"], "offset": i["offset"]}): i
             for i in canonical["instructions"]}
    identities = {p["image"]: p["image_sha256"] for p in catalog.values()}
    for key, i in packet["instructions"].items():
        source = facts[key]
        require(i["bytes"] == source["bytes"] and i["decoded"] == source["decoded"]
                and i["coordinate"]["offset"] == source["offset"]
                and i["coordinate"]["image"] == source["image"]["name"]
                and i["coordinate"]["image_sha256"] == identities[source["image"]["name"]]
                and i["source_execution_count"] == source["execution_count"],
                "Instruction coordinate/bytes/count mismatch")
    require(sum(c["count"] for c in packet["invocation_classes"]) == len(records), "Class counts mismatch")
    ids = [n for c in packet["invocation_classes"] for n in c["invocations"]]
    require(len(ids) == len(set(ids)) == len(records), "Class partition mismatch")
    own = [w["step_index"] for r in records for w in r["own_witnesses"]]
    require(len(own) == len(set(own)), "Recursive child included in parent-local projection")
    require(Counter(own) == Counter(n for r in packet["invocations"] for n in r["local_steps"]), "Local step counts mismatch")
    require(Counter(own) == Counter(n for b in packet["blocks"] for s in b["observed"]["executions"] for n in s["steps"]), "Block counts mismatch")
    projected = {r["call_step"]: r for r in packet["invocations"]}
    for r in records:
        invocation = projected[r["call"]["step_index"]]
        boundary_witnesses = [r["call"]] + [n["ret"] for n in r["nested_returns"].values()]
        for w in boundary_witnesses:
            s = packet["steps"][str(w["step_index"])]
            require(s["before"] == w["before"] and s["after"] == w["after"], "Call boundary state mismatch")
        for call_step, nested in r["nested_returns"].items():
            call = packet["calls"][str(call_step)]
            require(call["pre_call_state_step"] == call_step
                    and call["post_return_state_step"] == nested["ret"]["step_index"]
                    and call["hardware_return_proof"] == nested["relation"], "Call return join mismatch")
            effects = call["callee_memory_effects"]["guest_instruction_accesses"]
            require(len(effects) == len(nested["memory_witnesses"]), "Callee memory count mismatch")
            for e, w in zip(effects, nested["memory_witnesses"]):
                require(e["step"] == w["step_index"] and e["coordinate"] == coord(w["origin"])
                        and all(len(e[kind]) == len(w[kind])
                                and all(all(q[k] == a[k] for k in a) for q, a in zip(e[kind], w[kind]))
                                for kind in ("reads", "writes")), "Callee memory join mismatch")
        require(invocation["entry_sp"] == r["entry"]["before"]["sp"]
                and invocation["F"] == (invocation["entry_sp"] - invocation["frame_relation"]["bytes"]) & 65535,
                "Invocation frame mismatch")
        for w in r["own_witnesses"]:
            s = packet["steps"][str(w["step_index"])]
            require(s["scope"] == "local" and s["invocation"] == r["call"]["step_index"]
                    and s["before"] == w["before"] and s["after"] == w["after"],
                    "Local ownership/state mismatch")
            for kind in ("reads", "writes"):
                require(len(s[kind]) == len(w[kind])
                        and all(all(q[k] == a[k] for k in a) for q, a in zip(s[kind], w[kind])),
                        "Memory observation mismatch")
                for q in s[kind]:
                    relation = q.get("deduced_frame_relation")
                    require(relation is None or relation["F"] == invocation["F"], "Frame relation ownership mismatch")
    source_branches = Counter((coord(w["origin"]), w["control"]["taken"]) for r in records
                              for w in r["own_witnesses"] if w["control"]["kind"] in ("jump", "return", "call")
                              and "taken" in w["control"])
    joined_branches = Counter({(k, o["taken"]): o["count"] for k, b in packet["branches"].items() for o in b["outcomes"] if o["count"]})
    require(source_branches == joined_branches, "Branch outcome mismatch")
    observed_ids = {i["id"]: i for i in dynamic["instructions"]}
    dynamic_calls = Counter()
    for edge in dynamic["instruction_transitions"]:
        if edge["kind"] != "call":
            continue
        a, b = (observed_ids[edge[k]]["origin"] for k in ("from", "to"))
        if a["kind"] == b["kind"] == "image":
            site, target = f"{a['image']}+{a['offset']:04X}", f"{b['image']}+{b['offset']:04X}"
            if site in packet["instructions"] and packet["instructions"][site]["local_execution_count"]:
                dynamic_calls[(site, target)] += edge["count"]
    require(dynamic_calls == Counter({(c["callsite"], c["target"]): c["invocation_count"] for c in packet["callsites"]}), "Dynamic CALL inventory mismatch")
    callers = Counter(r["caller"] for r in packet["invocations"])
    require(callers == Counter({c["coordinate"]: c["counts_by_run"]["MINIMAL"] for c in catalog[packet["entry"]]["callers"]}), "Caller counts mismatch")
    for c in packet["calls"].values():
        require(c["contract_ref"] is None or c["target"] in catalog, "Contract does not cite an existing procedure")
        if c["recursive_child_invocation"] is not None:
            require(c["recursive_child_invocation"] in ids, "Missing separate recursive child")
    effects = [e for c in packet["calls"].values() for e in c["callee_memory_effects"]["guest_instruction_accesses"]]
    known_roles = {r["id"]: r for r in packet["accumulated_knowledge"]["roles"]}
    for w in list(packet["steps"].values()) + effects:
        for q in w["reads"] + w["writes"]:
            for role in q.get("joined_roles", []):
                require(role["address"] == q["address"] and role["raw_address_retained"], "Role erased raw address")
                require(role["role_id"] in known_roles
                        and role in role_matches(q["address"], [known_roles[role["role_id"]]]),
                        "Role join does not match existing scoped role")
            rel = q.get("deduced_frame_relation")
            if rel:
                require((rel["F"] + rel["offset"]) & 65535 == q["address"], "Frame offset mismatch")

    validate_local(packet)


def render(packet):
    checks = packet["quality_checks"]
    p = packet["accumulated_knowledge"]["procedure"]
    lines = [f"# Procedure evidence packet V0.1: {packet['entry']}", "",
             f"Run: `{packet['run_id']}`. Infrastructure baseline: `{packet['baseline_commit']}`.", "",
             f"OBSERVED: {checks['invocations']} invocations; {checks['recursive_children']} recursive children; "
             f"{checks['local_instruction_occurrences']} local instructions; {checks['derived_blocks']} blocks.", "",
             "## Procedure / frame", "",
             f"ACCUMULATED extent `[{p['start_offset']:04X},{p['end_offset']:04X})`; completeness `{p['completeness']}`.",
             f"Frame hypothesis: {packet['invocations'][0]['frame_relation'] if packet['invocations'] else 'no invocations'}.",
             "First-written local bytes are writes during the invocation, never an entry-memory snapshot.", "",
             "<details><summary>Unchanged accumulated contract / pseudocode</summary>", "", p['contract'], "", p['pseudocode'], "", "</details>", "",
             "## Invocation classes", "", "| Class | Members | Entry C | First-written discriminator bytes | Invocation references |",
             "|---|---:|---:|---|---|"]
    for c in packet['invocation_classes']:
        cond = c['distinguishing_observed_conditions']
        slots = ', '.join(f"F+{r['F_offset']}={r['value']:02X}" for r in cond['first_written_local_bytes'])
        lines.append(f"| {c['derived_id']} | {c['count']} | {cond['entry_C']} | {slots} | {c['representative_invocations']} |")
    lines += ["", "All member records and ordered paths remain in JSON. Class summaries reference individual invocations.", "",
              "## Predicate dependencies / branch polarity", "",
              "DEDUCED local conditions on recorded sources. Call outputs are boundary leaves; opaque algorithms remain unavailable. "
              "Partial substitution carries its exact scope; unspecified state stops the chain.", "",
              "| Branch / flag | Taken iff / unresolved | Transforms (representative occurrence) | Taken / fallthrough classes |", "|---|---|---|---|"]
    for key, branch in packet['branches'].items():
        if not branch['dependency_steps']:
            continue
        for group in branch['polarity_summaries']:
            outcomes = '; '.join(f"{'taken' if o['taken'] else 'fallthrough'} {o['count']} {o['classes']}" for o in group['outcomes'])
            pred = packet['local_dependencies']['branches'][group['dependency_steps'][0]]
            chain_nodes = dependency_chain(packet, pred)
            coordinates = dict.fromkeys(n['coordinate'] for n in chain_nodes
                                        if n['operation'] not in ('call-output', 'observed-read', 'constant', 'unresolved-input'))
            chain = ' → '.join(packet['instructions'][k]['decoded'] + '@' + k for k in coordinates)
            lines.append(f"| {key} / {pred['tested_flag']} | {group['condition'].replace('|', ' OR ')} | {chain} | {outcomes} |")
    lines += ["", "Exact instruction/step nodes and typed value/flag edges: `local_dependencies`. "
              "Each branch lists its per-occurrence dependency references; counts never substitute for member states.", "",
              "## Callsite contracts / concrete effects", ""]
    for c in packet['callsites']:
        policy = c['contract_presentation']
        lines += [f"- **{c['callsite']} → {c['target']} ×{c['invocation_count']}: {policy['kind']}**. "
                  f"Algorithmic contract: {policy['algorithmic_contract']}. Scope: {policy['scope'] or 'unavailable'}. "
                  f"Scope statuses: {[(g['status'], len(g['call_steps'])) for g in c['scope_status_groups']]}. Calls `{c['representative_call_steps']}`."]
        for g in c['observed_effect_groups'] if policy['kind'] == 'MISSING / OPAQUE' else []:
            addresses = ','.join(f"{a:04X}" for a in g['write_addresses']) or 'none'
            lines.append(f"  - OBSERVED guest write addresses: {addresses}; caller-frame offsets written: "
                         f"{g['caller_frame_written_offsets']}; calls {g['call_steps'][:2]} ({len(g['call_steps'])} members). "
                         "Stack traffic/full footprints and watched roles without guest writes remain in JSON. These effects are not a general contract.")
    lines += ["", "## Correlated pointer / frame / publication navigation", "",
              "| Class | Correlated child/decrement patterns | Member summary references |", "|---|---|---|"]
    for c in packet['invocation_classes']:
        patterns = {}
        for key in c['operational_members']:
            summary = packet['operational_summaries'][key]
            signature = (tuple(x['mode_C'] for x in summary['recursive_calls']),
                         tuple(x['F_offset'] for x in summary['frame_decrements']))
            patterns.setdefault(signature, []).append(key)
        desc = '; '.join(f"children modes {list(modes)} ({len(modes)} calls), frame decrements {list(slots)}: "
                         f"{len(members)} members" for (modes, slots), members in patterns.items())
        lines.append(f"| {c['derived_id']} | {desc} | {c['operational_members'][:2]} |")
    lines += ["", "Representative correlated members (all other members remain linked above):", "",
              "| Invocation | Pointer-role chronology | Frame word writes | Local publication channels / addresses |", "|---|---|---|---|"]
    pointer_roles = [r['id'] for r in packet['accumulated_knowledge']['roles'] if r['name'].endswith('pointer') and r['width'] == 2]
    for c in packet['invocation_classes']:
        for key in c['operational_members'][:2]:
            summary = packet['operational_summaries'][key]
            pointers = []
            for role in pointer_roles:
                writes = [w for w in summary['role_word_writes'] if w['role'] == role]
                reads = [w for w in summary['role_word_reads'] if w['role'] == role]
                if writes:
                    values = ([reads[0]['value']] if reads and reads[0]['step'] < writes[0]['step'] else []) + [w['value'] for w in writes]
                    pointers.append(role.split(':')[-1] + ': ' + '→'.join(f'{v:04X}' for v in values))
            frames = '; '.join(f"F+{w['F_offset']}={w['value']:04X}@{w['coordinate']}" for w in summary['frame_word_writes'])
            publications = {}
            for e in summary['events']:
                if e['channel'] in ('role-write', 'indirect-write'):
                    publications.setdefault(e['channel'], set()).add(e['address'])
            pubs = '; '.join(channel + ': ' + ','.join(f'{a:04X}' for a in sorted(addresses)) for channel, addresses in publications.items())
            lines.append(f"| {key} ({c['derived_id']}) | {'; '.join(pointers)} | {frames} | {pubs} |")
    lines += ["", "`operational_summaries[invocation]` retains ordered role-word writes (including callee P updates), "
              "frame-byte/word writes, child calls/modes, decrement events, and publication addresses/sources. "
              "Role, indirect, frame and callee effects are distinct channels. F+3/F+5 word snapshots link to their own writes; "
              "decrement counts are separate from child counts. No tree ownership is inferred.", "",
              "## Evidence gaps", ""]
    lines += ['- ' + g for g in packet['evidence_gaps']['facts']]
    lines += ['- ' + g for g in p['unresolved_paths']]
    lines += ["", "STATIC / UNOBSERVED supplement deferred: RAW holes have no retained decoded instruction stream; "
              "V0.1 does not decode them or invent outcomes. Unobserved ranges: "
              f"`{packet['evidence_gaps']['unobserved_extent_byte_ranges']}`.", "", "## Blocks", ""]
    for b in packet['blocks']:
        extent, obs = b['stable_instruction_range'], b['observed']
        lines += [f"### {b['derived_id']} · {extent['image']}+{extent['start_offset']:04X}..+{extent['end_offset']:04X}", "",
                  f"OBSERVED {obs['execution_count']} executions; classes {obs['invocation_classes']}. "
                  f"State refs {obs['entry_states'][:2]} → {obs['exit_states'][:2]}; CALL post-return refs in calls.", "", "```text"]
        lines += [f"{key} {packet['instructions'][key]['bytes']:6s} {packet['instructions'][key]['decoded']}" for key in b['instructions']]
        lines += ['```', '']
    return '\n'.join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=ROOT / "_build/minimal-baseline/capture")
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "_build/evidence-packet")
    parser.add_argument("--entry", default=TARGET)
    parser.add_argument("--frame-bytes", type=int, default=18)
    parser.add_argument("--class-slots", type=int, nargs="*", default=[9, 10])
    args = parser.parse_args()
    require(0 <= args.frame_bytes < 32768 and all(0 <= n < args.frame_bytes for n in args.class_slots),
            "Invalid frame/class-slot configuration")
    packet = build(args.capture, args.images, args.entry, args.frame_bytes, tuple(args.class_slots))
    args.output.mkdir(parents=True, exist_ok=True)
    stem = args.entry.replace(".OVL", "").replace(".COM", "")
    (args.output / f"{stem}.json").write_text(json.dumps(packet, separators=(",", ":")) + "\n")
    (args.output / f"{stem}.md").write_text(render(packet))
    print(json.dumps(packet["quality_checks"], sort_keys=True))
