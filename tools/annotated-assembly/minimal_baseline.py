#!/usr/bin/env python3
"""Ticket-specific MINIMAL factual inventory; no procedure inference from ownership."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path):
    text = Path(path).read_text()
    return json.loads(text[text.index("{") :])


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def coordinate(origin):
    if not origin:
        return None
    return f"{origin['image']['name']}+{origin['offset']:04X}"


def ranges(values):
    values = sorted(set(values))
    result = []
    for value in values:
        if result and value == result[-1][1]:
            result[-1][1] += 1
        else:
            result.append([value, value + 1])
    return result


def status_at(image, offset):
    return next(
        s["status"]
        for s in image["sections"]
        if s["start_offset"] <= offset < s["end_offset"]
    )


def analyze(capture, canonical_paths, manifest_path, images_dir, output):
    manifest = load(manifest_path)
    images = {i["name"]: i for i in manifest["images"]}
    originals = {n: (images_dir / n).read_bytes() for n in images}
    for n, i in images.items():
        assert hashlib.sha256(originals[n]).hexdigest() == i["sha256"]
    reports = {run: load(path) for run, path in canonical_paths.items()}
    new = load(capture / "canonical-code-blocks.json")
    assert new == reports["MINIMAL"], (
        "New capture differs from existing MINIMAL canonical evidence"
    )
    index = load(capture / "event-witnesses.json")
    source_summary = load(capture / "run-summary.json")
    facts = {
        (i["image"]["name"], i["offset"]): i for i in reports["MINIMAL"]["instructions"]
    }
    coverage = []
    instructions = []
    for name, image in images.items():
        observed = sorted(
            [i for i in facts.values() if i["image"]["name"] == name],
            key=lambda i: i["offset"],
        )
        fetched = set()
        for i in observed:
            raw = bytes.fromhex(i["bytes"])
            assert originals[name][i["offset"] : i["offset"] + len(raw)] == raw
            pcs = {pc for c in i["contexts"] for pc in c["runtime_pcs"]}
            assert pcs == {image["runtime_base"] + i["offset"]}
            fetched.update(range(i["offset"], i["offset"] + len(raw)))
            instructions.append(
                {
                    "image": name,
                    "image_sha256": image["sha256"],
                    "offset": i["offset"],
                    "runtime_pc": image["runtime_base"] + i["offset"],
                    "bytes": i["bytes"],
                    "decoded": i["decoded"],
                    "execution_count": i["execution_count"],
                    "first_step": i["first_step"],
                    "last_step": i["last_step"],
                }
            )
        counts = Counter(status_at(image, byte) for byte in fetched)
        coverage.append(
            {
                "image": name,
                "image_sha256": image["sha256"],
                "total_bytes": image["length"],
                "canonical_coordinates": len(observed),
                "executed_bytes": len(fetched),
                "executed_percent": round(100 * len(fetched) / image["length"], 4),
                "instruction_executions": sum(i["execution_count"] for i in observed),
                "executed_status_bytes": {
                    s: counts[s] for s in ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")
                },
                "executed_byte_ranges": ranges(fetched),
            }
        )
    entries = {}

    def entry_for(key, origin, pc):
        if key not in entries:
            image = images.get(origin["image"]["name"]) if origin else None
            entries[key] = {
                "entry": key,
                "image": image["name"] if image else None,
                "image_sha256": image["sha256"] if image else None,
                "offset": origin["offset"] if origin else None,
                "runtime_pc": pc,
                "invocations": 0,
                "callers": Counter(),
                "call_kinds": Counter(),
                "hardware_returns": Counter(),
                "software_returns_in_context": Counter(),
                "context_instructions": set(),
                "context_reads": Counter(),
                "context_writes": Counter(),
                "context_edges": Counter(),
                "downstream_calls": Counter(),
                "samples": [],
                "pending_count": 0,
                "first_call_step": None,
                "last_call_step": None,
            }
        return entries[key]

    active = {}
    pending = {}
    writers = {}
    transfers = Counter()
    ret_sites = Counter()
    software = []
    decoded_counts = Counter()
    exceptional = Counter()
    last = None
    context_key = None
    chunk_sources = []
    matched_samples = {}

    def context(sp):
        candidates = [
            call
            for call in active.values()
            if sp <= call["sp_after"]
            and writers.get(call["sp_after"]) == call["step_index"]
            and writers.get((call["sp_after"] + 1) & 65535) == call["step_index"]
        ]
        return min(candidates, key=lambda w: w["sp_after"]) if candidates else None

    for chunk in index["chunks"]:
        path = capture / "event-witnesses/chunks" / f"{chunk['id']:06d}.json"
        chunk_sources.append({"id": chunk["id"], "sha256": digest(path)})
        for event in load(path)["events"]:
            kind = event["type"]
            if kind == "instruction":
                w = event["witness"]
                last = w
                source = coordinate(w["origin"]) or f"UNKNOWN@{w['pc']:04X}"
                if w["origin"]:
                    decoded_counts[
                        (w["origin"]["image"]["name"], w["origin"]["offset"])
                    ] += 1
                else:
                    exceptional[(w["pc"], w["bytes"])] += 1
                call = context(w["sp_before"])
                context_key = call["_entry"] if call else None
                if context_key:
                    e = entries[context_key]
                    e["context_instructions"].add(source)
                    for r in w["reads"]:
                        e["context_reads"][r["address"]] += 1
                    for r in w["writes"]:
                        e["context_writes"][r["address"]] += 1
                flow = w["control"]
                taken = flow.get("taken", True)
                if flow["kind"] in ("call", "restart", "jump", "return") and taken:
                    target = (
                        coordinate(w.get("target_origin"))
                        or f"UNKNOWN@{w['pc_after']:04X}"
                    )
                    transfers[(flow["kind"], source, target, w["pc_after"])] += 1
                    if context_key:
                        e["context_edges"][(flow["kind"], source, target)] += 1
                    if flow["kind"] == "return":
                        ret_sites[source] += 1
                    if flow["kind"] in ("call", "restart"):
                        origin = w.get("target_origin")
                        e = entry_for(target, origin, w["pc_after"])
                        e["invocations"] += 1
                        e["callers"][source] += 1
                        e["call_kinds"][flow["kind"]] += 1
                        if e["first_call_step"] is None:
                            e["first_call_step"] = w["step_index"]
                        e["last_call_step"] = w["step_index"]
                        if context_key:
                            entries[context_key]["downstream_calls"][target] += 1
                        call = dict(w)
                        call["_entry"] = target
                        pending[w["step_index"]] = call
                        active[w["step_index"]] = call
                        if len(e["samples"]) < 3:
                            e["samples"].append(
                                {
                                    "call": w,
                                    "entry": None,
                                    "ret": None,
                                    "relation": None,
                                    "chunk_id": chunk["id"],
                                }
                            )
                # First executed instruction after CALL is an observed entry snapshot.
                if w["step_index"] - 1 in pending:
                    previous = pending[w["step_index"] - 1]
                    if previous["pc_after"] == w["pc"]:
                        for sample in entries[previous["_entry"]]["samples"]:
                            if sample["call"]["step_index"] == previous["step_index"]:
                                sample["entry"] = w
                for wr in w["writes"]:
                    writers[wr["address"]] = w["step_index"]
            elif kind == "hardware_frame_return":
                f = event["frame"]
                step = f["call_step"]
                call = pending.pop(step)
                assert last["step_index"] == event["step_index"]
                assert (
                    call["sp_after"] == last["sp_before"]
                    and last["pc_after"] == call["call_return_address"]
                )
                assert {r["address"]: r["value"] for r in last["reads"]} == {
                    r["address"]: r["new_value"] for r in call["writes"]
                }
                e = entries[call["_entry"]]
                site = coordinate(last["origin"]) or f"UNKNOWN@{last['pc']:04X}"
                e["hardware_returns"][site] += 1
                matched_samples.setdefault(
                    call["_entry"],
                    {
                        "call": {
                            k: v for k, v in call.items() if not k.startswith("_")
                        },
                        "ret": last,
                        "relation": event,
                    },
                )
                for sample in e["samples"]:
                    if sample["call"]["step_index"] == step:
                        sample["ret"] = last
                        sample["relation"] = event
                active.pop(step, None)
            elif kind == "software_continuation_return":
                software.append(event)
                if context_key:
                    entries[context_key]["software_returns_in_context"][
                        coordinate(event.get("consumer_origin"))
                        or f"UNKNOWN@{event['consumer_pc']:04X}"
                    ] += 1
            elif kind == "host_effect":
                detail = event.get("effect", event.get("detail", {}))
                # Host writes invalidate guest stack-byte history; decode serializer below.
                if "address" in detail:
                    writers.pop(detail["address"], None)
            elif kind == "bdos_record" and event["operation"] == "read_record":
                for address in range(
                    event["dma"], event["dma"] + len(bytes.fromhex(event["data"]))
                ):
                    writers.pop(address & 65535, None)
    assert sum(decoded_counts.values()) == sum(
        i["execution_count"] for i in facts.values()
    )
    assert all(decoded_counts[k] == i["execution_count"] for k, i in facts.items())
    for call in pending.values():
        entries[call["_entry"]]["pending_count"] += 1
    cross_calls = {}
    for run, path in canonical_paths.items():
        blocks = load(path.parent / "dynamic-blocks.json")
        observed = {i["id"]: i for i in blocks["instructions"]}
        targets = Counter()
        for edge in blocks["instruction_transitions"]:
            if edge["kind"] not in ("call", "restart"):
                continue
            instruction = observed[edge["to"]]
            origin = instruction["origin"]
            if origin["kind"] != "image":
                continue
            key = f"{origin['image']}+{origin['offset']:04X}"
            targets[key] += edge["count"]
        cross_calls[run] = targets
    assert cross_calls["MINIMAL"] == Counter(
        {key: entry["invocations"] for key, entry in entries.items()}
    ), "CALL transition inventory disagrees with witness targets"
    old_evidence = load(manifest_path.parent / manifest["evidence"])
    hypotheses = {s["id"]: s for s in old_evidence["seeds"]}
    by_image = defaultdict(set)
    for key, e in sorted(entries.items()):
        e["callers"] = dict(sorted(e["callers"].items()))
        e["call_kinds"] = dict(e["call_kinds"])
        e["hardware_returns"] = dict(sorted(e["hardware_returns"].items()))
        e["software_returns_in_context"] = dict(
            sorted(e["software_returns_in_context"].items())
        )
        e["context_instructions"] = sorted(e["context_instructions"])
        e["context_reads"] = {
            f"{a:04X}": c for a, c in sorted(e["context_reads"].items())
        }
        e["context_writes"] = {
            f"{a:04X}": c for a, c in sorted(e["context_writes"].items())
        }
        e["context_edges"] = [
            {"kind": k, "source": s, "target": t, "count": c}
            for (k, s, t), c in sorted(e["context_edges"].items())
        ]
        e["downstream_calls"] = dict(sorted(e["downstream_calls"].items()))
        e["status_at_entry"] = (
            status_at(images[e["image"]], e["offset"]) if e["image"] else None
        )
        seed = hypotheses.get(key)
        e["procedure_hypothesis"] = seed["description"] if seed else None
        e["classification"] = (
            "UNDERSTOOD"
            if seed
            and e["status_at_entry"] == "UNDERSTOOD"
            and seed.get("behavioral_contract")
            else "STRUCTURED"
            if seed
            and e["status_at_entry"] == "STRUCTURED"
            and seed["matched_return_sample"]
            else "unresolved"
        )
        e["cross_run_presence"] = {}
        for run, report in reports.items():
            seen = next(
                (
                    i
                    for i in report["instructions"]
                    if coordinate({"image": i["image"], "offset": i["offset"]}) == key
                ),
                None,
            )
            # Presence at entry is distinct from CALL-target presence; fills below from dynamic edges.
            e["cross_run_presence"][run] = {
                "entry_executed": seen is not None,
                "entry_execution_count": seen["execution_count"] if seen else 0,
                "observed_call_rst_count": cross_calls[run][key],
            }
        coords = [
            int(c.split("+")[1], 16)
            for c in e["context_instructions"]
            if c.startswith(f"{e['image']}+")
        ]
        e["observed_same_image_instruction_extent"] = (
            [min(coords), max(coords)] if coords else None
        )
        e["observed_same_image_instruction_offsets"] = coords
        if e["image"]:
            by_image[e["image"]].add(e["offset"])
    overlaps = []
    for name in images:
        relevant = [e for e in entries.values() if e["image"] == name]
        for n, a in enumerate(relevant):
            av = set(a["context_instructions"])
            for b in relevant[n + 1 :]:
                common = av & set(b["context_instructions"])
                common = {c for c in common if c.startswith(name + "+")}
                if common:
                    overlaps.append(
                        {
                            "a": a["entry"],
                            "b": b["entry"],
                            "shared_instruction_coordinates": sorted(common),
                        }
                    )
    new_coords = {
        (i["image"]["name"], i["offset"]) for i in reports["FIZZBUZ"]["instructions"]
    } - set(facts)
    delta = {name: sum(n == name for n, o in new_coords) for name in images}
    new_bytes = {name: set() for name in images}
    old_bytes = {name: set() for name in images}
    for i in reports["MINIMAL"]["instructions"]:
        old_bytes[i["image"]["name"]].update(
            range(i["offset"], i["offset"] + len(bytes.fromhex(i["bytes"])))
        )
    for i in reports["FIZZBUZ"]["instructions"]:
        new_bytes[i["image"]["name"]].update(
            range(i["offset"], i["offset"] + len(bytes.fromhex(i["bytes"])))
        )
    result = {
        "schema_version": 1,
        "run_id": index["run_id"],
        "source_summary": {
            k: v for k, v in source_summary.items() if not k.endswith("seconds")
        },
        "method": "Stable entries are taken CALL/RST targets, not RoutineCandidate IDs. Context coordinates use the nearest intact hardware frame at or above current SP; they are deduced execution contexts, NOT procedure ownership or contiguous procedure ranges. Host effects invalidate stack-byte writers.",
        "sources": [
            {"run": run, "path_at_capture": str(path), "sha256": digest(path)}
            for run, path in canonical_paths.items()
        ],
        "witness_index_sha256": digest(capture / "event-witnesses.json"),
        "witness_chunk_hashes": chunk_sources,
        "coverage": coverage,
        "instructions": instructions,
        "callable_entries": list(entries.values()),
        "overlapping_contexts": overlaps,
        "software_continuations": software,
        "ret_sites": dict(sorted(ret_sites.items())),
        "transfer_edges": [
            {"kind": k, "source": s, "target": t, "runtime_target": pc, "count": count}
            for (k, s, t, pc), count in sorted(transfers.items())
        ],
        "exceptional_executions": [
            {"runtime_pc": pc, "bytes": raw, "count": count}
            for (pc, raw), count in sorted(exceptional.items())
        ],
        "fizzbuz_minus_minimal": {
            "new_instruction_coordinates": len(new_coords),
            "coordinates_per_image": delta,
            "new_executed_bytes_per_image": {
                n: len(new_bytes[n] - old_bytes[n]) for n in images
            },
            "new_coordinates": [
                {"image": n, "offset": o} for n, o in sorted(new_coords)
            ],
            "new_callable_targets": [
                {"entry": key, "invocations": count}
                for key, count in sorted(
                    cross_calls["FIZZBUZ"].items(), key=lambda item: (-item[1], item[0])
                )
                if key not in cross_calls["MINIMAL"]
            ],
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "baseline.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "matched-samples.json").write_text(
        json.dumps(matched_samples, indent=2) + "\n"
    )
    print("coverage", coverage)
    print(
        "callable entries",
        len(entries),
        "software",
        len(software),
        "overlaps",
        len(overlaps),
        "delta",
        delta,
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--optimist", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("research/annotated-assembly/manifest.json"),
    )
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    paths = {
        run: args.corpus / run.lower() / "canonical-code-blocks.json"
        for run in ("MINIMAL", "FIZZBUZ", "FACTOR")
    }
    paths["OPTIMIST"] = args.optimist / "canonical-code-blocks.json"
    analyze(args.capture, paths, args.manifest, args.images, args.output)
