#!/usr/bin/env python3
"""Concrete contracts for the eight manually selected MINIMAL pass-4 entries."""

import argparse
import json
from collections import Counter
from pathlib import Path

from check_minimal_pass_2 import at, coord, pair, require, word
from check_minimal_pass_3 import gather as gather_frames
from check_minimal_pass_3 import stored

BOUNDS = {
    "PLI0.OVL+240B": (0x240B, 0x242B),
    "PLI0.OVL+23DF": (0x23DF, 0x240B),
    "PLI0.OVL+1A8C": (0x1A8C, 0x1AA6),
    "PLI1.OVL+7A4D": (0x7A4D, 0x7A63),
    "PLI.COM+0390": (0x390, 0x3E9),
    "PLI0.OVL+1A47": (0x1A47, 0x1A7D),
    "PLI0.OVL+1A14": (0x1A14, 0x1A47),
    "PLI0.OVL+4662": (0x4662, 0x466B),
}


def gather(capture):
    # Read two memory operands of the already established resident addition
    # contract, without adding a new hypothesis or promoting its callers.
    all_records = gather_frames(capture, {**BOUNDS, "PLI.COM+1A1C": (0x1A1C, 0x1A29)})
    dependencies = {r["call"]["step_index"]: r for key in ("PLI.COM+1A1C", "PLI0.OVL+4662")
                    for r in all_records[key]}
    for r in all_records["PLI0.OVL+1A14"]:
        addition = dependencies[at(local(r), 0x1A36)[0]["step_index"]]
        subtraction = dependencies[at(local(r), 0x1A3D)[0]["step_index"]]
        r["dependency_reads"] = {
            "working_base": [at(local(addition), o)[0] for o in (0x1A21, 0x1A25)],
            "record_top": [at(local(subtraction), o)[0] for o in (0x4663, 0x4667)],
        }
    return {key: all_records[key] for key in BOUNDS}


def local(r):
    return r["own_witnesses"]


def written_word(w):
    return w["writes"][0]["new_value"] + 256 * w["writes"][1]["new_value"]


def validate(r):
    key, ws = r["entry_key"], local(r)
    call, ret = r["call"], r["ret"]
    before, after = r["entry"]["before"], ret["after"]
    where = f"{key} CALL {call['step_index']}"
    require(ret["pc_after"] == call["call_return_address"]
            and ret["sp_before"] == call["sp_after"]
            and ret["sp_after"] == (call["sp_after"] + 2) & 65535
            and {q["address"]: q["value"] for q in ret["reads"]}
            == {q["address"]: q["new_value"] for q in call["writes"]}
            and r["relation"]["frame"]["call_step"] == call["step_index"],
            where + ": original hardware slot mismatch")
    a, b = BOUNDS[key]
    require(all(w["origin"] and coord(w["origin"]).split("+")[0] == key.split("+")[0]
                and a <= w["origin"]["offset"] < b for w in ws),
            where + ": own transfer leaves supported extent")
    if key == "PLI0.OVL+240B":
        requested = before["c"]
        field = at(ws, 0x2422)[0]["reads"][0]["value"] & 7
        result = field == requested
        require(stored(at(ws, 0x240E)[0]) == requested
                and at(ws, 0x2413)[0]["control"]["taken"],
                where + ": uninvestigated guard-true path")
        require(after["a"] == (255 if result else 0)
                and after["flags"]["carry"] == result
                and after["flags"]["zero"] == (not result)
                and pair(after, "b", "c") == 3
                and pair(after, "h", "l") == 0x6A96
                and pair(after, "d", "e") == 0x6A83,
                where + ": low-three-bit equality Boolean mismatch")
        require(at(ws, 0x2422)[0]["reads"][0]["address"] ==
                word(at(ws, 0x241C)[0]) + 3,
                where + ": wrong record field address")
    elif key == "PLI0.OVL+23DF":
        requested = before["c"]
        require(stored(at(ws, 0x23E2)[0]) == requested, where + ": saved scan mask")
        advances = at(ws, 0x23F5)
        for i, store in enumerate(advances):
            p = word(at(ws, 0x23EB)[i])
            length = at(ws, 0x23EE)[i]["reads"][0]
            next_p = (p + length["value"]) & 65535
            require(length["address"] == p and written_word(store) == next_p
                    and at(ws, 0x23FE)[i]["reads"][0]["address"] == (next_p + 1) & 65535,
                    where + ": length-based pointer advance mismatch")
        if ret["origin"]["offset"] == 0x2406:
            compare = at(ws, 0x2402)[-1]
            require(compare["before"]["a"] == requested == after["a"]
                    and after["flags"]["zero"] and not after["flags"]["carry"],
                    where + ": scan matched-tag exit mismatch")
        else:
            rotate = at(ws, 0x23E7)[-1]
            require(ret["origin"]["offset"] == 0x240A
                    and at(ws, 0x23E8)[-1]["control"]["taken"]
                    and after["a"] == ((rotate["before"]["a"] >> 1) |
                                          (128 if rotate["before"]["flags"]["carry"] else 0))
                    and not after["flags"]["carry"],
                    where + ": scan guard exit mismatch")
            require(all(after["flags"][f] == rotate["before"]["flags"][f]
                        for f in ("sign", "zero", "parity", "auxiliary_carry"))
                    and all(after[f] == rotate["before"][f] for f in ("b", "c", "d", "e", "h", "l")),
                    where + ": scan guard NZPA/register propagation")
        if len(advances) > 1:
            require(all(word(at(ws, 0x23EB)[i + 1]) == written_word(advances[i])
                        for i in range(len(advances) - 1)), where + ": scan cursor chain")
    elif key == "PLI0.OVL+1A47":
        index = at(ws, 0x1A47)[0]["reads"][0]["value"]
        low, high = at(ws, 0x1A51)[0]["reads"][0], at(ws, 0x1A53)[0]["reads"][0]
        target = low["value"] + 256 * high["value"]
        require(low["address"] == 0x6A0D + 2 * index and high["address"] == low["address"] + 1
                and written_word(at(ws, 0x1A55)[0]) == target,
                where + ": selected copy boundary mismatch")
        for i, copy in enumerate(at(ws, 0x1A71)):
            source = word(at(ws, 0x1A64)[i])
            destination = word(at(ws, 0x1A6C)[i])
            read_byte = at(ws, 0x1A70)[i]["reads"][0]
            require(source > target
                    and written_word(at(ws, 0x1A68)[i]) == source - 1
                    and read_byte["address"] == source - 1
                    and copy["writes"][0]["address"] == destination
                    and stored(copy) == read_byte["value"]
                    and written_word(at(ws, 0x1A76)[i]) == (destination - 1) & 65535,
                    where + ": descending byte copy/order mismatch")
            if i:
                require(source == written_word(at(ws, 0x1A68)[i - 1])
                        and destination == written_word(at(ws, 0x1A76)[i - 1]),
                        where + ": descending cursor chain mismatch")
        source = pair(after, "b", "c")
        result = (target - source) & 65535
        require(source <= target and pair(after, "h", "l") == result
                and after["a"] == result >> 8 and pair(after, "d", "e") == 0x6A57
                and not after["flags"]["carry"], where + ": copy loop terminal comparison")
    elif key == "PLI0.OVL+1A14":
        request = before["c"]
        previous = at(ws, 0x1A1D)[0]["reads"][0]["value"]
        count = previous + request
        require(count <= 255 and at(ws, 0x1A22)[0]["control"]["taken"]
                and stored(at(ws, 0x1A17)[0]) == request
                and stored(at(ws, 0x1A32)[0]) == count,
                where + ": extent byte-capacity contract")
        end = pair(at(ws, 0x1A39)[0]["before"], "h", "l")
        base_reads = [w["reads"][0] for w in r["dependency_reads"]["working_base"]]
        top_reads = [w["reads"][0] for w in r["dependency_reads"]["record_top"]]
        base = base_reads[0]["value"] + 256 * base_reads[1]["value"]
        top = top_reads[0]["value"] + 256 * top_reads[1]["value"]
        require([q["address"] for q in base_reads] == [0x69C5, 0x69C6]
                and [q["address"] for q in top_reads] == [0x1C36, 0x1C37]
                and end == (base + count) & 65535
                and end < top and pair(after, "h", "l") == (end - top) & 65535,
                where + ": extent address/difference formula mismatch")
        subtract = at(ws, 0x1A3D)[0]
        require(pair(subtract["before"], "d", "e") == end
                and pair(subtract["before"], "h", "l") == 0x1C36
                and at(ws, 0x1A40)[0]["control"]["taken"]
                and after["flags"]["carry"] and pair(after, "d", "e") == 0x1C37
                and pair(after, "b", "c") == pair(before, "b", "c"),
                where + ": extent top-guard/preserved BC contract")
    elif key == "PLI0.OVL+1A8C":
        cursor = word(at(ws, 0x1A93)[0])
        require(stored(at(ws, 0x1A8F)[0]) == before["c"]
                and written_word(at(ws, 0x1A96)[0]) == cursor
                and stored(at(ws, 0x1A9C)[0]) == 0
                and at(ws, 0x1AA2)[0]["before"]["c"] == before["c"],
                where + ": working-window initialization contract")
        # Entry at RET is the concrete state immediately after the nested +1A14.
        require(all(after[f] == at(ws, 0x1AA5)[0]["before"][f]
                    for f in ("a", "b", "c", "d", "e", "h", "l", "flags")),
                where + ": reserve helper results not propagated")
    elif key == "PLI0.OVL+4662":
        low = at(ws, 0x4663)[0]["reads"][0]
        high = at(ws, 0x4667)[0]["reads"][0]
        pointer, value = pair(before, "h", "l"), pair(before, "d", "e")
        subtractand = low["value"] + 256 * high["value"]
        result = (value - subtractand) & 65535
        require(low["address"] == pointer and high["address"] == (pointer + 1) & 65535
                and pair(after, "h", "l") == result and after["a"] == result >> 8
                and pair(after, "d", "e") == (pointer + 1) & 65535
                and pair(after, "b", "c") == pair(before, "b", "c")
                and after["flags"]["carry"] == (value < subtractand),
                where + ": DE-minus-indirect-word contract")
    elif key == "PLI1.OVL+7A4D":
        mapped = at(ws, 0x7A5A)[0]["reads"][0]
        output = at(ws, 0x7A61)[0]["reads"][0]
        require(stored(at(ws, 0x7A50)[0]) == before["c"]
                and mapped["address"] == 0xAA1F + before["c"]
                and output["address"] == 0xAAB4 + mapped["value"]
                and after["a"] == output["value"] and pair(after, "b", "c") == mapped["value"]
                and pair(after, "h", "l") == output["address"]
                and pair(after, "d", "e") == pair(before, "d", "e")
                and not after["flags"]["carry"]
                and all(after["flags"][f] == before["flags"][f]
                        for f in ("sign", "zero", "parity", "auxiliary_carry")),
                where + ": PLI1 mapped-byte lookup/preserved flags")
    elif key == "PLI.COM+0390":
        require(stored(at(ws, 0x393)[0]) == before["c"]
                and at(ws, 0x394)[0]["reads"][0]["value"] & 1 == 0
                and at(ws, 0x3D0)[0]["reads"][0]["value"] & 1 == 0
                and at(ws, 0x3E5)[0]["before"]["c"] == before["c"],
                where + ": plain console routing/cache contract")
        require(all(after[f] == at(ws, 0x3E8)[0]["before"][f]
                    for f in ("a", "b", "c", "d", "e", "h", "l", "flags")),
                where + ": console-wrapper outputs not delegated")
    return ws


def summarize(records):
    result = {}
    for key, rs in records.items():
        examples, edges, calls, outcomes = {}, Counter(), Counter(), Counter()
        for r in rs:
            ws = validate(r)
            outcomes[(r["ret"]["after"]["a"], r["ret"]["after"]["flags"]["carry"])] += 1
            for w in ws:
                if w["control"]["kind"] == "call":
                    calls[coord(w["target_origin"])] += 1
                if w["control"]["kind"] != "sequential":
                    edges[(w["origin"]["offset"], w["pc_after"], w["control"].get("taken", True))] += 1
            signature = (r["ret"]["after"]["a"], r["ret"]["after"]["flags"]["carry"])
            if key == "PLI0.OVL+1A47":
                signature = (min(len(at(ws, 0x1A71)), 2),)
            elif key == "PLI0.OVL+240B":
                difference = (at(ws, 0x2422)[0]["reads"][0]["value"] & 7) - r["entry"]["before"]["c"]
                signature = ((difference > 0) - (difference < 0),)
            elif key == "PLI0.OVL+23DF":
                signature = (r["ret"]["origin"]["offset"],)
            elif key in ("PLI0.OVL+1A8C", "PLI0.OVL+1A14"):
                signature = (r["entry"]["before"]["c"],)
            elif key == "PLI1.OVL+7A4D":
                signature = (r["entry"]["before"]["c"] >= 254, r["ret"]["after"]["a"] == 10)
            if signature not in examples:
                sample = {k: v for k, v in r.items() if k != "own_witnesses"}
                projected = []
                for w in ws:
                    row = {k: v for k, v in w.items() if k not in ("before", "after", "source", "runtime_pc")}
                    row["before"] = {k: w["before"][k] for k in ("a", "b", "c", "d", "e", "h", "l")}
                    if w["control"]["kind"] != "sequential" or w["disassembly"].split()[0] in ("CMP", "CPI", "RAR", "SBB", "ADI"):
                        row["before"]["flags"] = w["before"]["flags"]
                    projected.append(row)
                sample["own_witnesses"] = projected
                examples[signature] = sample
        result[key] = {
            "invocations_checked": len(rs), "own_instruction_occurrences": sum(len(local(r)) for r in rs),
            "outcomes": [{"a": a, "carry": c, "count": n} for (a, c), n in sorted(outcomes.items())],
            "branches": [{"offset": o, "runtime_after": p, "taken": t, "count": n}
                         for (o, p, t), n in sorted(edges.items())],
            "nested_calls": dict(sorted(calls.items())), "representatives": list(examples.values()),
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(summarize(gather(args.capture)), indent=2) + "\n")
