#!/usr/bin/env python3
"""Explicit checks for seven manually reviewed MINIMAL pass-3 hypotheses.

Uses corrected hardware-frame events, excluding nested invocations from each
local projection. This is a bounded evidence check, not procedure discovery.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

from check_minimal_pass_2 import at, coord, load, pair, require, word

BOUNDS = {
    "PLI.COM+0AF5": (0xAF5, 0xB2A),
    "PLI2.OVL+09BA": (0x9BA, 0xAFB),
    "PLI2.OVL+04BF": (0x4BF, 0x4D3),
    "PLI1.OVL+4281": (0x4281, 0x428E),
    "PLI0.OVL+24BC": (0x24BC, 0x289B),
    "PLI2.OVL+04D3": (0x4D3, 0x4E9),
    "PLI2.OVL+061B": (0x61B, 0x636),
}


def gather(capture, bounds=None, *, include_nested_returns=False):
    records = {key: [] for key in (BOUNDS if bounds is None else bounds)}
    active, returns, matched = {}, {}, {}
    last = None
    index = load(capture / "event-witnesses.json")
    for chunk in index["chunks"]:
        path = capture / "event-witnesses/chunks" / f"{chunk['id']:06d}.json"
        for event in load(path)["events"]:
            if event["type"] == "instruction":
                last = w = event["witness"]
                for r in active.values():
                    r["witnesses"].append(w)
                if w["control"]["kind"] == "call" and w["control"]["taken"]:
                    key = coord(w.get("target_origin"))
                    if key in records:
                        active[w["step_index"]] = {
                            "entry_key": key, "call": w, "witnesses": []
                        }
            elif event["type"] == "hardware_frame_return":
                step = event["frame"]["call_step"]
                require(last is not None and last["step_index"] == event["step_index"],
                        "Hardware return event lacks its instruction witness")
                returns[step] = last["step_index"]
                if include_nested_returns:
                    matched[step] = {"ret": last, "relation": event}
                if step in active:
                    r = active.pop(step)
                    r.update(entry=r["witnesses"][0], ret=last, relation=event)
                    records[r["entry_key"]].append(r)
    require(not active, "Selected CALL lacks a corrected matched return")
    for rs in records.values():
        for r in rs:
            own, skip = [], -1
            inclusive = r.pop("witnesses")
            for w in inclusive:
                if w["step_index"] <= skip:
                    continue
                own.append(w)
                if w["control"]["kind"] == "call" and w["control"]["taken"]:
                    require(w["step_index"] in returns,
                            "Nested call needs independent continuation reconstruction")
                    skip = returns[w["step_index"]]
            r["own_witnesses"] = own
            if include_nested_returns:
                r["nested_returns"] = {
                    w["step_index"]: dict(matched[w["step_index"]],
                        memory_witnesses=[q for q in inclusive
                            if w["step_index"] < q["step_index"] <= returns[w["step_index"]]
                            and (q["reads"] or q["writes"])])
                    for w in own
                    if w["control"]["kind"] == "call" and w["control"]["taken"]
                }
    return records


def local(r):
    return r["own_witnesses"]


def stored(w):
    return w["writes"][0]["new_value"]


def validate(r):
    key, ws = r["entry_key"], local(r)
    call, ret = r["call"], r["ret"]
    before, after = r["entry"]["before"], ret["after"]
    where = f"{key} CALL {call['step_index']}"
    require(
        ret["pc_after"] == call["call_return_address"]
        and ret["sp_before"] == call["sp_after"]
        and ret["sp_after"] == (call["sp_after"] + 2) & 65535
        and {q["address"]: q["value"] for q in ret["reads"]}
        == {q["address"]: q["new_value"] for q in call["writes"]}
        and r["relation"]["frame"]["call_step"] == call["step_index"],
        where + ": original hardware slot mismatch",
    )
    a, b = BOUNDS[key]
    require(all(w["origin"] and coord(w["origin"]).split("+")[0] == key.split("+")[0]
                and a <= w["origin"]["offset"] < b for w in ws),
            where + ": local transfer leaves supported extent")
    if key == "PLI.COM+0AF5":
        fetched = at(ws, 0xB00)[0]["before"]
        value = fetched["a"]
        require(at(ws, 0xAF5)[0]["reads"][0]["value"] == 0
                and not at(ws, 0xAFA)[0]["control"]["taken"],
                where + ": uninvestigated alternate source")
        require(stored(at(ws, 0xB00)[0]) == value == after["a"]
                and bool(at(ws, 0xB24)) == (value == 0x1A)
                and all(after[f] == fetched[f] for f in ("b", "c", "d", "e")),
                where + ": cached byte/EOF contract mismatch")
        require(after["flags"]["zero"] == (value == 0x1A)
                and after["flags"]["carry"] == (value < 0x1A),
                where + ": flags do not describe EOF comparison")
        writes = [(q["address"], q["new_value"]) for w in ws for q in w["writes"]
                  if w["control"]["kind"] != "call"]
        require(writes == [(0x209A, value)] + ([(0x2012, 1)] if value == 0x1A else []),
                where + ": EOF assignment/write footprint mismatch")
    elif key in ("PLI2.OVL+04BF", "PLI2.OVL+04D3", "PLI2.OVL+061B"):
        if key == "PLI2.OVL+04BF":
            classified = at(ws, 0x4CA)[0]["before"]["a"]
            output = at(ws, 0x4D1)[0]["reads"][0]
            require(stored(at(ws, 0x4C2)[0]) == before["c"]
                    and output["address"] == 0x2274 + classified
                    and output["value"] == after["a"]
                    and pair(after, "b", "c") == classified,
                    where + ": class-derived table lookup mismatch")
        elif key == "PLI2.OVL+04D3":
            mapped = at(ws, 0x4E0)[0]["reads"][0]
            output = at(ws, 0x4E7)[0]["reads"][0]
            require(stored(at(ws, 0x4D6)[0]) == before["c"]
                    and mapped["address"] == 0xAAB0 + before["c"]
                    and output["address"] == 0xA732 + mapped["value"]
                    and after["a"] == output["value"]
                    and pair(after, "b", "c") == mapped["value"],
                    where + ": mutable table read mismatch")
        else:
            mapped = at(ws, 0x62A)[0]["reads"][0]
            output = at(ws, 0x634)[0]["writes"][0]
            require(stored(at(ws, 0x61E)[0]) == before["e"]
                    and stored(at(ws, 0x620)[0]) == before["c"]
                    and mapped["address"] == 0xAAB0 + before["c"]
                    and output["address"] == 0xA732 + mapped["value"]
                    and output["new_value"] == after["a"] == before["e"]
                    and pair(after, "b", "c") == mapped["value"],
                    where + ": mutable table write mismatch")
        address = output["address"]
        require(pair(after, "h", "l") == address
                and pair(after, "d", "e") == pair(before, "d", "e")
                and not after["flags"]["carry"]
                and all(after["flags"][f] == before["flags"][f]
                        for f in ("sign", "zero", "parity", "auxiliary_carry")),
                where + ": table register/preserved flag mismatch")
    elif key == "PLI1.OVL+4281":
        pointer = at(ws, 0x4289)[0]["before"]
        value = pair(pointer, "h", "l")
        require(after["a"] == (255 if value else 0)
                and after["flags"]["carry"] == bool(value)
                and after["flags"]["zero"] == (value == 0)
                and pair(after, "h", "l") == value
                and pair(after, "d", "e") == 0xA864
                and pair(after, "b", "c") == pair(before, "b", "c"),
                where + ": pointer Boolean mismatch")
        require(not any(w["writes"] for w in ws if w["control"]["kind"] != "call"),
                where + ": pointer predicate unexpectedly stores data")
    elif key == "PLI2.OVL+09BA":
        require(all(w["reads"][0]["value"] == 0 for w in at(ws, 0xA37))
                and all(stored(w) == 0 for w in at(ws, 0x9E3)),
                where + ": uninvestigated mode/class path")
        current = stored(at(ws, 0x9C1)[0])
        require(stored(at(ws, 0x9C4)[0]) == current,
                where + ": initial span cursor mismatch")
        remaining, accum, child = None, None, None
        stop = None
        loops = 0
        for w in ws:
            offset = w["origin"]["offset"]
            if offset == 0xA57:
                remaining = stored(w)
            elif offset == 0xA5E:
                child = (current - 1) & 255
                require(stored(w) == child, where + ": initial child cursor")
            elif offset == 0xA68:
                accum = stored(w)
            elif offset == 0xA7B:
                stop = stored(w)
            elif offset == 0xABE:
                require(w["before"]["c"] == child, where + ": child read index")
            elif offset == 0xAC4:
                candidate = (w["before"]["a"] + remaining - 1) & 255
            elif offset == 0xAC6:
                require(stored(w) == candidate, where + ": modular candidate recurrence")
                accum = max(accum, candidate)
            elif offset == 0xADB:
                child = (stop - 1) & 255
                require(stored(w) == child, where + ": next span cursor")
            elif offset == 0xAE1:
                remaining -= 1
                loops += 1
                require(stored(w) == remaining, where + ": remaining weight decrement")
            elif offset == 0xAF0:
                require(remaining == 0 and w["before"]["c"] == current
                        and w["before"]["e"] == accum,
                        where + ": folded value/write index mismatch")
            elif offset == 0xAF6:
                current = (current + 1) & 255
                require(stored(w) == current, where + ": forward cursor increment")
        require(current == after["a"] == (at(ws, 0x9C7)[-1]["reads"][0]["value"] + 1) & 255
                and pair(after, "h", "l") == 0xAC4F
                and pair(after, "d", "e") == word(at(ws, 0xAEC)[-1])
                and after["flags"]["zero"] and not after["flags"]["carry"],
                where + ": span loop termination mismatch")
        require(loops == len(at(ws, 0xA78)), where + ": nested span count mismatch")
    elif key == "PLI0.OVL+24BC":
        frame = (before["sp"] - 18) & 65535
        require(at(ws, 0x24C3)[0]["sp_after"] == frame
                and at(ws, 0x24C2)[0]["writes"][0]["new_value"] == before["c"]
                and at(ws, 0x2899)[0]["sp_after"] == before["sp"],
                where + ": 18-byte local frame mismatch")
        require(word(at(ws, 0x24DF)[0]) ==
                at(ws, 0x24E7)[0]["writes"][0]["new_value"] +
                256 * at(ws, 0x24E9)[0]["writes"][0]["new_value"],
                where + ": saved pointer mismatch")
        tag = at(ws, 0x24F3)[0]["reads"][0]
        store = at(ws, 0x24F8)[0]["writes"][0]
        require(store["address"] == tag["address"]
                and store["new_value"] == tag["value"] & 127,
                where + ": tag bit7 clear mismatch")
        require(all(w["sp_before"] == (frame - (2 if w["origin"]["offset"] == 0x2790 else 0)) & 65535 for w in ws
                    if w["control"]["kind"] == "call"),
                where + ": local CALL stack base mismatch")
        require(len(at(ws, 0x24BC)) == 1 and len(at(ws, 0x289A)) == 1,
                where + ": recursive descendants included in local projection")
        result = at(ws, 0x285D)[0]["reads"][0]["value"] + 256 * at(ws, 0x285F)[0]["reads"][0]["value"]
        require(at(ws, 0x2861)[0]["writes"][0]["new_value"] == result & 255
                and at(ws, 0x2861)[0]["writes"][1]["new_value"] == result >> 8,
                where + ": output word publication mismatch")
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
            signature = (r["ret"]["after"]["a"] == 0x1A,) if key == "PLI.COM+0AF5" else (
                r["entry"]["before"]["c"],) if key == "PLI0.OVL+24BC" else (
                len(at(ws, 0xA78)),) if key == "PLI2.OVL+09BA" else (r["ret"]["after"]["a"],)
            if signature not in examples:
                # Keep full entry/exit/slot proofs; intermediate states retain
                # registers and flags at transfers/comparisons, not two full
                # machine snapshots per instruction. Chronology stays separate.
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
            "invocations_checked": len(rs),
            "own_instruction_occurrences": sum(len(local(r)) for r in rs),
            "outcomes": [{"a": a, "carry": c, "count": n} for (a, c), n in sorted(outcomes.items())],
            "branches": [{"offset": o, "runtime_after": p, "taken": t, "count": n}
                         for (o, p, t), n in sorted(edges.items())],
            "nested_calls": dict(sorted(calls.items())),
            "representatives": list(examples.values()),
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(summarize(gather(args.capture)), indent=2) + "\n")
