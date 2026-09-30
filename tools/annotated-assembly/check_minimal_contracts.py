#!/usr/bin/env python3
"""Validate this ticket's explicit low-level MINIMAL contracts against invocation witnesses.

These arithmetic/address predicates are independent of the CPU implementation.
No instruction decoding, automatic contract inference, or procedure ownership is
performed here. Gather only the explicitly selected CALL-to-hardware-RET windows.
"""

import argparse
import json
from collections import Counter
from pathlib import Path


def load(path):
    text = path.read_text()
    return json.loads(text[text.index("{") :])


entries = [
    "PLI.COM+02EE",
    "PLI.COM+0318",
    "PLI.COM+0380",
    "PLI.COM+1A0F",
    "PLI.COM+1A1C",
    "PLI.COM+1A1D",
    "PLI.COM+1A29",
    "PLI.COM+1A2C",
    "PLI.COM+1A33",
    "PLI.COM+1A35",
    "PLI.COM+1A38",
    "PLI.COM+1A40",
    "PLI.COM+1A43",
    "PLI0.OVL+210B",
    "PLI2.OVL+0F98",
    "PLI.COM+19BB",
]


def coord(o):
    return f"{o['image']['name']}+{o['offset']:04X}" if o else None


def gather_records(capture):
    records = {key: [] for key in entries}
    active = {}
    latest = None
    for p in sorted((capture / "event-witnesses/chunks").glob("*.json")):
        for event in load(p)["events"]:
            if event["type"] == "instruction":
                w = event["witness"]
                latest = w
                flow = w["control"]
                for record in active.values():
                    record["witnesses"].append(w)
                if flow["kind"] in ("call", "restart") and flow.get("taken", True):
                    key = coord(w.get("target_origin"))
                    if key in records:
                        active[w["step_index"]] = {
                            "call": w,
                            "entry_key": key,
                            "witnesses": [],
                        }
            elif event["type"] == "hardware_frame_return":
                step = event["frame"]["call_step"]
                if step in active:
                    rec = active.pop(step)
                    rec["relation"] = event
                    rec["entry"] = rec["witnesses"][0]
                    rec["ret"] = latest
                    records[rec["entry_key"]].append(rec)
    return records


def validate_records(records):
    checks = {}
    representatives = {}
    for key, recs in records.items():
        check = Counter()
        retpaths = {}
        for r in recs:
            call, ret = r["call"], r["ret"]
            if not (
                call["sp_after"] == ret["sp_before"]
                and ret["pc_after"] == call["call_return_address"]
                and {x["address"]: x["new_value"] for x in call["writes"]}
                == {x["address"]: x["value"] for x in ret["reads"]}
                and r["relation"]["frame"]["call_step"] == call["step_index"]
            ):
                raise ValueError(
                    f"{key}: invocation does not have a matching hardware return"
                )
            a = r["entry"]["before"]
            z = r["ret"]["after"]
            initialHL = a["h"] * 256 + a["l"]
            initialBC = a["b"] * 256 + a["c"]
            initialDE = a["d"] * 256 + a["e"]
            HL = z["h"] * 256 + z["l"]
            BC = z["b"] * 256 + z["c"]
            DE = z["d"] * 256 + z["e"]
            direct = [
                w
                for w in r["witnesses"]
                if coord(w["origin"])
                and w["origin"]["image"]["name"] == key.split("+")[0]
            ]
            reads = [
                (x["address"], x["value"])
                for w in direct
                for x in w["reads"]
                if w["control"]["kind"] != "return"
            ]
            writes = [
                (x["address"], x["new_value"]) for w in direct for x in w["writes"]
            ]
            mem = {p: v for p, v in reads}

            def word(p, memory=mem):
                return memory[p] + 256 * memory[(p + 1) & 65535]

            tag = key.split("+")[1]
            valid = True
            if key.startswith("PLI.COM+") and tag in [
                "1A1C",
                "1A1D",
                "1A29",
                "1A2C",
                "1A33",
                "1A35",
                "1A38",
                "1A40",
                "1A43",
            ]:
                if tag in ["1A1C", "1A1D"]:
                    p = initialDE if tag == "1A1C" else initialHL
                    result = word(p) + a["a"]
                    valid = (
                        HL == (result & 65535)
                        and DE == ((p + 1) & 65535)
                        and BC == initialBC
                        and z["flags"]["carry"] == (result > 65535)
                    )
                elif tag in ["1A29", "1A2C"]:
                    minuend = a["a"] if tag == "1A29" else initialDE
                    result = minuend - initialHL
                    valid = (
                        HL == (result & 65535)
                        and DE == minuend
                        and BC == initialBC
                        and z["flags"]["carry"] == (result < 0)
                    )
                elif tag in ["1A33", "1A35", "1A38"]:
                    sub = (
                        word(initialBC if tag == "1A33" else initialHL)
                        if tag != "1A38"
                        else initialBC
                    )
                    result = word(initialDE) - sub
                    valid = (
                        HL == (result & 65535)
                        and BC == sub
                        and DE == ((initialDE + 1) & 65535)
                        and z["flags"]["carry"] == (result < 0)
                    )
                else:
                    sub = a["a"] if tag == "1A40" else initialHL
                    result = word(initialDE) - sub
                    valid = (
                        HL == (result & 65535)
                        and BC == initialBC
                        and DE == ((initialDE + 1) & 65535)
                        and z["flags"]["carry"] == (result < 0)
                    )
                valid = valid and z["a"] == HL >> 8 and not writes
            elif key == "PLI.COM+1A0F":
                k = 0
                while (
                    k < 2
                    and mem[(initialDE + k) & 65535] == mem[(initialHL + k) & 65535]
                ):
                    k += 1
                x = mem[(initialDE + k) & 65535]
                y = mem[(initialHL + k) & 65535]
                valid = (
                    DE == ((initialDE + k) & 65535)
                    and HL == ((initialHL + k) & 65535)
                    and BC == initialBC
                    and z["a"] == x
                    and z["flags"]["zero"] == (x == y)
                    and z["flags"]["carry"] == (x < y)
                    and not writes
                )
            elif key == "PLI0.OVL+210B":
                index = word(0x6A6F)
                address = (0x65F3 + index) & 65535
                actual = {p: v for p, v in writes}
                valid = (
                    actual.get(0x6A6F) == ((index + 1) & 255)
                    and actual.get(0x6A70) == (((index + 1) & 65535) >> 8)
                    and HL == address
                    and BC == 0x65F3
                    and DE == initialDE
                    and z["a"] == mem[address]
                    and z["flags"]["carry"] == (0x65F3 + index > 65535)
                )
            elif key == "PLI2.OVL+0F98":
                result = a["c"] + a["e"]
                actual = {p: v for p, v in writes}
                valid = (
                    z["a"] == min(result, 255)
                    and actual == {0xAC87: a["e"], 0xAC86: result & 255}
                    and HL == 0xAC86
                    and BC == initialBC
                    and DE == initialDE
                    and z["flags"]["carry"] == (result > 255)
                )
            elif key in ["PLI.COM+02EE", "PLI.COM+0318", "PLI.COM+0380"]:
                off = {"02EE": 0x205F, "0318": 0x2063, "0380": 0x206A}[tag]
                function = {"02EE": 26, "0318": 20, "0380": 2}[tag]
                expected = initialBC if tag != "0380" else a["c"]
                actual = {p: v for p, v in writes}
                bridge = next(w for w in direct if coord(w["origin"]) == "PLI.COM+19D4")
                valid = (
                    actual[off] == (expected & 255)
                    and (tag == "0380" or actual[off + 1] == (expected >> 8))
                    and bridge["before"]["c"] == function
                    and bridge["before"]["d"] * 256 + bridge["before"]["e"] == expected
                )
                host_return = next(w for w in reversed(r["witnesses"]) if w["pc"] == 5)
                valid = valid and all(
                    z[reg] == host_return["after"][reg]
                    for reg in ("a", "b", "c", "d", "e", "h", "l", "flags")
                )
            elif key == "PLI.COM+19BB":
                bridge = next(w for w in direct if coord(w["origin"]) == "PLI.COM+19D4")
                valid = (
                    bridge["before"]["b"] == a["b"]
                    and bridge["before"]["c"] == a["c"]
                    and bridge["before"]["d"] == a["d"]
                    and bridge["before"]["e"] == a["e"]
                    and r["ret"]["pc"] == 5
                )
            if not valid:
                raise ValueError(
                    f"{key}: contract discrepancy at CALL step {r['call']['step_index']}"
                )
            check["invocations_checked"] += 1
            retpaths.setdefault(coord(r["ret"]["origin"]) or "UNKNOWN@0005", r)
        checks[key] = dict(check)
        representatives[key] = list(retpaths.values())
    return {"checks": checks, "representatives": representatives}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_records(gather_records(args.capture))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(result["checks"])
