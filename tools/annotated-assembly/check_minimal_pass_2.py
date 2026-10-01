#!/usr/bin/env python3
"""Explicit low-level checks for the ten manually selected MINIMAL pass-2 regions."""

import argparse
import json
from collections import Counter
from pathlib import Path

BOUNDS = {
    "PLI2.OVL+1DFF": (0x1DFF, 0x1FB5),
    "PLI2.OVL+0992": (0x992, 0x9BA),
    "PLI2.OVL+047D": (0x47D, 0x493),
    "PLI2.OVL+04A9": (0x4A9, 0x4BF),
    "PLI.COM+0D40": (0xD40, 0xE1F),
    "PLI.COM+0E1F": (0xE1F, 0xE47),
    "PLI1.OVL+4394": (0x4394, 0x43D5),
    "PLI1.OVL+8396": (0x8396, 0x83A0),
    "PLI.COM+05B2": (0x5B2, 0x5F8),
    "PLI.COM+0341": (0x341, 0x34A),
}


def load(path):
    text = path.read_text()
    return json.loads(text[text.index("{") :])


def coord(origin):
    return f"{origin['image']['name']}+{origin['offset']:04X}" if origin else None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pair(s, hi, lo):
    return s[hi] * 256 + s[lo]


def word(w):
    return w["reads"][0]["value"] + 256 * w["reads"][1]["value"]


def at(ws, offset):
    return [w for w in ws if w["origin"]["offset"] == offset]


def local(r):
    a, b = BOUNDS[r["entry_key"]]
    name = r["entry_key"].split("+")[0]
    return [
        w
        for w in r["witnesses"]
        if w["origin"]
        and w["origin"]["image"]["name"] == name
        and a <= w["origin"]["offset"] < b
    ]


def gather(capture):
    records = {key: [] for key in BOUNDS}
    active = {}
    last = None
    for path in sorted((capture / "event-witnesses/chunks").glob("*.json")):
        for event in load(path)["events"]:
            if event["type"] == "instruction":
                w = event["witness"]
                last = w
                for r in active.values():
                    r["witnesses"].append(w)
                if (
                    w["control"]["kind"] == "call"
                    and w["control"]["taken"]
                    and coord(w.get("target_origin")) in records
                ):
                    key = coord(w["target_origin"])
                    active[w["step_index"]] = {
                        "entry_key": key,
                        "call": w,
                        "witnesses": [],
                    }
            elif (
                event["type"] == "hardware_frame_return"
                and event["frame"]["call_step"] in active
            ):
                r = active.pop(event["frame"]["call_step"])
                r.update(entry=r["witnesses"][0], ret=last, relation=event)
                records[r["entry_key"]].append(r)
    require(not active, "Selected CALL lacked matched hardware return")
    return records


def validate(r):
    key = r["entry_key"]
    call, ret = r["call"], r["ret"]
    before = r["entry"]["before"]
    after = ret["after"]
    ws = local(r)
    where = f"{key} CALL {call['step_index']}"
    require(
        ret["pc_after"] == call["call_return_address"]
        and ret["sp_before"] == call["sp_after"]
        and ret["sp_after"] == call["sp_after"] + 2
        and {q["address"]: q["value"] for q in ret["reads"]}
        == {q["address"]: q["new_value"] for q in call["writes"]}
        and r["relation"]["frame"]["call_step"] == call["step_index"],
        where + ": hardware return mismatch",
    )
    if key in ("PLI2.OVL+047D", "PLI2.OVL+04A9"):
        a = BOUNDS[key][0]
        base = 0xA609 if a == 0x47D else 0xA6CF
        lookup = at(ws, a + 13)[0]["reads"][0]
        output = at(ws, a + 20)[0]["reads"][0]
        index = lookup["value"]
        require(
            at(ws, a + 3)[0]["writes"][0]["new_value"] == before["c"]
            and lookup["address"] == 0xAAB0 + before["c"]
            and output["address"] == base + index
            and after["a"] == output["value"]
            and pair(after, "b", "c") == index
            and pair(after, "h", "l") == base + index
            and pair(after, "d", "e") == pair(before, "d", "e")
            and not after["flags"]["carry"],
            where + ": two-table lookup mismatch",
        )
        require(
            all(
                after["flags"][f] == before["flags"][f]
                for f in ("sign", "zero", "parity", "auxiliary_carry")
            ),
            where + ": lookup changed preserved flags",
        )
    elif key == "PLI2.OVL+0992":
        cursor = before["c"]
        balance = 1
        stores = at(ws, 0x9A7)
        decrements = at(ws, 0x9B2)
        for i, store in enumerate(stores):
            weight = at(ws, 0x9A2)[i]["before"]["a"]
            balance = (balance + weight - 1) & 255
            require(
                store["writes"][0]["new_value"] == balance,
                where + ": balance recurrence mismatch",
            )
            if balance:
                require(
                    decrements[i]["writes"][0]["new_value"] == (cursor - 1) & 255,
                    where + ": backward cursor mismatch",
                )
                cursor = (cursor - 1) & 255
            else:
                require(i == len(stores) - 1, where + ": zero balance did not return")
        require(
            balance == 0
            and after["a"] == cursor
            and pair(after, "h", "l") == 0xAC3C
            and pair(after, "b", "c") == 0
            and pair(after, "d", "e") == pair(before, "d", "e")
            and after["flags"]["zero"]
            and not after["flags"]["carry"],
            where + ": balanced traversal result mismatch",
        )
    elif key == "PLI2.OVL+1DFF":
        count = at(ws, 0x1E06)[0]["reads"][0]["value"]
        cursor = before["c"]
        processed = 0
        cache = [255] * 5
        result = 1
        desc = at(ws, 0x1E3F)
        class_calls = at(ws, 0x1E68)
        class_i = 0
        require(
            len(
                [
                    q
                    for w in ws
                    for q in w["writes"]
                    if 0xAD15 <= q["address"] <= 0xAD19 and q["new_value"] == 255
                ]
            )
            == 5,
            where + ": cache initialization mismatch",
        )
        for item in desc:
            expected = item["reads"][0]["value"]
            cursor = (cursor - 1) & 255
            processed += 1
            require(
                at(ws, 0x1E47)[processed - 1]["writes"][0]["new_value"] == cursor
                and at(ws, 0x1E5B)[processed - 1]["writes"][0]["address"]
                == 0xAD0B + processed
                and at(ws, 0x1E5B)[processed - 1]["writes"][0]["new_value"] == cursor,
                where + ": cursor/position update mismatch",
            )
            if expected < 0xED:
                compare = at(ws, 0x1E6E)[class_i]
                classified = compare["before"]["a"]
                class_i += 1
                require(
                    class_calls[class_i - 1]["before"]["c"] == cursor
                    and compare["reads"][0]["value"] == expected,
                    where + ": literal-class comparison mismatch",
                )
                # MINIMAL exercises only the mismatch arm for literal descriptors.
                require(
                    classified != expected,
                    where + ": uninvestigated literal success path",
                )
                result = 0
                require(
                    after["flags"]["carry"] == (classified < expected),
                    where + ": mismatch carry is not unsigned comparison",
                )
                break
            require(
                expected in (0xFB, 0xFC) and cache[expected - 0xFB] == 255,
                where + ": uninvestigated descriptor/cache path",
            )
            slot = expected - 0xFB
            cache[slot] = processed
            marker = at(ws, 0x1FA4)[processed - 1]["writes"][0]
            require(
                marker["address"] == 0xAD15 + slot and marker["new_value"] == processed,
                where + ": marker cache mismatch",
            )
            resume = at(ws, 0x1FAC)[processed - 1]
            cursor = resume["before"]["a"]
        require(
            after["a"] == result and after["flags"]["zero"] == bool(result),
            where + ": predicate Boolean/Z result mismatch",
        )
        if result:
            require(
                processed == count and not after["flags"]["carry"],
                where + ": predicate completion mismatch",
            )
    elif key == "PLI.COM+0E1F":
        index = at(ws, 0xE23)[0]["reads"][0]["value"]
        next_index = (index + 1) & 255
        require(next_index < 120, where + ": uninvestigated capacity path")
        store = at(ws, 0xE3D)[0]["writes"][0]
        require(
            at(ws, 0xE30)[0]["writes"][0]["new_value"] == next_index
            and store["address"] == 0x1E8E + next_index
            and store["new_value"] == before["c"] == after["a"]
            and pair(after, "b", "c") == next_index
            and pair(after, "h", "l") == 0x1E8E + next_index
            and pair(after, "d", "e") == pair(before, "d", "e"),
            where + ": indexed append mismatch",
        )
        require(
            after["flags"]["zero"] == (next_index == 0)
            and after["flags"]["sign"] == bool(next_index & 128)
            and after["flags"]["parity"] == (next_index.bit_count() % 2 == 0)
            and after["flags"]["auxiliary_carry"] == ((index & 15) == 15),
            where + ": append flags do not describe the second INR",
        )
    elif key == "PLI.COM+0D40":
        require(
            at(ws, 0xD43)[0]["writes"][0]["new_value"] == 0
            and at(ws, 0xD4B)[0]["writes"][0]["new_value"] == 255
            and at(ws, 0xD50)[0]["writes"][0]["new_value"] == 0
            and at(ws, 0xD53)[0]["writes"][0]["new_value"] == 0,
            where + ": refill initial state mismatch",
        )
        inputs = [
            w["before"]["a"] for w in ws if w["origin"]["offset"] in (0xD58, 0xDF5)
        ]
        require(
            inputs
            and inputs[-1] in (10, 26)
            and all(v != 9 and v < 128 for v in inputs),
            where + ": uninvestigated tab/high-bit mode",
        )
        expected = []
        for value in inputs[:-1]:
            if value == 13:
                expected.append(0)
            elif 32 <= value < 127:
                expected.append(value)
        appends = [
            w["before"]["c"]
            for w in ws
            if w["origin"]["offset"] in (0xD94, 0xDEF, 0xE04)
        ]
        if inputs[0] == 26:
            require(
                len(inputs) == 1 and not appends,
                where + ": immediate EOF appended data",
            )
        else:
            require(
                appends == expected + [0],
                where + ": line filtering/count/terminator mismatch",
            )
            require(
                at(ws, 0xDFF)[0]["writes"][0]["new_value"] == len(expected),
                where + ": counted buffer length mismatch",
            )
        require(
            at(ws, 0xE0C)[0]["reads"][0]["value"] == 0
            and after["a"] == 0
            and not after["flags"]["carry"]
            and pair(after, "h", "l") == 0x1F06
            and at(ws, 0xE1C)[0]["writes"][0]["new_value"] == 0,
            where + ": refill final state mismatch",
        )
    elif key == "PLI1.OVL+8396":
        difference = pair(before, "d", "e") - before["a"]
        value = difference & 65535
        require(
            pair(after, "h", "l") == value
            and pair(after, "d", "e") == pair(before, "d", "e")
            and pair(after, "b", "c") == before["a"]
            and after["a"] == value >> 8
            and after["flags"]["carry"] == (difference < 0),
            where + ": byte-subtraction adapter mismatch",
        )
    elif key == "PLI1.OVL+4394":
        top = word(at(ws, 0x4398)[0])
        count = before["c"]
        p = (top - 9 - count) & 65535
        require(
            p >= 0xAE7A and at(ws, 0x43B5)[0]["control"]["taken"],
            where + ": uninvestigated allocation failure",
        )

        def written_word(offset):
            q = at(ws, offset)[0]["writes"]
            return q[0]["new_value"] + 256 * q[1]["new_value"]

        require(
            at(ws, 0x4397)[0]["writes"][0]["new_value"] == count
            and written_word(0x43AB) == p
            and written_word(0x43C2) == (p - 1) & 65535
            and at(ws, 0x43CD)[0]["writes"][0]["address"] == p
            and at(ws, 0x43CD)[0]["writes"][0]["new_value"] == (count + 10) & 255
            and at(ws, 0x43D2)[0]["writes"][0]["address"] == p + 1
            and at(ws, 0x43D2)[0]["writes"][0]["new_value"] == 0,
            where + ": downward record/header mismatch",
        )
        require(
            pair(after, "b", "c") == count
            and pair(after, "d", "e") == p
            and pair(after, "h", "l") == p + 1
            and after["a"] == (count + 10) & 255
            and after["flags"]["carry"] == (count + 10 > 255),
            where + ": allocator return registers mismatch",
        )
    elif key == "PLI.COM+0341":
        bridge = next(w for w in r["witnesses"] if coord(w["origin"]) == "PLI.COM+19D4")
        require(
            bridge["before"]["c"] == 11 and pair(bridge["before"], "d", "e") == 0,
            where + ": BDOS poll arguments mismatch",
        )
        host = next(w for w in r["witnesses"] if w["pc"] == 5)
        require(
            all(
                after[f] == host["after"][f]
                for f in ("a", "b", "c", "d", "e", "h", "l", "flags")
            ),
            where + ": poll output not delegated",
        )
    elif key == "PLI.COM+05B2":
        rotate = at(ws, 0x5B5)[0]
        a = rotate["before"]["a"]
        carry = rotate["before"]["flags"]["carry"]
        require(
            a & 1 == 0 and at(ws, 0x5B6)[0]["control"]["taken"],
            where + ": uninvestigated key-present branch",
        )
        require(
            after["a"] == ((a >> 1) | (128 if carry else 0))
            and not after["flags"]["carry"]
            and all(
                after[f] == rotate["before"][f] for f in ("b", "c", "d", "e", "h", "l")
            )
            and all(
                after["flags"][f] == rotate["before"]["flags"][f]
                for f in ("sign", "zero", "parity", "auxiliary_carry")
            ),
            where + ": no-key gate result mismatch",
        )
    return ws


def summarize(records):
    result = {}
    for key, rs in records.items():
        examples = {}
        edges = Counter()
        outcomes = Counter()
        for r in rs:
            ws = validate(r)
            outcomes[(r["ret"]["after"]["a"], r["ret"]["after"]["flags"]["carry"])] += 1
            for w in ws:
                if w["control"]["kind"] != "sequential":
                    edges[
                        (
                            w["origin"]["offset"],
                            w["pc_after"],
                            w["control"].get("taken", True),
                        )
                    ] += 1
            signature = (
                r["ret"]["origin"]["offset"],
                r["ret"]["after"]["a"],
                r["ret"]["after"]["flags"]["carry"],
            )
            if key == "PLI2.OVL+1DFF":
                signature += (at(ws, 0x1E06)[0]["reads"][0]["value"],)
            if key == "PLI2.OVL+0992":
                signature = (len(at(ws, 0x99F)),)
            if key in ("PLI2.OVL+047D", "PLI2.OVL+04A9"):
                signature = (r["ret"]["after"]["a"],)
            if key == "PLI.COM+0E1F":
                signature = (
                    r["entry"]["before"]["c"] == 0,
                    at(ws, 0xE23)[0]["reads"][0]["value"] == 255,
                )
            if key == "PLI.COM+0D40":
                signature = (
                    tuple(
                        w["before"]["a"]
                        for w in ws
                        if w["origin"]["offset"] in (0xD58, 0xDF5)
                    ),
                )
            if key in ("PLI.COM+05B2", "PLI.COM+0341"):
                signature = (r["ret"]["after"]["a"],)
            if signature not in examples:
                small = {
                    k: r[k] for k in ("entry_key", "call", "entry", "ret", "relation")
                }
                small["witnesses"] = ws
                if key == "PLI.COM+0341":
                    small["witnesses"] += [
                        w
                        for w in r["witnesses"]
                        if coord(w["origin"]) == "PLI.COM+19D4" or w["pc"] == 5
                    ]
                    small["witnesses"].sort(key=lambda w: w["step_index"])
                projected = []
                for witness in small["witnesses"]:
                    row = {
                        k: v
                        for k, v in witness.items()
                        if k not in ("before", "after", "source")
                    }
                    if (
                        key == "PLI.COM+05B2"
                        or witness["pc"] == 5
                        or coord(witness["origin"]) == "PLI.COM+19D4"
                    ):
                        row["before"] = witness["before"]
                    else:
                        row["before"] = {k: witness["before"][k] for k in ("a", "c")}
                    if witness["pc"] == 5:
                        row["after"] = witness["after"]
                    projected.append(row)
                small["witnesses"] = projected
                examples[signature] = small
        result[key] = {
            "invocations_checked": len(rs),
            "outcomes": [
                {"a": a, "carry": c, "count": n}
                for (a, c), n in sorted(outcomes.items())
            ],
            "branches": [
                {"offset": o, "runtime_after": p, "taken": t, "count": n}
                for (o, p, t), n in sorted(edges.items())
            ],
            "representatives": list(examples.values()),
        }
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = summarize(gather(args.capture))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print({k: r["invocations_checked"] for k, r in result.items()})
