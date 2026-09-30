#!/usr/bin/env python3
"""Explicit contracts for MINIMAL pass 1; no automatic procedure inference."""

import argparse
import json
from collections import Counter
from pathlib import Path

ENTRIES = [
    "PLI2.OVL+1FB5",
    "PLI.COM+070C",
    "PLI.COM+12AE",
    "PLI1.OVL+4693",
    "PLI1.OVL+4738",
    "PLI1.OVL+4468",
    "PLI0.OVL+23C3",
    "PLI.COM+09CB",
    "PLI.COM+0AA9",
]
BOUNDS = {
    "PLI2.OVL+1FB5": (0x1FB5, 0x20EB),
    "PLI.COM+070C": (0x70C, 0x788),
    "PLI.COM+12AE": (0x12AE, 0x12D9),
    "PLI1.OVL+4693": (0x4693, 0x46A7),
    "PLI1.OVL+4738": (0x4738, 0x478D),
    "PLI1.OVL+4468": (0x4468, 0x452B),
    "PLI0.OVL+23C3": (0x23C3, 0x23DF),
    "PLI.COM+09CB": (0x9CB, 0xAA5),
    "PLI.COM+0AA9": (0xAA9, 0xAE9),
}


def coord(origin):
    return f"{origin['image']['name']}+{origin['offset']:04X}" if origin else None


def load(path):
    text = path.read_text()
    return json.loads(text[text.index("{") :])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gather(capture):
    records = {key: [] for key in ENTRIES}
    active = {}
    handlers = {}
    done = []
    latest = None
    last_push = None
    for path in sorted((capture / "event-witnesses/chunks").glob("*.json")):
        for event in load(path)["events"]:
            if event["type"] == "instruction":
                w = event["witness"]
                latest = w
                flow = w["control"]
                for record in list(active.values()) + list(handlers.values()):
                    record["witnesses"].append(w)
                if coord(w["origin"]) == "PLI2.OVL+20AF":
                    last_push = w
                if coord(w["origin"]) == "PLI2.OVL+20B3":
                    require(
                        last_push is not None, "PCHL lacks observed continuation writer"
                    )
                    handlers[last_push["step_index"]] = {
                        "transfer": w,
                        "writer": last_push,
                        "entry_key": coord(w["target_origin"]),
                        "witnesses": [],
                    }
                if (
                    flow["kind"] == "call"
                    and flow["taken"]
                    and coord(w.get("target_origin")) in records
                ):
                    key = coord(w["target_origin"])
                    active[w["step_index"]] = {
                        "call": w,
                        "entry_key": key,
                        "witnesses": [],
                        "software_returns": [],
                    }
            elif event["type"] == "hardware_frame_return":
                step = event["frame"]["call_step"]
                if step in active:
                    r = active.pop(step)
                    r.update(ret=latest, entry=r["witnesses"][0], relation=event)
                    records[r["entry_key"]].append(r)
            elif event["type"] == "software_continuation_return":
                for record in active.values():
                    record["software_returns"].append(event)
                step = event["low_byte_writer"]["step"]
                if step in handlers:
                    r = handlers.pop(step)
                    r.update(ret=latest, entry=r["witnesses"][0], relation=event)
                    done.append(r)
                for callstep, record in list(active.items()):
                    if (
                        record["entry_key"] == "PLI1.OVL+4468"
                        and latest["pc_after"] == record["call"]["call_return_address"]
                    ):
                        r = active.pop(callstep)
                        r.update(ret=latest, entry=r["witnesses"][0], relation=event)
                        records[r["entry_key"]].append(r)
    require(
        not active and not handlers,
        "Selected invocation did not reach its witnessed return",
    )
    return records, done


def direct(record):
    a, b = BOUNDS[record["entry_key"]]
    name = record["entry_key"].split("+")[0]
    # Exclude recursive executions of the gateway at a deeper SP. The interval
    # and stack layout were manually established from its entry/restore blocks.
    return [
        w
        for w in record["witnesses"]
        if w["origin"]
        and w["origin"]["image"]["name"] == name
        and a <= w["origin"]["offset"] < b
        and (name != "PLI2.OVL" or w["sp_before"] >= record["entry"]["sp_before"] - 14)
    ]


def at(ws, offset):
    return [w for w in ws if w["origin"]["offset"] == offset]


def pair(state, hi, lo):
    return state[hi] * 256 + state[lo]


def read_word(w):
    return w["reads"][0]["value"] + 256 * w["reads"][1]["value"]


def software_proof(record):
    relation = record["relation"]
    ret = record["ret"]
    if "writer" in record:
        writer = record["writer"]
    else:
        writer = next(
            w
            for w in record["witnesses"]
            if w["step_index"] == relation["low_byte_writer"]["step"]
        )
    return {"writer": writer, "ret": ret, "relation": relation}


def check_software(proof):
    writer, ret, relation = proof["writer"], proof["ret"], proof["relation"]
    writes = {w["address"]: w["new_value"] for w in writer["writes"]}
    reads = {r["address"]: r["value"] for r in ret["reads"]}
    slot = ret["sp_before"]
    require(
        relation["type"] == "software_continuation_return"
        and writer["sp_after"] == slot
        and writer["step_index"] < ret["step_index"]
        and writes == reads
        and len(reads) == 2,
        "Software continuation writer/slot/bytes mismatch",
    )
    require(
        reads[slot] + 256 * reads[(slot + 1) & 65535]
        == ret["pc_after"]
        == relation["return_address"]
        and relation["stack_slot"] == slot
        and relation["step_index"] == ret["step_index"],
        "Software continuation target/consumer mismatch",
    )
    for key, address in [
        ("low_byte_writer", slot),
        ("high_byte_writer", (slot + 1) & 65535),
    ]:
        fact = relation[key]
        require(
            fact["step"] == writer["step_index"]
            and fact["pc"] == writer["pc"]
            and fact["origin"] == writer["origin"]
            and fact["value"] == writes[address],
            "Software continuation source writer mismatch",
        )


def validate(record):
    key = record["entry_key"]
    call, ret = record["call"], record["ret"]
    ws = direct(record)
    before = record["entry"]["before"]
    after = ret["after"]
    where = f"{key}, CALL step {call['step_index']}"
    require(
        ret["pc_after"] == call["call_return_address"],
        f"{where}: return target mismatch",
    )
    if key == "PLI1.OVL+4468":
        proof = software_proof(record)
        check_software(proof)
        require(
            ret["sp_before"] == call["sp_after"] + 2
            and after["sp"] == call["sp_after"] + 4,
            f"{where}: caller stack argument not consumed correctly",
        )
        require(
            proof["writer"]["bytes"] == "D5",
            f"{where}: continuation was not re-pushed by PUSH D",
        )
        source = read_word(at(ws, 0x4470)[0])
        count = before["c"]
        tag = before["e"]
        require(
            at(ws, 0x446B)[0]["writes"][0]["new_value"] == tag
            and at(ws, 0x446D)[0]["writes"][0]["new_value"] == count,
            f"{where}: argument scratch mismatch",
        )
        stores = at(ws, 0x44D9)
        require(
            len(stores) == count
            and [w["before"]["a"] for w in stores]
            == [w["reads"][0]["value"] for w in at(ws, 0x44D8)],
            f"{where}: payload copy length/value mismatch",
        )
        base = read_word(at(ws, 0x447C)[0])
        header = at(ws, 0x4484)[0]["writes"][0]
        require(
            header["address"] == base + 2 and header["new_value"] == tag,
            f"{where}: record tag mismatch",
        )
        for offset, field in [
            (0x448C, 3),
            (0x4493, 4),
            (0x449A, 5),
            (0x44B0, 6),
            (0x44B2, 7),
            (0x44A5, 8),
            (0x44A7, 9),
        ]:
            zero = at(ws, offset)[0]["writes"][0]
            require(
                zero["address"] == base + field and zero["new_value"] == 0,
                f"{where}: record zero field mismatch",
            )
        for index, w in enumerate(stores):
            read = at(ws, 0x44D8)[index]["reads"][0]
            require(
                w["writes"][0]["address"] == base + 10 + count - index - 1
                and read["address"] == source + count - index - 1
                and w["writes"][0]["new_value"] == read["value"],
                f"{where}: descending copy index mismatch",
            )
    else:
        require(
            ret["sp_before"] == call["sp_after"]
            and after["sp"] == call["sp_after"] + 2
            and {r["address"]: r["value"] for r in ret["reads"]}
            == {w["address"]: w["new_value"] for w in call["writes"]},
            f"{where}: hardware frame mismatch",
        )
    if key == "PLI2.OVL+1FB5":
        saved = [w["reads"][0]["value"] for w in at(ws, 0x1FC9)]
        restored = [w["writes"][0]["new_value"] for w in at(ws, 0x20D6)]
        require(
            len(saved) == 10 and saved == restored,
            f"{where}: gateway saved state not restored",
        )
        old = at(ws, 0x1FD1)[0]["reads"][0]["value"]
        require(
            at(ws, 0x20E2)[0]["writes"][0]["new_value"] == old == after["a"],
            f"{where}: AD0A not restored",
        )
        require(
            pair(after, "b", "c") == call["sp_after"] - 1
            and pair(after, "h", "l") == call["sp_after"]
            and pair(after, "d", "e") == 0xAD15,
            f"{where}: gateway return registers mismatch",
        )
        require(
            at(ws, 0x208B)[0]["reads"][0]["value"] & 1 == 0
            and at(ws, 0x20B4)[0]["reads"][0]["value"] & 1 == 0,
            f"{where}: uninvestigated tracing-mode branch occurred",
        )
    elif key == "PLI.COM+070C":
        flag = at(ws, 0x70C)[0]["reads"][0]["value"]
        site = ret["origin"]["offset"]
        if flag & 1:
            require(site == 0x715 and after["a"] == 0x1A, f"{where}: EOF gate mismatch")
        else:
            old = read_word(at(ws, 0x716)[0])
            next_index = (old + 1) & 65535
            if next_index < 512:
                base = read_word(at(ws, 0x72A)[0])
                require(
                    site == 0x72F
                    and after["a"] == at(ws, 0x72E)[0]["reads"][0]["value"]
                    and pair(after, "h", "l") == (base + next_index) & 65535,
                    f"{where}: buffered read mismatch",
                )
            else:
                require(
                    site == 0x787
                    and after["a"] == at(ws, 0x786)[0]["reads"][0]["value"],
                    f"{where}: refill result mismatch",
                )
                stores = at(ws, 0x780)[0]["writes"]
                require(
                    all(x["new_value"] == 0 for x in stores),
                    f"{where}: refill index not reset",
                )
    elif key == "PLI.COM+12AE":
        if ret["origin"]["offset"] == 0x12C4:
            require(
                after["a"] == 0x1A and at(ws, 0x12BB)[-1]["reads"][0]["value"] & 1,
                f"{where}: EOF value mismatch",
            )
        else:
            index = at(ws, 0x12C8)[-1]["reads"][0]["value"]
            write = at(ws, 0x12CC)[-1]["writes"][0]
            require(
                write["new_value"] == (index + 1) & 255
                and after["a"] == at(ws, 0x12D7)[-1]["reads"][0]["value"]
                and pair(after, "b", "c") == index
                and pair(after, "h", "l") == 0x1E8E + index,
                f"{where}: indexed read mismatch",
            )
    elif key == "PLI0.OVL+23C3":
        child = next(
            w for w in record["witnesses"] if coord(w["origin"]) == "PLI.COM+1A35"
        )
        low = child["reads"][0]["value"]
        high = next(
            w for w in record["witnesses"] if coord(w["origin"]) == "PLI.COM+1A37"
        )["reads"][0]["value"]
        limit = low + 256 * high
        pointer = read_word(at(ws, 0x23CE)[0])
        tag = at(ws, 0x23D5)[0]["reads"][0]["value"]
        first = 255 if pointer >= limit else 0
        result = 255 if first or tag & 0xE0 == 0x20 else 0
        require(
            after["a"] == result
            and pair(after, "b", "c") == first * 257
            and pair(after, "h", "l") == (pointer + 1) & 65535
            and pair(after, "d", "e") == 0x6A83
            and not after["flags"]["carry"],
            f"{where}: bound/tag predicate mismatch",
        )
    elif key == "PLI.COM+0AA9":
        require(
            at(ws, 0xAA9)[0]["reads"][0]["value"] & 1 == 0,
            f"{where}: uninvestigated byte-source mode occurred",
        )
        raw = at(ws, 0xADD)[0]["before"]["a"]
        require(
            at(ws, 0xADD)[0]["writes"][0]["new_value"] == raw
            and at(ws, 0xAE5)[0]["writes"][0]["new_value"] == raw & 127
            and after["a"] == raw & 127,
            f"{where}: byte caching/masking mismatch",
        )
    elif key == "PLI.COM+09CB":
        require(
            at(ws, 0x9CB)[0]["reads"][0]["value"] == 0,
            f"{where}: uninvestigated reuse mode occurred",
        )
        state = at(ws, 0x9E9)[0]["reads"][0]["value"]
        site = ret["origin"]["offset"]
        require(state in (0, 2), f"{where}: uninvestigated mode occurred")
        if state == 2:
            masked = at(ws, 0x9F1)[0]["reads"][0]["value"]
            expected_state = 0 if masked == 39 else 2
            require(
                site == 0xA01 and after["a"] == at(ws, 0x9FE)[0]["reads"][0]["value"],
                f"{where}: mode-2 result mismatch",
            )
        else:
            masked = at(ws, 0xA2C)[0]["reads"][0]["value"]
            expected_state = 2 if masked == 39 else 0
            require(
                masked not in (47, 37), f"{where}: uninvestigated delimiter occurred"
            )
            require(
                site == (0xA3B if masked == 39 else 0xAA4)
                and after["a"]
                == (39 if masked == 39 else at(ws, 0xAA1)[0]["reads"][0]["value"]),
                f"{where}: ordinary result mismatch",
            )
        state_writes = [
            q["new_value"] for w in ws for q in w["writes"] if q["address"] == 0x200D
        ]
        require(
            state_writes == ([expected_state] if expected_state != state else []),
            f"{where}: quote-mode update mismatch",
        )
    elif key == "PLI1.OVL+4693":
        require(
            at(ws, 0x4696)[0]["writes"][0]["new_value"] == before["c"],
            f"{where}: saved tag mismatch",
        )
        child = at(ws, 0x46A3)[0]
        require(
            child["before"]["c"] == read_word(at(ws, 0x469B)[0]) & 255
            and child["before"]["e"] == before["c"],
            f"{where}: constructor arguments mismatch",
        )
        push = at(ws, 0x469A)[0]
        require(
            {w["address"]: w["new_value"] for w in push["writes"]}
            == {push["sp_after"]: 0xC6, push["sp_after"] + 1: 0x20},
            f"{where}: source pointer argument mismatch",
        )
    elif key == "PLI1.OVL+4738":
        require(
            not at(ws, 0x4747)[0]["control"]["taken"],
            f"{where}: uninvestigated early return occurred",
        )
        field = read_word(at(ws, 0x4759)[0]) + 2
        original = (
            at(ws, 0x4761)[0]["reads"][0]["value"]
            + 256 * at(ws, 0x4763)[0]["reads"][0]["value"]
        )
        length = at(ws, 0x476D)[0]["reads"][0]["value"]
        result = (original + length) & 65535
        require(
            at(ws, 0x4775)[0]["writes"][0]["address"] == field
            and at(ws, 0x4775)[0]["writes"][0]["new_value"] == result & 255
            and at(ws, 0x4777)[0]["writes"][0]["new_value"] == result >> 8,
            f"{where}: field adjustment mismatch",
        )
        require(
            at(ws, 0x4789)[0]["writes"][0]["new_value"] == original & 255
            and at(ws, 0x478B)[0]["writes"][0]["new_value"] == original >> 8,
            f"{where}: saved field not copied into new +6 word",
        )
    return ws


def summarize(records, handlers):
    result = {}
    for key, rs in records.items():
        edges = Counter()
        examples = {}
        for record in rs:
            ws = validate(record)
            for w in ws:
                if w["control"]["kind"] != "sequential":
                    edges[
                        (
                            w["origin"]["offset"],
                            w["pc_after"],
                            w["control"].get("taken", True),
                        )
                    ] += 1
            # Preserve each return outcome, bound/tag result, and refill retry shape.
            outcome = (
                record["ret"]["origin"]["offset"],
                record["ret"]["after"]["a"] if key == "PLI0.OVL+23C3" else None,
                len(at(ws, 0x12AE)) if key == "PLI.COM+12AE" else None,
            )
            if key == "PLI0.OVL+23C3":
                outcome += (record["ret"]["after"]["b"],)
            if key == "PLI.COM+09CB":
                outcome += (
                    tuple(
                        q["new_value"]
                        for w in ws
                        for q in w["writes"]
                        if q["address"] == 0x200D
                    ),
                )
            if key == "PLI1.OVL+4468":
                outcome += (record["call"]["pc"],)
            if key == "PLI2.OVL+1FB5":
                outcome += (len(at(ws, 0x2037)),)
            if outcome not in examples:
                small = {
                    k: record[k]
                    for k in ("call", "entry", "ret", "relation", "entry_key")
                }
                small["witnesses"] = ws
                if key == "PLI0.OVL+23C3":
                    small["witnesses"] += [
                        w
                        for w in record["witnesses"]
                        if coord(w["origin"]) in ("PLI.COM+1A35", "PLI.COM+1A37")
                    ]
                if key == "PLI1.OVL+4468":
                    small["software_proof"] = software_proof(record)
                small["witnesses"].sort(key=lambda w: w["step_index"])
                examples[outcome] = small
        result[key] = {
            "invocations_checked": len(rs),
            "branches": [
                {"offset": o, "runtime_after": pc, "taken": t, "count": c}
                for (o, pc, t), c in sorted(edges.items())
            ],
            "representatives": list(examples.values()),
        }
    callbacks = []
    for h in handlers:
        proof = software_proof(h)
        check_software(proof)
        require(
            h["transfer"]["bytes"] == "E9"
            and h["transfer"]["pc_after"] == h["entry"]["pc"]
            and h["ret"]["pc_after"] == 0x42B4,
            "PCHL entry/continuation mismatch",
        )
        callbacks.append(
            {
                "entry": h["entry_key"],
                "transfer": h["transfer"],
                "entry_witness": h["entry"],
                "proof": proof,
                "return_site": coord(h["ret"]["origin"]),
                "classification": "unresolved",
            }
        )
    return {"regions": result, "continuation_entries": callbacks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records, handlers = gather(args.capture)
    result = summarize(records, handlers)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print({key: r["invocations_checked"] for key, r in result["regions"].items()})
