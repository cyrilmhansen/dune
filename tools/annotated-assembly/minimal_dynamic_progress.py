#!/usr/bin/env python3
"""Count canonical MINIMAL instruction occurrences by current byte annotation.

The denominator is historical-image instruction occurrences. Host BDOS RETs
have no canonical historical-image coordinate and are reported separately.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

STATUSES = ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")


def calculate(manifest, instructions, run_total=441855):
    images = {i["name"]: i for i in manifest["images"]}
    maps = {}
    for name, image in images.items():
        mapping = []
        for section in image["sections"]:
            if section["start_offset"] != len(mapping) or section["status"] not in STATUSES:
                raise ValueError(f"{name}: manifest gap/overlap/status")
            if section["end_offset"] - section["start_offset"] != section["length"]:
                raise ValueError(f"{name}: section length mismatch")
            mapping.extend([section["status"]] * section["length"])
        if len(mapping) != image["length"]:
            raise ValueError(f"{name}: manifest length mismatch")
        maps[name] = mapping
    counts = {name: Counter() for name in images}
    seen = set()
    for row in instructions:
        name, offset = row["image"], row["offset"]
        image = images[name]
        coordinate = (name, offset)
        if coordinate in seen:
            raise ValueError("Duplicate canonical instruction coordinate")
        seen.add(coordinate)
        if row["image_sha256"] != image["sha256"] or row["runtime_pc"] != image["runtime_base"] + offset:
            raise ValueError("Instruction image identity/runtime mapping mismatch")
        length = len(bytes.fromhex(row["bytes"]))
        statuses = maps[name][offset:offset + length]
        if offset < 0 or not length or len(statuses) != length or len(set(statuses)) != 1:
            raise ValueError("Instruction straddles statuses or lies outside image")
        count = row["execution_count"]
        if not isinstance(count, int) or count <= 0:
            raise ValueError("Invalid instruction execution count")
        counts[name][statuses[0]] += count

    def summary(count):
        total = sum(count.values())
        return {"instruction_occurrences": total,
                "occurrences_by_status": {s: count[s] for s in STATUSES},
                "understood_percent": round(100 * count["UNDERSTOOD"] / total, 6) if total else 0}

    total = sum(counts.values(), Counter())
    if run_total < sum(total.values()):
        raise ValueError("Full-run count smaller than canonical image occurrences")
    return {"metric": "MINIMAL canonical instruction occurrences by current annotation status",
            "denominator": "historical image instructions; modeled host instructions excluded",
            "per_image": [{"image": name, "image_sha256": images[name]["sha256"],
                           **summary(count)} for name, count in counts.items()],
            "total": summary(total), "full_run_instruction_occurrences": run_total,
            "outside_historical_images": run_total - sum(total.values()),
            "understood_percent_of_full_run": round(100 * total["UNDERSTOOD"] / run_total, 6)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("research/annotated-assembly/manifest.json"))
    parser.add_argument("--instructions", type=Path, default=Path("research/minimal-baseline/instructions.jsonl"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = calculate(json.loads(args.manifest.read_text()),
                       [json.loads(line) for line in args.instructions.read_text().splitlines()])
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
