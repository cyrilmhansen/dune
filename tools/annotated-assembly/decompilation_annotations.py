"""V1 comment/catalog formatting and validation, independent of CPU execution.

This module neither decodes bytes nor discovers procedures. The reviewed catalog
contains the existing hypotheses and authored block descriptions/local effects.
"""

import json
import re
import textwrap
from pathlib import Path

HEADER_FIELDS = (
    "Entry",
    "Extent",
    "Callers",
    "Returns",
    "Inputs",
    "Outputs",
    "Clobbers",
    "Memory",
    "Direct callees",
    "Coverage",
    "Unresolved",
    "Contract",
    "Hypothesis",
    "Completeness",
    "Evidence",
)


def header_lines(procedure):
    p = procedure
    counts = p["observed_paths"]["invocations_by_run"]
    coverage = "; ".join(f"{run}: {n} CALLs" for run, n in sorted(counts.items()))
    coverage += f"; {p['observed_paths']['represented_bytes']}/{p['length']} bytes represented as instructions"
    callers = (
        "; ".join(
            f"{c['coordinate']} ({', '.join(f'{run}={count}' for run, count in sorted(c['counts_by_run'].items()))})"
            for c in p["callers"]
        )
        or "no caller attribution retained"
    )
    returns = p["returns"]["convention"] + "; " + p["returns"]["sites_description"]
    fields = {
        "Entry": f"{p['stable_label']} = {p['id']} @ {p['runtime_entry']:04X}H; SHA-256 {p['image_sha256']}",
        "Extent": f"HYPOTHESIS [{p['start_offset']:04X},{p['end_offset']:04X}) file offsets; overlapping entries: "
        + (", ".join(p["overlapping_entries"]) or "none established"),
        "Callers": "OBSERVED " + callers,
        "Returns": "OBSERVED/DEDUCED " + returns,
        "Inputs": "DEDUCED " + p["inputs"],
        "Outputs": "DEDUCED " + p["outputs"],
        "Clobbers": "DEDUCED " + p["clobbers"],
        "Memory": "DEDUCED "
        + ("; ".join(p["memory_state"]) or "operand memory and return stack only"),
        "Direct callees": "OBSERVED "
        + (
            "; ".join(
                c["coordinate"] + f" @{c['runtime_address']:04X}H"
                for c in p["direct_callees"]
            )
            or "none"
        ),
        "Coverage": "OBSERVED " + coverage + "; " + p["observed_paths"]["description"],
        "Unresolved": " / ".join(p["unresolved_paths"])
        or "none at the stated low-level scope; execution is not exhaustive",
        "Contract": f"DEDUCED ({p['completeness']['contract']}; scope: {p['contract_scope']}) "
        + p["contract"],
        "Hypothesis": ("HYPOTHESIS " + p["semantic_hypothesis"])
        if p["semantic_hypothesis"]
        else "none beyond the low-level operational description",
        "Completeness": "; ".join(f"{k}={v}" for k, v in p["completeness"].items()),
        "Evidence": "; ".join(p["evidence_refs"]),
    }
    lines = [f"; @procedure-v1 {p['id']}", f"; ProcedureHypothesis: {p['description']}"]
    for field in HEADER_FIELDS:
        parts = textwrap.wrap(
            fields[field],
            width=94 - len(field),
            break_long_words=False,
            break_on_hyphens=False,
        ) or ["none"]
        lines.append(f"; {field}: {parts[0]}")
        lines.extend(";   " + part for part in parts[1:])
    if p["pseudocode"]:
        lines.append("; Procedure pseudo (operational; byte/word arithmetic wraps):")
        lines.extend(
            ";   " + part
            for part in textwrap.wrap(
                p["pseudocode"],
                width=94,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    lines.append(f"; @end-procedure-v1 {p['id']}")
    return lines


def render(root):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    catalog = json.loads((root / "procedures.json").read_text())
    procs = catalog["procedures"]
    for image in manifest["images"]:
        selected = [p for p in procs if p["image"] == image["name"]]
        by_start = {p["start_offset"]: p for p in selected}
        comments = {}
        blocks = {}
        # Shared-tail entries reuse one physical comment/block per coordinate.
        for p in selected:
            for offset, meaning in p["local_comments"].items():
                n = int(offset, 16)
                if n in comments and comments[n] != meaning:
                    raise ValueError(
                        f"{image['name']}+{n:04X}: conflicting shared-tail comment"
                    )
                comments[n] = meaning
            for block in p["blocks"]:
                blocks.setdefault(block["offset"], block["pseudocode"])
        lines = (root / image["source"]).read_text().splitlines()
        result = []
        skip = False
        for line in lines:
            if line.startswith(("; ProcedureHypothesis:", "; @procedure-v1 ")):
                skip = True
            if skip:
                if line.startswith("; SECTION "):
                    skip = False
                else:
                    continue
            # Remove only our generated near-code block notes for repeatable rendering.
            if line.startswith("; @block-pseudo "):
                continue
            if line.startswith(("; pseudo:", "; | ")):
                continue
            marker = re.match(r"; SECTION \[([0-9A-F]+),", line)
            if marker and int(marker[1], 16) in by_start:
                if result and result[-1] != "":
                    result.append("")
                result.extend(header_lines(by_start[int(marker[1], 16)]))
            instruction = re.match(rf"{image['label_prefix']}_([0-9A-F]+):", line)
            if instruction:
                offset = int(instruction[1], 16)
                if offset in blocks:
                    result.extend([f"; @block-pseudo {offset:04X}", "; pseudo:"])
                    result.extend("; | " + text for text in blocks[offset])
                if offset in comments:
                    statement = line.split(";", 1)[0].rstrip()
                    coordinate = re.search(
                        r"\+[0-9A-F]+ runtime=[0-9A-F]+H (?:OBSERVED|RAW)", line
                    )
                    if not coordinate:
                        raise ValueError(f"Missing coordinate at +{offset:04X}")
                    line = statement + " ; " + comments[offset] + " ; " + coordinate[0]
            result.append(line)
        (root / image["source"]).write_text("\n".join(result) + "\n")


def validate(root, manifest, evidence):
    root = Path(root)
    catalog = json.loads((root / "procedures.json").read_text())
    roles = json.loads((root / "data-roles.json").read_text())

    def require(condition, message):
        if not condition:
            fail(message)

    require(
        catalog["schema_version"] == 1 and roles["schema_version"] == 1,
        "Unknown decompilation conventions version",
    )
    seeds = {s["id"]: s for s in evidence["seeds"]}
    procs = {p["id"]: p for p in catalog["procedures"]}
    require(
        len(procs) == len(catalog["procedures"]) and set(procs) == set(seeds),
        "Procedure catalog must cover each existing hypothesis exactly once",
    )
    require(
        len({r["id"] for r in roles["roles"]}) == len(roles["roles"]),
        "Duplicate data-role name",
    )
    role_by_id = {r["id"]: r for r in roles["roles"]}
    images = {i["name"]: i for i in manifest["images"]}
    for p in procs.values():
        seed = seeds[p["id"]]
        image = images[p["image"]]
        require(
            p["image_sha256"] == image["sha256"] == seed["image_sha256"],
            "Procedure image identity mismatch",
        )
        require(
            p["start_offset"] == seed["start_offset"]
            and p["end_offset"] == seed["end_offset"]
            and p["length"] == p["end_offset"] - p["start_offset"],
            "Procedure extent differs from retained hypothesis",
        )
        require(
            p["runtime_entry"] == image["runtime_base"] + p["start_offset"]
            and p["stable_label"] == f"{image['label_prefix']}_{p['start_offset']:04X}",
            "Procedure stable entry mismatch",
        )
        for key, choices in [
            ("bounds", ("provisional", "stable")),
            ("control_flow", ("partial", "complete")),
            ("contract", ("partial", "complete")),
        ]:
            require(
                p["completeness"][key] in choices,
                f"{p['id']}: invalid completeness value",
            )
        represented = sum(len(bytes.fromhex(i["bytes"])) for i in seed["instructions"])
        require(
            represented == p["observed_paths"]["represented_bytes"],
            f"{p['id']}: observed byte count mismatch",
        )
        if (
            p["completeness"]["control_flow"] == "complete"
            or p["completeness"]["contract"] == "complete"
        ):
            require(
                represented == p["length"],
                f"{p['id']}: complete claim over RAW/unrepresented hole",
            )
        if p["completeness"]["contract"] == "partial":
            require(
                p["contract_scope"] and p["unresolved_paths"],
                f"{p['id']}: partial contract lacks scope/limitations",
            )
        for field in (
            "inputs",
            "outputs",
            "clobbers",
            "contract",
            "contract_scope",
            "returns",
            "observed_paths",
            "unresolved_paths",
            "direct_callees",
            "memory_state",
            "blocks",
            "local_comments",
        ):
            require(field in p, f"{p['id']}: missing {field}")
        for role in p["data_role_ids"]:
            require(
                role in role_by_id
                and role_by_id[role]["image_sha256"] == p["image_sha256"],
                f"{p['id']}: invalid scoped data role",
            )
        text = (root / image["source"]).read_text()
        expected = "\n".join(header_lines(p))
        require(
            text.count(f"; @procedure-v1 {p['id']}\n") == 1 and expected in text,
            f"{p['id']}: standardized source header mismatch",
        )
        instructions = {i["offset"]: i for i in seed["instructions"]}
        require(
            set(p["local_comments"]) == {f"{n:04X}" for n in instructions},
            f"{p['id']}: missing local instruction semantics",
        )
        for offset, meaning in p["local_comments"].items():
            require(
                meaning.strip() and "+ " + offset not in meaning,
                f"{p['id']}: empty/local coordinate-only meaning",
            )
            row = re.search(
                rf"^{image['label_prefix']}_{offset}:.*$", text, re.MULTILINE
            )
            require(
                row is not None and "; " + meaning + " ; +" + offset in row[0],
                f"{p['id']}+{offset}: local semantic comment mismatch",
            )
        for block in p["blocks"]:
            require(
                block["offset"] in instructions and block["pseudocode"],
                f"{p['id']}: block lacks established instruction start/pseudocode",
            )
            marker = f"; @block-pseudo {block['offset']:04X}\n; pseudo:\n"
            require(marker in text, f"{p['id']}: missing near-code pseudocode")


def fail(message):
    raise ValueError(message)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path("research/annotated-assembly")
    )
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()
    if args.render:
        render(args.root)
    manifest = json.loads((args.root / "manifest.json").read_text())
    evidence = json.loads((args.root / "evidence.json").read_text())
    validate(args.root, manifest, evidence)
    print(
        "V1 procedure headers, local semantics, block pseudocode, roles and completeness verified"
    )
