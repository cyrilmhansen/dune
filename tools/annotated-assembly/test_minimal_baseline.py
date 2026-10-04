#!/usr/bin/env python3
"""Validate durable MINIMAL facts and representative contracts; --images DIR required."""

import argparse
import copy
import hashlib
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

import verify as assembly_verify
from check_minimal_contracts import validate_records

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "research/minimal-baseline"


def load(name):
    return json.loads((BASELINE / name).read_text())


class MinimalBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coverage = load("coverage.json")
        cls.inventory = load("inventory.json")
        cls.instructions = [
            json.loads(line)
            for line in (BASELINE / "instructions.jsonl").read_text().splitlines()
        ]
        cls.contracts = load("contracts.json")
        cls.records = {c["entry"]: c["representatives"] for c in cls.contracts}
        cls.records["PLI.COM+19BB"] = load("bridge-structure.json")

    def test_canonical_coordinates_bytes_and_coverage(self):
        self.assertEqual(len(self.instructions), 10378)
        self.assertEqual(
            len({(i["image_sha256"], i["offset"]) for i in self.instructions}), 10378
        )
        for image in self.coverage["coverage_after"]:
            original = (IMAGES / image["image"]).read_bytes()
            self.assertEqual(
                hashlib.sha256(original).hexdigest(), image["image_sha256"]
            )
            instructions = [
                i for i in self.instructions if i["image"] == image["image"]
            ]
            union = set()
            after = Counter()
            for i in instructions:
                raw = bytes.fromhex(i["bytes"])
                self.assertEqual(original[i["offset"] : i["offset"] + len(raw)], raw)
                self.assertEqual(i["image_sha256"], image["image_sha256"])
                self.assertEqual(
                    i["runtime_pc"],
                    i["offset"] + (256 if i["image"] == "PLI.COM" else 8704),
                )
                union.update(range(i["offset"], i["offset"] + len(raw)))
                after[i["assembly_status_after"]] += len(raw)
            self.assertEqual(len(union), image["executed_bytes"])
            self.assertEqual(len(instructions), image["canonical_coordinates"])
            self.assertEqual(
                sum(i["execution_count"] for i in instructions),
                image["instruction_executions"],
            )
            self.assertEqual(
                dict(after),
                {k: v for k, v in image["executed_status_bytes"].items() if v},
            )
        self.assertEqual(
            sum(c["executed_bytes"] for c in self.coverage["coverage_after"]), 21012
        )
        self.assertEqual(
            sum(
                c["executed_status_bytes"]["UNDERSTOOD"]
                for c in self.coverage["coverage_after"]
            ),
            6450,
        )

    def test_inventory_target_counts_and_hardware_returns(self):
        entries = self.inventory["callable_entries"]
        self.assertEqual(len(entries), 391)
        self.assertEqual(len({e["entry"] for e in entries}), 391)
        self.assertEqual(sum(e["invocations"] for e in entries), 18412)
        self.assertEqual(sum(e["hardware_return_count"] for e in entries), 18405)
        self.assertEqual(sum(e["pending_count"] for e in entries), 7)
        targets = Counter()
        for edge in self.inventory["transfer_edges"]:
            if edge["kind"] in ("call", "restart"):
                targets[edge["target"]] += edge["count"]
        self.assertEqual(
            targets, Counter({e["entry"]: e["invocations"] for e in entries})
        )
        self.assertEqual(len(self.inventory["software_continuations"]), 16)
        self.assertEqual(
            self.inventory["classification_counts"],
            {"UNDERSTOOD": 126, "STRUCTURED": 8, "unresolved": 257},
        )
        for e in entries:
            self.assertEqual(sum(e["callers"].values()), e["invocations"])
            self.assertEqual(
                sum(e["hardware_returns"].values()) + e["pending_count"],
                e["invocations"],
            )
            self.assertEqual(
                e["cross_run_presence"]["MINIMAL"]["observed_call_rst_count"],
                e["invocations"],
            )

    def test_secondary_entries_and_shared_tails_stay_distinct(self):
        entries = {e["entry"]: e for e in self.inventory["callable_entries"]}
        self.assertEqual(entries["PLI.COM+1A33"]["invocations"], 2230)
        self.assertEqual(entries["PLI.COM+1A35"]["invocations"], 12)
        self.assertEqual(entries["PLI.COM+1A38"]["invocations"], 18)
        overlap = next(
            o
            for o in self.inventory["overlapping_contexts"]
            if {o["a"], o["b"]} == {"PLI.COM+1A33", "PLI.COM+1A38"}
        )
        self.assertIn("PLI.COM+1A3F", overlap["shared_instruction_coordinates"])

    def test_representative_contracts_and_both_saturation_exits(self):
        result = validate_records(self.records)
        self.assertEqual(len(result["checks"]), 16)
        exits = {r["ret"]["origin"]["offset"] for r in self.records["PLI2.OVL+0F98"]}
        self.assertEqual(exits, {0xFAD, 0xFB1})
        self.assertEqual(len({c["family_entry"] for c in self.contracts}), 10)
        self.assertEqual(
            sum(
                load("invocation-checks.json")[c["entry"]]["invocations_checked"]
                for c in self.contracts
            ),
            7951,
        )

    def test_contract_counterexample_detected(self):
        records = copy.deepcopy(self.records)
        records["PLI2.OVL+0F98"][0]["ret"]["after"]["a"] ^= 1
        with self.assertRaisesRegex(ValueError, "contract discrepancy"):
            validate_records(records)
        records = copy.deepcopy(self.records)
        records["PLI.COM+1A33"][0]["ret"]["after"]["flags"]["carry"] ^= True
        with self.assertRaisesRegex(ValueError, "contract discrepancy"):
            validate_records(records)

    def test_stack_pair_counterexample_detected(self):
        records = copy.deepcopy(self.records)
        records["PLI.COM+1A33"][0]["ret"]["reads"][0]["value"] ^= 1
        with self.assertRaisesRegex(ValueError, "matching hardware return"):
            validate_records(records)

    def test_declared_local_exit_requires_ret_bytes(self):
        annotated = ROOT / "research/annotated-assembly"
        evidence = json.loads((annotated / "evidence.json").read_text())
        images = {
            i["name"]: i
            for i in json.loads((annotated / "manifest.json").read_text())["images"]
        }
        originals = {name: (IMAGES / name).read_bytes() for name in images}
        seed = next(s for s in evidence["seeds"] if s["id"] == "PLI2.OVL+0F98")
        seed["observed_return_offsets"] = [0xF98]
        with self.assertRaisesRegex(
            assembly_verify.VerificationError, "declared RET site"
        ):
            assembly_verify.check_evidence(evidence, images, originals)

    def test_external_return_requires_exact_bdos_tail(self):
        annotated = ROOT / "research/annotated-assembly"
        evidence = json.loads((annotated / "evidence.json").read_text())
        images = {
            i["name"]: i
            for i in json.loads((annotated / "manifest.json").read_text())["images"]
        }
        originals = {name: (IMAGES / name).read_bytes() for name in images}
        seed = next(s for s in evidence["seeds"] if s["id"] == "PLI.COM+19BB")
        seed["matched_return_sample"]["ret"]["pc"] = 0
        with self.assertRaisesRegex(
            assembly_verify.VerificationError, "unsupported external return"
        ):
            assembly_verify.check_evidence(evidence, images, originals)
        seed["matched_return_sample"]["ret"]["pc"] = 5
        seed["tail_return_runtime_pc"] = 0
        with self.assertRaisesRegex(
            assembly_verify.VerificationError, "terminal JMP 0005H"
        ):
            assembly_verify.check_evidence(evidence, images, originals)

    def test_fizzbuz_delta_is_independent_coordinate_set(self):
        delta = self.coverage["fizzbuz_minus_minimal"]
        minimal = {(i["image"], i["offset"]) for i in self.instructions}
        new = {(i["image"], i["offset"]) for i in delta["new_coordinates"]}
        self.assertFalse(minimal & new)
        self.assertEqual(len(new), 4771)
        self.assertEqual(
            Counter(image for image, offset in new),
            Counter(delta["coordinates_per_image"]),
        )
        entries = {e["entry"] for e in self.inventory["callable_entries"]}
        self.assertFalse(entries & {e["entry"] for e in delta["new_callable_targets"]})
        self.assertEqual(len(delta["new_callable_targets"]), 135)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    args, unittest_args = parser.parse_known_args()
    IMAGES = args.images.resolve()
    unittest.main(argv=[sys.argv[0], *unittest_args])
