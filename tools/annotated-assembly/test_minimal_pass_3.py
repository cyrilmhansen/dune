#!/usr/bin/env python3
"""Pass-3 contracts, recursive frame isolation, dynamic metrics and identities."""

import argparse
import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

from check_minimal_pass_3 import at, local, validate
from minimal_dynamic_progress import calculate

ROOT = Path(__file__).resolve().parents[2]
PASS = ROOT / "research/minimal-baseline/pass-3"


def read(path):
    return json.loads(path.read_text())


class MinimalPassThreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions = read(PASS / "regions.json")
        cls.by_entry = {r["entry"]: r for r in cls.regions}
        cls.progress = read(PASS / "progress.json")
        cls.dynamic = read(PASS / "dynamic-progress.json")
        cls.manifest = read(ROOT / "research/annotated-assembly/manifest.json")
        cls.instructions = [json.loads(line) for line in
                            (ROOT / "research/minimal-baseline/instructions.jsonl").read_text().splitlines()]
        cls.originals = {i["name"]: (IMAGES / i["name"]).read_bytes() for i in cls.manifest["images"]}

    def test_checked_invocations_and_original_witness_bytes(self):
        self.assertEqual(len(self.regions), 7)
        self.assertEqual(sum(r["invocations_checked"] for r in self.regions), 407)
        self.assertEqual(sum(r["own_instruction_occurrences"] for r in self.regions), 16045)
        for region in self.regions:
            for sample in region["representatives"]:
                validate(sample)
                for w in [sample["call"], *local(sample)]:
                    origin = w["origin"]
                    raw = bytes.fromhex(w["bytes"])
                    self.assertEqual(self.originals[origin["image"]["name"]]
                                     [origin["offset"]:origin["offset"] + len(raw)], raw)
        for image in self.manifest["images"]:
            self.assertEqual(hashlib.sha256(self.originals[image["name"]]).hexdigest(), image["sha256"])

    def test_fetch_assigns_eof_without_claiming_alternate_path(self):
        region = self.by_entry["PLI.COM+0AF5"]
        self.assertEqual(region["completeness"],
                         {"bounds": "provisional", "control_flow": "partial", "contract": "partial"})
        eof = next(r for r in region["representatives"] if r["ret"]["after"]["a"] == 0x1A)
        altered = copy.deepcopy(eof)
        at(local(altered), 0xB24)[0]["writes"][0]["new_value"] = 3
        with self.assertRaisesRegex(ValueError, "EOF assignment"):
            validate(altered)

    def test_mutable_table_getter_and_setter_share_mapping(self):
        for key in ("PLI2.OVL+04BF", "PLI2.OVL+04D3", "PLI2.OVL+061B", "PLI1.OVL+4281"):
            self.assertEqual(self.by_entry[key]["completeness"],
                             {"bounds": "stable", "control_flow": "complete", "contract": "complete"})
        r = copy.deepcopy(self.by_entry["PLI2.OVL+061B"]["representatives"][0])
        at(local(r), 0x634)[0]["writes"][0]["address"] += 1
        with self.assertRaisesRegex(ValueError, "table write"):
            validate(r)

    def test_pointer_boolean_is_a_and_carry(self):
        region = self.by_entry["PLI1.OVL+4281"]
        self.assertEqual(region["outcomes"], [{"a": 0, "carry": False, "count": 5},
                                               {"a": 255, "carry": True, "count": 6}])
        r = copy.deepcopy(region["representatives"][0])
        r["ret"]["after"]["flags"]["carry"] = not r["ret"]["after"]["flags"]["carry"]
        with self.assertRaisesRegex(ValueError, "pointer Boolean"):
            validate(r)

    def test_span_fold_checks_modular_candidate_and_max(self):
        region = self.by_entry["PLI2.OVL+09BA"]
        self.assertEqual(region["status"], "UNDERSTOOD")
        self.assertEqual(region["completeness"]["contract"], "partial")
        r = copy.deepcopy(next(r for r in region["representatives"] if at(local(r), 0xAC6)))
        at(local(r), 0xAC6)[0]["writes"][0]["new_value"] ^= 1
        with self.assertRaisesRegex(ValueError, "candidate recurrence"):
            validate(r)
        # LHLD AC3F / XCHG loads the adjacent candidate into D as well as
        # the accumulator into E; the parent does not preserve caller D.
        r = copy.deepcopy(region["representatives"][-1])
        r["ret"]["after"]["d"] ^= 1
        with self.assertRaisesRegex(ValueError, "loop termination mismatch"):
            validate(r)

    def test_recursion_has_own_hardware_slot_and_frame(self):
        region = self.by_entry["PLI0.OVL+24BC"]
        self.assertEqual(region["bounds"], [0x24BC, 0x289B])
        self.assertEqual(region["nested_calls"]["PLI0.OVL+24BC"], 20)
        self.assertEqual(region["own_instruction_occurrences"], 11322)
        self.assertEqual(region["status"], "STRUCTURED")
        for r in region["representatives"]:
            self.assertEqual(len(at(local(r), 0x24BC)), 1)
            self.assertEqual(r["ret"]["sp_before"], r["entry"]["before"]["sp"])
        r = copy.deepcopy(region["representatives"][0])
        at(local(r), 0x24C3)[0]["sp_after"] += 1
        with self.assertRaisesRegex(ValueError, "18-byte local frame"):
            validate(r)

    def test_dynamic_metric_exact_counts_and_denominator(self):
        # Pass-3 metrics are an immutable snapshot; validate live classification
        # against the current baseline artifact after later intentional passes.
        self.assertEqual(calculate(self.manifest, self.instructions),
                         read(ROOT / "research/minimal-baseline/dynamic-progress.json"))
        totals = self.dynamic["total"]
        self.assertEqual(totals["instruction_occurrences"], 439998)
        self.assertEqual(totals["occurrences_by_status"],
                         {"RAW": 191972, "DECODED": 63790, "STRUCTURED": 58691, "UNDERSTOOD": 125545})
        self.assertEqual(sum(totals["occurrences_by_status"].values()), 439998)
        self.assertEqual(self.dynamic["outside_historical_images"], 1857)
        self.assertAlmostEqual(totals["understood_percent"], 100 * 125545 / 439998, places=6)
        bad = copy.deepcopy(self.instructions)
        bad[0]["image_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "identity/runtime"):
            calculate(self.manifest, bad)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            calculate(self.manifest, self.instructions + [self.instructions[0]])

    def test_dynamic_metric_rejects_mixed_instruction_status(self):
        manifest = {"images": [{"name": "X", "sha256": "H", "runtime_base": 256, "length": 3,
                                "sections": [{"start_offset": 0, "end_offset": 1, "length": 1, "status": "UNDERSTOOD"},
                                             {"start_offset": 1, "end_offset": 3, "length": 2, "status": "RAW"}]}]}
        rows = [{"image": "X", "image_sha256": "H", "offset": 0, "runtime_pc": 256,
                 "bytes": "210000", "execution_count": 2}]
        with self.assertRaisesRegex(ValueError, "straddles statuses"):
            calculate(manifest, rows)

    def test_progress_and_prior_labels_survive_promotion(self):
        def totals(rows):
            return {s: sum(r["executed_status_bytes"][s] for r in rows)
                    for s in ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")}
        self.assertEqual(totals(self.progress["coverage_before"]),
                         {"RAW": 18991, "DECODED": 304, "STRUCTURED": 862, "UNDERSTOOD": 855})
        self.assertEqual(totals(self.progress["coverage_after"]),
                         {"RAW": 18018, "DECODED": 304, "STRUCTURED": 1523, "UNDERSTOOD": 1167})
        self.assertEqual(self.progress["classification_after"],
                         {"UNDERSTOOD": 36, "STRUCTURED": 10, "unresolved": 345})
        for image in self.manifest["images"]:
            text = (ROOT / "research/annotated-assembly" / image["source"]).read_text()
            for offset in image.get("coordinate_only_labels", []):
                self.assertRegex(text, rf"{image['label_prefix']}_{offset:04X}: EQU 0{image['runtime_base'] + offset:04X}H")
        for audit in self.progress["stable_label_audit"]:
            self.assertFalse(audit["removed_coordinates"])
            source = (ROOT / "research/annotated-assembly" / audit["source"]).read_text()
            labels = set(re.findall(r"^([A-Z0-9]+_[0-9A-F]+):", source, re.MULTILINE))
            self.assertTrue(set(audit["prior_labels"]) <= labels)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True)
    args, rest = parser.parse_known_args()
    IMAGES = args.images
    unittest.main(argv=[sys.argv[0], *rest])
