#!/usr/bin/env python3
"""Pass-4 byte identities, eight contracts, caller refinement and dynamic progress."""

import argparse
import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

from check_minimal_pass_4 import at, local, validate
from minimal_dynamic_progress import calculate

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "research/minimal-baseline"
PASS = BASE / "pass-4"
ASM = ROOT / "research/annotated-assembly"


def read(path):
    return json.loads(path.read_text())


class MinimalPassFourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions = read(PASS / "regions.json")
        cls.by_entry = {r["entry"]: r for r in cls.regions}
        cls.progress = read(PASS / "progress.json")
        cls.dynamic = read(PASS / "dynamic-progress.json")
        cls.refinement = read(PASS / "caller-refinements.json")
        cls.manifest = read(ASM / "manifest.json")
        cls.catalog = {p["id"]: p for p in read(ASM / "procedures.json")["procedures"]}
        cls.instructions = [json.loads(line) for line in (BASE / "instructions.jsonl").read_text().splitlines()]
        cls.originals = {i["name"]: (IMAGES / i["name"]).read_bytes() for i in cls.manifest["images"]}

    def test_invocations_and_original_witness_bytes(self):
        self.assertEqual(len(self.regions), 8)
        self.assertEqual(sum(r["invocations_checked"] for r in self.regions), 1308)
        self.assertEqual(sum(r["own_instruction_occurrences"] for r in self.regions), 35488)
        for region in self.regions:
            for sample in region["representatives"]:
                validate(sample)
                witnesses = [sample["call"], *local(sample)]
                witnesses += [w for group in sample.get("dependency_reads", {}).values() for w in group]
                for w in witnesses:
                    o = w["origin"]
                    raw = bytes.fromhex(w["bytes"])
                    self.assertEqual(self.originals[o["image"]["name"]][o["offset"]:o["offset"] + len(raw)], raw)
        for image in self.manifest["images"]:
            self.assertEqual(hashlib.sha256(self.originals[image["name"]]).hexdigest(), image["sha256"])

    def test_field_test_is_equality_not_ordering(self):
        region = self.by_entry["PLI0.OVL+240B"]
        self.assertEqual(region["outcomes"], [{"a": 0, "carry": False, "count": 136},
                                               {"a": 255, "carry": True, "count": 16}])
        less = next(r for r in region["representatives"] if
                    (at(local(r), 0x2422)[0]["reads"][0]["value"] & 7) < r["entry"]["before"]["c"])
        self.assertEqual(less["ret"]["after"]["a"], 0)
        bad = copy.deepcopy(less)
        bad["ret"]["after"]["a"] = 255
        bad["ret"]["after"]["flags"]["carry"] = True
        with self.assertRaisesRegex(ValueError, "equality Boolean"):
            validate(bad)

    def test_scan_both_exits_have_distinct_flags(self):
        region = self.by_entry["PLI0.OVL+23DF"]
        self.assertEqual(region["hardware_return_sites"], {"PLI0.OVL+2406": 84, "PLI0.OVL+240A": 1})
        samples = {r["ret"]["origin"]["offset"]: r for r in region["representatives"]}
        self.assertTrue(samples[0x2406]["ret"]["after"]["flags"]["zero"])
        self.assertFalse(samples[0x240A]["ret"]["after"]["flags"]["zero"])
        self.assertEqual(samples[0x240A]["ret"]["after"]["a"], 0)
        bad = copy.deepcopy(samples[0x2406])
        at(local(bad), 0x23F5)[0]["writes"][0]["new_value"] ^= 1
        with self.assertRaisesRegex(ValueError, "pointer advance"):
            validate(bad)

    def test_tail_copy_order_and_arithmetic_return(self):
        region = self.by_entry["PLI0.OVL+1A47"]
        self.assertEqual(region["nested_calls"], {"PLI.COM+1A33": 1219})
        self.assertEqual(region["own_instruction_occurrences"], 19414)
        sample = next(r for r in region["representatives"] if at(local(r), 0x1A71))
        bad = copy.deepcopy(sample)
        at(local(bad), 0x1A71)[0]["writes"][0]["address"] -= 1
        with self.assertRaisesRegex(ValueError, "copy/order"):
            validate(bad)

    def test_window_initializer_propagates_guarded_extent(self):
        init = self.by_entry["PLI0.OVL+1A8C"]
        self.assertEqual(init["nested_calls"], {"PLI0.OVL+1A14": 87, "PLI0.OVL+1A47": 87})
        reserve = self.by_entry["PLI0.OVL+1A14"]
        bad = copy.deepcopy(reserve["representatives"][0])
        bad["dependency_reads"]["working_base"][0]["reads"][0]["value"] ^= 1
        with self.assertRaisesRegex(ValueError, "address/difference formula"):
            validate(bad)
        bad = copy.deepcopy(init["representatives"][0])
        at(local(bad), 0x1A96)[0]["writes"][0]["new_value"] ^= 1
        with self.assertRaisesRegex(ValueError, "working-window initialization"):
            validate(bad)

    def test_pli1_lookup_preserves_flags_and_unsigned_position(self):
        region = self.by_entry["PLI1.OVL+7A4D"]
        self.assertFalse(region["nested_calls"])
        self.assertTrue(any(r["entry"]["before"]["c"] >= 254 for r in region["representatives"]))
        bad = copy.deepcopy(region["representatives"][0])
        bad["ret"]["after"]["flags"]["zero"] = not bad["ret"]["after"]["flags"]["zero"]
        with self.assertRaisesRegex(ValueError, "preserved flags"):
            validate(bad)

    def test_console_gate_retains_distinct_plain_output_contract(self):
        region = self.by_entry["PLI.COM+0390"]
        self.assertEqual(region["nested_calls"], {"PLI.COM+0380": 424})
        self.assertEqual(region["completeness"]["contract"], "partial")
        bad = copy.deepcopy(region["representatives"][0])
        at(local(bad), 0x3E5)[0]["before"]["c"] ^= 1
        with self.assertRaisesRegex(ValueError, "routing/cache"):
            validate(bad)

    def test_caller_refinement_is_local_readable_and_remains_partial(self):
        ref = self.refinement
        caller = self.catalog["PLI0.OVL+24BC"]
        self.assertEqual(ref["status_after"], "STRUCTURED")
        self.assertEqual(caller["completeness"], {"bounds": "provisional", "control_flow": "partial", "contract": "partial"})
        # Pass-4 is a historical snapshot. Later evidence-backed corrections
        # refine this caller without rewriting the snapshot or promoting bytes.
        for term in ("field_equal240B", "scan23DF", "begin_window1A8C"):
            self.assertIn(term, ref["pseudocode_after"])
            self.assertIn(term, caller["pseudocode"])
            self.assertTrue(any(term in " ".join(b["pseudocode"]) for b in caller["blocks"]))
        self.assertIn("+21AB", " ".join(caller["unresolved_paths"]))
        self.assertEqual(ref["new_byte_promotions"], 0)

    def test_static_dynamic_and_callable_progress(self):
        def totals(rows):
            return {s: sum(r["executed_status_bytes"][s] for r in rows)
                    for s in ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")}
        self.assertEqual(totals(self.progress["coverage_before"]),
                         {"RAW": 18018, "DECODED": 304, "STRUCTURED": 1523, "UNDERSTOOD": 1167})
        self.assertEqual(totals(self.progress["coverage_after"]),
                         {"RAW": 17766, "DECODED": 304, "STRUCTURED": 1523, "UNDERSTOOD": 1419})
        self.assertEqual(self.progress["classification_after"], {"UNDERSTOOD": 44, "STRUCTURED": 10, "unresolved": 337})
        # Keep this pass snapshot immutable as later annotations accumulate.
        self.assertEqual(calculate(self.manifest, self.instructions), read(BASE / "dynamic-progress.json"))
        self.assertEqual(self.dynamic["total"]["occurrences_by_status"],
                         {"RAW": 156484, "DECODED": 63790, "STRUCTURED": 58691, "UNDERSTOOD": 161033})
        self.assertEqual(sum(r["newly_promoted_bytes"] for r in self.regions), 252)
        self.assertAlmostEqual(self.dynamic["total"]["understood_percent"], 100 * 161033 / 439998, places=6)

    def test_unobserved_paths_stay_raw_and_completeness_independent(self):
        def status(name, o):
            return next(s["status"] for i in self.manifest["images"] if i["name"] == name
                        for s in i["sections"] if s["start_offset"] <= o < s["end_offset"])
        for name, o in [("PLI0.OVL", 0x2416), ("PLI0.OVL", 0x1A25), ("PLI0.OVL", 0x1A43),
                        ("PLI0.OVL", 0x1A7D), ("PLI.COM", 0x39B), ("PLI.COM", 0x3D7)]:
            self.assertEqual(status(name, o), "RAW")
        self.assertEqual(self.by_entry["PLI0.OVL+1A8C"]["completeness"],
                         {"bounds": "stable", "control_flow": "complete", "contract": "partial"})
        for key in ("PLI0.OVL+23DF", "PLI0.OVL+1A47", "PLI0.OVL+4662", "PLI1.OVL+7A4D"):
            self.assertEqual(self.by_entry[key]["completeness"],
                             {"bounds": "stable", "control_flow": "complete", "contract": "complete"})

    def test_all_prior_labels_retained_and_next_queue_is_not_decompiled(self):
        for audit in self.progress["stable_label_audit"]:
            text = (ASM / audit["source"]).read_text()
            labels = set(re.findall(r"^([A-Z0-9]+_[0-9A-F]+):", text, re.MULTILINE))
            self.assertFalse(audit["removed_coordinates"])
            self.assertTrue(set(audit["prior_labels"]) <= labels)
        for r in self.progress["next_targets"]:
            self.assertNotIn(r["entry"], self.catalog)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True)
    args, rest = parser.parse_known_args()
    IMAGES = args.images
    unittest.main(argv=[sys.argv[0], *rest])
