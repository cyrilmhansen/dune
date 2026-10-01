#!/usr/bin/env python3
"""Durable MINIMAL pass-2 contracts, boundaries, flags and corroborating evidence."""

import argparse
import copy
import hashlib
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_2 import at, local, validate

ROOT = Path(__file__).resolve().parents[2]
PASS = ROOT / "research/minimal-baseline/pass-2"


class MinimalPassTwoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions = json.loads((PASS / "regions.json").read_text())
        cls.by_entry = {r["entry"]: r for r in cls.regions}
        cls.progress = json.loads((PASS / "progress.json").read_text())
        cls.corroboration = json.loads((PASS / "corroboration.json").read_text())
        cls.manifest = json.loads(
            (ROOT / "research/annotated-assembly/manifest.json").read_text()
        )
        cls.originals = {
            i["name"]: (IMAGES / i["name"]).read_bytes() for i in cls.manifest["images"]
        }

    def test_all_representatives_and_checked_counts(self):
        self.assertEqual(len(self.regions), 10)
        self.assertEqual(sum(r["invocations_checked"] for r in self.regions), 417)
        for region in self.regions:
            for representative in region["representatives"]:
                validate(representative)
        self.assertEqual(
            Counter(r["status"] for r in self.regions),
            {"UNDERSTOOD": 9, "STRUCTURED": 1},
        )

    def test_predicate_boolean_and_carry_are_distinct(self):
        predicate = self.by_entry["PLI2.OVL+1DFF"]
        self.assertEqual(
            predicate["outcomes"],
            [
                {"a": 0, "carry": False, "count": 1},
                {"a": 0, "carry": True, "count": 1},
                {"a": 1, "carry": False, "count": 11},
            ],
        )
        self.assertEqual(
            predicate["hardware_return_sites"],
            {"PLI2.OVL+1E74": 2, "PLI2.OVL+1FB4": 11},
        )
        for r in predicate["representatives"]:
            reads_writes = [
                q["address"] for w in local(r) for q in w["reads"] + w["writes"]
            ]
            self.assertNotIn(0xAD0A, reads_writes)
            self.assertEqual(r["relation"]["type"], "hardware_frame_return")

    def test_lookup_is_a_leaf_with_preserved_flags(self):
        for key in ("PLI2.OVL+047D", "PLI2.OVL+04A9"):
            self.assertEqual(self.by_entry[key]["nested_calls"], [])
            for r in self.by_entry[key]["representatives"]:
                self.assertFalse(r["ret"]["after"]["flags"]["carry"])
                self.assertEqual(
                    {
                        k: v
                        for k, v in r["ret"]["after"]["flags"].items()
                        if k != "carry"
                    },
                    {
                        k: v
                        for k, v in r["entry"]["before"]["flags"].items()
                        if k != "carry"
                    },
                )

    def test_allocator_has_ordinary_slot_and_exact_local_extent(self):
        region = self.by_entry["PLI1.OVL+4394"]
        self.assertEqual(region["bounds"], [0x4394, 0x43D5])
        self.assertEqual(region["hardware_return_sites"], {"PLI1.OVL+43D4": 3})
        for r in region["representatives"]:
            self.assertEqual(r["call"]["sp_after"], r["ret"]["sp_before"])
            self.assertEqual(r["relation"]["type"], "hardware_frame_return")
        self.assertEqual(self.by_entry["PLI1.OVL+8396"]["bounds"], [0x8396, 0x83A0])
        self.assertEqual(self.by_entry["PLI.COM+0D40"]["bounds"], [0xD40, 0xE1F])

    def test_append_flags_describe_index_not_data(self):
        representatives = self.by_entry["PLI.COM+0E1F"]["representatives"]
        first = next(
            r
            for r in representatives
            if at(local(r), 0xE23)[0]["reads"][0]["value"] == 255
        )
        self.assertTrue(first["ret"]["after"]["flags"]["zero"])
        self.assertNotEqual(first["ret"]["after"]["a"], 0)
        changed = copy.deepcopy(first)
        changed["ret"]["after"]["flags"]["zero"] = False
        with self.assertRaisesRegex(ValueError, "second INR"):
            validate(changed)

    def test_corroboration_is_not_applied_to_minimal_unchanged(self):
        j = self.corroboration
        proofs = {p["call"]["step_index"]: p for p in j["proofs"]}
        group = j["comparison_groups"]["OPTIMIST_three_rejected_fourth_accepted"]
        self.assertEqual([proofs[s]["result_a"] for s in group], [0, 0, 0, 1])
        self.assertEqual(
            [proofs[s]["ordinal_writer"]["writes"][0]["new_value"] for s in group],
            [1, 2, 3, 4],
        )
        self.assertEqual(
            [
                p["ordinal_writer"]["writes"][0]["new_value"]
                for p in j["MINIMAL_candidate_calls"]
            ],
            [1, 2],
        )
        self.assertTrue(all(p["result_a"] == 0 for p in j["MINIMAL_candidate_calls"]))
        for p in j["proofs"]:
            call, ret = p["call"], p["ret"]
            self.assertEqual(call["sp_after"], ret["sp_before"])
            self.assertEqual(call["call_return_address"], ret["pc_after"])
            self.assertEqual(
                {x["address"]: x["new_value"] for x in call["writes"]},
                {x["address"]: x["value"] for x in ret["reads"]},
            )
            for w in (call, ret):
                o = w["origin"]
                b = bytes.fromhex(w["bytes"])
                self.assertEqual(
                    self.originals[o["image"]["name"]][
                        o["offset"] : o["offset"] + len(b)
                    ],
                    b,
                )
        self.assertEqual(
            hashlib.sha256(self.originals["PLI2.OVL"]).hexdigest(), j["image_sha256"]
        )

    def test_byte_and_procedure_progress(self):
        p = self.progress
        totals = lambda rows: {
            s: sum(r["executed_status_bytes"][s] for r in rows)
            for s in ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")
        }
        self.assertEqual(
            totals(p["coverage_before"]),
            {"RAW": 19574, "DECODED": 304, "STRUCTURED": 659, "UNDERSTOOD": 475},
        )
        self.assertEqual(
            totals(p["coverage_after"]),
            {"RAW": 18991, "DECODED": 304, "STRUCTURED": 862, "UNDERSTOOD": 855},
        )
        self.assertEqual(sum(r["executed_bytes"] for r in p["coverage_after"]), 21012)
        self.assertEqual(p["classification_before"]["UNDERSTOOD"], 21)
        self.assertEqual(
            p["classification_after"],
            {"UNDERSTOOD": 30, "STRUCTURED": 9, "unresolved": 352},
        )
        self.assertEqual(sum(i["length"] for i in self.manifest["images"]), 94720)
        self.assertEqual(
            [r["sha256"] for r in p["whole_image_progress_before"]],
            [r["sha256"] for r in p["whole_image_progress_after"]],
        )

    def test_contract_and_hardware_counterexamples(self):
        for key in ("PLI2.OVL+047D", "PLI1.OVL+4394", "PLI.COM+0D40"):
            r = copy.deepcopy(self.by_entry[key]["representatives"][0])
            r["ret"]["after"]["a"] ^= 1
            with self.assertRaises(ValueError):
                validate(r)
        r = copy.deepcopy(self.by_entry["PLI2.OVL+1DFF"]["representatives"][0])
        r["ret"]["reads"][0]["value"] ^= 1
        with self.assertRaisesRegex(ValueError, "hardware return"):
            validate(r)

    def test_unprocessed_paths_and_neighbor_entries_stay_raw(self):
        points = {
            "PLI2.OVL": [0x1E75, 0x1E80, 0x1EA4, 0x1F53],
            "PLI.COM": [0xD09, 0xD3F, 0xDA2, 0xDC7, 0xE13, 0xE41, 0x5B9, 0x5F8],
            "PLI1.OVL": [0x43B8, 0x43D5, 0x83A0],
        }
        for name, offsets in points.items():
            sections = next(
                i["sections"] for i in self.manifest["images"] if i["name"] == name
            )
            for o in offsets:
                self.assertEqual(
                    next(
                        s["status"]
                        for s in sections
                        if s["start_offset"] <= o < s["end_offset"]
                    ),
                    "RAW",
                )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--images", type=Path, required=True)
    a, rest = p.parse_known_args()
    IMAGES = a.images.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
