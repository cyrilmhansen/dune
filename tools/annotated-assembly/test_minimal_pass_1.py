#!/usr/bin/env python3
"""Validate reviewed MINIMAL pass-1 contracts and unchanged historical identities."""

import argparse
import copy
import json
import sys
import unittest
from pathlib import Path

import verify as assembly_verify
from check_minimal_pass_1 import check_software, validate

ROOT = Path(__file__).resolve().parents[2]
PASS = ROOT / "research/minimal-baseline/pass-1"


class MinimalPassOneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions = json.loads((PASS / "regions.json").read_text())
        cls.callbacks = json.loads((PASS / "continuation-entries.json").read_text())
        cls.progress = json.loads((PASS / "progress.json").read_text())
        cls.manifest = json.loads(
            (ROOT / "research/annotated-assembly/manifest.json").read_text()
        )
        cls.evidence = json.loads(
            (ROOT / "research/annotated-assembly/evidence.json").read_text()
        )
        cls.originals = {
            i["name"]: (IMAGES / i["name"]).read_bytes() for i in cls.manifest["images"]
        }

    def test_all_representative_contracts(self):
        self.assertEqual(len(self.regions), 9)
        self.assertEqual(sum(r["invocations_checked"] for r in self.regions), 1104)
        for region in self.regions:
            for representative in region["representatives"]:
                validate(representative)
        self.assertEqual(
            {r["entry"] for r in self.regions if r["status"] == "UNDERSTOOD"},
            {
                "PLI.COM+070C",
                "PLI.COM+12AE",
                "PLI1.OVL+4693",
                "PLI0.OVL+23C3",
                "PLI.COM+09CB",
                "PLI.COM+0AA9",
            },
        )

    def test_new_byte_status_metrics_and_identity(self):
        before = self.progress["coverage_before"]
        after = self.progress["coverage_after"]
        self.assertEqual(sum(r["executed_bytes"] for r in before), 21012)
        self.assertEqual(sum(r["executed_bytes"] for r in after), 21012)
        totals = lambda rows: {
            status: sum(r["executed_status_bytes"][status] for r in rows)
            for status in ("RAW", "DECODED", "STRUCTURED", "UNDERSTOOD")
        }
        self.assertEqual(
            totals(before),
            {"RAW": 20422, "DECODED": 304, "STRUCTURED": 138, "UNDERSTOOD": 148},
        )
        self.assertEqual(
            totals(after),
            {"RAW": 19574, "DECODED": 304, "STRUCTURED": 659, "UNDERSTOOD": 475},
        )
        self.assertEqual(self.progress["classification_before"]["UNDERSTOOD"], 15)
        self.assertEqual(self.progress["classification_after"]["UNDERSTOOD"], 21)
        self.assertEqual(
            [r["sha256"] for r in self.progress["whole_image_progress_before"]],
            [r["sha256"] for r in self.progress["whole_image_progress_after"]],
        )
        self.assertEqual(sum(i["length"] for i in self.manifest["images"]), 94720)

    def test_pchl_entries_keep_separate_software_frames(self):
        self.assertEqual(len(self.callbacks), 11)
        self.assertEqual(len({r["entry"] for r in self.callbacks}), 11)
        for callback in self.callbacks:
            check_software(callback["proof"])
            self.assertEqual(callback["transfer"]["bytes"], "E9")
            self.assertEqual(
                callback["entry_witness"]["pc"], callback["transfer"]["pc_after"]
            )
            self.assertEqual(callback["proof"]["ret"]["pc_after"], 0x42B4)
            self.assertEqual(callback["classification"], "unresolved")
            for witness in (
                callback["entry_witness"],
                callback["transfer"],
                callback["proof"]["writer"],
                callback["proof"]["ret"],
            ):
                origin = witness["origin"]
                raw = bytes.fromhex(witness["bytes"])
                data = self.originals[origin["image"]["name"]]
                self.assertEqual(
                    data[origin["offset"] : origin["offset"] + len(raw)], raw
                )

    def test_argument_consuming_callee_is_not_wrapper_body(self):
        ctor = next(r for r in self.regions if r["entry"] == "PLI1.OVL+4468")
        self.assertEqual(len(ctor["representatives"]), 2)
        for representative in ctor["representatives"]:
            self.assertEqual(
                representative["ret"]["sp_before"] - representative["call"]["sp_after"],
                2,
            )
            self.assertEqual(
                representative["ret"]["sp_after"] - representative["call"]["sp_after"],
                4,
            )
            check_software(representative["software_proof"])
        wrappers = [
            r for r in self.regions if r["entry"] in ("PLI1.OVL+4693", "PLI1.OVL+4738")
        ]
        self.assertTrue(all(r["bounds"][0] > ctor["bounds"][1] for r in wrappers))
        self.assertEqual(
            [r["bounds"] for r in wrappers], [[0x4693, 0x46A7], [0x4738, 0x478D]]
        )

    def test_gateway_restoration_counterexample(self):
        gateway = copy.deepcopy(
            next(r for r in self.regions if r["entry"] == "PLI2.OVL+1FB5")[
                "representatives"
            ][0]
        )
        step = next(w for w in gateway["witnesses"] if w["origin"]["offset"] == 0x20D6)
        step["writes"][0]["new_value"] ^= 1
        with self.assertRaisesRegex(ValueError, "saved state not restored"):
            validate(gateway)

    def test_predicate_and_quote_counterexamples(self):
        for entry in ("PLI0.OVL+23C3", "PLI.COM+09CB"):
            representative = copy.deepcopy(
                next(r for r in self.regions if r["entry"] == entry)["representatives"][
                    0
                ]
            )
            representative["ret"]["after"]["a"] ^= 1
            with self.assertRaises(ValueError):
                validate(representative)

    def test_software_writer_counterexample(self):
        proof = copy.deepcopy(self.callbacks[0]["proof"])
        proof["writer"]["writes"][0]["new_value"] ^= 1
        with self.assertRaisesRegex(ValueError, "writer/slot/bytes"):
            check_software(proof)
        evidence = copy.deepcopy(self.evidence)
        seed = next(s for s in evidence["seeds"] if s["id"] == "PLI1.OVL+4468")
        seed["software_return_sample"]["relation"]["low_byte_writer"]["step"] += 1
        with self.assertRaisesRegex(assembly_verify.VerificationError, "latest-writer"):
            assembly_verify.check_evidence(
                evidence,
                {i["name"]: i for i in self.manifest["images"]},
                self.originals,
            )

    def test_unexercised_branches_remain_raw(self):
        points = {
            "PLI2.OVL": [0x203E, 0x2092, 0x20BB],
            "PLI1.OVL": [0x44E7],
            "PLI.COM": [0x9D9, 0xA0D, 0xA44, 0xA67, 0xAB0],
        }
        for image, offsets in points.items():
            sections = next(
                i["sections"] for i in self.manifest["images"] if i["name"] == image
            )
            for offset in offsets:
                self.assertEqual(
                    next(
                        s["status"]
                        for s in sections
                        if s["start_offset"] <= offset < s["end_offset"]
                    ),
                    "RAW",
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    args, rest = parser.parse_known_args()
    IMAGES = args.images.resolve()
    unittest.main(argv=[sys.argv[0], *rest])
