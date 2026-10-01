#!/usr/bin/env python3
"""V1 conventions: readable source, independent completeness and immutable encodings."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import decompilation_annotations as annotations

ROOT = Path(__file__).resolve().parents[2] / "research/annotated-assembly"


def read(path):
    return json.loads(path.read_text())


def surface(path):
    return (
        "\n".join(
            line.split(";", 1)[0].rstrip()
            for line in path.read_text().splitlines()
            if line.split(";", 1)[0].strip()
        )
        + "\n"
    )


class DecompilationConventionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = read(ROOT / "manifest.json")
        cls.evidence = read(ROOT / "evidence.json")
        cls.catalog = read(ROOT / "procedures.json")
        cls.review = read(ROOT / "conventions-v1-review.json")

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="atlas-conventions-v1-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for path in ROOT.iterdir():
            if path.suffix in (".asm", ".json"):
                shutil.copyfile(path, root / path.name)
        return root

    def test_all_existing_procedures_have_complete_headers_and_local_comments(self):
        annotations.validate(ROOT, self.manifest, self.evidence)
        self.assertEqual(
            {p["id"] for p in self.catalog["procedures"]},
            {s["id"] for s in self.evidence["seeds"]},
        )
        # The V1 review is an immutable snapshot; later passes add hypotheses.
        self.assertGreaterEqual(len(self.catalog["procedures"]), self.review["procedures_reviewed"])
        self.assertGreaterEqual(
            len(
                {
                    (p["image"], o)
                    for p in self.catalog["procedures"]
                    for o in p["local_comments"]
                }
            ),
            1054,
        )
        self.assertGreaterEqual(
            len(
                {
                    (p["image"], b["offset"])
                    for p in self.catalog["procedures"]
                    for b in p["blocks"]
                }
            ),
            145,
        )

    def test_historical_review_records_unchanged_surface_and_labels(self):
        # The immutable V1 audit must survive later intentional promotions;
        # live renderer immutability is tested separately below.
        for audit in self.review["images"]:
            self.assertEqual(
                audit["before_surface_sha256"], audit["after_surface_sha256"]
            )
            self.assertEqual(
                audit["before_labels_sha256"], audit["after_labels_sha256"]
            )
            image = next(
                i for i in self.manifest["images"] if i["name"] == audit["image"]
            )
            self.assertEqual(audit["original_sha256"], image["sha256"])

    def test_completeness_is_independent_from_understood_byte_status(self):
        p = {p["id"]: p for p in self.catalog["procedures"]}
        self.assertEqual(p["PLI.COM+09CB"]["byte_status_at_entry"], "UNDERSTOOD")
        self.assertEqual(
            p["PLI.COM+09CB"]["completeness"],
            {"bounds": "provisional", "control_flow": "partial", "contract": "partial"},
        )
        self.assertEqual(
            p["PLI2.OVL+047D"]["completeness"],
            {"bounds": "stable", "control_flow": "complete", "contract": "complete"},
        )
        self.assertEqual(p["PLI.COM+1A0F"]["completeness"]["control_flow"], "complete")
        self.assertIn("RNZ", p["PLI.COM+1A0F"]["observed_paths"]["description"])
        self.assertEqual(len(self.review["qualified_understood_entries"]), 13)

    def test_source_semantics_have_context_and_memory_width(self):
        lookup = (ROOT / "PLI2.asm").read_text()
        record = (ROOT / "PLI1.asm").read_text()
        self.assertIn("HL = &class_lookup_index (ABF8H)", lookup)
        self.assertIn("byte[class_lookup_index (ABF8H)] = C", lookup)
        self.assertIn("H = byte[ABF9H], later discarded", lookup)
        self.assertIn("BC = zero_extend(mapped byte j)", lookup)
        self.assertIn(
            "L = byte[repair_tag (A916H)]; H = byte[repair_saved_word (A917H)]", record
        )
        self.assertIn("record_floor_address (AE7AH literal guard)", record)

    def test_software_and_tail_returns_not_presented_as_local_hardware_returns(self):
        p = {p["id"]: p for p in self.catalog["procedures"]}
        self.assertIn(
            "two-byte caller argument cleanup",
            p["PLI1.OVL+4468"]["returns"]["convention"],
        )
        self.assertIn("no local RET", p["PLI.COM+19BB"]["returns"]["convention"])
        self.assertIn(
            "re-push original continuation two bytes", (ROOT / "PLI1.asm").read_text()
        )
        self.assertIn(
            "software continuation before PCHL", (ROOT / "PLI2.asm").read_text()
        )
        self.assertIn("second INR supplies return NZPA", (ROOT / "PLI.asm").read_text())

    def test_header_and_semantic_comment_removal_detected(self):
        root = self.fixture()
        path = root / "PLI2.asm"
        text = path.read_text()
        path.write_text(
            text.replace(
                "; Outputs: DEDUCED ABF8=input C", "; omitted: ABF8=input C", 1
            )
        )
        with self.assertRaisesRegex(ValueError, "source header mismatch"):
            annotations.validate(root, self.manifest, self.evidence)
        path.write_text(
            text.replace(" ; HL = &class_lookup_index (ABF8H) ; +047D", " ; +047D", 1)
        )
        with self.assertRaisesRegex(ValueError, "local semantic comment mismatch"):
            annotations.validate(root, self.manifest, self.evidence)

    def test_complete_claim_over_raw_holes_rejected(self):
        root = self.fixture()
        catalog = copy.deepcopy(self.catalog)
        procedure = next(p for p in catalog["procedures"] if p["id"] == "PLI.COM+05B2")
        procedure["completeness"]["contract"] = "complete"
        (root / "procedures.json").write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, "complete claim over RAW"):
            annotations.validate(root, self.manifest, self.evidence)

    def test_partial_contract_requires_explicit_scope(self):
        root = self.fixture()
        catalog = copy.deepcopy(self.catalog)
        procedure = next(p for p in catalog["procedures"] if p["id"] == "PLI.COM+09CB")
        procedure["contract_scope"] = ""
        (root / "procedures.json").write_text(json.dumps(catalog))
        with self.assertRaisesRegex(ValueError, "partial contract lacks scope"):
            annotations.validate(root, self.manifest, self.evidence)

    def test_renderer_idempotent_and_preserves_executable_surface(self):
        root = self.fixture()
        before = {
            i["source"]: (root / i["source"]).read_text()
            for i in self.manifest["images"]
        }
        statements = {
            i["source"]: surface(root / i["source"]) for i in self.manifest["images"]
        }
        annotations.render(root)
        for filename, text in before.items():
            self.assertEqual((root / filename).read_text(), text)
            self.assertEqual(surface(root / filename), statements[filename])
        annotations.validate(root, self.manifest, self.evidence)


if __name__ == "__main__":
    unittest.main()
