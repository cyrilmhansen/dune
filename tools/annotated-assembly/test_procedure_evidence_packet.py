#!/usr/bin/env python3
"""Packet joins, failure detection, deterministic output and recursive isolation."""

import argparse
import copy
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_3 import gather
from minimal_baseline import load
from procedure_evidence_packet import ROOT, TARGET, build, render, role_matches, validate_packet


class ProjectionTests(unittest.TestCase):
    def test_recursive_children_and_nested_memory_stay_separate(self):
        # Both invocations execute the same coordinates. Extent filtering would
        # incorrectly put the child's instructions in the parent.
        origin = {"image": {"name": "PLI0.OVL"}, "offset": 0x24BC}

        def instruction(step, kind="sequential", writes=None):
            return {"type": "instruction", "witness": {
                "step_index": step, "origin": origin, "target_origin": origin,
                "control": {"kind": kind, "taken": True},
                "reads": [], "writes": writes or []}}

        def returned(step, call):
            return {"type": "hardware_frame_return", "step_index": step,
                    "frame": {"call_step": call}}

        events = [instruction(0, "call"), instruction(1), instruction(2), instruction(3, "call"),
                  instruction(4, writes=[{"address": 123, "new_value": 42}]), instruction(5, "return"),
                  returned(5, 3), instruction(6), instruction(7, "return"), returned(7, 0)]
        with tempfile.TemporaryDirectory(prefix="atlas-evidence-packet-test-", dir="/tmp") as temp:
            capture = Path(temp)
            chunks = capture / "event-witnesses/chunks"
            chunks.mkdir(parents=True)
            (capture / "event-witnesses.json").write_text(json.dumps({"chunks": [{"id": 0}]}))
            (chunks / "000000.json").write_text(json.dumps({"events": events}))
            rs = gather(capture, {TARGET: (0x24BC, 0x289B)}, include_nested_returns=True)[TARGET]
            parent = next(r for r in rs if r["call"]["step_index"] == 0)
            child = next(r for r in rs if r["call"]["step_index"] == 3)
            self.assertEqual([w["step_index"] for w in parent["own_witnesses"]], [1, 2, 3, 6, 7])
            self.assertEqual([w["step_index"] for w in child["own_witnesses"]], [4, 5])
            self.assertEqual([w["step_index"] for w in parent["nested_returns"][3]["memory_witnesses"]], [4])
            (chunks / "000000.json").unlink()
            with self.assertRaises(FileNotFoundError):
                gather(capture, {TARGET: (0x24BC, 0x289B)})

    def test_unknown_role_length_does_not_invent_table_bounds(self):
        role = {"id": "X:t", "name": "t", "runtime_address": 100, "width": None}
        self.assertEqual(role_matches(101, [role]), [])
        self.assertEqual(role_matches(100, [role])[0]["address"], 100)


class ExistingMinimalPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = build(CAPTURE, IMAGES)
        cls.canonical = load(CAPTURE / "canonical-code-blocks.json")
        cls.dynamic = load(CAPTURE / "dynamic-blocks.json")
        cls.records = gather(CAPTURE, {TARGET: (0x24BC, 0x289B)}, include_nested_returns=True)[TARGET]
        cls.catalog = {p["id"]: p for p in load(ROOT / "research/annotated-assembly/procedures.json")["procedures"]}

    def check(self, packet):
        validate_packet(packet, self.canonical, self.dynamic, self.records, self.catalog)

    def test_source_counts_and_unchanged_accumulated_knowledge(self):
        self.assertEqual(self.packet["quality_checks"], {
            "invocations": 85, "local_instruction_occurrences": 11322,
            "local_instruction_coordinates": 371, "derived_blocks": 60,
            "invocation_path_classes": 13, "recursive_children": 20})
        source = json.loads((ROOT / "research/minimal-baseline/pass-3/regions.json").read_text())
        region = next(r for r in source if r["entry"] == TARGET)
        actual = Counter((self.packet["instructions"][k]["coordinate"]["offset"],
                          self.packet["steps"][str(s["step"])]["pc_after"], s["taken"])
                         for k, b in self.packet["branches"].items() for s in b["observations"])
        self.assertEqual(actual, Counter({(b["offset"], b["runtime_after"], b["taken"]): b["count"]
                                          for b in region["branches"]}))
        self.assertEqual(self.packet["accumulated_knowledge"]["procedure"], self.catalog[TARGET])
        self.assertEqual(len(self.packet["calls"]), 246)
        self.check(self.packet)

    def test_every_member_keeps_correlated_data_and_local_frame(self):
        invocations = {r["call_step"]: r for r in self.packet["invocations"]}
        for c in self.packet["invocation_classes"]:
            self.assertEqual(c["count"], len(c["invocations"]))
            for n in c["invocations"]:
                r = invocations[n]
                entry = self.packet["steps"][str(r["entry_step"])]["before"]
                self.assertEqual(entry["sp"] - 18, r["F"])
                self.assertEqual(entry["c"], c["distinguishing_observed_conditions"]["entry_C"])
                self.assertTrue(r["local_steps"])
                self.assertEqual(self.packet["steps"][str(r["return_step"])]["scope"], "local")
        # Different input counts within one path remain distinct, fully retained
        # records, rather than a cross product of independent sets.
        many = next(c for c in self.packet["invocation_classes"] if c["count"] == 54)
        self.assertGreater(len({invocations[n]["initial_local_bytes"][11]["value"]
                                for n in many["invocations"]}), 1)

    def test_detects_corrupt_bytes_and_branch_counts(self):
        p = copy.deepcopy(self.packet)
        p["instructions"][TARGET]["bytes"] = "00"
        with self.assertRaisesRegex(ValueError, "Instruction coordinate/bytes/count"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        next(iter(p["branches"].values()))["outcomes"][0]["count"] += 1
        with self.assertRaisesRegex(ValueError, "Branch outcome"):
            self.check(p)

    def test_detects_lost_recursive_ownership_and_frame_offsets(self):
        p = copy.deepcopy(self.packet)
        child = next(c["recursive_child_invocation"] for c in p["calls"].values()
                     if c["recursive_child_invocation"] is not None)
        invocation = next(r for r in p["invocations"] if r["call_step"] == child)
        p["steps"][str(invocation["return_step"])]["invocation"] = -1
        with self.assertRaisesRegex(ValueError, "Local ownership"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        q = next(q for w in p["steps"].values() for q in w["writes"] if "deduced_frame_relation" in q)
        q["deduced_frame_relation"]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "Frame offset"):
            self.check(p)

    def test_detects_role_address_and_call_join_corruption(self):
        p = copy.deepcopy(self.packet)
        role = next(role for w in p["steps"].values() for q in w["writes"]
                    for role in q.get("joined_roles", []))
        role["address"] += 1
        with self.assertRaisesRegex(ValueError, "Role erased"):
            self.check(p)
        p = copy.deepcopy(self.packet)
        next(iter(p["calls"].values()))["post_return_state_step"] += 1
        with self.assertRaisesRegex(ValueError, "Call return join"):
            self.check(p)

    def test_deterministic_regeneration(self):
        regenerated = build(CAPTURE, IMAGES)
        self.assertEqual(json.dumps(self.packet, separators=(",", ":")),
                         json.dumps(regenerated, separators=(",", ":")))
        self.assertEqual(render(self.packet), render(regenerated))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--capture", type=Path, default=ROOT / "_build/minimal-baseline/capture")
    args, rest = parser.parse_known_args()
    IMAGES, CAPTURE = args.images, args.capture
    unittest.main(argv=[sys.argv[0], *rest])
