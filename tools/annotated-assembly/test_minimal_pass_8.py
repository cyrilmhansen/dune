#!/usr/bin/env python3
"""Continuation ancestry, argument layouts, actual overlaps and scoped callers."""
import argparse
import copy
import json
import sys
import unittest
from pathlib import Path

from check_minimal_pass_8 import ROOT,gather,check,forensic,validate_copy,validate_short,validate_reset
from software_continuation import prove
from minimal_dynamic_progress import calculate

PASS=ROOT/'research/minimal-baseline/pass-8'


class MinimalPassEightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records=gather(CAPTURE);cls.regions=check(cls.records);cls.by={r['entry']:r for r in cls.regions}
        cls.catalog={p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}

    def test_every_observed_continuation_has_original_source_and_copied_consumer(self):
        self.assertEqual(sum(r['invocations_checked'] for r in self.regions),12)
        for k,expected in [('PLI1.OVL+4468',2),('PLI1.OVL+6708',8),('PLI1.OVL+43D5',2)]:
            for r in self.records[k]:
                p=forensic(r);s=r['call']['sp_before']
                self.assertEqual(p['original_return_slot'],s-2)
                self.assertEqual(p['relocated_return_slot'],s+expected-2)
                self.assertEqual(r['ret']['sp_after'],s+expected)
                self.assertEqual(p['consumed_caller_bytes'],expected)
                self.assertEqual(p['continuation_register'],'DE')

    def test_same_return_value_in_another_slot_is_not_ancestry(self):
        r=copy.deepcopy(self.records['PLI1.OVL+43D5'][0]);prefix=r['continuation_sample']['prefix']
        pop=next(w for w in prefix if w['disassembly']=='POP D');pop['reads'][0]['address']+=2
        with self.assertRaisesRegex(ValueError,'original CALL slot'):
            forensic(r)
        r=copy.deepcopy(self.records['PLI1.OVL+6708'][0]);prefix=r['continuation_sample']['prefix']
        next(w for w in prefix if w['disassembly']=='DCX H' and w['step_index']>259551)['disassembly']='INX D'
        with self.assertRaisesRegex(ValueError,'DE ancestry'):
            forensic(r)

    def test_argument_order_and_unused_high_bytes(self):
        copies=self.by['PLI1.OVL+6708']['members']
        self.assertEqual([[a['value'] for a in m['arguments']] for m in copies],
                         [[0xFBD0,0xFB00,0xFBC6,0x002B],[0xFBD0,0xC602,0xFBC6,0x002B]])
        self.assertEqual([[a['producer'] for a in m['arguments']] for m in copies],
                         [['PLI1.OVL+2973','PLI1.OVL+296B','PLI1.OVL+2968','PLI1.OVL+295A'],
                          ['PLI1.OVL+2AA8','PLI1.OVL+2AA0','PLI1.OVL+2A9C','PLI1.OVL+2A8E']])
        short=self.by['PLI1.OVL+43D5']['members'][0]
        self.assertEqual((short['arguments'][0]['value'],short['argument_low'],short['ignored_high']),(0xA730,0x30,0xA7))
        self.assertEqual([m['arguments'][0]['value'] for m in self.by['PLI1.OVL+4468']['members']],[0x20C6,0xA948])

    def test_copy_control_alias_and_fresh_limit_are_kept_correlated(self):
        first,second=self.by['PLI1.OVL+6708']['members']
        self.assertEqual((first['output_count'],first['source_reads'],first['padding'],first['final_selector']),(150,7,143,32))
        self.assertEqual(first['limit_history'][0],{'offset':0,'selector':0,'address':0xA62B,'limit':254})
        self.assertEqual(first['limit_history'][-1],{'offset':150,'selector':32,'address':0xA64B,'limit':0})
        self.assertEqual([a['address'] for a in first['control_aliases']],list(range(0xA9DA,0xA9DE)))
        self.assertEqual((second['output_count'],second['padding'],second['final_selector']),(7,0,2))
        self.assertFalse(second['control_aliases'])
        bad=copy.deepcopy(self.records['PLI1.OVL+6708'][0]);last=next(w for w in reversed(bad['own_witnesses']) if w['origin']['offset']==0x6771)
        last['reads'][0]['address']=0xA62B
        with self.assertRaisesRegex(ValueError,'Fresh selector'):
            validate_copy(bad)

    def test_returned_complement_and_flags_are_different_channels(self):
        for m in self.by['PLI1.OVL+6708']['members']:
            self.assertEqual(m['returned_A'],255)
            self.assertFalse(m['returned_flags']['carry'])
            self.assertTrue(m['returned_flags']['zero'])
        r=copy.deepcopy(self.records['PLI1.OVL+6708'][0]);r['ret']['after']['a']=0
        with self.assertRaisesRegex(ValueError,'CMA return A'):
            validate_copy(r)

    def test_short_block_old_word_and_parent_reset_are_distinct(self):
        m=self.by['PLI1.OVL+43D5']['members'][0]
        self.assertEqual((m['new_pointer'],m['old_head'],m['old_word'],m['delta'],m['new_old_word']),
                         (0xFBD7,0xFBE1,0,2,2))
        parent=self.by['PLI1.OVL+4B69']['members'][0]
        self.assertEqual((parent['zeroed_words'],parent['word_before_parent_subtract'],parent['word_after']),(128,2,0))
        self.assertEqual(parent['created_pointer'],m['new_pointer'])
        bad=copy.deepcopy(self.records['PLI1.OVL+4B69'][0]);store=next(w for w in bad['own_witnesses'] if w['origin']['offset']==0x4BD1)
        store['writes'][0]['new_value']=2
        with self.assertRaisesRegex(ValueError,'subtraction'):
            validate_reset(bad)

    def test_caller_owned_psw_and_semantic_limits(self):
        m=self.by['PLI1.OVL+28AA']['members'][0]
        self.assertEqual((m['saved_2185_A'],m['first_return_A'],m['first_JNC_taken']),(0,255,True))
        self.assertTrue(m['second_JC_taken'])
        partial={'bounds':'provisional','control_flow':'partial','contract':'partial'}
        for k in ('PLI1.OVL+6708','PLI1.OVL+4B69','PLI1.OVL+28AA'):
            self.assertEqual(self.catalog[k]['completeness'],partial)
        self.assertEqual(self.catalog['PLI1.OVL+28AA']['byte_status_at_entry'],'STRUCTURED')
        self.assertEqual(self.catalog['PLI1.OVL+43D5']['completeness'],{'bounds':'stable','control_flow':'complete','contract':'partial'})

    def test_progress_is_live_consistent_and_historical_bytes_unchanged(self):
        manifest=json.loads((ROOT/'research/annotated-assembly/manifest.json').read_text())
        self.assertEqual(sum(i['length'] for i in manifest['images']),94720)
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        dynamic=calculate(manifest,rows)
        self.assertEqual(dynamic,json.loads((ROOT/'research/minimal-baseline/dynamic-progress.json').read_text()))
        # Pass-8 progress is a historical snapshot; later semantic passes may
        # improve the live manifest without changing that capture or report.
        historical=json.loads((PASS/'dynamic-progress.json').read_text())
        self.assertEqual(historical['total']['occurrences_by_status']['UNDERSTOOD'],205904)
        self.assertEqual(next(i for i in historical['per_image'] if i['image']=='PLI1.OVL')['occurrences_by_status']['UNDERSTOOD'],31713)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,remaining=parser.parse_known_args();CAPTURE=args.capture.resolve()
    unittest.main(argv=[sys.argv[0],*remaining])
