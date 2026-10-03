#!/usr/bin/env python3
"""Pass-7 contracts, branch polarity, word emissions and structural caveats."""
import argparse
import copy
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

from check_minimal_pass_7 import ROOT,collect,validate_direct,validate_bbf,validate_software_sample
from minimal_dynamic_progress import calculate
from procedure_evidence_packet import verify_return

PASS=ROOT/'research/minimal-baseline/pass-7'


class MinimalPassSevenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.regions,cls.records,cls.packets=collect(CAPTURE,IMAGES,ROOT/'_build/minimal-pass-7/packets')
        cls.by={r['entry']:r for r in cls.regions}
        cls.catalog={p['id']:p for p in json.loads((ROOT/'research/annotated-assembly/procedures.json').read_text())['procedures']}

    def test_all_contract_invocations(self):
        self.assertEqual(sum(r['invocations_checked'] for r in self.regions),188)
        self.assertEqual({k:len(v) for k,v in self.records.items()},
                         {'PLI1.OVL+7A79':11,'PLI1.OVL+82E1':36,'PLI1.OVL+82BB':37,'PLI1.OVL+82C9':36,'PLI1.OVL+7ABF':14,'PLI1.OVL+7E46':7,'PLI1.OVL+7E56':7})

    def test_word_alias_doubling_and_distinct_external_use(self):
        rows=self.by['PLI1.OVL+82BB']['members']
        equal=[r for r in rows if r['left_pointer']==r['right_pointer']]
        self.assertEqual(len(equal),36)
        self.assertTrue(all(r['left']==r['right'] and r['sum']==2*r['left']%65536 for r in equal))
        self.assertEqual(len(rows)-len(equal),1)
        bad=copy.deepcopy(self.records['PLI1.OVL+82BB'][0]);bad['ret']['after']['flags']['carry'] ^= True
        with self.assertRaisesRegex(ValueError,'ADC flags'):
            validate_direct(bad)

    def test_masked_word_helpers_do_not_write_memory(self):
        for key in ('PLI1.OVL+82E1','PLI1.OVL+82BB','PLI1.OVL+82C9'):
            self.assertTrue(all(not w['writes'] for r in self.records[key] for w in r['own_witnesses']))
        for key in ('PLI1.OVL+82E1','PLI1.OVL+82C9'):
            self.assertTrue(all(m['result']==m['value'] & m['mask'] for m in self.by[key]['members']))

    def test_bbf_original_predicates_and_complete_scope(self):
        p=self.packets['PLI1.OVL+7BBF'];members=self.by[p['entry']]['members']
        self.assertEqual([(m['initial_word'],m['shifts'],m['shifted_word'],m['returned_counter']) for m in members],
                         [(1,15,0x8000,1),(0x252,6,0x9480,10),(1,15,0x8000,1)])
        branches=[b for b in p['local_dependencies']['branches'].values() if b['coordinate']=='PLI1.OVL+7C02']
        self.assertEqual((len(branches),sum(b['taken'] for b in branches)),(36,3))
        self.assertTrue(all(b['condition']['op']=='not' and b['condition']['arg']['op']=='and' for b in branches))
        bad=copy.deepcopy(p);iv=bad['invocations'][0]
        store=next(bad['steps'][str(s)] for s in iv['local_steps'] if bad['steps'][str(s)]['coordinate']=='PLI1.OVL+7BED')
        store['writes'][0]['address']+=1
        with self.assertRaisesRegex(ValueError,'Shifted word publication'):
            validate_bbf(bad,iv)
        self.assertEqual(self.catalog[p['entry']]['completeness'],{'bounds':'stable','control_flow':'complete','contract':'complete'})

    def test_bounded_shift_condition_all_65536_words(self):
        # Independent expected stopping point from original adjacent bits;
        # neither helper implementations nor packet prose supplies the oracle.
        for original in range(65536):
            bits=f'{original:016b}'+'0'
            expected=next((i for i in range(1,17) if bits[i]!=bits[i-1]),16)
            current=original;counter=15;shifts=0
            while True:
                old=current;current=(current*2)%65536;shifts+=1
                if counter==0 or (old^current)&0x8000:break
                counter-=1
            self.assertEqual(shifts,expected)
            self.assertEqual(counter,16-expected)

    def test_parent_emission_channels_stay_distinct(self):
        rows=self.by['PLI1.OVL+7D53']['members'];channels=[c for r in rows for c in r['emission_channels']]
        self.assertEqual(Counter(c['channel'] for c in channels),{'mapped-byte':16,'primary-auxiliary-byte':9,'second-auxiliary-byte':1,'mapped-word-low':7,'mapped-word-high':7})
        self.assertEqual(len(channels),40)
        for r in rows:
            pending=[]
            for c in r['emission_channels']:
                if c['channel']=='mapped-word-low':pending.append(c['word'])
                if c['channel']=='mapped-word-high':self.assertEqual(c['word'],pending.pop(0))
            self.assertFalse(pending)
        self.assertEqual(len(self.by['PLI1.OVL+7C1B']['members']),16)
        for k in ('PLI1.OVL+7C1B','PLI1.OVL+7D53'):
            self.assertEqual(self.catalog[k]['completeness'],{'bounds':'provisional','control_flow':'partial','contract':'partial'})
        self.assertEqual(self.catalog['PLI1.OVL+7D53']['byte_status_at_entry'],'UNDERSTOOD')

    def test_software_boundaries_are_structural_only(self):
        data=json.loads((PASS/'large-structural.json').read_text())
        self.assertEqual({k:(s['own_coordinates'],s['own_occurrences']) for k,s in data.items()},
                         {'PLI1.OVL+28AA':(351,351),'PLI1.OVL+4B69':(52,2088)})
        for k,s in data.items():
            self.assertEqual(s['classification'],'STRUCTURE ONLY')  # immutable pass-7 result
            sample=s['parent_hardware_return_sample'];verify_return(sample['call'],sample['ret'],sample['relation'])
            for q in s['software_nested_returns']:
                self.assertEqual(validate_software_sample(q['sample']),q['argument_words_consumed'])
        bad=copy.deepcopy(data['PLI1.OVL+4B69']['software_nested_returns'][0]['sample'])
        pop=next(w for w in bad['prefix'] if w['disassembly']=='POP D');pop['reads'][0]['address']+=2
        with self.assertRaisesRegex(ValueError,'original-slot POP'):
            validate_software_sample(bad)

    def test_live_progress_and_qualified_wrappers(self):
        for k in ('PLI1.OVL+7E46','PLI1.OVL+7E56'):
            self.assertEqual(self.catalog[k]['completeness'],{'bounds':'stable','control_flow':'complete','contract':'partial'})
            self.assertTrue(any('0EF6' in g for g in self.catalog[k]['unresolved_paths']))
        m=json.loads((ROOT/'research/annotated-assembly/manifest.json').read_text())
        rows=[json.loads(s) for s in (ROOT/'research/minimal-baseline/instructions.jsonl').read_text().splitlines()]
        current=calculate(m,rows)
        self.assertEqual(current,json.loads((ROOT/'research/minimal-baseline/dynamic-progress.json').read_text()))
        historical=json.loads((PASS/'dynamic-progress.json').read_text())
        self.assertEqual(historical['total']['occurrences_by_status']['UNDERSTOOD'],199700)
        self.assertEqual(next(i for i in historical['per_image'] if i['image']=='PLI1.OVL')['occurrences_by_status']['UNDERSTOOD'],25509)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--images',type=Path,required=True)
    parser.add_argument('--capture',type=Path,default=ROOT/'_build/minimal-baseline/capture')
    args,rest=parser.parse_known_args();IMAGES=args.images.resolve();CAPTURE=args.capture.resolve()
    unittest.main(argv=[sys.argv[0],*rest])
