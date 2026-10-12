#!/usr/bin/env python3
"""Natural k123 boundary evidence and CPU-shadowed executable tail."""
import argparse, unittest
from pathlib import Path
import run_k123_handler_pass_75 as d

class K123(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d.prove(IMAGES)
        cls.proof = d.load(d.REPORT/'execution-boundary-proof.json')

    def test_natural_scope_and_hardware_ancestry(self):
        q = self.proof
        self.assertEqual(q['observed_k123_count'], 2)
        self.assertEqual(q['five_source_handler_map']['sources'], {'FACTOR':2})
        self.assertEqual({c['gateway_input_C'] for c in q['cases']}, {10,56})
        for c in q['cases']:
            self.assertEqual((c['gateway_caller'],c['canonical_index'],c['descriptor_pointer'],c['handler_runtime']),('374B',123,0x4357,0x476e))
            self.assertEqual(c['direct_calls'],[['256E','467B',1],['2575','279E',1]])
            self.assertEqual(c['software_transfer']['offset'],0x20b3)
            self.assertEqual(c['software_word_writers'][0]['offset'],0x20af)
            self.assertEqual(c['software_continuation_word'],[0xb4,0x42])
            self.assertEqual(c['handler_exit_state']['pc'],0x42b4)
            self.assertEqual(c['handler_exit_state']['sp'],c['handler_entry_state']['sp']+2)

    def test_full_concrete_journals_and_child_dependency(self):
        self.assertTrue(self.proof['journal_replay_full_RAM_matches'])
        self.assertEqual([c['full_instruction_steps'] for c in self.proof['cases']],[3263,3438])
        self.assertEqual([c['ordered_writes'] for c in self.proof['cases']],[775,815])
        self.assertEqual([c['BDOS_record_events'] for c in self.proof['cases']],[0,0])
        self.assertEqual([c['ADxx_writes'][-2:] for c in self.proof['cases']],[[['2578','AD07',15],['2598','AD06',15]]]*2)
        children = d.load(d.REPORT/'child-dependencies.json')
        self.assertIn('PLI2.OVL+247B',children['unresolved'])
        self.assertIn(['24D5','A5DC',1],children['child_247B_direct_calls_by_case'][0])
        self.assertIn(['24C6','A3AA',1],children['child_247B_direct_calls_by_case'][1])
        self.assertEqual(children['native_roots_installed'],0)

    def test_faithful_tail_and_output_identity(self):
        for c in self.proof['cases']:
            self.assertTrue(c['tail_proof']['natural_passed'])
            self.assertEqual(c['tail_proof']['synthetic_cases'],24)
            self.assertEqual(c['tail_entry_state']['a'],15)
            self.assertEqual(c['handler_exit_state']['a'],15)
        self.assertEqual(self.proof['FACTOR_REL_sha256'],self.proof['archived_FACTOR_REL_sha256'])
        self.assertLess((d.REPORT/'implementation-packet.json').stat().st_size,28672)

    def test_certified_full_epoch_preserved_and_category_growth(self):
        import run_host_compiler_regressions as runner
        policy=d.load('research/host-compiler/validation-policy.json')
        epochs=[*policy['previous_full_epochs'],policy['current_full_epoch']]
        pass74=next(e for e in epochs if e['name']=='Pass74')
        self.assertEqual((pass74['epoch'],pass74['implementation_commit']),(3,'878544acb368b5635c4fa242a03508103eaf30aa'))
        certificate=d.load(pass74['certification_artifact'])
        self.assertTrue(certificate['certification_complete'])
        _,selected,_=runner.select_categories(runner.commands(str(IMAGES),d.OUT),policy,profile='historical-full')
        self.assertEqual(len(selected),len(set(selected)))
        self.assertTrue(set(certificate['selected_categories'])<=set(selected))
        self.assertEqual(sum(i['length'] for i in d.load('research/annotated-assembly/manifest.json')['images']),94720)

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--images',required=True,type=Path)
    args,rest=p.parse_known_args()
    IMAGES=args.images
    unittest.main(argv=[__file__]+rest)
