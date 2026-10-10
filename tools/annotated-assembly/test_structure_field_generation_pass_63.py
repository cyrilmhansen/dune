#!/usr/bin/env python3
"""Independent Pass63 provenance, channels, stack, scope and hybrid proofs."""
import argparse,json,unittest
from pathlib import Path
from run_structure_field_generation_pass_63 import prove,OUT,REPORT
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
def writes(w):return[(v['address'],v['new_value'])for v in w['writes']]
class StructureField(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.rows=load(OUT/'rows.json');cls.nat=load(OUT/'proof/natural-cases.json')['sources']
 def natural(self):return[r for g in self.rows.values()for r in g['PLI2.OVL+829C']]
 def test_extent_entry_return_and_callers(self):
  self.assertEqual([len(g['PLI2.OVL+829C'])for g in self.rows.values()],[1,1,1]);cfg=load(OUT/'cfg.json')['PLI2.OVL+829C'];self.assertEqual(sum(len(bytes.fromhex(b))for _,b,_ in cfg),25)
  for r in self.natural():
   self.assertEqual(r['entry']['origin']['offset'],0x829c);self.assertEqual(r['call']['origin']['offset'],0x19a7);self.assertEqual(r['ret']['origin']['offset'],0x82b4)
 def test_source_publication_and_fresh_reread(self):
  for r in self.natural():
   w=own(r);rs=w[0x829c]['reads'];self.assertEqual([v['address']for v in rs],[0xaca3,0xaca4]);self.assertEqual(writes(w[0x829f]),[(0xac9f,rs[0]['value']),(0xaca0,rs[1]['value'])]);self.assertEqual(w[0x82a9]['reads'],[dict(address=0xac9f,value=rs[0]['value']),dict(address=0xaca0,value=rs[1]['value'])])
   self.assertTrue(all(w[o]['after']['flags']==w[o]['before']['flags']for o in[0x829c,0x829f,0x82a2,0x82a4,0x82a9,0x82ac,0x82ad,0x82ae,0x82af,0x82b0]))
 def test_header_literal_channels_and_bit_order(self):
  for r in self.natural():
   w=own(r);q=w[0x82a6]['before'];self.assertEqual((q['c'],q['e']),(0x94,7));child=r['nested_returns'][str(w[0x82a6]['step_index'])]
   rotated=[v['new_value']for x in child['memory_witnesses']for v in x['writes']if v['address']==0x20b7][1:]
   self.assertEqual([v&1 for v in rotated],[1,0,0,1,0,1,0])
 def test_exact_payload_offsets_low_then_high(self):
  for r in self.natural():
   w=own(r);q=w[0x82a9]['after'];p=q['h']*256+q['l'];low=w[0x82ae]['reads'];high=w[0x82b0]['reads'];self.assertEqual([v['address']for v in low+high],[p+2,p+3]);self.assertEqual((w[0x82b1]['before']['c'],w[0x82b1]['before']['b']),(low[0]['value'],high[0]['value']))
   self.assertFalse(any(v['address']in[p,p+1]for x in r['own_witnesses']for v in x['reads']))
 def test_direct_children_and_exact_component_shadows(self):
  for r in self.natural():
   rr={**r,'nested_returns':{int(k):v for k,v in r['nested_returns'].items()}};self.assertEqual([c['target']for c in children_any(rr)],['PLI.COM+119E','PLI.COM+11C3'])
  for s in self.nat:self.assertEqual([(e['offset'],len(e['members']))for e in s['entries']],[(0x829c,1),(0x119e,4),(0x11c3,1)])
 def test_hardware_calls_RET_and_stack_last_writers(self):
  for r in self.natural():
   w=own(r);sp=r['entry']['before']['sp'];pc=r['call']['before']['pc']+3;self.assertEqual(writes(r['call']),[(sp+1,pc>>8),(sp,pc&255)])
   for site,resume in[(0x82a6,0xa4a9),(0x82b1,0xa4b4)]:self.assertEqual(writes(w[site]),[(sp-1,resume>>8),(sp-2,resume&255)])
   self.assertEqual((r['ret']['after']['sp'],r['ret']['after']['pc']),(sp+2,pc))
  for s in self.nat:
   c=s['entries'][0]['members'][0];sp=c['input']['sp'];last={v[0]:v for v in c['journal']};self.assertEqual((last[sp-1][2],last[sp-2][2]),(0xa4b1,0xa4b1));self.assertNotIn(sp,last);self.assertNotIn(sp+1,last)
 def test_provenance_synthetic_original_CPU_and_flush(self):
  cs=[q for q in load(OUT/'proof/synthetic-checkpoints.json')['cases']if q['route'].startswith('829C_')];self.assertEqual(len(cs),30);self.assertTrue(all(c['all_passed']for c in cs))
  for c in cs:
   if c['route']=='829C_record_boundary':self.assertEqual(c['record_count'],1);continue
   w={q['pc']:q for q in c['checkpoints']};self.assertIn(0xa49c,w);self.assertIn(0xa4ae,w);self.assertIn(0xa4b0,w);self.assertIn(0xa4b4,w)
  self.assertEqual(len({c['route']for c in cs}),10)
 def test_cross_evidence_is_natural_and_independent(self):
  for source in ['FACTOR','OPTIMIST']:
   r=load(OUT/(source+'-natural-cases.json'))['sources'][0];self.assertEqual(r['source'],source);self.assertEqual(len(r['entries'][0]['members']),1)
 def test_exact_hybrids_and_actual_economics(self):
  hashes=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for name in['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=load(OUT/'proof'/name)['sources'];self.assertEqual([r['result']['REL_sha256']for r in rows],hashes);self.assertTrue(all(r['result']['PASS1']and r['result']['PASS2']and r['result']['END_COMPILATION']and r['result']['termination']=='warm_boot'for r in rows))
  rows=load(OUT/'proof/cumulative-hybrid-summary.json')['sources'];self.assertEqual([r['pre_guest_instructions']for r in rows],[299837,566802,346318]);self.assertEqual([r['guest_instructions_removed']for r in rows],[321,321,321]);self.assertEqual([r['result']['host_transitions']for r in rows],[102,258,93])
 def test_hierarchy_residual_serializer(self):
  rows=load(REPORT/'topology-summary.json');self.assertEqual([r['remaining']['PLI.COM+119E']['calls']for r in rows.values()],[35,35,42]);self.assertTrue(all(r['absorbed']=={'PLI.COM+11C3':1}and r['net_host_delta']==0 for r in rows.values()))
 def test_current_contract_and_prior_epoch_totals(self):
  from historical_catalog_epoch import _checkpoint
  current={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};old=_checkpoint('692a4da420409e14970e94754067a33532f41adc');p=current['PLI2.OVL+829C'];self.assertEqual((p['start_offset'],p['end_offset'],p['length']),(0x829c,0x82b5,25));self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'))
  for k,v in old.items():
   for source,n in v['observed_paths']['invocations_by_run'].items():self.assertGreaterEqual(current[k]['observed_paths']['invocations_by_run'].get(source,0),n)
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
