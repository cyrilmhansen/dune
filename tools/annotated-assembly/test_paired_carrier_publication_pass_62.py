#!/usr/bin/env python3
"""Independent natural provenance, flags, stack and transactional scope checks."""
import argparse,collections,json,unittest
from pathlib import Path
from run_paired_carrier_publication_pass_62 import prove,OUT,REPORT

def load(p):return json.loads(Path(p).read_text())
def own(r):return{w['origin']['offset']:w for w in r['own_witnesses']}
def written(w):return[(v['address'],v['new_value'])for v in w['writes']]
def paired(w):return sum(v['value']<<(8*i)for i,v in enumerate(w['reads']))
def psw(f):return 2|128*f['sign']|64*f['zero']|16*f['auxiliary_carry']|4*f['parity']|f['carry']
class PairedPublication(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  prove(IMAGES);cls.raw=load(OUT/'rows.json');cls.nat=load(OUT/'proof/natural-cases.json')['sources']
 def rows(self):return[r for g in self.raw.values()for r in g['PLI2.OVL+7338']]
 def test_true_entry_extent_counts_and_two_children(self):
  self.assertEqual([len(g['PLI2.OVL+7338'])for g in self.raw.values()],[3,11,4])
  cfg=load(OUT/'cfg.json')['PLI2.OVL+7338'];self.assertEqual(max(o+len(bytes.fromhex(b))for o,b,_ in cfg),0x7365)
  for r in self.rows():
   self.assertEqual(r['entry']['origin']['offset'],0x7338);self.assertEqual(r['ret']['origin']['offset'],0x7364)
   self.assertEqual([w['target_origin']['offset']for w in r['own_witnesses']if w['control']['kind']=='call'],[0x7314,0x7314])
 def test_three_saves_order_HL_and_preserved_flags(self):
  for r in self.rows():
   w=own(r);e=r['entry']['before'];self.assertEqual([written(w[s])for s in[0x733b,0x733d,0x733f]],[[(0xadbf,e['d'])],[(0xadbe,e['e'])],[(0xadbd,e['c'])]])
   for site,hl in[(0x733b,0xadbf),(0x733d,0xadbe),(0x733f,0xadbd)]:
    q=w[site]['before'];self.assertEqual(q['h']*256+q['l'],hl);self.assertEqual(q['flags'],e['flags'])
 def test_fresh_CPI6_natural_route(self):
  for r in self.rows():
   w=own(r);c=r['entry']['before']['c'];self.assertEqual(w[0x7340]['reads'],[dict(address=0xadbd,value=c)]);f=w[0x7343]['after']['flags'];v=(c-6)&255
   self.assertEqual(f,dict(sign=bool(v&128),zero=v==0,parity=v.bit_count()%2==0,auxiliary_carry=(c&15)>=(6&15),carry=c<6))
   self.assertFalse(f['zero']);self.assertEqual(w[0x7345]['after']['pc'],0x9549)
 def test_first_paired_reads_and_child_arguments(self):
  for r in self.rows():
   w=own(r);e=r['entry']['before'];self.assertEqual(w[0x7349]['reads'],[dict(address=0xadbe,value=e['e']),dict(address=0xadbf,value=e['d'])]);self.assertEqual(w[0x734d]['reads'],[dict(address=0xadbd,value=e['c']),dict(address=0xadbe,value=e['e'])]);q=w[0x7352]['before'];self.assertEqual((q['c'],q['e']),(e['c'],e['d']))
 def test_children_cannot_mutate_saved_carriers(self):
  for r in self.rows():
   for child in r['nested_returns'].values():self.assertFalse(any(v['address']in range(0xadbd,0xadc0)for w in child['memory_witnesses']for v in w['writes']))
 def test_INR_flags_CY_and_byte_arithmetic(self):
  for r in self.rows():
   w=own(r);a=w[0x7358]['before'];b=w[0x7358]['after'];v=(a['a']+1)&255;self.assertEqual(b['a'],v);self.assertEqual(b['flags'],dict(sign=bool(v&128),zero=v==0,parity=v.bit_count()%2==0,auxiliary_carry=(a['a']&15)==15,carry=a['flags']['carry']))
 def test_PSWT_stack_and_POPB_transport(self):
  for r in self.rows():
   w=own(r);q=w[0x735c]['before'];sp=q['sp'];f=psw(q['flags']);self.assertEqual(written(w[0x735c]),[(sp-1,q['a']),(sp-2,f)])
   pop=w[0x735f]['after'];self.assertEqual((pop['b'],pop['c']),(q['a'],f));self.assertEqual(pop['sp'],sp);self.assertEqual(pop['flags'],q['flags']);self.assertEqual(w[0x7360]['after']['c'],q['a'])
 def test_second_fresh_reads_and_child_arguments(self):
  for r in self.rows():
   w=own(r);e=r['entry']['before'];self.assertEqual(w[0x7355]['reads'],[dict(address=0xadbd,value=e['c'])]);self.assertEqual(w[0x7359]['reads'],[dict(address=0xadbe,value=e['e']),dict(address=0xadbf,value=e['d'])]);q=w[0x7361]['before'];self.assertEqual((q['c'],q['e']),((e['c']+1)&255,e['e']))
 def test_hardware_CALL_RET_and_last_writers(self):
  for r in self.rows():
   w=own(r);sp=r['entry']['before']['sp']
   continuation=r['call']['before']['pc']+3
   self.assertEqual(written(r['call']),[(sp+1,continuation>>8),(sp,continuation&255)])
   for site,pc in[(0x7352,0x9555),(0x7361,0x9564)]:self.assertEqual(written(w[site]),[(sp-1,pc>>8),(sp-2,pc&255)])
   self.assertEqual((r['ret']['after']['sp'],r['ret']['after']['pc']),(sp+2,continuation))
  for source in self.nat:
   cases=next(e['members']for e in source['entries']if e['offset']==0x7338)
   for c in cases:
    writes={v[0]:v for v in c['journal']};sp=c['input']['sp'];self.assertEqual(writes[sp-1][2],0x9561);self.assertEqual(writes[sp-2][2],0x9561)
 def test_static_earlyreturn_and_distinct_value_CPU_discriminants(self):
  cases=[v for v in load(OUT/'proof/synthetic-checkpoints.json')['cases']if v['route'].startswith('7338_')];self.assertEqual(len(cases),54)
  for c in cases:
   self.assertTrue(c['all_passed']);self.assertTrue(c['checkpoints']);w={v['pc']-0x2200:v for v in c['checkpoints']}
   if c['C']==6:self.assertIn(0x7348,w);self.assertNotIn(0x7352,w);self.assertEqual(w[0x7343]['A'],6)
   else:self.assertEqual(w[0x7352]['BC']&255,c['C']);self.assertEqual(w[0x7352]['DE']&255,0x91);self.assertEqual(w[0x7361]['BC']&255,c['C']+1);self.assertEqual(w[0x7361]['DE']&255,0x2c)
 def test_hierarchy_actual_transitions_and_external_zero(self):
  hs=load(REPORT/'hierarchy-summary.json')['sources']
  self.assertEqual([h['roots']for h in hs],[3,11,4]);self.assertEqual([h['pre_host']for h in hs],[99,247,89]);self.assertEqual([h['post_host']for h in hs],[102,258,93]);self.assertTrue(all(h['absorbed_runner_roots']=={}for h in hs));self.assertTrue(all(h['remaining']['PLI2.OVL+7314']['calls']==0 for h in hs));self.assertEqual([h['remaining']['PLI.COM+119E']['calls']for h in hs],[36,36,43])
 def test_catalog_promotions_epoch_and_packet(self):
  cat={p['id']:p for p in load('research/annotated-assembly/procedures.json')['procedures']};p=cat['PLI2.OVL+7338'];self.assertEqual((p['start_offset'],p['end_offset'],p['length']),(0x7338,0x7365,45));self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='partial'));self.assertEqual(p['returns']['observed_file_offsets'],[0x7364]);f=load(REPORT/'fidelity.json');self.assertEqual((f['OBSERVED_bytes'],f['DEDUCED_STATIC_UNOBSERVED_bytes']),(44,1));self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,28672)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=['test_paired_carrier_publication_pass_62.py']+rest)
