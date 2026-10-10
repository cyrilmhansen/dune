#!/usr/bin/env python3
"""Actual software ownership and independent bounded generation proofs."""
import argparse,collections,json,os,unittest
from pathlib import Path
from run_generation_parent_discovery_pass_67 import OUT,REPORT,BOUNDS,prove
from check_selector02_pass_40 import children_any

def load(p):return json.loads(Path(p).read_text())
class PairedGenerationParent(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('RUNES_PASS67_REUSE_PROOF')!='1':prove(IMAGES)
  cls.rows=load(OUT/'rows.json');cls.ownership=load(REPORT/'ownership-map.json');cls.primary=load(OUT/'proof/natural-cases.json')
  for g in cls.rows.values():
   for rs in g.values():
    for r in rs:r['nested_returns']={int(k):v for k,v in r['nested_returns'].items()}
 def roots(self):return[r for g in self.rows.values()for r in g['PLI2.OVL+6EA5']]
 def test_true_entry_not_false_callsite_roots(self):
  self.assertEqual([len(g['PLI2.OVL+6EA5'])for g in self.rows.values()],[1,4,1])
  for r in self.roots():
   self.assertEqual(r['call']['bytes'],'E9');self.assertEqual(r['call']['origin']['offset'],0x20b3);self.assertIsNone(r['call']['call_return_address']);self.assertEqual(r['entry']['origin']['offset'],0x6ea5);self.assertEqual(r['ret']['origin']['offset'],0x6f18)
  cat=load('research/annotated-assembly/procedures.json')['procedures'];ids={p['id']for p in cat}
  self.assertNotIn('PLI2.OVL+6ED7',ids);self.assertNotIn('PLI2.OVL+6EE5',ids);self.assertNotIn('PLI2.OVL+6ED1',ids)
 def test_gateway_PUSH_PCHL_RET_last_writers(self):
  for rs in self.ownership.values():
   for r in rs:
    self.assertEqual(r['nearest_hardware_owner']['target'],'PLI2.OVL+1FB5');self.assertEqual([w['origin']['offset']for w in r['gateway']],[0x20ac,0x20af,0x20b0,0x20b3]);sp=r['entry_SP'];push=r['gateway'][1]
    self.assertEqual([(q['address'],q['new_value'])for q in push['writes']],[(sp+1,0x42),(sp,0xb4)]);self.assertEqual(push['sp_before'],sp+2);self.assertEqual(r['gateway'][-1]['writes'],[]);self.assertEqual(r['gateway'][-1]['sp_before'],sp)
  for r in self.roots():
   self.assertEqual(r['ret']['after']['sp'],r['entry']['before']['sp']+2);self.assertEqual(r['ret']['after']['pc'],0x42b4)
 def test_every_hardware_child_original_continuation(self):
  for r in self.roots():
   self.assertEqual([c['target']for c in children_any(r)],['PLI2.OVL+052C','PLI2.OVL+8350','PLI.COM+1A29','PLI2.OVL+8072','PLI2.OVL+742A','PLI2.OVL+8072','PLI2.OVL+8357','PLI.COM+1A29','PLI2.OVL+8248'])
   for c in children_any(r):
    w=next(w for w in r['own_witnesses']if w['step_index']==c['call_step']);ret=r['nested_returns'][w['step_index']]['ret'];sp=w['sp_after'];resume=w['pc']+3
    self.assertEqual([(q['address'],q['new_value'])for q in w['writes']],[(sp+1,resume>>8),(sp,resume&255)]);self.assertEqual(ret['after']['sp'],sp+2);self.assertEqual(ret['after']['pc'],resume)
 def test_paired_argument_provenance_and_interposed_reset(self):
  for r in self.roots():
   cs=children_any(r);own={w['origin']['offset']:w for w in r['own_witnesses']};a=next(c for c in cs if c['callsite']==0x6ed7);b=next(c for c in cs if c['callsite']==0x6ee5);middle=next(c for c in cs if c['callsite']==0x6eda)
   self.assertEqual([q['address']for q in own[0x6ed1]['reads']],[0xada2,0xada3]);v=own[0x6ed1]['reads'];self.assertEqual([a['entry'][k]for k in ['c','d','e']],[2,v[1]['value'],v[0]['value']]);self.assertEqual([b['entry'][k]for k in ['c','d','e']],[0,0,0]);self.assertLess(a['return_step'],middle['call_step']);self.assertLess(middle['return_step'],b['call_step']);self.assertEqual(middle['target'],'PLI2.OVL+742A')
   self.assertEqual([(q['address'],q['new_value'])for q in own[0x6edd]['writes']],[(0xada0,middle['output']['l']),(0xada1,middle['output']['h'])])
 def test_masks_flags_and_natural_gate(self):
  for r in self.roots():
   w={q['origin']['offset']:q for q in r['own_witnesses']}
   self.assertEqual(w[0x6ec3]['writes'][0]['new_value'],0);self.assertTrue(w[0x6ec7]['control']['taken']);self.assertTrue(w[0x6eec]['control']['taken']);self.assertTrue(w[0x6f06]['control']['taken'])
   for o in [0x6ec6,0x6eeb]:
    old=w[o]['before'];new=w[o]['after'];self.assertEqual(new['a'],(old['a']>>1)|(int(old['flags']['carry'])<<7));self.assertEqual(new['flags'],dict(old['flags'],carry=bool(old['a']&1)))
 def test_two_independent_mapped_bytes_and_PSW_carrier(self):
  for source,g in self.rows.items():
   for r in g['PLI2.OVL+052C']:
    cs=children_any(r);w={q['origin']['offset']:q for q in r['own_witnesses']};self.assertEqual([c['target']for c in cs],['PLI2.OVL+04FF','PLI2.OVL+04E9','PLI2.OVL+0515']);self.assertEqual([q['address']for q in w[0x0530]['reads']],[0xac01,0xac02]);self.assertEqual([q['address']for q in w[0x0538]['reads']],[0xac01,0xac02]);first,second,last=cs
    self.assertEqual(last['entry']['c'],first['output']['a']);self.assertEqual(last['entry']['e'],second['output']['a']);self.assertEqual(last['output']['h'],second['output']['a']);self.assertEqual(last['output']['l'],first['output']['a'])
    push=w[0x0537];pop=w[0x0540];self.assertEqual(pop['after']['b'],first['output']['a']);self.assertEqual(push['sp_after'],pop['sp_before']);self.assertEqual(pop['after']['flags'],pop['before']['flags'])
 def test_leaf_indices_are_zero_extended_and_fresh(self):
  for g in self.rows.values():
   for key,base in [('PLI2.OVL+04FF',0xa7f8),('PLI2.OVL+04E9',0xa795)]:
    for r in g[key]:
     reads=[q for w in r['own_witnesses']for q in w['reads']];selector=r['entry']['before']['c'];mapped=next(q['value']for q in reads if q['address']==0xaab0+selector);out=r['ret']['after'];self.assertEqual(out['b'],0);self.assertEqual(out['c'],mapped);self.assertEqual(out['h']*256+out['l'],base+mapped);self.assertEqual(out['a'],next(q['value']for q in reads if q['address']==base+mapped));self.assertFalse(out['flags']['carry'])
 def test_all_primary_components_full_state_shadow(self):
  for s,count in zip(self.primary['sources'],[1,4,1]):
   by={e['offset']:e['members']for e in s['entries']};self.assertEqual(len(by[0x6ea5]),count)
   for o in [0x052c,0x04e9,0x04ff,0x0515,0x8350,0x8357,0x742a,0x8248]:self.assertEqual(len(by[o]),count)
   self.assertEqual(len(by[0x8072]),count*2);self.assertGreaterEqual(len(by[0x1a29]),count*2)
   for c in by[0x6ea5]:self.assertEqual(c['output']['pc'],0x42b4);self.assertEqual(c['output']['sp'],c['input']['sp']+2);self.assertEqual(c['entry_dma'],c['post_dma'])
 def test_independent_cross_source_and_bit80_diversity(self):
  words=[]
  for source,count in [('FACTOR',1),('OPTIMIST',4)]:
   x=load(OUT/'proof'/(source+'-natural-cases.json'))['sources'][0];by={e['offset']:e['members']for e in x['entries']};self.assertEqual(len(by[0x6ea5]),count);self.assertEqual(len(by[0x8072]),2*count)
   for c in by[0x6ea5]:words.append(c['entry_shared_state']['mapped_word_bytes'][0]);self.assertEqual(c['output']['pc'],0x42b4)
   ins=load(OUT/'proof'/(source+'-natural-instruction-witnesses.json'));pcs={w['offset']for w in ins if w['owner']=='PLI2.OVL+6EA5'}
   if source=='OPTIMIST':self.assertTrue({0x6f09,0x6f0c,0x6f0f}<=pcs)
  self.assertIn(0x90,words)
 def test_CPU_synthetic_independent_channels_and_carry(self):
  cases=[c for c in load(OUT/'proof/synthetic-checkpoints.json')['cases']if c['route'].startswith('6EA5_')];self.assertEqual(len(cases),96);self.assertTrue(all(c['all_passed']for c in cases));labels={c['route']for c in cases}
  for word in ['0000','0211','0252','0290','02FE']:
   for cy in [0,1]:self.assertIn(f'6EA5_word{word}_CY{cy}',labels)
  self.assertIn('6EA5_first_success_equal',labels);self.assertIn('6EA5_first_success_plus1',labels)
  for c in cases:
   if c['route']=='6EA5_first_success_equal':self.assertTrue(next(q for q in c['checkpoints']if q['pc']==0x90da)['PSW']&1)
  self.assertIn('6EA5_selectorFF_j01_word022A',labels);self.assertIn('6EA5_selector07_jFF_word0252',labels)
 def test_partial_knowledge_not_static_recursive_promotions(self):
  cfg=load(REPORT/'cfg.json');root=[w for w in cfg if w['owner']=='PLI2.OVL+6EA5'];self.assertEqual(sum(len(bytes.fromhex(w['bytes']))for w in root),116);raw={w['offset']for w in root if w['evidence']!='OBSERVED'};self.assertEqual(raw,{0x6eca,0x6ecd,0x6ece,0x6eef,0x6ef2,0x6ef5});k=load(REPORT/'knowledge-summary.json');self.assertEqual(k['RAW_to_UNDERSTOOD'],213);self.assertEqual(k['root_observed'],100);self.assertEqual(k['helper_observed'],113);self.assertEqual(k['static_promoted'],0)
 def test_standalone_cumulative_goldens_and_actual_economics(self):
  expected={'MINIMAL':(294603,294445,95,92),'FIZZBUZ':(561279,560647,235,223),'PICTURE':(340468,340310,84,81)}
  for name in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   h=load(OUT/'proof'/name);self.assertTrue(h['all_passed']);self.assertEqual(len(h['sources']),3)
   for s in h['sources']:
    r=s['result'];self.assertTrue(r['PASS1']and r['PASS2']and r['END_COMPILATION']);self.assertEqual(r['termination'],'warm_boot')
    if name.startswith('cumulative'):self.assertEqual((s['pre_guest_instructions'],r['actual_guest_instructions'],sum(s['pre_transition_vector']),r['host_transitions']),expected[r['source']])
 def test_historical_selection_and_FULL_handoff(self):
  s=load(REPORT/'historical-full-selection.json');self.assertEqual(s['count'],98);self.assertTrue(s['all_92_preserved']);self.assertFalse(s['executed']) # original list-only proof
  h=load(REPORT/'full-checkpoint-handoff.json');self.assertEqual(h['status'],'certified_after_harness_only_reruns')
  full=load(REPORT/h['certification_receipt']);self.assertTrue(full['all_passed']);self.assertFalse(full['initial_all_passed']);self.assertEqual(full['category_count'],98)
  self.assertEqual(h['semantic_commit'],full['semantic_implementation_commit']);self.assertEqual(h['previous_certified_FULL'],'Pass62')
  policy=load('research/host-compiler/validation-policy.json');epochs=[policy['current_full_epoch'],*policy.get('previous_full_epochs',[])]
  self.assertTrue(any(e['name']=='Pass67'and e['implementation_commit']==h['semantic_commit']for e in epochs))
 def test_software_gateway_verifier_rejects_false_frames(self):
  import copy
  from software_gateway_pass_67 import prove_gateway
  seed=next(s for s in load('research/annotated-assembly/evidence.json')['seeds']if s['id']=='PLI2.OVL+6EA5');images={i['name']:i for i in load('research/annotated-assembly/manifest.json')['images']};originals={n:(Path(IMAGES)/n).read_bytes()for n in images}
  self.assertEqual(prove_gateway(seed,images,originals)['continuation'],0x42b4)
  for change in [lambda p:p.update(kind='hardware_CALL'),lambda p:p.update(continuation=0x1234),lambda p:p['writer'].update(sp_after=0),lambda p:p['gateway'][2]['reads'][0].update(value=0),lambda p:p['call'].update(writes=[dict(address=0,value=0)]),lambda p:p['ret'].update(pc_after=0),lambda p:p['gateway'][0].update(bytes='000000'),lambda p:p['entry']['before'].update(a=255)]:
   bad=copy.deepcopy(seed);change(bad['software_return_sample'])
   with self.assertRaises(ValueError):prove_gateway(bad,images,originals)
 def test_packet_and_unchanged_historical_contracts(self):
  self.assertLess((REPORT/'implementation-packet.json').stat().st_size,32768);top=load(REPORT/'topology-summary.json')
  for source,n in [('MINIMAL',1),('FIZZBUZ',4),('PICTURE',1)]:self.assertEqual(top[source]['absorbed'],{'PLI2.OVL+8072':2*n,'PLI2.OVL+742A':n,'PLI2.OVL+8248':n});self.assertEqual(top[source]['net_delta'],-3*n)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');p.add_argument('-v',action='store_true');p.add_argument('-q',action='store_true');args=p.parse_args();IMAGES=args.images;unittest.main(argv=['test','-v'if args.v else'-q'])
