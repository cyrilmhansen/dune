"""Natural pointer-publication, fresh-read, ABI and negative evidence tests."""
import argparse,copy,sys,unittest
from pathlib import Path
from collections import Counter
from check_5a46_pass_34 import *
class PassThirtyFourTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.analyses=[analyze(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()];cls.actual=derive(cls.analyses)
  cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_durable_cases_canonical_identity(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  self.assertEqual([len(a['roots'])for a in self.analyses],[0,9,4])
  self.assertEqual([len(a['wrappers'])for a in self.analyses],[2,11,6])
 def test_catalog_counts_callers_and_own_byte_union(self):
  for key,p in load(REPORT/'after.json').items():
   self.assertEqual(p,self.catalog[key]);union=set()
   for s,g in self.rows.items():
    rs=g[key];self.assertEqual(len(rs),p['observed_paths']['invocations_by_run'][s])
    self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),{c['coordinate']:c['counts_by_run'][s]for c in p['callers']if s in c['counts_by_run']})
    union|={w['origin']['offset']+i for r in rs for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),p['observed_paths']['represented_bytes'])
 def test_gate_and_pointer_bound_mask_flag_channels(self):
  for a in self.analyses:
   for r in a['roots']:
    self.assertEqual(r['children'][0]['output']['a'],255);self.assertEqual(r['gate_RAR']['output_A'],127)
    self.assertTrue(r['gate_RAR']['flags']['carry']);self.assertEqual(r['children'][2]['output']['a'],255)
    self.assertTrue(r['pointer_mask_RAR']['flags']['carry']);self.assertFalse(r['children'][2]['output']['flags']['carry'])
 def test_index_wrap_fresh_slot_and_publication_order(self):
  for a in self.analyses:
   for r in a['roots']:
    self.assertEqual((r['old_index'],r['new_index']),(255,0));self.assertEqual(r['first_slot'],r['first_base']);self.assertEqual(r['final_slot'],r['fresh_base'])
    self.assertEqual(r['discarded_neighbor'],r['fresh_base']&255)
    self.assertEqual([(w['address'],w['value'])for w in r['local_writes']],[(0xa6ca,0),(r['final_slot'],r['pointer']&255),(r['final_slot']+1,r['pointer']>>8)])
 def test_exact_return_registers_and_flags(self):
  for a in self.analyses:
   for r in a['roots']:
    self.assertEqual(r['output']['a'],0);self.assertEqual(pair(r['output'],'h','l'),r['final_slot']+1);self.assertEqual(pair(r['output'],'d','e'),r['pointer'])
    self.assertEqual(r['output']['flags'],dict(sign=False,zero=True,auxiliary_carry=True,parity=True,carry=False))
    self.assertEqual(r['output']['sp'],r['entry']['sp']+2)
 def test_temporary_push_pop_stack_last_writer(self):
  for a in self.analyses:
   for r in a['roots']:
    slots={x['relative_address']:x for x in r['stack']}
    for address,value in [(-2,r['final_slot']&255),(-1,r['final_slot']>>8)]:
     self.assertEqual(slots[address]['writer'],'PLI1.OVL+5A98');self.assertEqual(slots[address]['value'],value)
     self.assertIn('PLI1.OVL+5A87',slots[address]['overwritten_writers'])
 def test_complete_leaf_paired_read_and_checksum_reuse(self):
  self.assertEqual([len(a['leaves'])for a in self.analyses],[3,22,7])
  self.assertEqual(self.catalog['PLI1.OVL+4562']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for a in self.analyses:
   for r in a['leaves']:
    q=r['law'];self.assertEqual(len(q['source_reads']),q['count']);self.assertEqual(q['result'],sum(v for ad,v in q['source_reads'])&127)
    self.assertEqual(pair(r['output'],'d','e'),q['saved_pair']);self.assertNotEqual(q['count'],q['discarded_for_count'])
 def test_scan_floor_and_matching_routes_separate(self):
  self.assertEqual([counts(r['law']['route']for r in a['scans'])for a in self.analyses],[{'positive_exact_payload_match':4},{'pointer_at_or_below_top':5,'positive_exact_payload_match':20},{'pointer_at_or_below_top':2,'positive_exact_payload_match':6}])
  for a in self.analyses:
   for r in a['scans']:
    q=r['law'];self.assertEqual(r['return_coordinate'],'PLI1.OVL+45EF'if q['route']=='pointer_at_or_below_top'else'PLI1.OVL+45DD')
    if q['route']=='pointer_at_or_below_top':self.assertNotEqual(r['output']['a'],0)
    else:self.assertEqual([c['index']for c in q['comparisons']],list(reversed(range(q['count']))))
 def test_subsequent_acquisition_preserves_correlation(self):
  for a in self.analyses:
   rs=[r for r in a['roots']if r['subsequent_acquisition']]
   self.assertEqual(len(rs),{'MINIMAL':0,'FIZZBUZ':8,'PICTURE':2}[a['source']])
   for r in rs:self.assertEqual([c['target']for c in r['subsequent_acquisition']['children']],['PLI1.OVL+5A46','PLI1.OVL+784E','PLI1.OVL+4275'])
 def test_corrupted_destination_or_flag_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+4584'][0]);ats(r['own_witnesses'],0x45d1)[0]['reads'][0]['address']+=1
  with self.assertRaises(ValueError):validate_scan(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+4562'][0]);one(r['own_witnesses'],0x4562)['reads'][1]['address']+=1
  with self.assertRaises(ValueError):validate_leaf(r)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+5A46'][0]);one(r['own_witnesses'],0x5a98)['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):stack_proof(r)
 def test_raw_alternatives_remain_raw(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL')
  for lo,hi in [(0x5a57,0x5a77),(0x5aa4,0x5aab),(0x5aae,0x5ab1),(0x45e1,0x45e6),(0x45e9,0x45ef)]:
   self.assertTrue(all(s['status']=='RAW'for s in im['sections']if s['start_offset']<hi and s['end_offset']>lo))
  self.assertEqual(self.catalog['PLI1.OVL+5A46']['completeness']['contract'],'partial');self.assertEqual(self.catalog['PLI1.OVL+4584']['completeness']['contract'],'partial')
 def test_candidate_falsification_and_next_boundary(self):
  q=load(REPORT/'candidate-falsification.json');self.assertEqual(q['historical_binary_query_cases'],0);self.assertEqual(q['natural_leaf_cases'],32)
  b=load(REPORT/'boundary-assessment.json');self.assertFalse(b['5E98_native_ready']);self.assertFalse(b['61A4_620C_native_ready']);self.assertEqual(b['next_causal_blocker'],'PLI1.OVL+3DD9')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);args,rest=p.parse_known_args();IMAGES=args.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
