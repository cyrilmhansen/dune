"""Independent natural pointer transitions, exact flags and corruption checks."""
import argparse,copy,sys,unittest
from pathlib import Path
from collections import Counter
from check_3a76_pass_36 import *
class PassThirtySixTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.analyses=[analyze(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()]
  cls.actual=derive(cls.analyses)
  cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_durable_facts_regenerated(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  self.assertEqual([len(a['cases']['PLI1.OVL+3A76'])for a in self.analyses],[0,9,4])
  self.assertEqual(sum(len(v)for a in self.analyses for v in a['cases'].values()),122)
 def test_initial_packet_and_occurrences(self):
  packet=load(REPORT/'work-packet.json');self.assertEqual(packet['baseline_commit'],'1e7961c1559aebba910831fda14eb7af5b401fb3')
  self.assertEqual([q['structure']['calls']for q in packet['sources']],[0,9,4])
  self.assertEqual(sum(r['ret']['step_index']-r['call']['step_index']for g in self.rows.values()for r in g['PLI1.OVL+3A76']),4040)
  self.assertEqual([q['direct_contracts']['PLI1.OVL+3963']for q in [packet]],[None])
 def test_catalog_callers_counts_union(self):
  for key,p in load(REPORT/'after.json').items():
   self.assertEqual(p,self.catalog[key])
   if key not in BOUNDS:continue
   union=set()
   for source,g in self.rows.items():
    rs=g[key];self.assertEqual(len(rs),p['observed_paths']['invocations_by_run'][source])
    self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),{c['coordinate']:c['counts_by_run'][source]for c in p['callers']if source in c['counts_by_run']})
    union|={w['origin']['offset']+i for r in rs for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),p['observed_paths']['represented_bytes'])
  self.assertEqual([self.catalog[f'PLI1.OVL+{x:04X}']['observed_paths']['represented_bytes']for x in ENTRIES[:-1]],[142,36,14,38,145])
 def test_range_exit_routes(self):
  self.assertEqual([a['root_routes']for a in self.actual['route-distribution']['sources']],[{},dict(above_saved_input=3,below_reference=6),dict(above_saved_input=4)])
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+3A76']:
    q=r['law'];self.assertEqual(len(q['gate_checks']),2);self.assertFalse(q['gate_checks'][0]['exit']);self.assertTrue(q['gate_checks'][1]['exit'])
    if q['route']=='below_reference':self.assertEqual(q['advanced_pointer'],0)
    else:self.assertGreater(q['advanced_pointer'],q['input_pointer'])
 def test_actual_child_result_and_final_ABI(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+3A76']:
    q=r['law'];self.assertIn(q['result_word'],[0,2]);self.assertEqual(r['output']['a'],0);self.assertEqual(r['output']['flags'],cmp(0,0));self.assertEqual(pair(r['output'],'h','l'),(q['input_pointer']-q['advanced_pointer'])&65535)
    self.assertEqual(r['output']['sp'],r['entry']['sp']+2);self.assertEqual(r['output']['pc'],0x5e98)
 def test_PSW_final_writers(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+3A76']:
    slots={q['relative_address']:q for q in r['stack']}
    for off in [-2,-1]:self.assertEqual(slots[off]['writer'],'PLI1.OVL+3AB2')
    self.assertEqual((slots[-2]['value'],slots[-1]['value']),(0x87,0)if r['law']['route']=='below_reference'else(0x56,255))
 def test_inherited_ten_byte_frame(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+3963']:
    q=r['law'];self.assertEqual(q['frame_base'],r['entry']['sp']-10);self.assertEqual(pair(r['output'],'d','e'),q['inherited_HL']);self.assertEqual(pair(r['output'],'h','l'),r['output']['a'])
 def test_search_advance_before_limit_and_match(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+424F']:
    q=r['law'];self.assertIn(len(q['iterations']),[1,2]);self.assertEqual(q['iterations'][-1]['beyond'],q['route']=='at_or_above_limit_clear')
    if len(q['iterations'])==2:self.assertNotEqual(q['iterations'][0]['field'],q['wanted'])
 def test_advance_preserves_independent_channels(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+4241']:
    q=r['law'];self.assertEqual(q['next_pointer'],(q['fresh_pointer']+q['size'])&65535);self.assertEqual(r['output']['a'],r['entry']['a'])
    for flag in ['sign','zero','auxiliary_carry','parity']:self.assertEqual(r['output']['flags'][flag],r['entry']['flags'][flag])
 def test_classifier_flags_not_literal_return(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+429D']:
    if r['law']['route']=='fallback_literal0':self.assertEqual(r['output']['a'],0);self.assertFalse(r['output']['flags']['zero'])
 def test_finite_three_shift_no_seven_mask(self):
  # Finite local algebra, not historical-binary queries or dynamic coverage.
  for byte in range(256):
   value=byte&252;carry=False
   for _ in range(3):value,carry=(int(carry)<<7)|(value>>1),bool(value&1)
   self.assertEqual(value,byte>>3);self.assertEqual(carry,bool(byte&4));self.assertEqual((value+1)&255,(byte>>3)+1)
 def test_complete_leaves_partial_parents_RAW_retained(self):
  for x in [0x4241,0x424f]:self.assertEqual(self.catalog[f'PLI1.OVL+{x:04X}']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  for x in [0x3a76,0x3963,0x429d]:self.assertEqual(self.catalog[f'PLI1.OVL+{x:04X}']['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');status={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  for a,b in [(0x3a8d,0x3a93),(0x3aed,0x3be4),(0x3c00,0x3c15),(0x3987,0x3a76)]:self.assertTrue(all(status[n]=='RAW'for n in range(a,b)))
 def test_corrupt_route_publication_and_stack_rejected(self):
  base=self.rows['FIZZBUZ']['PLI1.OVL+3A76'][0]
  for off,change in [(0x3abc,lambda w:w['control'].__setitem__('taken',True)),(0x3aa0,lambda w:w['writes'][0].__setitem__('new_value',99)),(0x3bfb,lambda w:w['before'].__setitem__('a',1))]:
   r=copy.deepcopy(base);change(ats(r['own_witnesses'],off)[0])
   with self.assertRaises(ValueError):validate_root(r)
  r=copy.deepcopy(base);ats(r['own_witnesses'],0x3ab2)[0]['writes'][1]['new_value']^=2
  with self.assertRaises(ValueError):stack(r)
 def test_wrong_image_rejected(self):
  rows=copy.deepcopy(self.rows['PICTURE']);rows['PLI1.OVL+3A76'][0]['own_witnesses'][0]['origin']['image']['name']='PLI.COM'
  with self.assertRaises(ValueError):analyze('PICTURE',CAPTURES['PICTURE'],IMAGES,rows)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
