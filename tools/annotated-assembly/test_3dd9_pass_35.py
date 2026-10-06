"""Natural causal laws, exact flag channels and corruption regressions."""
import argparse,copy,sys,unittest
from pathlib import Path
from collections import Counter
from check_3dd9_pass_35 import *
class PassThirtyFiveTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.analyses=[analyze(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()]
  cls.actual=derive(cls.analyses,cls.rows,IMAGES)
  cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_all_durable_correlations_regenerated(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  self.assertEqual([len(a['roots'])for a in self.analyses],[0,12,4])
 def test_catalog_counts_callers_byte_union(self):
  for key,p in load(REPORT/'after.json').items():
   prior36=load(ROOT/'research/host-compiler/pass-36/before.json')
   self.assertEqual(p,prior36.get(key) or self.catalog[key]);union=set()
   for source,g in self.rows.items():
    rs=g[key];self.assertEqual(len(rs),p['observed_paths']['invocations_by_run'][source])
    self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),{c['coordinate']:c['counts_by_run'][source]for c in p['callers']if source in c['counts_by_run']})
    union|={w['origin']['offset']+i for r in rs for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),p['observed_paths']['represented_bytes'])
  self.assertEqual([self.catalog[f'PLI1.OVL+{x:04X}']['observed_paths']['represented_bytes']for x in ENTRIES],[460,63,23,39,11])
 def test_CE_routes_and_child_chronology(self):
  self.assertEqual([counts(r['law']['route']for r in a['roots'])for a in self.analyses],[{},dict(E0_scan_only=3,E1_publication_scan_postcheck=8,E_other_publication_scan=1),dict(E1_publication_scan_postcheck=2,E_other_publication_scan=2)])
  for a in self.analyses:
   for r in a['roots']:
    q=r['law'];targets=[c['target']for c in q['children']]
    self.assertEqual('PLI1.OVL+3C8A'in targets,q['E']!=0)
    self.assertEqual(len(q['publications']),6 if q['E']!=0 else 0)
    self.assertEqual(q['C'],0);self.assertEqual(q['counter'],0)
 def test_single_record_fresh_step_and_termination(self):
  for a in self.analyses:
   for r in a['roots']:
    q=r['law'];self.assertEqual(q['first_pointer'],q['last_pointer'])
    self.assertEqual(q['scan']['next_pointer'],(q['scan']['pointer']+q['scan']['size'])&65535)
    self.assertGreater(q['scan']['next_pointer'],q['last_pointer'])
    self.assertEqual(q['scan']['field_bit7_mask'],0);self.assertEqual(q['scan']['bound_test_A'],0)
 def test_return1_keeps_zero_flag_and_machine_state(self):
  for a in self.analyses:
   for r in a['roots']:
    q=r['law'];self.assertEqual(r['output']['a'],1);self.assertTrue(r['output']['flags']['zero'])
    self.assertFalse(r['output']['flags']['auxiliary_carry']);self.assertFalse(r['output']['flags']['carry'])
    self.assertEqual(pair(r['output'],'b','c'),0);self.assertEqual(pair(r['output'],'d','e'),0xa75d)
    self.assertEqual(pair(r['output'],'h','l'),q['first_pointer']+3)
    self.assertEqual(r['output']['sp'],r['entry']['sp']+2)
 def test_small_mask_leaf_complete_and_all_finite_inputs(self):
  p=self.catalog['PLI1.OVL+3558'];self.assertEqual(p['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  # Independent finite algebra over represented bytes. Not binary-oracle queries.
  for field in range(256):
   value=field&128;value=(value-128)&255;borrow=value<1;value=(value-1)&255
   result=(value-value-int(borrow))&255
   self.assertEqual(result,255 if field&128 else 0)
   self.assertEqual(cmp(0,int(borrow)),dict(sign=bool(field&128),zero=not bool(field&128),auxiliary_carry=not bool(field&128),parity=True,carry=bool(field&128)))
  self.assertEqual([len(a['dependencies']['PLI1.OVL+3558'])for a in self.analyses],[0,21,8])
 def test_bound_mismatch_zero_does_not_set_zero_flags(self):
  for a in self.analyses:
   for r in a['dependencies']['PLI1.OVL+387F']:
    q=r['law'];self.assertLessEqual(q['pointer'],q['end']);self.assertEqual(r['output']['a'],0)
    self.assertEqual(r['output']['flags'],cmp(q['field'],0x70));self.assertFalse(r['output']['flags']['zero'])
 def test_zero_frame_preserves_opaque_child_BC(self):
  values=set()
  for a in self.analyses:
   for r in a['dependencies']['PLI1.OVL+3C8A']:
    q=r['law'];self.assertEqual(q['frame_length'],6);self.assertEqual(q['frame_base'],r['entry']['sp']-6)
    self.assertEqual(pair(r['output'],'b','c'),pair(q['child']['output'],'b','c'));values.add(q['BC'])
    self.assertEqual(pair(r['output'],'d','e'),0);self.assertEqual(pair(r['output'],'h','l'),0)
  self.assertEqual(values,{0,65535})
 def test_stack_PSW_and_last_writer_are_mechanical(self):
  for a in self.analyses:
   for r in a['roots']:
    slot={q['relative_address']:q for q in r['stack']}
    for off in (-2,-1):self.assertEqual(slot[off]['writer'],'PLI1.OVL+4148')
    self.assertEqual(slot[-2]['value'],2|64|16|4);self.assertEqual(slot[-1]['value'],0)
  for a in self.analyses:
   for r in a['dependencies']['PLI1.OVL+3558']:
    slot={q['relative_address']:q for q in r['stack']};self.assertEqual((slot[-2]['value'],slot[-1]['value']),(0x5b,0x57))
 def test_unobserved_holes_stay_RAW_and_no_native(self):
  m=load(ROOT/'research/annotated-assembly/manifest.json');im=next(i for i in m['images']if i['name']=='PLI1.OVL')
  status={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  before=load(REPORT/'before.json');self.assertTrue(all(v is None for v in before.values()))
  for a,b in [(0x3e1d,0x3f43),(0x3fde,0x3ff0),(0x4011,0x4054),(0x40c8,0x40e1),(0x410b,0x410e),(0x4111,0x4130),(0x4158,0x415b),(0x3cbd,0x3dcd),(0x416e,0x4173),(0x3895,0x3898)]:
   self.assertTrue(all(status[n]=='RAW'for n in range(a,b)))
  self.assertFalse(load(REPORT/'boundary-assessment.json')['native_implementation_added'])
 def test_corrupted_flag_address_route_and_PSW_rejected(self):
  base=self.rows['FIZZBUZ']['PLI1.OVL+3DD9'][0]
  for off,change in [(0x3f48,lambda w:w['control'].__setitem__('taken',True)),(0x3dfe,lambda w:w['reads'][0].__setitem__('address',0)),(0x4137,lambda w:w['writes'][0].__setitem__('new_value',1)),(0x4153,lambda w:w['after']['flags'].__setitem__('auxiliary_carry',True))]:
   r=copy.deepcopy(base);change(one(r['own_witnesses'],off))
   with self.assertRaises(ValueError):validate_root(r)
  r=copy.deepcopy(base);one(r['own_witnesses'],0x4148)['writes'][1]['new_value']^=2
  with self.assertRaises(ValueError):stack(r)
 def test_wrong_image_and_return_ancestry_rejected(self):
  rows=copy.deepcopy(self.rows['PICTURE']);rows['PLI1.OVL+3DD9'][0]['own_witnesses'][0]['origin']['image']['name']='PLI.COM'
  with self.assertRaises(ValueError):analyze('PICTURE',CAPTURES['PICTURE'],IMAGES,rows)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
