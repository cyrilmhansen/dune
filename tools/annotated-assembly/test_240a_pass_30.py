#!/usr/bin/env python3
"""Fresh corrected natural windows, independent publication/flag/RAW assertions."""
import argparse,copy,hashlib,json,unittest
from pathlib import Path
from collections import Counter
from check_240a_pass_30 import ROOT,BOUNDS,CAPTURES,FILES,analyze_source,derive,minimum,publication,one
from check_minimal_pass_3 import gather
from check_minimal_pass_2 import coord,load
REPORT=ROOT/'research/host-compiler/pass-30'
class PassThirtyTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()}
  cls.actual=derive([analyze_source(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()])
  cls.catalog={p['id']:p for p in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
 def test_fresh_reports_and_catalog_counts(self):
  for n in FILES:self.assertEqual(self.actual[n],load(REPORT/(n+'.json')))
  for source,rows in self.rows.items():
   for key in ['PLI1.OVL+240A','PLI1.OVL+23A0','PLI1.OVL+23D2']:
    p=self.catalog[key];self.assertEqual(len(rows[key]),p['observed_paths']['invocations_by_run'][source])
    self.assertEqual(Counter(coord(r['call']['origin'])for r in rows[key]),{c['coordinate']:c['counts_by_run'][source]for c in p['callers']if source in c['counts_by_run']})
  self.assertEqual([len(rs['PLI1.OVL+240A'])for rs in self.rows.values()],[8,77,12])
 def test_all_indices_selector_paths_and_no_new_raw_arm(self):
  for source,rows in self.rows.items():
   for r in rows['PLI1.OVL+240A']:
    ws=r['own_witnesses'];sel=one(ws,0x2417)['reads'][0]['value'];i=r['entry']['before']['c']
    self.assertIn(i,[0,2]);self.assertEqual(one(ws,0x2417)['reads'][0]['address'],0xa628+i)
    self.assertEqual(one(ws,0x2418)['after']['flags']['zero'],sel==0x15)
    self.assertEqual(one(ws,0x241a)['control']['taken'],sel!=0x15)
    last_compare=one(ws,0x2442 if sel==0x15 else 0x24aa)
    self.assertEqual(r['ret']['after']['flags'],dict(last_compare['after']['flags'],carry=False))
    if sel==0x15:
     self.assertEqual(one(ws,0x2441)['reads'],[dict(address=0xa62e+i,value=0)])
     self.assertEqual(one(ws,0x2442)['after']['flags']['zero'],True);self.assertTrue(one(ws,0x2444)['control']['taken'])
    else:
     self.assertNotIn(sel,[0x16,0x19]);self.assertTrue(one(ws,0x2464)['control']['taken']);self.assertTrue(one(ws,0x24ac)['control']['taken'])
    self.assertFalse(any(0x2447<=w['origin']['offset']<0x2455 or 0x2467<=w['origin']['offset']<0x24a0 or 0x24af<=w['origin']['offset']<0x24d5 for w in ws))
 def test_minimum_both_arms_flags_and_right_then_left_order(self):
  paths=Counter()
  for rs in self.rows.values():
   for r in rs['PLI1.OVL+23A0']:
    c,e=r['entry']['before']['c'],r['entry']['before']['e'];out=r['ret']['after'];v=(c-e)%256
    paths['C>=E'if c>=e else'C<E']+=1
    self.assertEqual(out['a'],e if c>=e else c)
    self.assertEqual(out['flags'],dict(sign=v>=128,zero=c==e,parity=bin(v).count('1')%2==0,carry=c<e,auxiliary_carry=(c%16)>=(e%16)))
    self.assertEqual(out['flags'],one(r['own_witnesses'],0x23ac)['after']['flags'])
    self.assertEqual([(q['address'],q['new_value'])for w in r['own_witnesses']for q in w['writes']],[(0xa64f,e),(0xa64e,c)])
    self.assertEqual(r['ret']['origin']['offset'],0x23b7 if c>=e else 0x23b3)
  self.assertEqual(paths,{'C>=E':59,'C<E':9})
  # The new lower arm is observed outside +240A, never attributed to that parent.
  for s in self.actual['23a0-cases']['sources']:
   self.assertTrue(all(c['path']=='C>=E'for c in s['cases']if c['caller']=='PLI1.OVL+242B'))
 def test_pointer_and_three_channels_preserve_invocation_chronology(self):
  pubs={(s['source'],c['entry_step']):c for s in self.actual['publication-correlations']['sources']for c in s['cases']}
  for s in self.actual['natural-paths']['sources']:
   for c in s['cases']:
    word=c['word_publication'];pub=pubs[s['source'],c['byte_publication_entry']]
    self.assertEqual(word['writes'][-2:],[[word['destination'],c['pointer']['word']%256],[word['destination']+1,c['pointer']['word']//256]])
    self.assertLess(word['call_step'],pub['call_step']);self.assertEqual(pub['index'],c['index'])
    channels=pub['channels'];self.assertEqual([x['channel']for x in channels],['control','primary','secondary'])
    for x,base,dest in zip(channels,[0xa628,0xa62b,0xa62e],[0xac73,0xad08,0xad9d]):
     self.assertEqual(x['source_address'],base+c['index']);self.assertEqual(x['destination'],dest+x['map_index'])
     self.assertLess(x['source_read_step'],x['position_read_step']);self.assertLess(x['position_read_step'],x['call_step']);self.assertLess(x['call_step'],x['publication_step'])
     self.assertEqual(x['output']['a'],x['source_value'])
    self.assertEqual([x['position_read_step']for x in channels],sorted(set(x['position_read_step']for x in channels)))
    self.assertEqual(c['output'],dict(pub['output'],sp=c['output']['sp'],pc=c['output']['pc']))
 def test_entry_cells_have_exact_prior_writer_and_index2_scope(self):
  for s in self.actual['natural-paths']['sources']:
   for c in s['cases']:
    for a,v in c['entry_cells'].items():
     if v['last_writer']is not None:self.assertLess(v['last_writer']['step'],c['entry_step'])
    self.assertEqual(c['entry_cells'][f"{0xa628+c['index']:04X}"]['value'],c['selector'])
    if c['index']==2:
     self.assertEqual(c['selector'],0x28)
     self.assertEqual(c['entry_cells']['A62A']['last_writer']['coordinate'],'PLI1.OVL+27DA')
     self.assertEqual(c['entry_cells']['A63F']['last_writer']['coordinate'],'PLI1.OVL+3296')
 def test_exact_promotion_union_and_completeness(self):
  manifest=load(ROOT/'research/annotated-assembly/manifest.json')
  self.assertEqual(sum(i['length']for i in manifest['images']),94720)
  for im in manifest['images']:self.assertEqual(hashlib.sha256((IMAGES/im['original_filename']).read_bytes()).hexdigest(),im['sha256'])
  image=(IMAGES/'PLI1.OVL').read_bytes();self.assertEqual(image[0x23b0:0x23b4],bytes.fromhex('3A4EA6C9'))
  pli=next(i for i in manifest['images']if i['name']=='PLI1.OVL')
  self.assertEqual(next(s['status']for s in pli['sections']if s['start_offset']==0x23b0),'UNDERSTOOD')
  for key in ['PLI1.OVL+23A0','PLI1.OVL+23D2','PLI1.OVL+240A']:
   union={w['origin']['offset']+i for rs in self.rows.values()for r in rs[key]for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),self.catalog[key]['observed_paths']['represented_bytes'])
  self.assertEqual(self.catalog['PLI1.OVL+23A0']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
  self.assertEqual(self.catalog['PLI1.OVL+240A']['completeness'],dict(bounds='provisional',control_flow='partial',contract='partial'))
  for start,end in [(0x2447,0x2455),(0x2467,0x24a0),(0x24af,0x24d5)]:
   self.assertTrue(all(s['status']=='RAW'for s in pli['sections']if s['start_offset']<end and s['end_offset']>start))
 def test_corrupted_flags_and_channel_writes_rejected(self):
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+23A0'][0]);r['ret']['after']['flags']['carry']=not r['ret']['after']['flags']['carry']
  with self.assertRaises(ValueError):minimum(r,(IMAGES/'PLI1.OVL').read_bytes())
  r=copy.deepcopy(self.rows['MINIMAL']['PLI1.OVL+23D2'][0]);child=r['nested_returns'][one(r['own_witnesses'],0x2406)['step_index']]
  child['memory_witnesses'][-2]['writes'][0]['new_value']^=1
  with self.assertRaises(ValueError):publication(r)
 def test_before_after_and_bounded_recommendation(self):
  before=load(REPORT/'before.json');after=load(REPORT/'after.json')
  for key,p in after.items():self.assertEqual(p,self.catalog[key])
  self.assertEqual(before['PLI1.OVL+23A0']['observed_paths']['represented_bytes'],20)
  self.assertEqual(after['PLI1.OVL+23A0']['observed_paths']['represented_bytes'],24)
  self.assertEqual(before['PLI1.OVL+240A']['observed_paths']['represented_bytes'],122)
  b=load(REPORT/'boundary-assessment.json');self.assertEqual(b['decision'],'A');self.assertEqual(b['native_implementation_added'],False)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',type=Path,required=True);args,rest=parser.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
