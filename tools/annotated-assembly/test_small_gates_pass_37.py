"""Compact packet regeneration and accumulated natural small-gate proof."""
import argparse,copy,sys,unittest,json,subprocess
from pathlib import Path
from collections import Counter
from check_small_gates_pass_37 import *
class PassThirtySevenTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.rows={s:gather(c,BOUNDS,include_nested_returns=True)for s,c in CAPTURES.items()};cls.analyses=[analyze(s,c,IMAGES,cls.rows[s])for s,c in CAPTURES.items()]
  cls.catalog={q['id']:q for q in load(ROOT/'research/annotated-assembly/procedures.json')['procedures']}
  base=json.loads(subprocess.check_output(['git','show','98a01655e0b7cad44f2909c96969cc051eadd174:research/annotated-assembly/procedures.json'],text=True));cls.reference={q['id']:q for q in base['procedures']};cls.reference.update(load(REPORT/'after.json'))
 def test_packet_regenerated_below_target(self):
  packet=build_packet(self.rows,self.reference);self.assertEqual(packet,load(REPORT/'work-packet.json'));self.assertLessEqual(len((json.dumps(packet,separators=(',',':'))+'\n').encode()),32768)
  self.assertEqual(len(packet['cases']),69);self.assertEqual(len(packet['routes']),16);self.assertEqual(len(packet['stack_patterns']),13)
 def test_aggregate_natural_claims_regenerated(self):
  self.assertEqual(derive(self.analyses),load(REPORT/'natural-summary.json'));self.assertEqual(sum(len(v)for a in self.analyses for v in a['cases'].values()),428)
  self.assertEqual([len(a['cases']['PLI1.OVL+4601'])for a in self.analyses],[0,5,2])
 def test_invocation_deltas_restore_exact_ABI_and_writes(self):
  packet=build_packet(self.rows,self.reference);by={(s,k['call']['step_index']):k for s,g in self.rows.items()for v in g.values()for k in v}
  for c in packet['cases']:
   source=packet['sources'][c[0]];r=by[source,c[2]];route=packet['routes'][c[4]];stackp=packet['stack_patterns'][c[5]]
   restored=[]
   for base,delta in [(route['base_abi'][0],c[6]),(route['base_abi'][1],c[7]),(route['base_write_values'],c[8]),(stackp['base_values'],c[9])]:
    q=base[:]
    for i,v in delta:q[i]=v
    restored.append(q)
   self.assertEqual(restored[0][:9],[r['entry']['before'][q]for q in ['a','b','c','d','e','h','l','sp','pc']]);self.assertEqual(restored[1][:9],[r['ret']['after'][q]for q in ['a','b','c','d','e','h','l','sp','pc']]);self.assertEqual(restored[2],[q['value']for q in writes(r['own_witnesses'])]);self.assertEqual(restored[3],[q['value']for q in stack(r)])
 def test_full_proof_size_hash_and_efficiency(self):
  encoded=(json.dumps(dict(rows=self.rows,analyses=self.analyses),separators=(',',':'))+'\n').encode();m=load(REPORT/'efficiency.json')
  self.assertEqual(len(encoded),m['full_rederivable_evidence_bytes']);self.assertEqual(hashlib.sha256(encoded).hexdigest(),m['full_rederivable_evidence_sha256']);self.assertEqual((REPORT/'work-packet.json').stat().st_size,m['model_facing_packet_bytes']);self.assertEqual(m['compression_ratio'],round(len(encoded)/m['model_facing_packet_bytes'],3))
  self.assertEqual(m['repeated_route_structures_eliminated'],412);self.assertEqual(m['repeated_stack_patterns_eliminated'],415);self.assertEqual(m['new_historical_oracle_queries'],0)
 def test_catalog_counts_callers_byte_union(self):
  for key,p in load(REPORT/'after.json').items():
   self.assertEqual(p,self.catalog[key])
   if key not in BOUNDS:continue
   union=set()
   for s,g in self.rows.items():
    rs=g[key];self.assertEqual(len(rs),p['observed_paths']['invocations_by_run'][s]);self.assertEqual(Counter(coord(r['call']['origin'])for r in rs),{c['coordinate']:c['counts_by_run'][s]for c in p['callers']if s in c['counts_by_run']})
    union|={w['origin']['offset']+i for r in rs for w in r['own_witnesses']for i in range(len(bytes.fromhex(w['bytes'])))}
   self.assertEqual(len(union),p['observed_paths']['represented_bytes'])
 def test_cleanup_control_channel_and_fresh_successor(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+4601']:
    q=r['law'];self.assertEqual(q['payload_pointer'],(q['input_pointer']+10)&65535);self.assertEqual(q['control'],1 if a['source']=='FIZZBUZ'else 6);self.assertEqual(q['successor'],0);self.assertNotEqual(q['result_word'],0);self.assertEqual(r['output']['a'],q['top']>>8)
 def test_cleanup_stack_last_writers(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+4601']:
    st={v['relative_address']:v for v in r['stack']}
    for off,value,writer in [(-2,0x2c,'PLI1.OVL+4629'),(-1,0x68,'PLI1.OVL+4629'),(-4,0x95,'PLI1.OVL+4592'),(-3,0x67,'PLI1.OVL+4592')]:self.assertEqual((st[off]['value'],st[off]['writer']),(value,writer))
 def test_21AD_finite_disjoint_delegation_domain(self):
  fast_count=0;slow_count=0
  for c in range(256):
   x=(c-0x30)&255;first=(-int(x+255>255))&255;borrow=0x31<c;second=(~((-int(borrow))&255))&255;mask=first&second
   self.assertEqual(bool(mask&1),c!=0x30 and c<=0x31)
   if mask:fast_count+=1
   else:slow_count+=1;self.assertNotIn(c,[0x0b,0x0c,0x0d,2,3,4])
  self.assertEqual((fast_count,slow_count),(49,207));self.assertEqual(self.catalog['PLI1.OVL+21AD']['completeness'],dict(bounds='stable',control_flow='complete',contract='complete'))
 def test_21AD_all_fast_slow_ABI_and_residue(self):
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+21AD']:
    c=r['entry']['c'];fast=c!=0x30 and c<=0x31;st={v['relative_address']:v for v in r['stack']};self.assertEqual((st[-2]['value'],st[-1]['value']),(0x87,255)if fast else(0xd3,0x43))
    if not fast:self.assertEqual(pair(r['output'],'b','c'),(0 if c==0x30 else 0xff00)+c);self.assertEqual(r['output']['flags'],cmp(c,4))
 def test_required_gate_classifier_distribution(self):
  required=[[(r['law']['selector'],r['output']['a'])for r in a['cases']['PLI1.OVL+239A']if r['caller']=='PLI1.OVL+3FB7']for a in self.analyses]
  self.assertEqual([dict(Counter(q))for q in required],[{},dict([((0x15,4),6),((0x80,5),3)]),dict([((0x15,4),3),((0x31,6),1)])])
 def test_same_four_retains_distinct_carry_provenance(self):
  flags={r['output']['flags']['carry']for a in self.analyses for r in a['cases']['PLI1.OVL+230E']if r['output']['a']==4};self.assertEqual(flags,{False,True})
  for a in self.analyses:
   for r in a['cases']['PLI1.OVL+22CB']:
    q=r['law'];self.assertEqual(r['output']['flags'],cmp(q['selector'],0x15 if q['selector']==0x15 else 0x19))
 def test_raw_literal_alternatives_preserved(self):
  im=next(i for i in load(ROOT/'research/annotated-assembly/manifest.json')['images']if i['name']=='PLI1.OVL');st={n:s['status']for s in im['sections']for n in range(s['start_offset'],s['end_offset'])}
  for start in [0x2148,0x2153,0x215e,0x2174,0x217f,0x22f0,0x2302,0x232f,0x238e]:self.assertTrue(all(st[n]=='RAW'for n in range(start,start+3)))
  for k in ['239A','2355','213C','230E','22CB']:self.assertEqual(self.catalog['PLI1.OVL+'+k]['completeness']['contract'],'partial')
 def test_contract_references_are_hashes_not_copied_prose(self):
  p=load(REPORT/'work-packet.json')
  for k,q in p['contracts'].items():self.assertEqual(set(q),{'id','sha256','completeness'});self.assertEqual(q['sha256'],hashlib.sha256(json.dumps(self.reference[k],sort_keys=True).encode()).hexdigest())
 def test_modified_source_byte_address_flags_rejected(self):
  base=self.rows['FIZZBUZ']['PLI1.OVL+4601'][0];r=copy.deepcopy(base);one(r['own_witnesses'],0x4625)['reads'][1]['address']^=1
  with self.assertRaises(ValueError):validate_cleanup(r)
  rows=copy.deepcopy(self.rows['PICTURE']);rows['PLI1.OVL+4601'][0]['own_witnesses'][0]['bytes']='00'
  with self.assertRaises(ValueError):analyze('PICTURE',CAPTURES['PICTURE'],IMAGES,rows)
 def test_wrong_image_and_PSW_corruption_rejected(self):
  rows=copy.deepcopy(self.rows['PICTURE']);rows['PLI1.OVL+4601'][0]['own_witnesses'][0]['origin']['image']['name']='PLI.COM'
  with self.assertRaises(ValueError):analyze('PICTURE',CAPTURES['PICTURE'],IMAGES,rows)
  r=copy.deepcopy(self.rows['FIZZBUZ']['PLI1.OVL+21AD'][0]);one(r['own_witnesses'],0x21b9)['writes'][1]['new_value']^=2
  with self.assertRaises(ValueError):stack(r)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);a,rest=p.parse_known_args();IMAGES=a.images.resolve();unittest.main(argv=[sys.argv[0],*rest])
