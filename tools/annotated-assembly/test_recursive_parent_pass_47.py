#!/usr/bin/env python3
"""Focused topology/dataflow evidence checks; these are not native root shadows."""
import json,unittest,argparse
from run_recursive_parent_pass_47 import prove
from pathlib import Path
REPORT=Path('research/host-compiler/pass-47')
class Topology(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.packet=json.loads((REPORT/'implementation-packet.json').read_text());cls.cases=cls.packet['cases']
 def test_corrected_containment(self):
  for source in ['MINIMAL','FIZZBUZ','PICTURE']:
   rs=[q for q in self.cases if q['source']==source]
   for q in rs:
    parents=[p for p in rs if p['call']<q['call']<q['ret']<p['ret']]
    self.assertEqual(q['parent'],max(parents,key=lambda p:p['call'])['call']if parents else None)
    self.assertEqual(q['depth'],1+len(parents))
 def test_logical_outer_nested(self):
  for source,expected in {'MINIMAL':(1,1,0,1),'FIZZBUZ':(8,1,7,5),'PICTURE':(2,2,0,1)}.items():
   rs=[q for q in self.cases if q['source']==source]
   self.assertEqual((len(rs),sum(q['parent']is None for q in rs),sum(q['parent']is not None for q in rs),max(q['depth']for q in rs)),expected)
 def test_hardware_return_frame(self):
  for q in self.cases:
   e=q['entry'];o=q['output'];self.assertEqual(o[7],e[7]+2);self.assertEqual(o[5]*256+o[6],e[1]*256+e[2])
   image,offset=q['caller'].split('+');self.assertEqual(o[8],int(offset,16)+(0x2200 if image=='PLI1.OVL'else 0x100)+3)
 def test_direct_and_mediated_recursion(self):
  rs={q['call']:q for q in self.cases if q['source']=='FIZZBUZ'};direct=mediated=0
  for q in rs.values():
   if q['parent']is None:continue
   parent=rs[q['parent']]
   if q['caller']in ['PLI1.OVL+03CD','PLI1.OVL+03E8']:
    direct+=1;self.assertEqual(q['entry'][7],parent['entry'][7]-4)
   else:
    mediated+=1;self.assertEqual(q['caller'],'PLI1.OVL+0B79');self.assertLess(q['entry'][7],parent['entry'][7]-4)
  self.assertEqual((direct,mediated),(6,1))
 def test_cumulative_baseline(self):
  p=json.loads((REPORT/'hierarchy-summary.json').read_text())
  for s,expected in {'MINIMAL':(441855,414704,112),'FIZZBUZ':(1145517,967554,340),'PICTURE':(518213,494793,139)}.items():
   self.assertEqual(tuple(p[s][k]for k in ['historical','guest','host']),expected)
 def test_compact_packet(self):self.assertLessEqual((REPORT/'implementation-packet.json').stat().st_size,32768)
 def test_local_law_proof(self):
  p=json.loads((REPORT/'local-proof-summary.json').read_text());self.assertEqual(p['natural_case_counts'],{'02E9':26,'01D8_clear_route':11});self.assertEqual(p['assertions'],436);self.assertEqual(p['oracle_queries'],0)
class NativeParent(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.proof=prove(IMAGES);cls.roots=json.loads((cls.proof/'natural-cases.json').read_text())['sources']
 def test_all_logical_recursive_windows(self):
  q=json.loads((self.proof/'02F0.json').read_text())
  self.assertEqual([g['field15_matched']for g in q['sources']],[1,8,2])
  self.assertTrue(all(g['field80_boundary_matched']==0 for g in q['sources']))
 def test_all_outer_windows_and_stack(self):
  self.assertEqual([len(g['members'])for g in self.roots],[1,1,2])
  for g in self.roots:
   for c in g['members']:
    self.assertEqual(c['output']['sp'],c['input']['sp']+2)
    self.assertEqual(c['output']['h']*256+c['output']['l'],c['input']['b']*256+c['input']['c'])
    self.assertTrue(any(w[4]=='compatibility'for w in c['journal']))
 def test_reader_family_and_quoted_cross_callers(self):
  q=json.loads((self.proof/'quoted.json').read_text());self.assertEqual([g['field15_matched']for g in q['sources']],[2,6,2])
  counts={}
  for file in ['reader3','reader4','reader5']:
   for g in json.loads((self.proof/(file+'.json')).read_text())['sources']:counts.setdefault(g['operation'],{})[g['source']]=g['field15_matched']
  for key in ['1C07','1AFD','2006']:
   self.assertEqual([counts[key][s]for s in ['MINIMAL','FIZZBUZ','PICTURE']],[1,4,1])
 def test_whole_run_savings_and_isolation(self):
  q=json.loads((self.proof/'cumulative-hybrid-summary.json').read_text())['sources']
  self.assertEqual([g['pre_guest_instructions']for g in q],[414704,967554,494793])
  self.assertEqual([g['result']['actual_guest_instructions']for g in q],[405284,869593,476266])
  self.assertEqual([g['guest_instructions_removed']for g in q],[9420,97961,18527])
  self.assertEqual([sum(g['pre_transition_vector'])for g in q],[112,340,139])
  self.assertEqual([g['result']['host_transitions']for g in q],[89,119,88])
  self.assertEqual([g['transition_vector'][:3]for g in q],[[1,0,0],[1,0,0],[2,0,0]])
 def test_both_hybrid_goldens(self):
  expected=['7339d230f13c2614f6b1acb632081959659d7292814c747f7853b6944e91f119','68ec16931d4dae7a8f0831a29c9ae8b9ca139279f5104bb34e299644a8b2a203','c02f738a7504384a236289633210d1bf4e7ea5391e51e091e373950eefacc4f1']
  for file in ['single-hybrid-summary.json','cumulative-hybrid-summary.json']:
   rows=json.loads((self.proof/file).read_text())['sources'];qs=[g.get('result',g)for g in rows]
   self.assertEqual([g['REL_sha256']for g in qs],expected)
   self.assertEqual([g['REL_size']for g in qs],[256,768,256])
   self.assertTrue(all(g['PASS1']and g['PASS2']and g['END_COMPILATION']and g['termination']=='warm_boot'for g in qs))
 def test_pure_algorithm_and_bounded_catalog(self):
  for file in ['recursive_parent.ml','reader_construction.ml','resident_reader.ml']:
   code=Path('lib/pli80_host',file).read_text()
   for forbidden in ['Runner.','Cpu8080','Cpm.','entry_step','source_name','sha256']:self.assertNotIn(forbidden,code)
  catalog={q['id']:q for q in json.loads(Path('research/annotated-assembly/procedures.json').read_text())['procedures']}
  for key in ['PLI1.OVL+02F0','PLI1.OVL+1C07','PLI1.OVL+1AFD','PLI.COM+1376']:
   self.assertEqual(catalog[key]['completeness']['contract'],'partial')
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--images',required=True,type=Path)
 args,rest=parser.parse_known_args();IMAGES=args.images
 unittest.main(argv=[__file__]+rest)
