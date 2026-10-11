#!/usr/bin/env python3
"""Concrete gateway-own laws and partial-child decomposition, not a native certificate."""
import argparse,collections,json,unittest
from run_gateway_decomposition_pass_71 import OUT,REPORT,SOURCES,GOLDENS,load,discovery,accesses,word
class GatewayDecomposition(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  discovery(IMAGES);cls.rs=load(OUT/'roots.json');cls.inv=load(OUT/'inventory.json')
 def test_counts_callers_and_goldens(self):
  self.assertEqual([self.inv[s]['count']for s in SOURCES],[11,61,12,33,120]);self.assertEqual(len(self.rs),237)
  for s,sha in zip(SOURCES,GOLDENS):self.assertEqual(self.inv[s]['REL_sha256'],sha)
  for r in self.rs:
   call=r['entry']['CALL'];self.assertEqual(call['image'],'PLI2.OVL');self.assertEqual(call['kind'],'call');self.assertEqual(call['bytes'],'CDB541');self.assertEqual(call['after'],r['entry']['entry']);self.assertEqual(call['before']['sp'],call['after']['sp']+2)
 def test_exact_twelve_byte_frame_save_and_restore(self):
  for r in self.rs:
   s=r['entry']['entry']['sp'];w=r['own'];by={q['offset']:q for q in w};expected={s-12:r['entry_C'],s-1:r['entry']['saved_state'][0]}|{s-12+i:v for i,v in enumerate(r['entry']['saved_state'])if i}
   before=[q for q in w if q['offset']<0x1fde];last={a['address']:a['value']for q in before for a in accesses(q,'write')};self.assertEqual({a:last[a]for a in expected},expected)
   self.assertEqual(by[0x1fb9]['after']['sp'],s-11);self.assertEqual(by[0x1fbb]['after']['sp'],s-13);self.assertEqual(by[0x1fbc]['after']['sp'],s-12)
   restore=[q for q in w if q['offset']>=0x20c8];written=[a for q in restore for a in accesses(q,'write')if 0xad0a<=a['address']<=0xad14];self.assertEqual([(a['address'],a['value'])for a in written],[(0xad0b+i,v)for i,v in enumerate(r['entry']['saved_state'][1:])]+[(0xad0a,r['entry']['saved_state'][0])])
   reads=[a for q in restore for a in accesses(q,'read')if s-12<=a['address']<s];self.assertEqual([(a['address'],a['value'])for a in reads],[(s-11+i,v)for i,v in enumerate(r['entry']['saved_state'][1:])]+[(s-1,r['entry']['saved_state'][0])])
 def test_lookup_and_three_table_provenances(self):
  for r in self.rs:
   by={q['offset']:q for q in r['own']};k=r['k'];self.assertEqual(r['lookup']['call']['after']['c'],r['entry_C']);self.assertEqual(r['lookup']['ret']['after']['a'],k)
   self.assertEqual(accesses(by[0x1fec],'read'),[dict(kind='read',address=0x3c21+2*k,value=r['descriptor']&255)]);self.assertEqual(accesses(by[0x1fee],'read'),[dict(kind='read',address=0x3c22+2*k,value=r['descriptor']>>8)])
   self.assertEqual(accesses(by[0x2009],'read'),[dict(kind='read',address=0x3ddd+2*k,value=r['handler']&255)]);self.assertEqual(accesses(by[0x200b],'read'),[dict(kind='read',address=0x3dde+2*k,value=r['handler']>>8)])
   if r['fallback']:
    source=accesses(by[0x206e],'read')[0];self.assertEqual(source['address'],0x1b4b+k);self.assertEqual(source['value']&7,r['fallback_index']);j=r['fallback_index'];low=accesses(by[0x2077],'read')[0];high=accesses(by[0x2079],'read')[0];self.assertEqual([low['address'],high['address']],[0x3c13+2*j,0x3c14+2*j]);self.assertEqual(r['fallback_pointer'],((high['value']*256+low['value'])+1)&65535)
 def test_candidate_actual_result_bit_gate_and_shared_skip(self):
  for r in self.rs:
   own=r['own'];self.assertLessEqual(r['scan_calls'],r['initial_count']);self.assertEqual(r['success'],not r['fallback'])
   for p in r['predicates']:
    self.assertIn(p['ret']['after']['a'],[0,1]);self.assertEqual(p['call']['after']['c'],r['entry_C'])
    if p['call']['offset']==0x2037:
     rar=next(q for q in own if q['offset']==0x203a and q['step']>p['ret']['step']);self.assertEqual(rar['before'],p['ret']['after']);a=rar['before'];b=rar['after'];self.assertEqual(b['a'],(a['a']>>1)|(int(a['CY'])<<7));self.assertEqual(b['CY'],bool(a['a']&1));self.assertEqual([b[k]for k in ['S','Z','AC','P']],[a[k]for k in ['S','Z','AC','P']])
     branch=next(q for q in own if q['step']==rar['step']+1);self.assertEqual(branch['taken'],not b['CY'])
   for q in own:
    if q['offset']==0x204f:self.assertEqual(word(q['after']),(word(q['before'])+q['before']['e'])&65535);self.assertEqual(q['after']['CY'],word(q['before'])+q['before']['e']>65535)
 def test_observed_success_publication_flags_and_order(self):
  rr=[r for r in self.rs if r['success']];self.assertEqual(len(rr),53);self.assertEqual(collections.Counter(r['source']for r in rr),dict(FIZZBUZ=12,PICTURE=2,FACTOR=10,OPTIMIST=29))
  for r in rr:
   w=[q for q in r['own']if 0x203e<=q['offset']<0x2046];self.assertEqual([q['offset']for q in w],[0x203e,0x2041,0x2043,0x2044]);self.assertEqual([(a['address'],a['value'])for q in w for a in accesses(q,'write')],[(0xad1a,0),(0xad1b,1)])
   for q in w:self.assertEqual([q['before'][k]for k in ['S','Z','AC','P','CY']],[q['after'][k]for k in ['S','Z','AC','P','CY']])
 def test_software_PUSH_PCHL_and_handler_RET(self):
  self.assertEqual(len(set(r['handler']for r in self.rs)),47)
  for r in self.rs:
   by={q['offset']:q for q in r['own']};s=r['entry']['entry']['sp'];push=by[0x20af];self.assertEqual(word(push['before']),0x42b4);self.assertEqual(accesses(push,'write'),[dict(kind='write',address=s-13,value=0x42),dict(kind='write',address=s-14,value=0xb4)])
   pchl=by[0x20b3];self.assertEqual(pchl['bytes'],'E9');self.assertEqual(pchl['before']['sp'],s-14);self.assertEqual(pchl['after']['sp'],s-14);self.assertEqual(pchl['after']['pc'],r['handler'])
   ret=r['handler_ret'];self.assertIsNotNone(ret);self.assertEqual(accesses(ret,'read'),[dict(kind='read',address=s-14,value=0xb4),dict(kind='read',address=s-13,value=0x42)]);self.assertEqual(ret['after'],by[0x20b4]['before'])
 def test_trace_clear_restore_final_registers_and_hardware_RET(self):
  for r in self.rs:
   self.assertEqual((r['trace_before'],r['trace_after']),(0,0));q=r['exit']['exit'];s=r['entry']['entry']['sp'];self.assertEqual(q['a'],r['entry']['saved_state'][0]);self.assertEqual(q['b']*256+q['c'],s-1);self.assertEqual(q['d']*256+q['e'],0xad15);self.assertEqual(word(q),s);self.assertEqual(q['sp'],s+2);self.assertEqual(q['pc'],r['entry']['continuation']);self.assertEqual([q[k]for k in ['S','Z','AC','P','CY']],[False,True,True,True,False]);self.assertEqual(r['original_slot_writes'],[]);self.assertEqual(r['descendant_original_slot_writes'],[])
 def test_nested_frames_remain_distinct(self):
  by={(r['source'],r['entry']['id']):r for r in self.rs};self.assertEqual(sum(r['entry']['parent']!=0 for r in self.rs),222)
  for r in self.rs:
   if r['entry']['parent']:
    p=by[(r['source'],r['entry']['parent'])];self.assertLess(r['entry']['entry']['sp']+1,p['entry']['entry']['sp']-12);self.assertLess(p['entry']['step'],r['entry']['step']);self.assertLess(r['exit']['step'],p['exit']['step'])
 def test_blocker_callsite_subset_still_requires_handlers(self):
  r=[r for r in self.rs if r['caller']in [0x374b,0x3cae,0x3740]];self.assertEqual(len(r),16);self.assertEqual(set(x['handler']-0x2200 for x in r),{0x3e36,0x256e,0x3ffd,0x6d47});self.assertTrue(all(x['handler']-0x2200==0x3e36 for x in r if x['source']=='FIZZBUZ'))
 def test_component_shadows_and_synthetic_fragments(self):
  q=load(OUT/'component-shadows.json');self.assertTrue(q['all_passed']);self.assertEqual(sum(c['count']for c in q['components']if c['offset']==0x047d),2064);self.assertEqual(sum(c['count']for c in q['components']if c['offset']==0x6ea5),11)
  q=load(OUT/'fragment-proof.json');self.assertTrue(q['all_passed']);self.assertEqual(q['save_restore_cases'],30);self.assertEqual(q['success_cases'],768)
 def test_no_fake_gateway_native_scope_or_FULL(self):
  q=load(REPORT/'implementation-packet.json');self.assertFalse(q['native_root_installed']);self.assertEqual(q['current_full'],'Pass67');self.assertEqual(q['oracle_queries'],0);self.assertEqual(q['promotions'],{'RAW -> UNDERSTOOD':8,'STRUCTURED -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0})
if __name__=='__main__':
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
