#!/usr/bin/env python3
"""Concrete ownership and table proofs; does not install or certify a native root."""
import argparse,copy,json,os,unittest
from pathlib import Path
from run_selector_dispatch_pass_69 import OUT,BASE,SOURCES,GOLDENS,discover,load,extract
from check_selector02_pass_40 import coord

def transfer(r):
 g=r['gateway'];s=r['entry']['sp']
 assert [q['before']['pc']for q in g]==[0x42ac,0x42af,0x42b0,0x42b3]
 assert [q['bytes']for q in g]==['21B442','E5','2A1FAD','E9']
 assert all(q['image']=='PLI2.OVL'for q in g)
 for a,b in zip(g,g[1:]):assert a['after']==b['before'] and b['step']==a['step']+1
 assert g[-1]['after']==r['entry']
 assert g[0]['after']['h']*256+g[0]['after']['l']==0x42b4
 assert g[1]['before']['sp']==s+2 and g[1]['after']['sp']==s
 assert g[1]['accesses']==[dict(kind='write',address=s+1,value=0x42),dict(kind='write',address=s,value=0xb4)]
 assert g[2]['accesses']==[dict(kind='read',address=0xad1f,value=0xe4),dict(kind='read',address=0xad20,value=0x5f)]
 assert g[-1]['before']['sp']==s and g[-1]['after']['sp']==s and g[-1]['accesses']==[]
 assert r['low_writer']['instruction']==g[1] and r['high_writer']['instruction']==g[1]
 assert r['low_writer']['value']==0xb4 and r['high_writer']['value']==0x42
 assert r['continuation']==0x42b4
 assert r['ret']['before']['sp']==s and r['ret']['after']['sp']==s+2 and r['ret']['after']['pc']==0x42b4
 assert r['ret']['reads']==[dict(address=s,value=0xb4),dict(address=s+1,value=0x42)]

class SelectorDispatchDiscovery(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.environ.get('RUNES_PASS69_REUSE_CAPTURE')!='1':discover(IMAGES)
  cls.inventory=load(OUT/'inventory.json');cls.roots=load(OUT/'roots.json');cls.front=load(OUT/'frontend-proof.json')
 def test_exact_five_source_inventory_and_goldens(self):
  self.assertEqual([self.inventory[s]['roots']for s in SOURCES],[0,2,1,2,3])
  for source in SOURCES:self.assertFalse(any(0x3de4<=int(k.split('+')[1],16)<0x3e36 for k in self.inventory[source]['global_calls']))
  for source,sha in zip(SOURCES,GOLDENS):self.assertEqual(self.inventory[source]['REL_sha256'],sha)
 def test_actual_software_entry_and_return_provenance(self):
  for r in self.roots:transfer(r);self.assertEqual(r['gateway_hardware_call']['after']['pc'],0x41b5)
 def test_transfer_mutations_are_detected_without_native_abi(self):
  for field in ['bytes','sp','target','writer']:
   r=copy.deepcopy(self.roots[0])
   if field=='bytes':r['gateway'][-1]['bytes']='C9'
   elif field=='sp':r['gateway'][-1]['after']['sp']+=2
   elif field=='target':r['gateway'][2]['accesses'][0]['value']^=1
   else:r['low_writer']['value']^=1
   with self.assertRaises(AssertionError):transfer(r)
 def test_selector_distribution_actual_child_and_shared_RET(self):
  self.assertEqual([r['selector']for r in self.roots],[1,2,1,4,4,1,4,2])
  for r in self.roots:
   self.assertEqual([c['target']for c in r['children']],['PLI2.OVL+3660',{1:'PLI2.OVL+3D10',2:'PLI2.OVL+3C27',4:'PLI2.OVL+3B7A'}[r['selector']]])
   self.assertEqual(r['ret']['origin']['offset'],0x3e35)
   self.assertEqual(r['children'][1]['ret']['origin']['offset'],{1:0x3de3,2:0x3d0f,4:0x3bfa}[r['selector']])
   self.assertNotIn(str(r['entry']['sp']),r['stack_last_writers']);self.assertNotIn(str(r['entry']['sp']+1),r['stack_last_writers'])
   arm=r['children'][1]['call'];self.assertEqual(arm['after']['c'],{1:1,2:1,4:1}[r['selector']])
 def test_actual_child_result_RAR_flags_and_optional_path_absence(self):
  for r in self.roots:
   own={w['origin']['offset']:w for w in r['own']};a=own[0x3de7]['before'];b=own[0x3de7]['after']
   self.assertEqual(a,r['children'][0]['ret']['after'])
   self.assertEqual(b['a'],(a['a']>>1)|(int(a['flags']['carry'])<<7));self.assertEqual(b['flags'],dict(a['flags'],carry=bool(a['a']&1)))
   self.assertTrue(own[0x3de8]['control']['taken']);self.assertNotIn(0x3def,own)
 def test_fresh_paired_selector_and_little_endian_table_reads(self):
  for r in self.roots:
   w={q['origin']['offset']:q for q in r['own']};i=r['selector'];target={1:0x600d,2:0x6013,4:0x6023}[i]
   self.assertEqual([q['address']for q in w[0x3df5]['reads']],[0xad0a,0xad0b]);self.assertEqual(w[0x3df8]['after']['c'],w[0x3df5]['reads'][0]['value']);self.assertEqual(w[0x3df9]['after']['b'],0)
   self.assertEqual(w[0x3dfe]['after']['h']*256+w[0x3dfe]['after']['l'],0x602b+i)
   self.assertEqual(w[0x3dff]['after']['h']*256+w[0x3dff]['after']['l'],0x602b+2*i)
   self.assertEqual(w[0x3e00]['reads'],[dict(address=0x602b+2*i,value=target&255)]);self.assertEqual(w[0x3e02]['reads'],[dict(address=0x602c+2*i,value=target>>8)]);self.assertEqual(w[0x3e04]['after']['pc'],target)
 def test_children_hardware_stack_words_and_final_child_flags(self):
  for r in self.roots:
   for c in r['children']:
    w=c['call'];ret=c['ret'];sp=w['after']['sp'];pc=w['pc']+3
    self.assertEqual(w['writes'],[dict(address=sp+1,old_value=None,new_value=pc>>8),dict(address=sp,old_value=None,new_value=pc&255)])
    self.assertEqual(ret['after']['pc'],pc);self.assertEqual(ret['after']['sp'],sp+2)
   self.assertEqual(r['children'][-1]['ret']['after']['flags'],r['ret']['after']['flags'])
 def test_naturally_required_large_gateway_is_not_hidden(self):
  for r in self.roots:
   if r['selector']==1:self.assertEqual(r['gateway_calls'],[])
   elif r['selector']==2:self.assertEqual(r['gateway_calls'][0]['callsite'],'PLI2.OVL+3CAE')
   else:self.assertEqual(r['gateway_calls'][0]['callsite'],'PLI2.OVL+374B')
 def test_CPU_frontend_all_selectors_adjacent_byte_and_carry(self):
  self.assertTrue(self.front['all_passed']);self.assertEqual(len(self.front['cases']),72);self.assertEqual(self.front['RAR_cases'],512)
  for q in self.front['cases']:
   self.assertTrue(q['RAM_unchanged']);self.assertEqual(q['supported_table_domain'],q['selector']<5);self.assertEqual(len(q['steps']),11)
   if q['selector']<5:self.assertEqual(q['target'],[0x6005,0x600d,0x6013,0x601b,0x6023][q['selector']]^q['table_xor'])
 def test_existing_canonical_children_are_independently_shadowed(self):
  q=load(OUT/'component-shadows.json');self.assertTrue(q['all_passed'])
  for c in q['components']:
   expected=sum(r['source']==c['source'] and (c['offset']==0x3660 or r['selector']==1)for r in self.roots)
   #3660 is also called in arm children; every contained natural instance shadows.
   if c['offset']==0x3660:self.assertGreaterEqual(c['count'],expected)
   else:self.assertEqual(c['count'],expected)
 def test_frozen_discovery_scope_and_FULL_provenance(self):
  # This archived proof must remain usable after legitimate later semantic passes.
  # Task scope belongs to its durable packet, not a permanent ban on future edits.
  packet=load('research/host-compiler/pass-69/implementation-packet.json')
  self.assertFalse(packet['runtime_changes']);self.assertEqual(packet['current_full'],'Pass67')
  self.assertEqual(packet['promotions'],{'RAW -> UNDERSTOOD':0,'DECODED -> UNDERSTOOD':0,'STRUCTURED -> UNDERSTOOD':0})
  self.assertGreaterEqual(load('research/host-compiler/validation-policy.json')['current_full_epoch']['epoch'],1)

if __name__=='__main__':
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--images',default='/home/john/pli/cpm/pli80/DISK1');a,rest=p.parse_known_args();IMAGES=a.images;unittest.main(argv=[__file__]+rest)
