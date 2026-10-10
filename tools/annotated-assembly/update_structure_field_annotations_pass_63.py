"""Byte-exact Pass63 natural structure/payload provenance annotations."""
import os,runpy,json
from pathlib import Path
os.environ['RUNES_ANNOTATION_PASS']='63'
os.environ['RUNES_ANNOTATION_BASE']='692a4da420409e14970e94754067a33532f41adc'
runpy.run_path(str(Path(__file__).with_name('update_buffered_rel_annotations_pass_52.py')),run_name='__main__')
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());p=next(q for q in cat['procedures']if q['id']=='PLI2.OVL+829C')
p['inputs']='Fresh word[ACA3] selects supported four-byte structure target; actual entry register/flag channels are preserved or overwritten instructionally; canonical119E/11C3 output scope inherited. Target is nonwrapping, disjoint from code/output/source/publication/stack/sentinel.'
p['memory_state']=['ACA3/A4 source pointer, low then high read. AC9F/A0 publication low then high, freshly reread after header child.','Target+2 -> C then target+3 -> B; target+0/+1 are not read by this operation.','Canonical20B7/B8 counted serializer;20B9/BA tagged-word cache;REL buffer/index/bit/FCB/DMA state inherited.','Original hardware return word; childCALL and writerPSW/service residue below entrySP; no private frame.']
p['blocks']=[dict(offset=o,pseudocode=[s])for o,s in [(0x829c,'Fresh ACA3 pointer acquisition; SHLD AC9F low then high. This is direct word copying, not a dereference at ACA3.'),(0x82a2,'Literal C94,E7 invokes canonical119E: seven MSB-first rotations select bits7..1; output bit sequence1001010.'),(0x82a9,'After child, independently reread AC9F. Two INX H; fresh payload low at p+2; one INX H; fresh high at p+3. Flags preserved by INX/MOV.'),(0x82b1,'Canonical11C3 receives BC=payload little-endian word; tag00/low8/high8. RET82B4 preserves final canonical child register/flag channels.')]]
p['pseudocode']='; '.join(q['pseudocode'][0]for q in p['blocks']);p['unresolved_paths']=['Pointer-source/compiler structure meaning is unproved; this is a representation-level operation.','Wrapping and source/publication/code/output/stack/sentinel aliases unsupported; canonical child successful-writer scope inherited.']
for source in ['FACTOR','OPTIMIST']:
 file=Path('_build/host-compiler-pass-63')/(source+'-natural-cases.json')
 if file.exists():
  g=json.loads(file.read_text())['sources'][0];rs=next(e['members']for e in g['entries']if e['offset']==0x829c)
  p['observed_paths']['invocations_by_run'][source]=len(rs)
  for caller in sorted({q['caller']for q in rs}):
   row=next((q for q in p['callers']if q['coordinate']==caller),None)
   if row is None:row=dict(coordinate=caller,counts_by_run={});p['callers'].append(row)
   row['counts_by_run'][source]=sum(q['caller']==caller for q in rs)
roles=json.loads((r/'data-roles.json').read_text())
for name,address,text in [('structure_field_source_pointer',0xaca3,'Fresh low/high source pointer acquired by829C before header emission.'),('structure_field_pointer_publication',0xac9f,'Low/high pointer publication reread after canonical header serialization.')]:
 ident='PLI2.OVL:'+name
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image='PLI2.OVL',image_sha256=p['image_sha256'],name=name,runtime_address=address,width=2,role=text,scope='Pass63 bounded829C only; compiler type/ownership meaning unproved.'))
 p['data_role_ids'].append(ident)
(r/'data-roles.json').write_text(json.dumps(roles,indent=2)+'\n')
p['local_comments']['829C']='HL=fresh little_endian_word[structure_field_source_pointer (ACA3H)]; low then high read; flags preserved'
p['local_comments']['829F']='Publish L then H to structure_field_pointer_publication (AC9FH); same-valued writes retained; flags preserved'
p['local_comments']['82A9']='HL=fresh little_endian_word[structure_field_pointer_publication (AC9FH)] after header child; independently reacquired low/high bytes'
(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n')
from decompilation_annotations import render
render(r)
