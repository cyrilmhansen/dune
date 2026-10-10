"""Reviewed Pass64 roles and block explanations; byte promotion is separate."""
import json
from pathlib import Path
from decompilation_annotations import render
r=Path('research/annotated-assembly');cat=json.loads((r/'procedures.json').read_text());roles=json.loads((r/'data-roles.json').read_text())
by={p['id']:p for p in cat['procedures']}
root=by['PLI2.OVL+82DD']
for child in root['direct_callees']:
 if child['callsite_offset']==0x8306:child['evidence_status']='STATIC / UNOBSERVED'
root['inputs']='Fresh1C2C and1C2E words; freshAE6A bit0; freshACA3 pointer. Successful canonical output state; console202A/201E bit0 clear, zero-key poll, supported nonwrapping/nonalias pointer/string/stack/sentinel scope. No caller/source/ordinal selection.'
root['memory_state']=['1C2C initial representation/first console word;1C2E distinct final console word.','AE6A fresh bit0 selects tag40 versus tag00 zero-word emission.','ACA3/A4 -> AC9F/A0 low then high publication; post-publication fresh pointer+2 low and+3 high payload.','Literal94EB/94FA/9507 are dollar-string pointers;resident206A..2080 scratch andcanonicalREL buffer/index/FCB/DMA inherited.','Ordinary outerCALL from046E; nestedCALLs andcanonicalPSW/service frames belowentrySP; no private frame.']
root['blocks']=[dict(offset=o,pseudocode=[s])for o,s in[(0x82dd,'119E literal9A E7 -> bits1001101; fresh1C2C word -> canonicaltag40 low/high.119E9C E7 ->1001110.'),(0x82f3,'FreshAE6A RAR; CY=oldbit0, NZPA preserved. BC0;bit0set calls11E5 tag40,clear calls11C3 tag00;equal words retain distinct tags.'),(0x8309,'124B: conditional alignment with zero bits, then9E E7 trailer1001111. No file close in this child.'),(0x830c,'05FF emits CRLF and fresh dollar string94EB;0466 prints fresh1C2C high-byte then low-byte hexadecimal.'),(0x831a,'05FF94FA;freshACA3 paired read;SHLDAC9F low then high;freshAC9F;INX twice;C=byte[p+2];INX;B=byte[p+3];0466 emits derivedword.'),(0x8331,'05FF9507;fresh1C2E (not1C2C) ->BC ->0466. RET preserves actual final childflags/registers.')]]
root['pseudocode']='; '.join(b['pseudocode'][0]for b in root['blocks'])
root['unresolved_paths']=['Source-language meaning of headers/payload/word states unproved.','AE6A-clear six bytes are independently concrete-CPU proved DEDUCED/STATIC/UNOBSERVED; no natural primary coverage fabricated.','Listing/redirected output, key-present poll, write errors, wrapping/aliased pointers and strings unsupported. No file close/warm boot inside this root.']
for image,name,address,width,text in [('PLI2.OVL','lifecycle_payload_pointer',0xac9f,2,'Visible copied ACA3 pointer, freshly reread for p+2/p+3.'),('PLI2.OVL','lifecycle_zero_word_tag_gate',0xae6a,1,'Fresh bit0 selects zero-word tag40 or tag00.'),('PLI.COM','console_character_carrier',0x206a,1,'Saved character zeroextended toDE forBDOS2.'),('PLI.COM','console_policy_carrier',0x206b,1,'Saved character independently reread after listing/file gates.'),('PLI.COM','console_string_index',0x206c,1,'Published byte scan index with paired adjacent pointer read.'),('PLI.COM','console_string_pointer',0x206d,2,'Saved little-endian dollar-string pointer.'),('PLI.COM','console_string_byte',0x206f,1,'Fresh pointedbyte publication before dollar comparison.'),('PLI.COM','console_hex_nibble',0x2070,1,'Literal arithmetic character formation carrier.'),('PLI.COM','console_hex_byte',0x2071,1,'Independent high/low nibble reads.'),('PLI.COM','console_hex_word',0x2072,2,'B high then C low save;independent high/low byte reads.'),('PLI.COM','console_line_string_pointer',0x207f,2,'Pointer preserved visibly across poll/CRLF children.')]:
 ident=image+':'+name;p=root if image=='PLI2.OVL'else by['PLI.COM+05FF']
 if not any(q['id']==ident for q in roles['roles']):roles['roles'].append(dict(id=ident,image=image,image_sha256=p['image_sha256'],name=name,runtime_address=address,width=width,role=text,scope='Pass64 bounded lifecycle and resident console paths.'))
 if ident not in p['data_role_ids']:p['data_role_ids'].append(ident)
for key,p in by.items():
 if key in json.loads(Path('research/host-compiler/pass-64/contract-laws-PLI.COM.json').read_text()):
  p['unresolved_paths']=['Console-only required routes independently shadowed; listing/redirected output, key-present poll and arbitrary string/scratch/stack alias routes unsupported.']
  p['blocks']=[dict(offset=p['start_offset'],pseudocode=[p['contract']])]
  if key=='PLI.COM+0390':p['unresolved_paths'].append('Listing/page/file arms remain RAW; local CFG partial.')
  if key=='PLI.COM+124B':p['unresolved_paths']=['Suppressed2029 earlyRET1252 remains RAW/UNOBSERVED; active natural writer/padding/trailer scope supported.','No file-close effects; canonical writer-error routes unsupported.']
(r/'data-roles.json').write_text(json.dumps(roles,indent=2)+'\n');(r/'procedures.json').write_text(json.dumps(cat,indent=2)+'\n');render(r)
