"""Select only independently proved natural local instructions for Pass47."""
import json,re,hashlib
from pathlib import Path
OUT=Path('_build/host-compiler-pass-47');REPORT=Path('research/host-compiler/pass-47')
def load(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
cat={p['id']:p for p in load(Path('research/annotated-assembly/procedures.json'))['procedures']}
rows={s:{}for s in ['MINIMAL','FIZZBUZ','PICTURE']}
for path in OUT.glob('*rows.json'):
 for source,groups in load(path).items():
  for key,cases in groups.items():
   existing=rows[source].setdefault(key,{})
   for case in cases:existing[case['call']['step_index']]=case
rows={s:{k:sorted(v.values(),key=lambda r:r['call']['step_index'])for k,v in ks.items()}for s,ks in rows.items()}
texts={
'02F0':'PUSH the original BC word; compose 80CA and 02E9; publish A6CA=0; fresh resident18DB and RAR select the cached-probe route. Otherwise exact selector probes choose the reader tail, mediated11E2 frame, or 82/B4/B3 direct-recursion sequence. Direct recursive calls receive BC=0 from instructions; 0A32-mediated recursion receives its fresh inherited frame word. Recursion follows changing acquisition state and historical predicates with no depth limit. Final01D8 state and POP H restore the original BC word to HL; final RET consumes the actual caller word.',
'1C07':'Save C at A621 and A5F7, publish mode through8268. Fresh selector probes C6/C7/C2 choose descriptor construction, structure traversal/publication, or literal prefix adaptation; loop from newly acquired selector after the C2 path. Compose1AFD,140D,80B7 and witnessed trailing784E reads until the fresh semicolon. No source-level stream or type inference.',
'1AFD':'Allocate the historical two-byte private frame; retain input C and independent prior state. Publish A619=0, mode8268; require actual parenthesis match and clear saved input bit. C=0 invokes canonical19F0, then140D consumes its returned A. Fresh comma probe controls witnessed no-repeat path;156D acquires the closing delimiter. Literal A=0, POP H and RET preserve the path flags and surviving private residue.',
'1D13':'1BA8 initializes construction state;1BBF builds the independent descriptor publications; fresh copies update the historical A5xx channels in instruction order. Child effects remain delegated to their independently proved bounded laws.',
'1BBF':'Historical descriptor construction around1421 and canonical mapped publications; fresh selector and count channels remain distinct. Descending balance indices and the actual comparison predicates terminate the demonstrated route.',
'1421':'Repeated balance traversal and descriptor adjustment use fresh A610/A60F and mapped table reads. The carry-producing compare selects swap or nonswap; both arms restore AE35, freshly publish A610 from A60F, and call14C8. Retain each iteration and fresh reread; no fixed iteration count.',
'2006':'Clear A61E/A606/A5F9/A5FA/A5FB in order; complete57B7(BC=3594H) supplies the actual not-found result and RAR. Actual8C/90 selector probes choose the bounded C=1 reader1C07 operation; final13AD fresh semicolon probe controls ordinary return.',
'0A32':'Eight-byte historical frame: DCX SP, two PUSH H, MOV D,E/PUSH D/INX SP, PUSH B. Each iteration reinitializes frame F3/F4 before02E9 and independent18DB/020E probes. Fresh cached predicate or unmatched87/A7/9B route invokes the same canonical02F0 using the frame word. Actual8A route composes0146,45F0, fresh pointer comparison and784E; semicolon plus0266 terminate; four POP H consume only the private frame.',
'11E2':'Eleven-byte private frame retains BC and E independently, plus four PUSH H words.020E/RAR selects the demonstrated route;0E00 publishes header state. Fresh A5E3/A5EC/A5E5/A5F0/A5E2/A5E6 populate F3..F10 in historical order.0A32 receives independently reloaded BC/E and may recurse into02F0. Fresh frame publications feed58BB/590E,0D94,3304,2308/classifier and2511; final fresh semicolon test, LXI H,000BH/DAD SP/SPHL discard the eleven private bytes before ordinary RET.',
'0E00':'Initialize A5F2/A5E1..A5E5; exact cached/lookahead mask constructions select1014/1187. Preserve fresh count and pointer publications; independent590E calls consume the two producer words.3304, fresh classifier+39H and2511 precede common24/1/0 publications,240A,0FC9 and8179 restoration. Final independent mask tests,8048(A8),7ED7 and2511(6A) delegate the exact returned state.',
'109E':'Cache independent position difference through8152;6639 and8179 restore it;3262 establishes fresh indexed channels. Exact 2/3/4 equality masks and independent balance comparisons choose A5F5. Reconstruct2DC3 and the final PSW comparison; bounded81F1 consumes C=2 only when the actual final predicate selects it.',
'08D9':'Four-byte inherited-pointer/input frame; preserve old A5BA separately, clear fresh A5BA and copy private input into F1. Actual selector/gate predicates choose nested-base acquisition,5A46 and3DD9(C0,E2). Independent null-word check controls A5BA/A5BC/A5B8 publications; actual field reads,784E and8273 precede0187/086E. Restore old A5BA from F2/F3, then two POP H; no snapshot substitution.',
'0D40':'Reset the witnessed listing gate; clear reader cursor/count and independently fetch raw source. Fresh LF/EOF masks terminate; CR appends zero, witnessed printable bytes append through0E1F, fresh source fetch repeats. Record line counter is a separate four-byte representation. Publish count=cursor+1, append final zero, publish200A=1, and reset cursor. Unseen tab/high-bit/listing/error alternatives remain excluded.',
'070C':'Fresh EOF bit may return literal1A; otherwise increment word1D08 and compare against01FF. Available byte reads use fresh1D06 base and cursor. Refill polls console, sets cursor0, compares current cursor with0200, sets DMA and reads sequential source records. Success advances128; EOF writes1A and forces cursor0200. Recheck actual predicates, reset cursor, freshly read first buffer byte; no arbitrary-input termination claim.',
'1688':'Initialize independent lookahead depth, replay length/index, cursor and cached context. State-driven scan tests whitespace, equals, semicolon, nesting delimiters and identifier/digit masks; calls18A2/18BC/1843 in historical order.1843 reads counted buffered data or appends raw fetch to replay; fresh predicates terminate or advance. Quoted/slash/EOF and unobserved scanner alternatives remain excluded.',
'18DB':'A=0 SUB fresh2008 SBB A; OR fresh2087; historical RAR. Clear-bit route returns independently fresh2089. Set-bit route publishes2087=1, calls canonical1688, and caches its returned A at2089; flags remain the actual producer flags.',
'1376':'Pass41/44 letter, literal, descriptor and numeric contracts remain valid. Pass47 additionally establishes ten independent natural selector05 quoted routes, including PLI0 callers: publish initial selector5, clear context at13F7, skip zero-context append and selector5 adaptation, append raw counted bytes until a quote. Historical156D consumes following context; exclude doubled quotes, B suffix, caret escapes and quoted EOF. Final flags come from fresh context CPI27, independent of returned selector. Counted reads may use the separately proved no-listing refill scope; no global resident-input completion.',
'12AE':'Fresh cursor versus count controls direct increment/index read or actual CALL0D40 refill. Fresh2012 RAR after refill selects literal1A or another counted read. Refill and reader state are historical shared bytes; no stream abstraction.',
'4929':'Existing complete table/link cleanup contract reused unchanged.',
'8273':'Existing complete mapping reset contract reused unchanged.'}
laws={}
for filename,image in [('reader_construction.ml','PLI1.OVL'),('recursive_parent.ml','PLI1.OVL'),('resident_reader.ml','PLI.COM')]:
 code=Path('lib/pli80_host/'+filename).read_text();bounds=code[code.index('let bounds='):code.index('let run')]
 for op,a,b in re.findall(r'([A-Za-z_]+)->(0x[0-9a-f]+),(0x[0-9a-f]+)',bounds):
  key=image+'+'+f'{int(a,16):04X}'
  if key in cat and cat[key]['completeness']['contract']=='complete':continue
  cases=sum((rows[s].get(key,[])for s in rows),[])
  if not cases:continue
  prior=cat.get(key);complete=prior['completeness']if prior else dict(bounds='provisional',control_flow='partial',contract='partial')
  contract=texts.get(key.split('+')[1],f'Bounded historical {op.replace("_"," ")} operation in the canonical {filename} implementation; actual registers/shared-memory tests select the represented natural paths. Fresh low/high reads, wrapped arithmetic and ordered publications follow the annotated local instructions. Child calls retain their separately established contracts. Returned registers/flags are independent path channels; exact CALL/PUSH/POP residue is derived, never copied. Unexecuted alternatives and inherited unsupported child states remain excluded.')
  laws[key]=dict(end=int(b,16),description='Pass47 bounded '+op.replace('_',' ').lower(),completeness=[complete[k]for k in ['bounds','control_flow','contract']],contract=contract,implementation='lib/pli80_host/'+filename+'#'+op)
# Local adapters share the one Acquisition_family dispatcher, never duplicate child algorithms.
for offset,end in [(0x33d6,0x33dc),(0x33ad,0x33d6),(0x335b,0x33ad),(0x2dca,0x2e26),(0x2dc3,0x2dca),(0x13ad,0x13ba),(0x0187,0x01af),(0x61b6,0x61c5),(0x256c,0x25a9)]:
 key='PLI1.OVL+'+f'{offset:04X}'
 if not any(rows[source].get(key)for source in rows):continue
 law={0x33d6:'C=1; delegate33AD then ordinary RET.',0x33ad:'Save C atA669; canonical31FB supplies fresh acquisition groups; independent masks preserve PSW channels; freshly reload saved C into335B.',0x335b:'Save C atA668; publish A634=2; require fresh A628!=31. Fresh saved C feeds28AA; required selector02 or guard scope is chosen by current indexed state. Fresh A628 classification via2185/RAR selects bounded2DCA.',0x2dca:'Fresh A62A excludes2A/28 alternatives; publish A634=2, call2DC3 and return exact child state.',0x2dc3:'Compose canonical2C59 then independent2705 fresh A628 comparison; selector16 unsupported.',0x13ad:'C=3B; fresh01AF selector equality mask; historicalRAR returns its exact flags on the demonstrated matched path.',0x0187:'Fresh2010; RAR; witnessed bit0-clear return only, flags retain rotate ancestry.',0x61b6:'Compose61A4 then CPI00; actual zero route ordinary return; nonzero arm remains excluded.',0x256c:'Existing attr4 composition retained. Pass47 additionally proves attr6: private saved C is independently reloaded for8048 and7EC0; fresh AE32 and A5B0 feed7AF0, C=0 feeds23D2 between them; discard only the private byte, return final7EC0 state.'}[offset]
 laws[key]=dict(end=end,description='Pass47 bounded canonical adapter',completeness=[cat[key]['completeness'][k]for k in ['bounds','control_flow','contract']]if key in cat else ['provisional','partial','partial'],contract=law,implementation='lib/pli80_host/acquisition_family.ml')
# Quoted extension retains only proved quoted witnesses, not unrelated resident arms.
steps=load(OUT/'quoted-cases.json');allowed={}
for line in (OUT/'quoted-case-steps.txt').read_text().splitlines():
 source,values=line.split();allowed[source]={int(v)for v in values.split(',')}
for source in rows:rows[source]['PLI.COM+1376']=[c for c in rows[source].get('PLI.COM+1376',[])if c['entry']['step_index']in allowed[source]]
for key,end in [('PLI.COM+1376',0x15da),('PLI.COM+12AE',0x12d9)]:
 prior=cat[key];laws[key]=dict(end=end,description='Pass47 bounded resident acquisition extension',completeness=[prior['completeness'][k]for k in ['bounds','control_flow','contract']],contract=texts[key.split('+')[1]],implementation='lib/pli80_host/acquisition_parent.ml')
for image in ['PLI1.OVL','PLI.COM']:
 save(OUT/('annotation-rows-'+image+'.json'),{s:{k:v for k,v in ks.items()if k in laws and k.startswith(image+'+')}for s,ks in rows.items()})
 save(REPORT/('contract-laws-'+image+'.json'),{k:v for k,v in laws.items()if k.startswith(image+'+')})
print('reviewable bounded contracts',len(laws))
