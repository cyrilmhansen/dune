#!/usr/bin/env python3
"""Real single-controller mixed execution; original k23 campaign stays pass74."""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
BASE='36c5d4fbdb2b91cd5704f17c9cf693d88b49fb92'
OUT=Path('_build/host-compiler-pass-87')
REPORT=Path('research/host-compiler/pass-87')
def load(p):return json.loads(Path(p).read_text())
def save(p,x):Path(p).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def vector(q):
    flags=q['flags']
    psw=2|sum(n for k,n in [('sign',128),('zero',64),('auxiliary_carry',16),('parity',4),('carry',1)] if flags[k])
    return [q['pc'],q['sp'],q['a'],q['b']*256+q['c'],q['d']*256+q['e'],q['h']*256+q['l'],psw]
def sha(b):return hashlib.sha256(b).hexdigest()
def prove(images):
    OUT.mkdir(parents=True,exist_ok=True)
    REPORT.mkdir(parents=True,exist_ok=True)
    if not os.environ.get('RUNES_HOST_IMAGES'):
        subprocess.run(['dune','build','bin/native_k123_gateway.exe','test/native_dispatch_partial.exe'],check=True,stdout=subprocess.DEVNULL)
    start=time.monotonic()
    subprocess.run(['_build/default/test/native_dispatch_partial.exe'],check=True)
    subprocess.run(['_build/default/bin/native_k123_gateway.exe','--images',str(images),'--output',str(OUT/'mixed.json')],check=True)
    q=load(OUT/'mixed.json')
    old=load('research/host-compiler/pass-74/natural-shadow-summary.json')
    old_goldens=load('research/host-compiler/pass-74/single-hybrid-summary.json')['sources']
    for s,g in zip(q['sources'],old_goldens):
        assert s['REL_sha256']==g['result']['REL_sha256'],s['source']
        prior=next(x for x in old if x['source']==s['source'])
        roots=[r for r in s['roots'] if r['route']=='k23']
        assert len(roots)==len(prior['roots'])
        for a,b in zip(roots,prior['roots']):
            assert a['input']==vector(b['input']) and a['output']==vector(b['output'])
            assert (a['input_sha256'],a['post_sha256'],a['legacy_journal_sha256'])==(
                b['entry_RAM_sha256'],b['post_RAM_sha256'],b['ordered_journal_sha256'])
        assert s['combined_host']==s['k23']+s['k123']
        assert s['k23_host']==s['k23']
        assert s['single_oracle_order_verified'] and s['full_equivalence']
    k123=[r for s in q['sources'] for r in s['roots'] if r['route']=='k123']
    archived=load('research/host-compiler/pass-86/natural-shadow.json')['cases']
    assert len(k123)==len(archived)
    for a,b in zip(k123,archived):
        assert a['input_sha256']==b['entry']['RAM_sha256'] and a['post_sha256']==b['returned']['RAM_sha256']
    q.update(baseline=BASE,measured_seconds=round(time.monotonic()-start,3),
             previous_k23_exactly_preserved=True,Pass86_natural_RAM_hashes_preserved=True,
             knowledge_promotions=0,new_controller_coordinates=0,
             installation='combined mode of the existing controller at41B5; legacy mode preserved',
             oracle='one chronological accepted-root stream; state/ancestry choose before oracle inspection',
             final_CPU_proof='Exact live root post-state checks and deterministic identical intervening guest execution/suffix establish equality by induction; final full RAM is also directly compared.',
             services='Root services compared in exact call/resume/RAM/DMA/event order; complete INT/REL record stream and file-event chronology compared; guest plus actual native BDOS counts equal reference.')
    save(REPORT/'mixed-execution.json',q)
    save(REPORT/'implementation-packet.json',dict(
        baseline=BASE,entry='PLI2.OVL+1FB5 /41B5',one_controller=True,
        routing='unchangedk23 applicability first; K123 only after Inapplicable; documented Pass86 declines only',
        prepare='unchanged k23 preparation or unchanged Pass86 complete copied transaction into existing ordered host program',
        chronology='one chronological oracle sequence across both operations; declines consume none; eligible errors propagate',
        cursor='combined controller proof cursor advances in existing host-program callback after dispatch post-state/write checks; generic dispatcher unchanged',
        writers='complete ordered stream retained including same-valued writes; k123 site/depth metadata explicitly unavailable(-1), never guessed; physical private-stack writes classified as compatibility; full stream matches concrete CPU',
        measured=[{k:s[k] for k in ['source','k23','k123','declined','guest_reference','k23_guest','combined_guest','k23_host','combined_host','host_BDOS_services']}for s in q['sources']],
        unsupported=['unproved k123 descriptors/predicate/handler/output/alias domains','trace-set','k33/k216 and other indices'],
        native_child_absorption='gateway-only comparisons have no separately enabled child controllers; two added FACTOR roots add two transitions. Legacy cumulative child absorption remains covered by pass74.',
        recovery='same-boundary staged prepare retry; existing partial-controller transient retry; fresh controller required to restart an aborted full program with open guest frames',
        knowledge_promotions=0,oracle_queries=0,FULL='not executed/scheduled/awaited; Pass74epoch3 remains last certified',
        evidence=['mixed-execution.json','validation.json']))
    assert (REPORT/'implementation-packet.json').stat().st_size<28672
    return q
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--images',required=True);prove(p.parse_args().images)
