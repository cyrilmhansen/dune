#!/usr/bin/env python3
"""Compact composition input, derived from corrected windows; never native semantics."""
import argparse,hashlib,json,re,time
from pathlib import Path
from collections import Counter
from check_6223_pass_32 import ROOT,BOUNDS,CAPTURES,analyze
from check_selector02_pass_40 import gather_selected

def build(images):
 started=time.monotonic();sources=[]
 for source,capture in CAPTURES.items():
  rows=gather_selected(capture,BOUNDS,include_nested_returns=True,software_callees={'PLI1.OVL+4468':2,'PLI1.OVL+6708':8})
  a=analyze(source,capture,images,rows);roots=a['roots']
  sources.append(dict(source=source,capture_sha256=a['capture_sha256'],logical_count=len(roots),outer_count=sum(r['window_depth']==1 for r in roots),nested_count=sum(r['window_depth']>1 for r in roots),maximum_depth=max(r['window_depth']for r in roots),routes=dict(Counter(r['route']for r in roots)),outer_routes=dict(Counter(r['route']for r in roots if r['window_depth']==1)),invocations=[{k:r[k]for k in ['caller','call_step','entry_step','return_step','entry','output','route','nearest_enclosing_6223_call_step','window_depth']}|dict(direct_children=[[c['callsite'],c['target']]for c in r['children']])for r in roots]))
 contracts=[]
 for p in range(32,44):
  path=ROOT/f'research/host-compiler/pass-{p}/README.md'
  contracts.append(dict(pass_number=p,path=str(path.relative_to(ROOT)),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
 cfg=[]
 for line in (ROOT/'research/annotated-assembly/PLI1.asm').read_text().splitlines():
  m=re.match(r'PLI1_([0-9A-F]{4}): (.*?) ;',line)
  if m and 0x620c<=int(m[1],16)<0x624d:cfg.append([m[1],m[2]])
 return dict(baseline='fbaf7b86491c7a30449d826e4f6a21a937f3020d',semantics_use_oracle_identity=False,sources=sources,local_CFG=cfg,contracts=contracts,frame_60E5=dict(size=5,base='entrySP-5',fields=['F0 loop mask','F1 direct 5E98 result','F2 old base low','F3 old base high','F4 old index']),field_routes={'15':['5A46','784E','4275','4601','4275','01AF','3DD9','5E65','419F','5E65','5E53'],'80':['5A46','784E','4275','419F','3DD9','5E65','419F','3DD9','506E']},recursive_spine=['500F','4F54','6619','65F9','654E','64F2','6477','640D','6314','625D','6223'],continuations={'hardware':'actual CALL+3 at actual nested SP','4468':'N=2 copied continuation; final entrySP+4','6708':'N=8 copied continuation; final entrySP+10'},generation_seconds=round(time.monotonic()-started,3),numeric_scope_extension=dict(contract='PLI.COM+1376',evidence='numeric-acquisition-cases.json',sha256=hashlib.sha256((ROOT/'research/host-compiler/pass-44/numeric-acquisition-cases.json').read_bytes()).hexdigest(),contexts_hex=['31','33','35'],prefixes_hex=[['31','35'],['33'],['35']],selector=2,following_hex='29',oracle_queries=0))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--images',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();packet=build(a.images);data=json.dumps(packet,separators=(',',':'))+'\n';assert len(data.encode())<=32768;a.output.write_text(data)
 print(json.dumps({'packet_bytes':len(data.encode()),'sources':[{k:s[k]for k in ['source','logical_count','outer_count','nested_count','maximum_depth','routes','outer_routes']}for s in packet['sources']],'elapsed':packet['generation_seconds']}))
