"""Compact durable projections of independently proved native root operations.

No raw snapshots, combined packet format, or semantic selection by oracle identity.
The operation journal is native logical/compatibility evidence, not a CPU trace.
"""
from collections import Counter, defaultdict

FILES=['root-cases','early-return-cases','reverse-cases','forward-cases',
       'root-operation-trees','stack-compatibility','shadow-summary',
       'single-hybrid-summary','cumulative-hybrid-summary','host-service-summary']

def derive(raw, shadow, single, cumulative):
    result={n:{'sources':[]} for n in FILES[:6]}
    services=[]
    for source in raw['sources']:
        name=source['source'];cases=source['cases']
        root=[];early=[];reverse=[];forward=[];trees=[];stack=[];counts=Counter()
        def nodes(n):
            counts['Recursive_mapped_nodes']+=1
            counts['recursive_path:'+n['path']]+=1
            counts['maximum_recursive_depth']=max(counts['maximum_recursive_depth'],n['depth']+1)
            for h in n['helpers']:
                if h['kind'] in ('packed','balance'):counts['recursive_'+h['kind']]+=1
            for child in n['children']:nodes(child)
        for c in cases:
            identity={k:c[k] for k in ('caller','entry_step','return_step')}
            root.append({k:v for k,v in c.items() if k not in ('reverse','forward','children','journal','services')})
            counts['path:'+c['path']]+=1
            if c['path']!='work':early.append(root[-1])
            reverse.append(identity|{'iterations':c['reverse']})
            forward.append(identity|{'iterations':c['forward']})
            trees.append(identity|{'children':c['children']})
            for r in c['reverse']:
                if r['direct_result'] is not None:counts['reverse_selections']+=1
            for f in c['forward']:
                counts['forward_iterations']+=1;counts['attribute:'+str(f['attribute'])]+=1
                counts['Int_emitter']+=len(f['channels'])
                for channel,_ in f['channels']:counts['channel:'+channel]+=1
            for child in c['children']:
                counts['direct:'+child['operation']]+=1
                if child['recursive_tree'] is not None:nodes(child['recursive_tree'])
            cells=defaultdict(list);psws=[]
            for w in c['journal']:
                if w['address']<c['input']['sp'] and w['address']>=0xae60:
                    cells[w['address']-c['input']['sp']].append({k:v for k,v in w.items() if k!='address'})
                if w['writer_runtime']==0x9f82:psws.append(w)
            stack.append(identity|{'PUSH_PSW_writes':psws,'cells':[{'offset':a,'overwrite_ancestry':ws,
                'final_writer':ws[-1]} for a,ws in sorted(cells.items())]})
            if c['services']:services.append({'source':name}|identity|{'services':c['services']})
        for n,rows in zip(FILES[:6],[root,early,reverse,forward,trees,stack]):
            result[n]['sources'].append({'source':name,'cases':rows})
        result['root-operation-trees']['sources'][-1]['aggregate']=dict(sorted(counts.items()))
    result['shadow-summary']=shadow
    result['single-hybrid-summary']=single
    result['cumulative-hybrid-summary']=cumulative
    result['host-service-summary']={'internal_roots':services,'sources':[]}
    for s in cumulative['sources']:
        name=s['result']['source'];total=s['result']['host_bdos_services']//2
        internal=sum(len(c['services'])//2 for c in services if c['source']==name)
        result['host-service-summary']['sources'].append({'source':name,'BDOS26':total,'BDOS21':total,
            'inside_7D53_pairs':internal,'external_emitter_pairs':total-internal})
    return result
