"""Exact Pass72 PUSH-H/PCHL witness check; not a generalized continuation ABI."""
def prove_gateway(seed,images,originals):
 def need(test,message):
  if not test:raise ValueError('Pass72 software gateway: '+message)
 proof=seed['software_return_sample'];need(proof.get('kind')=='pass72_push_h_pchl','explicit proof kind')
 need(seed['id']=='PLI2.OVL+3E36'and seed['image']=='PLI2.OVL'and seed['start_offset']==0x3e36 and seed['end_offset']==0x3ef6,'canonical handler identity')
 gateway=proof['gateway'];need(len(gateway)==4,'complete gateway prefix')
 call,writer,ret,entry=(proof[k]for k in ['call','writer','ret','entry']);need(call==gateway[3]and writer==gateway[1],'writer/transfer identities')
 for w in [*gateway,entry,ret]:
  origin=w['origin'];need(origin is not None,'origin');name=origin['image']['name'];o=origin['offset'];raw=bytes.fromhex(w['bytes'])
  need(originals[name][o:o+len(raw)]==raw and w['pc']==images[name]['runtime_base']+o,'witness code/coordinate')
 need([w['origin']['offset']for w in gateway]==[0x20ac,0x20af,0x20b0,0x20b3],'gateway coordinates')
 need([w['bytes']for w in gateway]==['21B442','E5','2A1FAD','E9'],'literal/PUSH/fresh pointer/PCHL bytes')
 for before,after in zip(gateway,gateway[1:]):
  need(before['after']==after['before']and before['step_index']+1==after['step_index'],'contiguous register/flag/step ancestry')
 need(call['after']==entry['before']and call['step_index']+1==entry['step_index'],'handler entry state')
 slot=entry['sp_before'];need(writer['before']['h']*256+writer['before']['l']==0x42b4,'literal carrier')
 need(writer['sp_before']==slot+2 and writer['sp_after']==slot,'PUSH SP')
 need([(w['address'],w['new_value'])for w in writer['writes']]==[(slot+1,0x42),(slot,0xb4)],'ordered PUSH writes')
 need(gateway[2]['reads']==[dict(address=0xad1f,value=0x36),dict(address=0xad20,value=0x60)],'fresh paired handler pointer')
 need(call['writes']==[]and call['call_return_address']is None and call['sp_before']==slot and call['sp_after']==slot,'PCHL creates no CALL word')
 need(call['before']['h']*256+call['before']['l']==0x6036 and call['pc_after']==0x6036 and call['control']==dict(kind='jump',target=0x6036,taken=True),'actual PCHL target')
 need(ret['origin']['offset']==0x3ef5 and ret['bytes']=='C9'and ret['step_index']>entry['step_index'],'owned RET')
 need(ret['sp_before']==slot and ret['sp_after']==slot+2 and ret['pc_after']==0x42b4 and ret['reads']==[dict(address=slot,value=0xb4),dict(address=slot+1,value=0x42)],'RET consumer')
 need(proof['original_slot']==slot and proof['continuation']==0x42b4,'declared continuation')
 return dict(slot=slot,continuation=0x42b4,entry=0x6036,writer_step=writer['step_index'])
