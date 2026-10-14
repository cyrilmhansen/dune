[@@@warning "-4-40-41-42"]
module B=Acquisition_family_bridge
module S=Pli80_host.State
let handler ?(observe_read=(fun _ _ _->())) bridge (boundary:Runner.instruction_boundary)=
 let entry=boundary.state in
 let need c s=if not c then invalid_arg("k216 complete: "^s)in
 need(entry.pc=0x8f47&&entry.sp>=0xb260&&entry.sp<=0xfff0)"entry/frame";
 let ram=boundary.copy_memory()in
 need(Char.code(Bytes.get ram entry.sp)=0xb4&&Char.code(Bytes.get ram(entry.sp+1))=0x42)"software continuation";
 for off=0x6d47 to 0x6d59 do need(Char.code(Bytes.get ram(off+0x2200))=Char.code(Bytes.get bridge.B.pli2 off))"handler code"done;
 let writes=[entry.sp-1,0x8f;entry.sp-2,0x4a]in
 let first=List.map(fun(a,v)->Runner.Memory_write(a,v))writes in
 let state={entry with Runner.pc=0x8992;sp=entry.sp-2}in
 let before=match boundary.preview_host_program{Runner.effects=first;next_state=state;validate=(fun _->Ok());on_commit=ignore}with Ok p->p|Error e->invalid_arg e in
 let view:Runner.instruction_boundary={state;read_memory=(fun a->Char.code(Bytes.get before.memory a));copy_memory=(fun()->Bytes.copy before.memory);dma=before.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy before.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=first@p.effects})}in
 let child=K216_selected_hierarchy.selected bridge view in
 need(child.state.pc=0x8f4a&&child.state.sp=entry.sp)"fresh6792 return";
 let effects=first@child.program.effects in
 let current=match boundary.preview_host_program{child.program with effects}with Ok p->p|Error e->invalid_arg e in
 let tail_view:Runner.instruction_boundary={state=child.state;read_memory=(fun a->Char.code(Bytes.get current.memory a));copy_memory=(fun()->Bytes.copy current.memory);dma=current.dma;copy_filesystem=(fun()->Cpm.Filesystem.copy current.filesystem);preview_host_program=(fun p->boundary.preview_host_program{p with effects=effects@p.effects})}in
 let tail=K216_handler_return.prepare ~observe_read bridge tail_view in
 need(tail.state.pc=0x42b4&&tail.state.sp=entry.sp+2)"original software RET";
 let journal=List.map(fun(address,value)->{B.address;value;writer=0x8f47;depth=0;kind="compatibility"})writes@child.journal@tail.journal in
 {tail with program={tail.program with effects=effects@tail.program.effects};journal;logical_writes=child.logical_writes@tail.logical_writes}
