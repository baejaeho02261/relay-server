'use strict';
// Synthetic byte streams test the inspector; GNU/LLVM execution below is a
// real decoder invocation, never Windows CFG enforcement or product evidence.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const t=require("../../tools/build/peace.cfg-callsite-audit"),{PE}=require("../fixtures/protocol/peace.completion-6-10-fixture");
let checks=0;const test=fn=>{fn();checks++;};
function Fixture(cfg=true){const b=PE('O',undefined,cfg);b.fill(0x90,512,1024);b.writeUInt32LE(0x1000,b.readUInt32LE(60)+40);return b;}
function Ins(rva,hex,assembly){return {rva,bytes:Buffer.from(hex,'hex'),assembly};}
function Decode(b){const rows=[];for(let i=0;i<512;i++)rows.push(Ins(0x1000+i,b.subarray(512+i,513+i).toString('hex'),'nop'));return {instructions:rows,errors:[]};}
function Insert(b,d,rva,hex,assembly){const value=Buffer.from(hex,'hex');value.copy(b,512+rva-0x1000);d.instructions=d.instructions.filter(x=>x.rva<rva||x.rva>=rva+value.length);d.instructions.push(Ins(rva,hex,assembly));return d;}
function SlotCall(rva,slot){const b=Buffer.from('ff1500000000','hex');b.writeInt32LE(slot-rva-6,2);return b.toString('hex');}
test(()=>{const b=Fixture(),d=Decode(b),r=t.Analyze(b,d);assert.equal(r.outcome,'STATIC_SCAN_COMPLETE');assert.equal(r.allRuntimeCallsitesVerified,false);assert.equal(r.windowsEnforcement,'NOT_RUN');assert.equal(r.counts.instructions,512);});
test(()=>{const b=Fixture(false);assert.equal(t.Analyze(b,Decode(b)).outcome,'UNSUPPORTED');});
test(()=>{const b=Fixture(),d=Decode(b);Insert(b,d,0x1000,SlotCall(0x1000,0x22f0),'call qword ptr [rip+0x12ea]');const r=t.Analyze(b,d);assert.equal(r.outcome,'STATIC_SCAN_COMPLETE');assert.equal(r.indirectTransfers[0].classification,'CFG_DISPATCH');});
test(()=>{const b=Fixture(),d=Decode(b);Insert(b,d,0x1000,'ffd0','call rax');const r=t.Analyze(b,d);assert.equal(r.outcome,'UNGUARDED_OR_UNRESOLVED');assert.equal(r.counts.unverified,1);});
test(()=>{const b=Fixture(),d=Decode(b);Insert(b,d,0x1000,SlotCall(0x1000,0x22e0),'call [rip]');Insert(b,d,0x1006,'ffd0','call rax');const r=t.Analyze(b,d);assert.equal(r.indirectTransfers[0].classification,'CFG_CHECK_HELPER_ONLY');assert.equal(r.counts.unverified,1,'check helper does not certify a later register target');});
test(()=>{const b=Fixture(),d=Decode(b);Insert(b,d,0x1000,'ffe0','jmp rax');const r=t.Analyze(b,d);assert.equal(r.counts.indirectJumps,1);assert.equal(r.outcome,'UNGUARDED_OR_UNRESOLVED');});
test(()=>{const b=Fixture(),d=Decode(b),near=Buffer.from(SlotCall(0x1000,0x22f0),'hex');near[1]=0x1d;Insert(b,d,0x1000,near.toString('hex'),'call far [rip]');const r=t.Analyze(b,d);assert.equal(r.indirectTransfers[0].far,true);assert.equal(r.counts.unverified,1);});
function Imports(b){
 const opt=b.readUInt32LE(60)+24;b.fill(0,1024,1536);
 b.writeUInt32LE(0,opt+136);b.writeUInt32LE(0,opt+140);
 b.writeUInt32LE(0x2000,opt+120);b.writeUInt32LE(40,opt+124);
 b.writeUInt32LE(0x20a0,opt+208);b.writeUInt32LE(16,opt+212);
 b.writeUInt32LE(0x20c0,1024);b.writeUInt32LE(0x20e0,1036);b.writeUInt32LE(0x20a0,1040);
 b.writeBigUInt64LE(0x2100n,1184);b.writeBigUInt64LE(0x2100n,1216);
 b.write('test.dll\0',1248,'ascii');b.writeUInt16LE(0,1280);b.write('Symbol\0',1282,'ascii');return b;
}
test(()=>{const b=Imports(Fixture()),d=Decode(b);Insert(b,d,0x1000,SlotCall(0x1000,0x20a0),'call [rip]');const r=t.Analyze(b,d);assert.equal(r.outcome,'STATIC_SCAN_COMPLETE');assert.equal(r.indirectTransfers[0].classification,'READONLY_DECLARED_IAT');});
test(()=>{for(const edit of [b=>b.writeUInt32LE(0,1036),b=>b.writeBigUInt64LE(0x8000000000010001n,1216),b=>b.writeBigUInt64LE(0x100000000n,1216),b=>b.fill(65,1248,1536)]){const b=Imports(Fixture());edit(b);assert.throws(()=>t.Analyze(b,Decode(b)),/CFG_IMPORT/);}});
test(()=>{const b=Fixture(),d=Decode(b);Insert(b,d,0x1000,'e82b000000','call 140001030');assert.equal(t.Analyze(b,d).counts.indirectCalls,0);});
test(()=>{const b=Fixture(),d=Decode(b);d.instructions.splice(250,1);const r=t.Analyze(b,d);assert.equal(r.outcome,'INCOMPLETE');assert(r.issues.some(x=>x.reason==='UNDECODED_EXECUTABLE_BYTES'));});
test(()=>{const b=Fixture(),d=Decode(b);d.instructions.at(-1).bytes=Buffer.from('c3','hex');assert.equal(t.Analyze(b,d).outcome,'INCOMPLETE');});
test(()=>{const b=Fixture(),d=Decode(b);d.instructions.push(d.instructions[0]);assert.equal(t.Analyze(b,d).outcome,'INCOMPLETE');});
test(()=>{const b=Fixture(),d=Decode(b);d.instructions[0].assembly='(bad)';assert.equal(t.Analyze(b,d).outcome,'INCOMPLETE');});
test(()=>{for(const directive of ['.byte 0x90','.word 0x90','.long 0x90','db 90h']){const b=Fixture(),d=Decode(b);d.instructions[0].assembly=directive;assert.equal(t.Analyze(b,d).outcome,'INCOMPLETE');}});
test(()=>{const b=Fixture(),d=Decode(b);b.writeUInt32LE(513,0x188+8);assert(t.Analyze(b,d).issues.some(x=>x.reason==='UNINITIALIZED_EXECUTABLE_MEMORY'));});
test(()=>{const b=Fixture(),d=Decode(b);b.writeUInt32LE(0x1001,1728);Insert(b,d,0x1000,'6690','xchg ax,ax');assert(t.Analyze(b,d).issues.some(x=>x.reason==='GFID_NOT_DECODED_BOUNDARY'));});
test(()=>{const base=0x140000000n;for(const line of ['  0000000140001000: FF 15 EA 12 00 00  call qword ptr [00000001400022F0h]','   140001000:\tff 15 ea 12 00 00    \tcall QWORD PTR [rip+0x12ea]']){const r=t.ParseDisassembly(line,base);assert.equal(r.instructions.length,1);assert.equal(t.Transfer(r.instructions[0]).slot,0x22f0);}});
test(()=>{const r=t.ParseDisassembly('  0000000140001000: 0F 1F 84 00 00 00 00  nop dword ptr [rax+rax]\n  0000000140001007: 00  \n',0x140000000n);assert.equal(r.instructions[0].bytes.length,8);});
test(()=>{assert.throws(()=>t.Arguments(['--a','x']),/ARGUMENTS/);assert.throws(()=>t.Arguments(['--file','x','--file','y','--out','z']),/ARGUMENTS/);assert.equal(t.Arguments(['--file','"x y"','--out','z'])['--file'],'x y');});
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cfg-callsite-contract-'));let decoderExecuted=false;
try{
 test(()=>{const b=Fixture(),p=path.join(dir,'SyntheticOnly.exe');b[512]=0xc3;fs.writeFileSync(p,b);let tool;try{tool=t.LocateTool();}catch(e){if(e.message==='CFG_DISASSEMBLER_NOT_FOUND_USE_VS_X64_PROMPT')return;throw e;}const r=t.Audit(p,tool);assert.equal(r.inputUnchanged,true);assert.equal(r.coverage[0].decodedBytes,512);assert.equal(r.allRuntimeCallsitesVerified,false);decoderExecuted=true;});
 console.log(JSON.stringify({suite:'CFG_CALLSITE_INSPECTOR',status:'PASS',checks,syntheticImages:true,decoderExecuted,windowsEnforcement:'NOT_RUN',productionCfgVerified:false}));
}finally{fs.rmSync(dir,{recursive:true,force:true});}
