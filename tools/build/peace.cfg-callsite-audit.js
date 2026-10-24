'use strict';
// Read-only final-image inspection. Decoder output is checked against every
// initialized executable byte. A static sweep is NOT a proof of all possible
// runtime instruction boundaries, nor evidence that Windows enforced CFG.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {Read}=require("../../services/artifacts/peace.bounded-artifact-read");
const {PeCapabilities}=require("../../services/artifacts/peace.pe-capabilities");
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
const MAX=64*1024*1024;
function fail(reason){throw Error(reason);}
function Pe(bytes){
 const cap=PeCapabilities(bytes);
 if(cap.cfg.status==='INVALID')fail('CFG_PE_INVALID_'+cap.cfg.reason);
 if(bytes.length<512||bytes.readUInt16LE(0)!==0x5a4d)fail('CFG_PE_INVALID');
 const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20);
 const base=bytes.readBigUInt64LE(opt+24),imageSize=bytes.readUInt32LE(opt+56),sections=[];
 const toRva=va=>{const r=va-base;if(r<0n||r>=BigInt(imageSize))fail('CFG_ADDRESS_OUTSIDE_IMAGE');return Number(r);};
 for(let i=0;i<bytes.readUInt16LE(pe+6);i++){
  const at=table+i*40,rawSize=bytes.readUInt32LE(at+16),virtualSize=bytes.readUInt32LE(at+8);
  sections.push({name:bytes.subarray(at,at+8).toString('ascii').replace(/\0.*$/s,''),rva:bytes.readUInt32LE(at+12),raw:bytes.readUInt32LE(at+20),rawSize,virtualSize,flags:bytes.readUInt32LE(at+36)});
 }
 const rawAt=(rva,n)=>{const s=sections.find(x=>rva>=x.rva&&rva+n<=x.rva+x.rawSize);if(!s)fail('CFG_UNMAPPED_RANGE');return {at:s.raw+rva-s.rva,s};};
 const dirs=bytes.readUInt32LE(opt+108),directory=index=>index<dirs?{rva:bytes.readUInt32LE(opt+112+index*8),size:bytes.readUInt32LE(opt+116+index*8)}:{rva:0,size:0};
 let check=null,dispatch=null,gfids=[];
 if(cap.compiledCfg){
  const d=directory(10),lc=rawAt(d.rva,d.size).at;
  const c=bytes.readBigUInt64LE(lc+112),v=bytes.readBigUInt64LE(lc+120);
  check=c?toRva(c):null;dispatch=v?toRva(v):null;
  const count=Number(bytes.readBigUInt64LE(lc+136)),stride=4+(bytes.readUInt32LE(lc+144)>>>28);
  const t=rawAt(toRva(bytes.readBigUInt64LE(lc+128)),count*stride).at;
  for(let i=0;i<count;i++)gfids.push({rva:bytes.readUInt32LE(t+i*stride),suppressed:stride>4&&!!(bytes[t+i*stride+4]&1)});
 }
 const readonlySlot=rva=>{
  if(rva===null)return false;
  const s=rawAt(rva,8).s,pageStart=rva&~4095,pageEnd=(rva+7|4095)+1;
  return !!(s.flags&0x40000000)&&!(s.flags&0x80000000)&&!sections.some(x=>(x.flags&0x80000000)&&x.rva<pageEnd&&x.rva+Math.max(x.virtualSize,x.rawSize)>pageStart);
 };
 // Only actual normal-import descriptors/thunks qualify. The IAT directory
 // by itself must not exempt an attacker-controlled arbitrary writable slot.
 const iat=directory(12),imports=directory(1),importSlots=new Set();
 if(iat.rva&&iat.size&&imports.rva&&imports.size){
  if(iat.size%8||iat.size>MAX||imports.size>MAX)fail('CFG_IMPORT_BOUNDS');
  const cstring=(rva,max)=>{const mapped=rawAt(rva,1),available=Math.min(max,mapped.s.raw+mapped.s.rawSize-mapped.at),zero=bytes.subarray(mapped.at,mapped.at+available).indexOf(0);if(zero<1||!bytes.subarray(mapped.at,mapped.at+zero).every(x=>x>=32&&x<127))fail('CFG_IMPORT_NAME_INVALID');};
  const im=rawAt(imports.rva,imports.size);let terminated=false;
  for(let pos=0;pos+20<=imports.size;pos+=20){
   const at=im.at+pos,fields=Array.from({length:5},(_,j)=>bytes.readUInt32LE(at+j*4));
   if(fields.every(x=>x===0)){terminated=true;break;}
   if(!fields[3])fail('CFG_IMPORT_DLL_NAME_MISSING');cstring(fields[3],261);
   const first=fields[4],lookup=fields[0]||first;if(!first||first<iat.rva||first>=iat.rva+iat.size)fail('CFG_IMPORT_THUNK_RANGE');
   let ended=false,index=0;
   for(let slot=first;slot+8<=iat.rva+iat.size;slot+=8,index++){
    const target=rawAt(slot,8),lookupEntry=bytes.readBigUInt64LE(rawAt(lookup+index*8,8).at),iatEntry=bytes.readBigUInt64LE(target.at);
    if(lookupEntry===0n){if(iatEntry!==0n)fail('CFG_IMPORT_TERMINATOR_MISMATCH');ended=true;break;}
    if(iatEntry===0n)fail('CFG_IMPORT_TERMINATOR_MISMATCH');
    if(lookupEntry&(1n<<63n)){if((lookupEntry&0x7fffffffffff0000n)!==0n||(lookupEntry&65535n)===0n)fail('CFG_IMPORT_ORDINAL_INVALID');}
    else{if(lookupEntry>0xffffffffn)fail('CFG_IMPORT_NAME_RVA_INVALID');const name=Number(lookupEntry);rawAt(name,2);cstring(name+2,4096);}
    if(readonlySlot(slot))importSlots.add(slot);
   }
   if(!ended)fail('CFG_IMPORT_THUNK_UNTERMINATED');
  }
  if(!terminated)fail('CFG_IMPORT_UNTERMINATED');
 }
 const exception=directory(3),functions=[];
 if(exception.rva||exception.size){
  if(!exception.rva||!exception.size||exception.size%12||exception.size>16*1024*1024)fail('CFG_EXCEPTION_TABLE_INVALID');
  const t=rawAt(exception.rva,exception.size).at;let prior=-1;
  for(let i=0;i<exception.size;i+=12){const begin=bytes.readUInt32LE(t+i),end=bytes.readUInt32LE(t+i+4);if(begin<=prior||end<=begin||!sections.some(s=>(s.flags&0x20000000)&&begin>=s.rva&&end<=s.rva+s.rawSize))fail('CFG_EXCEPTION_FUNCTION_INVALID');functions.push({begin,end});prior=begin;}
 }
 return {base,sections,cap,check,dispatch,gfids,readonlySlot,importSlots,toRva,functions};
}
function ParseDisassembly(text,base){
 const instructions=[],errors=[];
 for(const line of text.split(/\r?\n/)){
  const m=/^\s*([a-f0-9]{4,16}):\s+((?:[a-f0-9]{2}[\t ]+)+)(.*?)\s*$/i.exec(line);
  if(!m)continue;
  const va=BigInt('0x'+m[1]),delta=va-base;if(delta<0n||delta>0xffffffffn)continue;
  const bytes=Buffer.from(m[2].replace(/\s/g,''),'hex'),assembly=m[3].trim(),rva=Number(delta);
  if(!assembly){
   const prev=instructions.at(-1);
   if(prev&&prev.rva+prev.bytes.length===rva&&prev.bytes.length+bytes.length<=15)prev.bytes=Buffer.concat([prev.bytes,bytes]);
   else errors.push({rva,reason:'DECODER_CONTINUATION_WITHOUT_INSTRUCTION'});
  }else instructions.push({rva,bytes,assembly});
 }
 return {instructions,errors};
}
function Transfer(ins){
 const b=ins.bytes;let at=0,address32=false,segment=false;
 while(at<b.length){const p=b[at];if(p===0x67)address32=true;if([0x26,0x2e,0x36,0x3e,0x64,0x65].includes(p))segment=true;
  if((p>=0x40&&p<=0x4f)||[0x66,0x67,0xf0,0xf2,0xf3,0x26,0x2e,0x36,0x3e,0x64,0x65].includes(p))at++;else break;
 }
 if(b[at]!==0xff||at+1>=b.length)return null;
 const modrm=b[at+1],op=(modrm>>>3)&7;if(![2,3,4,5].includes(op))return null;
 let slot=null;
 if(!address32&&!segment&&(modrm>>>6)===0&&(modrm&7)===5&&at+6===b.length)slot=ins.rva+b.length+b.readInt32LE(at+2);
 return {kind:[2,3].includes(op)?'CALL':'TAIL_OR_COMPUTED_JUMP',slot,far:[3,5].includes(op)};
}
function Analyze(bytes,decoded){
 const pe=Pe(bytes),executable=pe.sections.filter(s=>s.flags&0x20000000),errors=[...decoded.errors],rows=[],coverage=[];
 if(!executable.length)fail('CFG_NO_EXECUTABLE_SECTION');
 const relevant=decoded.instructions.filter(i=>executable.some(s=>i.rva>=s.rva&&i.rva<s.rva+s.rawSize)).sort((a,b)=>a.rva-b.rva);
 const boundaries=new Set(relevant.map(x=>x.rva));
 for(const s of executable){
  let next=s.rva,decodedBytes=0;
  for(const ins of relevant.filter(x=>x.rva>=s.rva&&x.rva<s.rva+s.rawSize)){
   const offset=s.raw+ins.rva-s.rva;
   if(ins.rva!==next)errors.push({rva:next,reason:ins.rva<next?'DECODER_OVERLAP':'UNDECODED_EXECUTABLE_BYTES'});
   if(!ins.bytes.length||ins.bytes.length>15||ins.rva+ins.bytes.length>s.rva+s.rawSize||!bytes.subarray(offset,offset+ins.bytes.length).equals(ins.bytes))errors.push({rva:ins.rva,reason:'DECODER_BYTES_MISMATCH'});
   if(/\(bad\)|<unknown>|(?:^|\s)(?:db|\.byte|\.word|\.long)(?:\s|$)/i.test(ins.assembly))errors.push({rva:ins.rva,reason:'UNRECOGNIZED_INSTRUCTION'});
   next=Math.max(next,ins.rva+ins.bytes.length);decodedBytes+=ins.bytes.length;
  }
  if(next!==s.rva+s.rawSize)errors.push({rva:next,reason:'UNDECODED_EXECUTABLE_TAIL'});
  if(s.virtualSize>s.rawSize)errors.push({rva:s.rva+s.rawSize,reason:'UNINITIALIZED_EXECUTABLE_MEMORY'});
  if(s.flags&0x80000000)errors.push({rva:s.rva,reason:'WRITABLE_EXECUTABLE_SECTION'});
  coverage.push({section:s.name,rva:s.rva,initializedBytes:s.rawSize,virtualBytes:s.virtualSize,decodedBytes});
 }
 for(const f of pe.gfids)if(!boundaries.has(f.rva))errors.push({rva:f.rva,reason:'GFID_NOT_DECODED_BOUNDARY'});
 for(const f of pe.functions){
  if(!boundaries.has(f.begin))errors.push({rva:f.begin,reason:'FUNCTION_NOT_DECODED_BOUNDARY'});
  if(!boundaries.has(f.end)&&!executable.some(s=>f.end===s.rva+s.rawSize))errors.push({rva:f.end,reason:'FUNCTION_END_NOT_DECODED_BOUNDARY'});
 }
 if(pe.cap.compiledCfg){
  if(!pe.readonlySlot(pe.check))errors.push({rva:pe.check,reason:'CFG_CHECK_SLOT_WRITABLE'});
  if(pe.dispatch!==null&&!pe.readonlySlot(pe.dispatch))errors.push({rva:pe.dispatch,reason:'CFG_DISPATCH_SLOT_WRITABLE'});
 }
 // Exception table and entrypoint provide additional independent boundaries.
 const opt=bytes.readUInt32LE(60)+24,entry=bytes.readUInt32LE(opt+16);
 if(!boundaries.has(entry))errors.push({rva:entry,reason:'ENTRY_NOT_DECODED_BOUNDARY'});
 for(const ins of relevant){
  const t=Transfer(ins);if(!t)continue;
  let classification='UNVERIFIED_INDIRECT_TRANSFER';
  if(!t.far&&t.slot!==null&&t.slot===pe.dispatch&&pe.readonlySlot(pe.dispatch))classification='CFG_DISPATCH';
  else if(!t.far&&t.slot!==null&&t.slot===pe.check&&pe.readonlySlot(pe.check))classification='CFG_CHECK_HELPER_ONLY';
  else if(!t.far&&t.slot!==null&&pe.importSlots.has(t.slot))classification='READONLY_DECLARED_IAT';
  rows.push({rva:ins.rva,bytes:ins.bytes.toString('hex'),assembly:ins.assembly,kind:t.kind,far:t.far,slotRva:t.slot,classification});
 }
 const unverified=rows.filter(x=>x.classification==='UNVERIFIED_INDIRECT_TRANSFER');
 const calls=rows.filter(x=>x.kind==='CALL'),metadata=pe.cap.cfg.status;
 const outcome=metadata!=='STRUCTURALLY_VALID'?'UNSUPPORTED':errors.length?'INCOMPLETE':unverified.length?'UNGUARDED_OR_UNRESOLVED':'STATIC_SCAN_COMPLETE';
 return {version:1,kind:'CFG_CALLSITE_AUDIT',artifactSha512:sha(bytes),outcome,metadata:pe.cap.cfg,coverage,issues:errors,indirectTransfers:rows,
  counts:{instructions:relevant.length,indirectCalls:calls.length,indirectJumps:rows.length-calls.length,dispatch:rows.filter(x=>x.classification==='CFG_DISPATCH').length,unverified:unverified.length},
  callsiteInspectionImplemented:true,staticScope:'LINEAR_DECODE_ALL_INITIALIZED_EXECUTABLE_SECTIONS',allRuntimeCallsitesVerified:false,windowsEnforcement:'NOT_RUN',publicationApproval:false,
  limitation:'Static instruction boundaries can contain embedded data or overlapping code. Unresolved check/call pairs, register dispatch, jump tables and alternate entries require toolchain review. No full CFG attestation is created.'};
}
function LocateTool(selected){
 let executable=selected;
 if(!executable){
  for(const name of process.platform==='win32'?['dumpbin.exe','llvm-objdump.exe','objdump.exe']:['llvm-objdump','objdump']){
   const found=spawnSync(process.platform==='win32'?path.join(process.env.SystemRoot||'C:\\Windows','System32','where.exe'):'which',[name],{encoding:'utf8',windowsHide:true,timeout:10000});
   if(found.status===0){executable=found.stdout.split(/\r?\n/).map(x=>x.trim()).find(x=>x&&path.isAbsolute(x));if(executable)break;}
  }
 }
 if(!executable||!path.isAbsolute(executable))fail('CFG_DISASSEMBLER_NOT_FOUND_USE_VS_X64_PROMPT');
 const name=path.basename(executable).toLowerCase();
 const kind=name==='dumpbin.exe'?'dumpbin':/^llvm-objdump(?:\.exe)?$/.test(name)?'llvm':/^objdump(?:\.exe)?$/.test(name)?'gnu':null;
 if(!kind)fail('CFG_DISASSEMBLER_UNSUPPORTED');
 executable=fs.realpathSync(executable);
 const tool=Read(executable,MAX);return {executable,kind,sha512:sha(tool)};
}
function Audit(file,tool){
 const bytes=Read(file,MAX),pe=Pe(bytes),dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-cfg-audit-'));
 try{
  const snapshot=path.join(dir,'final.exe');fs.writeFileSync(snapshot,bytes,{flag:'wx',mode:0o600});
  const args=tool.kind==='dumpbin'?['/nologo','/disasm:bytes',snapshot]:tool.kind==='llvm'?['--disassemble-all','--disassemble-zeroes','--x86-asm-syntax=intel',snapshot]:['-D','-z','-w','-Mintel',snapshot];
  const p=spawnSync(tool.executable,args,{encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:256*1024*1024,shell:false});
  if(p.error||p.status!==0)fail('CFG_DISASSEMBLER_FAILED');
  const result=Analyze(bytes,ParseDisassembly(p.stdout,pe.base));
  if(sha(Read(file,MAX))!==result.artifactSha512||sha(Read(tool.executable,MAX))!==tool.sha512)fail('CFG_INPUT_CHANGED_DURING_AUDIT');
  return {...result,decoder:{kind:tool.kind,sha512:tool.sha512,outputSha512:sha(Buffer.from(p.stdout)),exitCode:p.status},inputUnchanged:true};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
function Arguments(argv){
 const out={};for(let i=0;i<argv.length;i+=2){if(!['--a','--b','--o','--file','--disassembler','--out'].includes(argv[i])||!argv[i+1]||Object.hasOwn(out,argv[i]))fail('CFG_ARGUMENTS_INVALID');out[argv[i]]=argv[i+1].replace(/^"(.*)"$/s,'$1');}
 if(!out['--out']||!!out['--file']===!!(out['--a']||out['--b']||out['--o'])||!out['--file']&&!['--a','--b','--o'].every(k=>out[k]))fail('CFG_ARGUMENTS_INVALID');return out;
}
function Main(argv){
 const a=Arguments(argv),tool=LocateTool(a['--disassembler']),artifacts={};
 for(const [role,file]of a['--file']?[['FILE',a['--file']]]:[['A',a['--a']],['B',a['--b']],['O',a['--o']]])artifacts[role]=Audit(path.resolve(file),tool);
 const result={version:1,kind:'CFG_FINAL_ARTIFACT_SET',recordedAt:new Date().toISOString(),artifacts,allRuntimeCallsitesVerified:false,windowsEnforcement:'NOT_RUN',ciEvidenceCreated:false,publicationApproval:false};
 fs.writeFileSync(path.resolve(a['--out']),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(JSON.stringify({output:path.resolve(a['--out']),outcomes:Object.fromEntries(Object.entries(artifacts).map(([k,v])=>[k,v.outcome])),allRuntimeCallsitesVerified:false}));
 return Object.values(artifacts).some(x=>x.outcome!=='STATIC_SCAN_COMPLETE')?2:0;
}
if(require.main===module){try{process.exitCode=Main(process.argv.slice(2));}catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'CFG_AUDIT_FAILED');process.exitCode=1;}}
module.exports={Pe,ParseDisassembly,Transfer,Analyze,LocateTool,Audit,Arguments};
