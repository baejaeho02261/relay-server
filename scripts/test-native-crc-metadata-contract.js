'use strict';
// Portable model of the retained-file / mapped-image contract. This is not a
// Delphi build or Windows loader test. Supply actual A/B/O executables through
// NATIVE_CRC_BINARY_DIR to exercise their linker layouts and relocation tables.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {CodeImage}=require('../services/desktopIntegrity');
const crc=require('../services/crcLayers'),policy=require('../services/desktopCrcPolicy');
const marker=Buffer.from('47435243414e4348038d47912a60b5ec','hex');
const u32=(b,n)=>b.readUInt32LE(n),u16=(b,n)=>b.readUInt16LE(n);
const frame=(...values)=>{const b=Buffer.alloc(values.length*4);values.forEach((v,i)=>b.writeUInt32LE(v,i*4));return b;};
function nativePlan(file){
 const pe=u32(file,60),opt=pe+24,table=opt+u16(file,pe+20),count=u16(file,pe+6),sections=[];
 for(let i=0;i<count;i++){const at=table+i*40,rawSize=u32(file,at+16);sections.push({rva:u32(file,at+12),span:u32(file,at+8)||rawSize,rawSize,raw:u32(file,at+20),flags:u32(file,at+36)});}
 sections.sort((a,b)=>a.rva-b.rva);
 const locate=(rva,size)=>sections.find(s=>rva>=s.rva&&rva+size<=s.rva+Math.min(s.span,s.rawSize));
 const rawAt=(rva,size)=>{const s=locate(rva,size);assert(s,'file-backed metadata');return s.raw+rva-s.rva;};
 const meta=s=>s&&!!(s.flags&0x40000000)&&!(s.flags&0x20000000),code=s=>s&&!!(s.flags&0x20000000)&&!(s.flags&0x80000000);
 const matches=[];
 for(const s of sections.filter(meta))for(let at=s.raw;at+16<=s.raw+Math.min(s.span,s.rawSize);at++)if(file.subarray(at,at+16).equals(marker)){assert(at+72<=s.raw+Math.min(s.span,s.rawSize));matches.push({raw:at,rva:s.rva+at-s.raw});}
 assert.equal(matches.length,1,'unique metadata anchor');
 const anchor=matches[0],base=file.readBigUInt64LE(opt+24),targets=[];
 assert.equal(u32(file,anchor.raw+16),1);assert.equal(u32(file,anchor.raw+20),6);
 for(let i=0;i<6;i++){const rva=Number(file.readBigUInt64LE(anchor.raw+24+i*8)-base);assert(code(locate(rva,1)));targets.push(rva);}
 const fixups=[];let at=rawAt(u32(file,opt+152),u32(file,opt+156)),end=at+u32(file,opt+156);
 while(at<end){const page=u32(file,at),size=u32(file,at+4);assert(size>=8&&size%2===0&&at+size<=end);for(let p=at+8;p<at+size;p+=2){const entry=u16(file,p),kind=entry>>>12;if(!kind)continue;assert([3,10].includes(kind));fixups.push({rva:page+(entry&4095),width:kind===10?8:4});}at+=size;}
 for(let i=0;i<6;i++)assert.equal(fixups.filter(f=>f.rva===anchor.rva+24+i*8&&f.width===8).length,1);
 const functions=[];at=rawAt(u32(file,opt+136),u32(file,opt+140));end=at+u32(file,opt+140);
 for(;at<end;at+=12){const rva=u32(file,at),finish=u32(file,at+4),unwind=u32(file,at+8);assert(finish>rva&&code(locate(rva,finish-rva)));assert(meta(locate(unwind,4)));functions.push({rva,span:finish-rva});}
 const roles={};for(const [role,indexes] of Object.entries({nvme:[0],jones:[1,2],iso:[3,4,5]})){const ranges=indexes.map(i=>functions.find(f=>targets[i]>=f.rva&&targets[i]<f.rva+f.span));assert(ranges.every(Boolean));roles[role]=ranges.filter((r,i)=>ranges.findIndex(x=>x.rva===r.rva)===i).sort((a,b)=>a.rva-b.rva);}
 const headers=[[0,2],[60,4],[pe,8],[pe+20,4],[opt,2],[opt+16,8],[opt+32,8],[opt+56,8],[opt+108,4]];
 if(u32(file,opt+108))headers.push([opt+112,u32(file,opt+108)*8]);for(let i=0;i<count;i++)headers.push([table+i*40+8,16],[table+i*40+36,4]);
 return {file,opt,base,sections,fixups,anchor,magic:Buffer.from(file.subarray(anchor.raw,anchor.raw+16)),targets,roles,headers,imageSize:u32(file,opt+56),headerSize:u32(file,opt+60)};
}
function mapped(plan,base){
 const image=Buffer.alloc(plan.imageSize);plan.file.copy(image,0,0,plan.headerSize);
 for(const s of plan.sections)plan.file.copy(image,s.rva,s.raw,s.raw+Math.min(s.span,s.rawSize));
 const operands=new Map();for(const f of plan.fixups){const original=f.width===8?image.readBigUInt64LE(f.rva):BigInt(u32(image,f.rva)),value=BigInt.asUintN(f.width*8,original+base-plan.base);operands.set(f.rva,value);if(f.width===8)image.writeBigUInt64LE(value,f.rva);else image.writeUInt32LE(Number(value),f.rva);}
 return {image,operands,base};
}
function measured(plan,loaded){
 const {image,base,operands}=loaded,a=plan.anchor.rva;
 assert(image.subarray(a,a+16).equals(plan.magic),'ANCHOR_MAGIC_CHANGED');assert.equal(u32(image,a+16),1,'ANCHOR_VERSION_CHANGED');assert.equal(u32(image,a+20),6,'ANCHOR_COUNT_CHANGED');
 for(let i=0;i<6;i++)assert.equal(image.readBigUInt64LE(a+24+i*8),base+BigInt(plan.targets[i]),'ANCHOR_TARGET_CHANGED');
 const sections=plan.sections.filter(s=>(s.flags&0x20000000)&&!(s.flags&0x80000000)),parts=[Buffer.from('GAME-CODE-V1\0'),frame(sections.length)],normalized=[];
 for(const s of sections){const bytes=Buffer.from(image.subarray(s.rva,s.rva+s.span));for(const f of plan.fixups.filter(f=>f.rva>=s.rva&&f.rva<s.rva+s.span)){assert(f.rva+f.width<=s.rva+s.span);const value=f.width===8?image.readBigUInt64LE(f.rva):BigInt(u32(image,f.rva));assert.equal(value,operands.get(f.rva),'CODE_RELOCATION_CHANGED');bytes.fill(0,f.rva-s.rva,f.rva-s.rva+f.width);}normalized.push({...s,bytes});parts.push(frame(s.rva,s.span),bytes);}
 const code=Buffer.concat(parts),checkers={};for(const [role,ranges] of Object.entries(plan.roles)){const chunks=[Buffer.from('CRC-CHECKERS-V1\0'),frame(ranges.length)];for(const r of ranges){const s=normalized.find(s=>r.rva>=s.rva&&r.rva+r.span<=s.rva+s.span);assert(s);chunks.push(frame(r.rva,r.span),s.bytes.subarray(r.rva-s.rva,r.rva-s.rva+r.span));}checkers[role]=Buffer.concat(chunks);}
 const headerParts=[];for(const [at,size] of plan.headers){assert(image.subarray(at,at+size).equals(plan.file.subarray(at,at+size)),'HEADER_CHANGED');headerParts.push(frame(at,size),image.subarray(at,at+size));}
 const er=u32(plan.file,plan.opt+112),es=u32(plan.file,plan.opt+116),exports=er?Buffer.concat([Buffer.from('GAME-EXPORT-V1\0'),frame(plan.opt+112),image.subarray(plan.opt+112,plan.opt+120),image.subarray(er,er+es)]):Buffer.alloc(0);
 return crc.measureCrcLayers({code,headers:Buffer.concat(headerParts),exports,checkers});
}
const inputs=process.env.NATIVE_CRC_BINARY_DIR?['GameLauncher','GameConnect','GameOverlay'].map(name=>[name,fs.readFileSync(path.join(process.env.NATIVE_CRC_BINARY_DIR,name+'.exe'))]):[['fixture',require('./desktop-bootstrap-fixture').PE('A')]];
for(const [name,file] of inputs){
 const plan=nativePlan(file),expected=CodeImage(file).crcLayers;assert.equal(policy.Compare(expected,expected).complete,true);
 for(const delta of [0n,0x40000000n,-0x40000000n]){
  const live=mapped(plan,plan.base+delta),actual=measured(plan,live);assert.deepEqual(actual,expected,name+' relocated metadata and all nine CRC roles');
  for(const offset of [0,16,20,24,64]){live.image[plan.anchor.rva+offset]^=1;assert.throws(()=>measured(plan,live),/ANCHOR_(MAGIC|VERSION|COUNT|TARGET)_CHANGED/);live.image[plan.anchor.rva+offset]^=1;}
  const target=plan.roles.nvme[0].rva,mutation=live.image[target];live.image[target]^=1;
  assert.equal(policy.Compare(measured(plan,live),expected).matched,false,'checker code alteration must reject');live.image[target]=mutation;
 }
 console.log('PASS '+name+': retained metadata plan, 0/positive/negative ASLR, all nine roles, live anchor and checker-code tamper');
}
