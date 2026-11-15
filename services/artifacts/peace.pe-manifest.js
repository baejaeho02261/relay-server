'use strict';
// Bounded PE resource traversal. This parses RESOURCE DIRECTORY structures, not
// XML or executable code. The exact expected manifest bytes are checked later
// and the Windows build independently parses its XML with XmlResolver disabled.
const crypto=require('node:crypto');
function Extract(bytes){
 const bad=()=>{throw Error('PE_MANIFEST_INVALID');};
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
 const pe=bytes.readUInt32LE(60);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
 const opt=pe+24,optSize=bytes.readUInt16LE(pe+20),count=bytes.readUInt16LE(pe+6),table=opt+optSize;
 if(optSize<136||count<1||count>96||table>bytes.length-count*40||bytes.readUInt16LE(opt)!==0x20b||bytes.readUInt32LE(opt+108)<3)bad();
 const rva=bytes.readUInt32LE(opt+128),size=bytes.readUInt32LE(opt+132),headers=bytes.readUInt32LE(opt+60);
 if(!rva||size<16||size>16*1024*1024)bad();
 const sections=[];
 for(let i=0;i<count;i++){
  const p=table+i*40,s={rva:bytes.readUInt32LE(p+12),size:bytes.readUInt32LE(p+16),raw:bytes.readUInt32LE(p+20)};
  if(s.size&&(s.raw<headers||s.raw>bytes.length-s.size)||s.rva+s.size>0xffffffff||sections.some(t=>s.size&&t.size&&(s.rva<t.rva+t.size&&t.rva<s.rva+s.size||s.raw<t.raw+t.size&&t.raw<s.raw+s.size)))bad();sections.push(s);
 }
 const at=(address,length)=>{const s=sections.find(s=>address>=s.rva&&length<=s.size&&address-s.rva<=s.size-length);if(!s)bad();return s.raw+address-s.rva;};
 const start=at(rva,size),region=bytes.subarray(start,start+size),seenDirs=new Set();let entries=0;
 const check=(offset,length)=>{if(offset<0||length<0||offset>region.length-length)bad();};
 function directory(offset){
  check(offset,16);if(seenDirs.has(offset))bad();seenDirs.add(offset);
  const named=region.readUInt16LE(offset+12),ids=region.readUInt16LE(offset+14),n=named+ids;
  if(n>256||(entries+=n)>4096)bad();check(offset+16,n*8);
  const seen=new Set(),rows=[];let previousId=-1;
  for(let i=0;i<n;i++){
   const p=offset+16+i*8,name=region.readUInt32LE(p),target=region.readUInt32LE(p+4);let id=name;
   if(!!(name&0x80000000)!==(i<named))bad();
   if(name&0x80000000){const location=name&0x7fffffff;check(location,2);const length=region.readUInt16LE(location);if(length>256)bad();check(location+2,length*2);id='NAME:'+region.subarray(location+2,location+2+length*2).toString('hex');}
   else{if(name>65535||name<=previousId)bad();previousId=name;}
   if(seen.has(id))bad();seen.add(id);rows.push({id,directory:!!(target&0x80000000),target:target&0x7fffffff});
  }
  return rows;
 }
 const type=directory(0).find(x=>x.id===24);if(!type||!type.directory)throw Error('PE_MANIFEST_MISSING');
 const name=directory(type.target).find(x=>x.id===1);if(!name||!name.directory)throw Error('PE_MANIFEST_MISSING');
 const languages=directory(name.target);if(!languages.length||languages.length>64)bad();
 return languages.map(row=>{
  if(row.directory||typeof row.id!=='number')bad();check(row.target,16);
  const address=region.readUInt32LE(row.target),length=region.readUInt32LE(row.target+4);
  if(length<1||length>65536||address<rva||address-rva>size-length||region.readUInt32LE(row.target+12)!==0)bad();
  return {language:row.id,bytes:Buffer.from(bytes.subarray(at(address,length),at(address,length)+length))};
 });
}
function AssertExpected(bytes,expected){
 if(!Buffer.isBuffer(expected)||expected.length<1||expected.length>65536)throw Error('PE_MANIFEST_EXPECTED_INVALID');
 const manifests=Extract(bytes);if(manifests.some(m=>!m.bytes.equals(expected)))throw Error('OVERLAY_EXE_MANIFEST_STALE');
 return {status:'EXACT_SOURCE_BYTES_MATCH',resourceType:24,resourceId:1,languages:manifests.map(m=>m.language),sha512:crypto.createHash('sha512').update(expected).digest('hex'),xmlValidation:'WINDOWS_BUILD_STAGE_REQUIRED',runtimeDpi:'NOT_RUN_BY_THIS_TOOL'};
}
module.exports={Extract,AssertExpected};
