'use strict';
// PE preflight V1: also embedded verbatim into standalone approval tools.
function ValidatePeImage(bytes,reject,checkBuildConfiguration=false){
 const bad=()=>reject('BOOTSTRAP_PE_INVALID');
 if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
 const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe>bytes.length-24||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
 const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
 if(count<1||count>96||optSize<160||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
 const imageSize=bytes.readUInt32LE(opt+56),headerSize=bytes.readUInt32LE(opt+60),dirCount=bytes.readUInt32LE(opt+108);
 if(imageSize<4096||imageSize>128*1024*1024||headerSize<table+count*40||headerSize>bytes.length||dirCount>16||112+dirCount*8>optSize)bad();
 const sections=[];let total=0;
 for(let i=0;i<count;i++){
  const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),rva=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),span=virtualSize||rawSize,mapped=Math.max(span,rawSize);
  if(!span||rva<headerSize||rva+mapped>imageSize||rawSize&&(raw<headerSize||raw+rawSize>bytes.length)||sections.some(s=>rva<s.rva+s.mapped&&rva+mapped>s.rva||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
  const protectedCode=!!(flags&0x20000000)&&!(flags&0x80000000);if(protectedCode){total+=span;if(total>64*1024*1024)bad();}
  sections.push({rva,span,mapped,raw,rawSize,flags,protectedCode});
 }
 const protectedSections=sections.filter(s=>s.protectedCode).sort((a,b)=>a.rva-b.rva);if(!protectedSections.length)bad();
 ValidatePeExceptionTable(bytes,opt,dirCount,sections,reject);
 // Core PE measurement can report unsupported exports; release approval must
 // additionally reject Debug and malformed configuration metadata.
 const buildConfiguration=checkBuildConfiguration?ValidatePeBuildConfiguration(bytes,opt,dirCount,imageSize,sections,reject):null;
 for(const section of protectedSections){section.bytes=Buffer.alloc(section.span);bytes.copy(section.bytes,0,section.raw,section.raw+Math.min(section.rawSize,section.span));}
 const rawAt=(rva,length)=>{if(!Number.isSafeInteger(length)||length<0)bad();if(rva<headerSize&&rva+length<=headerSize)return rva;const s=sections.find(s=>rva>=s.rva&&rva+length<=s.rva+s.rawSize);if(!s)bad();return s.raw+(rva-s.rva);};
 const relocRva=dirCount>5?bytes.readUInt32LE(opt+112+5*8):0,relocSize=dirCount>5?bytes.readUInt32LE(opt+116+5*8):0;
 if(!!relocRva!==!!relocSize||relocSize>16*1024*1024)bad();
 let relocations=0;
 if(relocSize){
  let cursor=rawAt(relocRva,relocSize),end=cursor+relocSize;const seen=[];
  while(cursor<end){
   if(cursor+8>end)bad();const page=bytes.readUInt32LE(cursor),block=bytes.readUInt32LE(cursor+4);if(block<8||block%2||cursor+block>end||page>=imageSize)bad();
   for(let at=cursor+8;at<cursor+block;at+=2){
    const entry=bytes.readUInt16LE(at),type=entry>>>12,target=page+(entry&0xfff);if(type===0)continue;
    const width=type===10?8:type===3?4:1,section=protectedSections.find(s=>target<s.rva+s.span&&target+width>s.rva);
    if(buildConfiguration&&buildConfiguration.rva&&target<buildConfiguration.end&&target+width>buildConfiguration.rva)reject('SECURITY_BUILD_CONFIGURATION_INVALID');
    if(!section)continue;if(type!==10&&type!==3||target<section.rva||target+width>section.rva+section.span)bad();
    section.bytes.fill(0,target-section.rva,target-section.rva+width);seen.push([target,target+width]);if(++relocations>1000000)bad();
   }
   cursor+=block;
  }
  seen.sort((a,b)=>a[0]-b[0]);for(let i=1;i<seen.length;i++)if(seen[i][0]<seen[i-1][1])bad();
 }
 if(buildConfiguration&&buildConfiguration.configuration==='DEBUG')reject('SECURITY_DEBUG_BUILD_NOT_PUBLISHABLE');
 return true;
}
function ValidatePeBuildConfiguration(bytes,opt,dirCount,imageSize,sections,reject){
 // Only bounded export-name entries identify build configuration. A marker-like
 // string elsewhere in code/resources/overlay data does not change the result.
 const bad=()=>reject('SECURITY_BUILD_CONFIGURATION_INVALID');
 const rva=dirCount?bytes.readUInt32LE(opt+112):0,span=dirCount?bytes.readUInt32LE(opt+116):0;
 if(!rva&&!span)return {configuration:'UNMARKED',rva:0,end:0};
 if(!rva||span<40||span>8*1024*1024||rva+span>imageSize)bad();
 const section=sections.find(s=>rva>=s.rva&&rva+span<=s.rva+Math.min(s.rawSize,s.span));
 if(!section||(section.flags&0x80000000))bad();
 const start=section.raw+rva-section.rva,end=rva+span;
 const inside=(at,length)=>{if(!Number.isSafeInteger(at)||!Number.isSafeInteger(length)||length<0||at<rva||at+length>end)bad();return start+at-rva;};
 const stringAt=(at,forwarder=false)=>{const offset=inside(at,1);for(let i=0;i<512;i++){if(at+i>=end)bad();const c=bytes[offset+i];if(c===0){if(!i)bad();return bytes.toString('ascii',offset,offset+i);}if(c<32||c>126||forwarder&&c===32)bad();}bad();};
 const functions=bytes.readUInt32LE(start+20),names=bytes.readUInt32LE(start+24);
 if(functions>131072||names>131072||names>functions)bad();
 stringAt(bytes.readUInt32LE(start+12));
 const functionAt=functions?inside(bytes.readUInt32LE(start+28),functions*4):0;
 const nameAt=names?inside(bytes.readUInt32LE(start+32),names*4):0;
 const ordinalAt=names?inside(bytes.readUInt32LE(start+36),names*2):0;
 for(let i=0;i<functions;i++){
  const target=bytes.readUInt32LE(functionAt+i*4);if(!target)continue;
  if(target>=imageSize)bad();if(target>=rva&&target<end)stringAt(target,true);
 }
 let configuration=null;
 for(let i=0;i<names;i++){
  const ordinal=bytes.readUInt16LE(ordinalAt+i*2);if(ordinal>=functions)bad();
  const name=stringAt(bytes.readUInt32LE(nameAt+i*4));
  if(!/^GAME_BUILD_(?:DEBUG|RELEASE)_/.test(name))continue;
  if(configuration||!/^GAME_BUILD_(DEBUG|RELEASE)_V1$/.test(name))bad();
  const target=bytes.readUInt32LE(functionAt+ordinal*4);
  if(!target||target>=rva&&target<end||!sections.some(s=>target>=s.rva&&target-s.rva<Math.min(s.span,s.rawSize)&&(s.flags&0x60000000)===0x60000000&&!(s.flags&0x80000000)))bad();
  configuration=name==='GAME_BUILD_RELEASE_V1'?'RELEASE':'DEBUG';
 }
 return {configuration:configuration||'UNMARKED',rva,end};
}
function ValidatePeExceptionTable(bytes,opt,dirCount,sections,reject){
 // Read-only preflight: normalization belongs to the completed build, before
 // detached approval binds its SHA-512. Server CRC/coverage checks still apply.
 const rva=dirCount>3?bytes.readUInt32LE(opt+136):0,size=dirCount>3?bytes.readUInt32LE(opt+140):0;
 if(!rva&&!size)return; // The server separately determines missing CRC coverage.
 const bad=()=>reject('PE_EXCEPTION_TABLE_INVALID');
 if(!rva||rva%4||!size||size%12||size>16*1024*1024)bad();
 const locate=(at,length)=>sections.find(s=>at>=s.rva&&at+length<=s.rva+Math.min(s.rawSize,s.span));
 const table=locate(rva,size);
 if(!table||(table.flags&0x80000000)||(table.flags&0x20000000))bad();
 const raw=table.raw+rva-table.rva,end=raw+size;let previousBegin=-1,previousEnd=0;
 for(let at=raw;at<end;at+=12){
  const begin=bytes.readUInt32LE(at),finish=bytes.readUInt32LE(at+4),unwind=bytes.readUInt32LE(at+8);
  if(finish<=begin||unwind%4)bad();
  const code=locate(begin,finish-begin),metadata=locate(unwind,4);
  if(!code||!(code.flags&0x20000000)||(code.flags&0x80000000)||!metadata||!(metadata.flags&0x40000000)||(metadata.flags&0x20000000))bad();
  if(begin<previousBegin)reject('PE_EXCEPTION_TABLE_UNSORTED');
  if(begin<previousEnd)bad();
  previousBegin=begin;previousEnd=finish;
 }
}

module.exports={ValidatePeImage,ValidatePeExceptionTable};
