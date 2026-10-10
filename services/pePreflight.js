'use strict';
// PE preflight V1: also embedded verbatim into standalone approval tools.
function ValidatePeImage(bytes,reject){
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
    if(!section)continue;if(type!==10&&type!==3||target<section.rva||target+width>section.rva+section.span)bad();
    section.bytes.fill(0,target-section.rva,target-section.rva+width);seen.push([target,target+width]);if(++relocations>1000000)bad();
   }
   cursor+=block;
  }
  seen.sort((a,b)=>a[0]-b[0]);for(let i=1;i<seen.length;i++)if(seen[i][0]<seen[i-1][1])bad();
 }
 return true;
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
