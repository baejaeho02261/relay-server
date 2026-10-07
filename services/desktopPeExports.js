'use strict';
// Immutable export directory/address-table evidence. This is not a guessed
// function-length checksum or IAT check. The original PE determines the range;
// a client must measure the same header entry and export bytes in its image.
const {Digests}=require('./desktopIntegrity');
const PREFIX=Buffer.from('GAME-EXPORT-V1\0','ascii');
const MAX_SPAN=8*1024*1024,MAX_ENTRIES=131072,MAX_STRING=512;
function ExportTable(bytes){
 const unsupported={status:'UNSUPPORTED_EXPORT_LAYOUT',sha512:'',crc64:''};
 const bad=()=>{throw Error('EXPORT_LAYOUT');};
 try{
  if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad();
  const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad();
  const count=bytes.readUInt16LE(pe+6),opt=pe+24,optSize=bytes.readUInt16LE(pe+20),table=opt+optSize;
  if(count<1||count>96||optSize<112||table+count*40>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad();
  const imageSize=bytes.readUInt32LE(opt+56),headers=bytes.readUInt32LE(opt+60),dirs=bytes.readUInt32LE(opt+108);
  if(imageSize<4096||imageSize>128*1024*1024||headers<table+count*40||headers>bytes.length||dirs>16||112+dirs*8>optSize)bad();
  if(!dirs)return {status:'NO_EXPORTS',sha512:'',crc64:''};
  const directoryOffset=opt+112,rva=bytes.readUInt32LE(directoryOffset),span=bytes.readUInt32LE(directoryOffset+4);
  if(!rva&&!span)return {status:'NO_EXPORTS',sha512:'',crc64:''};
  if(!rva||span<40||span>MAX_SPAN||rva+span>imageSize)bad();
  const sections=[];
  for(let i=0;i<count;i++){
   const at=table+i*40,virtualSize=bytes.readUInt32LE(at+8),start=bytes.readUInt32LE(at+12),rawSize=bytes.readUInt32LE(at+16),raw=bytes.readUInt32LE(at+20),flags=bytes.readUInt32LE(at+36),mapped=Math.max(virtualSize||rawSize,rawSize);
   if(!mapped||start<headers||start+mapped>imageSize||rawSize&&(raw<headers||raw+rawSize>bytes.length)||sections.some(s=>start<s.start+s.mapped&&start+mapped>s.start||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
   sections.push({start,mapped,span:virtualSize||rawSize,rawSize,raw,flags});
  }
  const section=sections.find(s=>rva>=s.start&&rva+span<=s.start+s.rawSize&&rva+span<=s.start+s.span);
  if(!section||(section.flags&0x80000000))bad();
  const start=section.raw+rva-section.start,end=rva+span;
  const inside=(at,length)=>{if(!Number.isSafeInteger(at)||!Number.isSafeInteger(length)||length<0||at<rva||at+length>end)bad();return start+at-rva;};
  const stringAt=(at,forwarder=false)=>{const offset=inside(at,1);for(let i=0;i<MAX_STRING;i++){if(at+i>=end)bad();const c=bytes[offset+i];if(c===0){if(i===0)bad();return i;}if(c<32||c>126||forwarder&&c===32)bad();}bad();};
  const functions=bytes.readUInt32LE(start+20),names=bytes.readUInt32LE(start+24);
  if(functions>MAX_ENTRIES||names>MAX_ENTRIES||names>functions)bad();
  stringAt(bytes.readUInt32LE(start+12));
  const functionRva=bytes.readUInt32LE(start+28),nameRva=bytes.readUInt32LE(start+32),ordinalRva=bytes.readUInt32LE(start+36);
  const functionAt=functions?inside(functionRva,functions*4):0,nameAt=names?inside(nameRva,names*4):0,ordinalAt=names?inside(ordinalRva,names*2):0;
  let exported=0,code=0,forwarded=0;
  for(let i=0;i<functions;i++){
   const target=bytes.readUInt32LE(functionAt+i*4);if(!target)continue;if(target>=imageSize)bad();exported++;
   if(target>=rva&&target<end){stringAt(target,true);forwarded++;}
   else if(sections.some(s=>target>=s.start&&target<s.start+s.span&&(s.flags&0x20000000)&&!(s.flags&0x80000000)))code++;
  }
  for(let i=0;i<names;i++){if(bytes.readUInt16LE(ordinalAt+i*2)>=functions)bad();stringAt(bytes.readUInt32LE(nameAt+i*4));}
  // Export tables should hold RVAs, not loader-relocated VA operands. Decline
  // unsupported images rather than normalize away a redirected API address.
  if(dirs>5){
   const relocRva=bytes.readUInt32LE(opt+152),relocSize=bytes.readUInt32LE(opt+156);
   if(!!relocRva!==!!relocSize||relocSize>16*1024*1024)bad();
   if(relocSize){const rs=sections.find(s=>relocRva>=s.start&&relocRva+relocSize<=s.start+s.rawSize);if(!rs)bad();let at=rs.raw+relocRva-rs.start,stop=at+relocSize;
    while(at<stop){if(at+8>stop)bad();const page=bytes.readUInt32LE(at),size=bytes.readUInt32LE(at+4);if(size<8||size%2||at+size>stop||page>=imageSize)bad();
     for(let p=at+8;p<at+size;p+=2){const entry=bytes.readUInt16LE(p),type=entry>>>12,target=page+(entry&0xfff);if(!type)continue;const width=type===10?8:type===3?4:1;if(target<end&&target+width>rva)bad();}
     at+=size;
    }
   }
  }
  const offset=Buffer.alloc(4);offset.writeUInt32LE(directoryOffset);
  const normalized=Buffer.concat([PREFIX,offset,bytes.subarray(directoryOffset,directoryOffset+8),bytes.subarray(start,start+span)]),result={status:'MEASURED',...Digests(normalized),directoryOffset,rva,span,exportCount:exported,codeExportCount:code,forwardedExportCount:forwarded};Object.defineProperty(result,'normalized',{value:normalized});return result;
 }catch(_){return unsupported;}
}
module.exports={ExportTable,MAX_SPAN,MAX_ENTRIES,MAX_STRING};
