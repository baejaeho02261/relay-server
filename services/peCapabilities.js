'use strict';
const DOMAIN='GAME-AUTHORITY-V2';
function PeCapabilities(bytes){
 const authorityVersion=Buffer.isBuffer(bytes)&&(bytes.includes(Buffer.from(DOMAIN))||bytes.includes(Buffer.from(DOMAIN,'utf16le')))?1:0;
 let cfg={status:'ABSENT',instrumentedMetadata:false,functionCount:0,reason:'NO_CFG_METADATA',callSiteCoverage:'REQUIRES_TOOLCHAIN_AND_WINDOWS_EVIDENCE'};
 const bad=reason=>{throw Error(reason);};
 try{
  if(!Buffer.isBuffer(bytes)||bytes.length<512||bytes.length>64*1024*1024||bytes.readUInt16LE(0)!==0x5a4d)bad('PE_HEADER');
  const pe=bytes.readUInt32LE(0x3c);if(pe<64||pe+24>bytes.length||bytes.readUInt32LE(pe)!==0x4550||bytes.readUInt16LE(pe+4)!==0x8664)bad('PE_MACHINE');
  const opt=pe+24,size=bytes.readUInt16LE(pe+20),count=bytes.readUInt16LE(pe+6),table=opt+size;
  if(size<112||count<1||count>96||table+40*count>bytes.length||bytes.readUInt16LE(opt)!==0x20b)bad('PE_OPTIONAL_HEADER');
  const dirs=bytes.readUInt32LE(opt+108),headers=bytes.readUInt32LE(opt+60),imageSize=bytes.readUInt32LE(opt+56),base=bytes.readBigUInt64LE(opt+24),sections=[];
  if(dirs>16||112+dirs*8>size||headers<table+40*count||headers>bytes.length||imageSize<4096||imageSize>128*1024*1024)bad('PE_BOUNDS');
  for(let i=0;i<count;i++){const p=table+40*i,s={rva:bytes.readUInt32LE(p+12),span:Math.max(bytes.readUInt32LE(p+8),bytes.readUInt32LE(p+16)),raw:bytes.readUInt32LE(p+20),rawSize:bytes.readUInt32LE(p+16),flags:bytes.readUInt32LE(p+36)};
   if(!s.span||s.rva<headers||s.rva+s.span>imageSize||s.rawSize&&(s.raw<headers||s.raw+s.rawSize>bytes.length)||sections.some(x=>s.rva<x.rva+x.span&&x.rva<s.rva+s.span||s.rawSize&&x.rawSize&&s.raw<x.raw+x.rawSize&&x.raw<s.raw+s.rawSize))bad('PE_SECTIONS');sections.push(s);}
  const rawAt=(rva,length)=>{const s=sections.find(s=>rva>=s.rva&&rva+length<=s.rva+s.rawSize);if(!s)bad('CFG_UNMAPPED');return {at:s.raw+rva-s.rva,s};};
  const toRva=va=>{if(va<base||va-base>=BigInt(imageSize))bad('CFG_VA');return Number(va-base);};
  const hasFlag=!!(bytes.readUInt16LE(opt+70)&0x4000);
  if(dirs<=10){if(hasFlag)bad('CFG_FLAG_WITHOUT_LOAD_CONFIG');return {authorityVersion,compiledCfg:false,cfg};}
  const rva=bytes.readUInt32LE(opt+192),length=bytes.readUInt32LE(opt+196);
  if(!rva&&!length){if(hasFlag)bad('CFG_FLAG_WITHOUT_LOAD_CONFIG');return {authorityVersion,compiledCfg:false,cfg};}
  if(!rva||!length)bad('CFG_LOAD_CONFIG_RANGE');
  const lc=rawAt(rva,length);if(length<148){if(hasFlag)bad('CFG_LOAD_CONFIG_SHORT');return {authorityVersion,compiledCfg:false,cfg};}
  const structSize=bytes.readUInt32LE(lc.at),flags=bytes.readUInt32LE(lc.at+144);
  if(structSize<148||structSize>length)bad('CFG_LOAD_CONFIG_SIZE');
  if(!hasFlag&&(flags&0x500))bad('CFG_INCONSISTENT_FLAGS');
  if(!hasFlag)return {authorityVersion,compiledCfg:false,cfg};
  if((flags&0x500)!==0x500)bad('CFG_INSTRUMENTATION_FLAGS');
  const check=bytes.readBigUInt64LE(lc.at+112),tableVA=bytes.readBigUInt64LE(lc.at+128),n=bytes.readBigUInt64LE(lc.at+136);
  if(!check||!tableVA||n===0n||n>1000000n)bad('CFG_TABLE_MISSING');
  rawAt(toRva(check),8);const stride=4+((flags>>>28)&15),total=Number(n)*stride,entries=rawAt(toRva(tableVA),total);
  if(entries.s.flags&0x80000000)bad('CFG_TABLE_WRITABLE');
  let previous=-1;for(let i=0;i<Number(n);i++){const target=bytes.readUInt32LE(entries.at+i*stride);if(target<=previous)bad('CFG_TARGET_ORDER');previous=target;const s=sections.find(s=>target>=s.rva&&target<s.rva+s.span);if(!s||!(s.flags&0x20000000)||(s.flags&0x80000000))bad('CFG_TARGET_NOT_IMMUTABLE_CODE');}
  cfg={...cfg,status:'STRUCTURALLY_VALID',instrumentedMetadata:true,functionCount:Number(n),reason:'',guardFlags:flags};
 }catch(error){cfg={...cfg,status:'INVALID',reason:error.message};}
 return {authorityVersion,compiledCfg:cfg.instrumentedMetadata,cfg};
}
module.exports={PeCapabilities};
