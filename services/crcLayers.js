'use strict';
// CRCs detect corruption; authorization still requires the signed server
// baseline, challenge and session. They do not establish hardware attestation.
// Params: Rocksoft model; JONES is the all-ones-init variant (not REDIS).
const crypto = require('node:crypto');
const defs = [
 ['ecma182','CRC-64/ECMA-182',64,0x42f0e1eba9ea3693n,0n,false,0n,0x6c40df5f0b497347n],
 ['nvme','CRC-64/NVME',64,0xad93d23594c93659n,0xffffffffffffffffn,true,0xffffffffffffffffn,0xae8b14860a799888n],
 ['jones','CRC-64/JONES',64,0xad93d23594c935a9n,0xffffffffffffffffn,true,0n,0xcaa717168609f281n],
 ['xz','CRC-64/XZ',64,0x42f0e1eba9ea3693n,0xffffffffffffffffn,true,0xffffffffffffffffn,0x995dc9bbdf1939fan],
 ['we','CRC-64/WE',64,0x42f0e1eba9ea3693n,0xffffffffffffffffn,false,0xffffffffffffffffn,0x62ec59e3f1a4f00an],
 ['iso','CRC-64/GO-ISO',64,0x1bn,0xffffffffffffffffn,true,0xffffffffffffffffn,0xb90956c775a41001n],
 ['crc32c','CRC-32/ISCSI',32,0x1edc6f41n,0xffffffffn,true,0xffffffffn,0xe3069283n],
 ['crc16_arc','CRC-16/ARC',16,0x8005n,0n,true,0n,0xbb3dn],
 ['crc8_smbus','CRC-8/SMBUS',8,0x07n,0n,false,0n,0xf4n]
];
const registry = Object.freeze(Object.fromEntries(defs.map(([id,name,width,poly,init,reflected,xorout,check]) => [id,Object.freeze({id,name,width,poly,init,reflected,xorout,check})])));
const tables = new Map();
for (const spec of Object.values(registry)) {
  let poly = spec.poly;
  if (spec.reflected) { let reverse=0n; for(let i=0;i<spec.width;i++){reverse=(reverse<<1n)|(poly&1n);poly>>=1n;} poly=reverse; }
  const top=1n<<BigInt(spec.width-1),mask=(1n<<BigInt(spec.width))-1n;
  const lo=new Uint32Array(256),hi=new Uint32Array(256);
  for(let i=0;i<256;i++){
    let v=BigInt(i); if(!spec.reflected)v<<=BigInt(spec.width-8);
    for(let bit=0;bit<8;bit++) v=spec.reflected ? ((v>>1n)^((v&1n)?poly:0n)) : (((v<<1n)^((v&top)?poly:0n))&mask);
    lo[i]=Number(v&0xffffffffn);hi[i]=Number(v>>32n);
  }
  tables.set(spec.id,{lo,hi});
}
function requireBytes(value){if(!Buffer.isBuffer(value)&&!(value instanceof Uint8Array))throw TypeError('CRC_BYTES_REQUIRED');return value;}
function specFor(kind){const spec=registry[kind];if(!spec)throw TypeError('CRC_VARIANT_INVALID');return spec;}
class CrcStream {
 constructor(kind){this.spec=specFor(kind);this.lo=Number(this.spec.init&0xffffffffn);this.hi=Number(this.spec.init>>32n);this.bytes=0;}
 update(bytes){
  requireBytes(bytes);if(!Number.isSafeInteger(this.bytes+bytes.length))throw RangeError('CRC_INPUT_TOO_LONG');
  const {width,reflected,id}=this.spec,{lo:tl,hi:th}=tables.get(id);let lo=this.lo,hi=this.hi;
  if(width===64){
   if(reflected){for(const byte of bytes){const ix=(lo^byte)&255;lo=(((lo>>>8)|(hi<<24))^tl[ix])>>>0;hi=((hi>>>8)^th[ix])>>>0;}}
   else{for(const byte of bytes){const ix=(hi>>>24)^byte;hi=(((hi<<8)|(lo>>>24))^th[ix])>>>0;lo=((lo<<8)^tl[ix])>>>0;}}
  }else if(reflected){for(const byte of bytes)lo=((lo>>>8)^tl[(lo^byte)&255])>>>0;}
  else{const mask=width===32?0xffffffff:(1<<width)-1;for(const byte of bytes)lo=(((lo<<8)^tl[((lo>>>(width-8))^byte)&255])&mask)>>>0;}
  this.lo=lo;this.hi=hi;this.bytes+=bytes.length;return this;
 }
 value(){return ((BigInt(this.hi)<<32n)|BigInt(this.lo))^this.spec.xorout;}
 digest(){return this.value().toString(16).padStart(this.spec.width/4,'0').toUpperCase();}
}
function crcHex(kind,bytes){return new CrcStream(kind).update(bytes).digest();}
function tableBytes(kind){specFor(kind);const {lo,hi}=tables.get(kind),out=Buffer.alloc(2048);for(let i=0;i<256;i++){out.writeUInt32LE(lo[i],i*8);out.writeUInt32LE(hi[i],i*8+4);}return out;}
function allTableBytes(){return Buffer.concat(defs.map(([id])=>tableBytes(id)));}
function parameterBytes(){const out=Buffer.alloc(defs.length*34);let at=0;for(const spec of Object.values(registry)){out[at++]=spec.width;out[at++]=Number(spec.reflected);for(const name of ['poly','init','xorout','check']){out.writeBigUInt64LE(spec[name],at);at+=8;}}return out;}
const CODE_PREFIX=Buffer.from('GAME-CODE-V1\0','ascii'),PAGE_PREFIX=Buffer.from('CRC-PAGES-V1\0','ascii');
function codePageManifest(code){
 requireBytes(code);code=Buffer.from(code.buffer,code.byteOffset,code.byteLength);
 const bad=()=>{throw Error('CRC_CODE_FRAME_INVALID');};
 if(code.length<CODE_PREFIX.length+4||code.length>64*1024*1024+4096||!code.subarray(0,CODE_PREFIX.length).equals(CODE_PREFIX))bad();
 let at=CODE_PREFIX.length;const count=code.readUInt32LE(at);at+=4;if(count<1||count>96)bad();
 const entries=[];let lastEnd=0;
 for(let i=0;i<count;i++){
  if(at+8>code.length)bad();let rva=code.readUInt32LE(at),span=code.readUInt32LE(at+4);at+=8;
  if(!span||at+span>code.length||rva+span>0xffffffff||rva<lastEnd)bad();lastEnd=rva+span;
  while(span){const size=Math.min(span,4096-(rva&4095)),entry=Buffer.alloc(12);entry.writeUInt32LE(rva);entry.writeUInt32LE(size,4);entry.writeUInt32LE(Number(new CrcStream('crc32c').update(code.subarray(at,at+size)).value()),8);entries.push(entry);at+=size;rva+=size;span-=size;}
 }
 if(at!==code.length)bad();const head=Buffer.alloc(PAGE_PREFIX.length+8);PAGE_PREFIX.copy(head);head.writeUInt32LE(4096,PAGE_PREFIX.length);head.writeUInt32LE(entries.length,PAGE_PREFIX.length+4);return Buffer.concat([head,...entries]);
}
function layoutState(codeBytes,headerBytes,exportBytes){const out=Buffer.alloc(25);out[0]=1;for(const [i,n] of [codeBytes,headerBytes,exportBytes].entries()){if(!Number.isSafeInteger(n)||n<0)throw RangeError('CRC_LENGTH_INVALID');out.writeBigUInt64LE(BigInt(n),1+i*8);}return out;}
// The exact fields retained by Game.SelfImageHeaders, with explicit offset and
// size framing. The loader's resolved IAT and ASLR ImageBase are excluded.
function headerMetadata(file){
 requireBytes(file);file=Buffer.from(file.buffer,file.byteOffset,file.byteLength);
 const bad=()=>{throw Error('CRC_PE_HEADER_INVALID');};
 if(file.length<64||file.length>64*1024*1024||file.readUInt16LE(0)!==0x5a4d)bad();
 const pe=file.readUInt32LE(0x3c);if(pe<64||pe+24>file.length||file.readUInt32LE(pe)!==0x4550||file.readUInt16LE(pe+4)!==0x8664)bad();
 const count=file.readUInt16LE(pe+6),opt=pe+24,optSize=file.readUInt16LE(pe+20),table=opt+optSize;
 if(count<1||count>96||optSize<112||table+count*40>file.length||file.readUInt16LE(opt)!==0x20b)bad();
 const image=file.readUInt32LE(opt+56),header=file.readUInt32LE(opt+60),dirs=file.readUInt32LE(opt+108);
 if(image<4096||image>128*1024*1024||header<table+count*40||header>image||header>file.length||dirs>16||112+dirs*8>optSize)bad();
 const ranges=[[0,2],[0x3c,4],[pe,8],[pe+20,4],[opt,2],[opt+16,8],[opt+32,8],[opt+56,8],[opt+108,4]];
 if(dirs)ranges.push([opt+112,dirs*8]);for(let i=0;i<count;i++)ranges.push([table+i*40+8,16],[table+i*40+36,4]);
 const chunks=[];for(const [offset,size] of ranges){if(offset+size>header)bad();const frame=Buffer.alloc(8);frame.writeUInt32LE(offset);frame.writeUInt32LE(size,4);chunks.push(frame,file.subarray(offset,offset+size));}return Buffer.concat(chunks);
}

const CHECKER_MARKER=Buffer.from('47435243414e4348038d47912a60b5ec','hex');
const CHECKER_PREFIX=Buffer.from('CRC-CHECKERS-V1\0','ascii');
function checkerPlan(file){
 headerMetadata(file);file=Buffer.from(file.buffer,file.byteOffset,file.byteLength);
 const bad=()=>{throw Error('CRC_CHECKER_PLAN_INVALID');};
 const pe=file.readUInt32LE(0x3c),count=file.readUInt16LE(pe+6),opt=pe+24,table=opt+file.readUInt16LE(pe+20),dirs=file.readUInt32LE(opt+108),imageSize=file.readUInt32LE(opt+56),headerSize=file.readUInt32LE(opt+60),imageBase=file.readBigUInt64LE(opt+24);
 const sections=[];
 for(let i=0;i<count;i++){
  const at=table+i*40,raw=file.readUInt32LE(at+20),rawSize=file.readUInt32LE(at+16),rva=file.readUInt32LE(at+12),span=file.readUInt32LE(at+8)||rawSize,flags=file.readUInt32LE(at+36),mapped=Math.max(rawSize,span);
  if(!span||rva<headerSize||rva+mapped>imageSize||rawSize&&(raw<headerSize||raw+rawSize>file.length))bad();
  if(sections.some(s=>rva<s.rva+s.mapped&&rva+mapped>s.rva||rawSize&&s.rawSize&&raw<s.raw+s.rawSize&&raw+rawSize>s.raw))bad();
  sections.push({raw,rawSize,rva,span,mapped,flags});
 }
 const locate=(rva,size)=>sections.find(s=>rva>=s.rva&&rva+size<=s.rva+Math.min(s.rawSize,s.span));
 const rawAt=(rva,size)=>{const s=locate(rva,size);if(!s)bad();return s.raw+rva-s.rva;};
 const ro=s=>!(s.flags&0x80000000),exec=s=>ro(s)&&!!(s.flags&0x20000000);
 let candidate;
 for(const section of sections.filter(s=>ro(s)&&!(s.flags&0x20000000))){
  const end=section.raw+Math.min(section.rawSize,section.span);
  for(let at=file.indexOf(CHECKER_MARKER,section.raw);at>=section.raw&&at+16<=end;at=file.indexOf(CHECKER_MARKER,at+1)){
   if(candidate||at+72>end)bad();candidate={raw:at,rva:section.rva+at-section.raw};
  }
 }
 if(!candidate)return {status:'unavailable',reason:'CHECKER_ANCHOR_REQUIRED',roles:{}};
 if(file.readUInt32LE(candidate.raw+16)!==1||file.readUInt32LE(candidate.raw+20)!==6)bad();
 const targets=[];
 for(let i=0;i<6;i++){
  const va=file.readBigUInt64LE(candidate.raw+24+i*8);if(va<imageBase||va-imageBase>=BigInt(imageSize))bad();const rva=Number(va-imageBase);
  const section=locate(rva,1);if(!section||!exec(section))bad();targets.push(rva);
 }
 // The anchor pointer slots must be actual DIR64 relocation operands. This
 // prevents treating an accidental marker/string in a release as a registry.
 if(dirs<=5)bad();const relocRva=file.readUInt32LE(opt+152),relocSize=file.readUInt32LE(opt+156);
 if(!relocRva||!relocSize||relocSize>16*1024*1024)bad();const relocSection=locate(relocRva,relocSize);if(!relocSection||!ro(relocSection))bad();let at=rawAt(relocRva,relocSize),end=at+relocSize;const hits=new Set();
 while(at<end){
  if(at+8>end)bad();const page=file.readUInt32LE(at),size=file.readUInt32LE(at+4);if(page>=imageSize||size<8||size%2||at+size>end)bad();
  for(let p=at+8;p<at+size;p+=2){const value=file.readUInt16LE(p),kind=value>>>12,target=page+(value&4095);if(!kind)continue;
   const width=kind===10?8:kind===3?4:1;
   if(target<candidate.rva+72&&target+width>candidate.rva+24){if(kind!==10||(target-candidate.rva-24)%8||target<candidate.rva+24||target+8>candidate.rva+72||hits.has(target))bad();hits.add(target);}
  }at+=size;
 }
 if(hits.size!==6)bad();
 const exceptionRva=dirs>3?file.readUInt32LE(opt+136):0,exceptionSize=dirs>3?file.readUInt32LE(opt+140):0;
 if(!exceptionRva&&!exceptionSize)return {status:'unavailable',reason:'UNWIND_RANGES_REQUIRED',roles:{}};
 if(!exceptionRva||exceptionRva%4||!exceptionSize||exceptionSize%12||exceptionSize>16*1024*1024)bad();
 const exceptionSection=locate(exceptionRva,exceptionSize);if(!exceptionSection||!ro(exceptionSection)||exec(exceptionSection))bad();
 at=rawAt(exceptionRva,exceptionSize);end=at+exceptionSize;let previous=0;const functions=[];
 for(;at<end;at+=12){
  const rva=file.readUInt32LE(at),finish=file.readUInt32LE(at+4),unwind=file.readUInt32LE(at+8),section=locate(rva,finish-rva),unwindSection=locate(unwind,4);
  if(finish<=rva||unwind%4||rva<previous||!section||!exec(section)||!unwindSection||!ro(unwindSection))bad();previous=finish;functions.push({rva,span:finish-rva});
 }
 const assignments={nvme:[0],jones:[1,2],iso:[3,4,5]},roles={};
 for(const [role,indexes] of Object.entries(assignments)){
  const spans=indexes.map(index=>functions.find(f=>targets[index]>=f.rva&&targets[index]<f.rva+f.span));
  if(spans.every(Boolean))roles[role]=spans.filter((f,i)=>spans.findIndex(g=>g.rva===f.rva)===i).sort((a,b)=>a.rva-b.rva);
 }
 return {status:Object.keys(roles).length===3?'measured':'partial',reason:'UNWIND_RANGES_REQUIRED',roles,anchor:{rva:candidate.rva,targets}};
}
function checkerStreams(code,plan){
 codePageManifest(code);let at=CODE_PREFIX.length,count=code.readUInt32LE(at);at+=4;const sections=[];
 for(let i=0;i<count;i++){const rva=code.readUInt32LE(at),span=code.readUInt32LE(at+4);at+=8;sections.push({rva,span,data:code.subarray(at,at+span)});at+=span;}
 const result={};
 for(const role of ['nvme','jones','iso']){
  const spans=plan.roles[role];if(!spans)continue;const head=Buffer.alloc(CHECKER_PREFIX.length+4);CHECKER_PREFIX.copy(head);head.writeUInt32LE(spans.length,CHECKER_PREFIX.length);const chunks=[head];
  for(const span of spans){const s=sections.find(s=>span.rva>=s.rva&&span.rva+span.span<=s.rva+s.span);if(!s)throw Error('CRC_CHECKER_CODE_INVALID');const frame=Buffer.alloc(8);frame.writeUInt32LE(span.rva);frame.writeUInt32LE(span.span,4);chunks.push(frame,s.data.subarray(span.rva-s.rva,span.rva-s.rva+span.span));}
  result[role]=Buffer.concat(chunks);
 }
 return result;
}

function measured(kind,role,bytes){return {algorithm:registry[kind].name,role,status:'measured',digest:crcHex(kind,bytes),bytes:bytes.length};}
function unavailable(kind,role){return {algorithm:registry[kind].name,role,status:'unavailable',reason:'CHECKER_RANGES_REQUIRED'};}
function measureCrcLayers({code,headers,exports:exportStream=Buffer.alloc(0),checkers={}}){
 requireBytes(code);requireBytes(headers);requireBytes(exportStream);
 const params=parameterBytes(),pageManifest=codePageManifest(code);
 return {version:'CRC-LAYERS-V1',
  ecma182:measured('ecma182','normalized-code',code),
  nvme:checkers.nvme?measured('nvme','ecma-checker-and-table',Buffer.concat([checkers.nvme,tableBytes('ecma182')])):{...measured('nvme','ecma-lookup-table',tableBytes('ecma182')),status:'partial',reason:'CHECKER_RANGES_REQUIRED'},
  jones:checkers.jones?measured('jones','integrity-routine-code',checkers.jones):unavailable('jones','integrity-routine-code'),
  xz:measured('xz','header-ranges-and-export',Buffer.concat([headers,exportStream])),
  we:measured('we','crc-tables-parameters-and-baseline',Buffer.concat([allTableBytes(),params,Buffer.from(crypto.createHash('sha512').update(code).digest('hex'),'ascii')])),
  iso:checkers.iso?measured('iso','auxiliary-checker-code',checkers.iso):unavailable('iso','auxiliary-checker-code'),
  crc32c:{algorithm:'CRC-32/ISCSI',role:'rva-aligned-code-pages',status:'measured',digest:crypto.createHash('sha512').update(pageManifest).digest('hex'),digestAlgorithm:'SHA-512-PAGE-MANIFEST',pageSize:4096,pages:pageManifest.readUInt32LE(PAGE_PREFIX.length+4),bytes:pageManifest.length},
  crc16_arc:measured('crc16_arc','crc-parameters',params),
  crc8_smbus:measured('crc8_smbus','layout-state',layoutState(code.length,headers.length,exportStream.length))
 };
}
module.exports={registry,CrcStream,crcHex,tableBytes,allTableBytes,parameterBytes,codePageManifest,layoutState,headerMetadata,measureCrcLayers,checkerPlan,checkerStreams};
