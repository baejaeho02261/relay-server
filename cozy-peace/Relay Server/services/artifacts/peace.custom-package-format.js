'use strict';
// cozy.Client's own archive framing. This is an encrypted DATA container, not
// a PE loader, executable virtualizer, signing service, or authorization grant.
const crypto=require('node:crypto'),zlib=require('node:zlib');
const MAGIC=Buffer.from('GCPK0001'),HEADER=96,TAG=16,MAX=224*1024*1024,MAX_FILES=4096;
const sha=b=>crypto.createHash('sha512').update(b).digest();
function fail(code){const e=Error(code);e.desktopError=true;e.status=400;throw e;}
function keyValid(k){if(!Buffer.isBuffer(k)||k.length!==32)fail('CUSTOM_PACKAGE_KEY_INVALID');}
function nameValid(s){return typeof s==='string'&&s.length<=1024&&/^[A-Za-z0-9_. /()-]+$/.test(s)&&!s.startsWith('/')&&!s.includes('\\')&&!s.includes(':')&&s.split('/').every(x=>x&&x!=='.'&&x!=='..'&&!/[. ]$/.test(x)&&!/^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(x));}
function Archive(files,metadata={}){
 if(!Array.isArray(files)||!files.length||files.length>MAX_FILES)fail('CUSTOM_PACKAGE_COUNT_INVALID');
 const meta=Buffer.from(JSON.stringify(metadata));if(meta.length>16384)fail('CUSTOM_PACKAGE_METADATA_INVALID');
 const pieces=[],seen=new Set();let total=4+meta.length;const m=Buffer.alloc(4);m.writeUInt32LE(meta.length);pieces.push(m,meta);
 for(const f of files){
  if(!f||!nameValid(f.name)||!Buffer.isBuffer(f.bytes)||f.bytes.length>64*1024*1024||seen.has(f.name.toLowerCase()))fail('CUSTOM_PACKAGE_ENTRY_INVALID');seen.add(f.name.toLowerCase());
  const name=Buffer.from(f.name),head=Buffer.alloc(70);head.writeUInt16LE(name.length);head.writeUInt32LE(f.bytes.length,2);sha(f.bytes).copy(head,6);
  total+=head.length+name.length+f.bytes.length;if(total>MAX)fail('CUSTOM_PACKAGE_SIZE_LIMIT');pieces.push(head,name,f.bytes);
 }
 return Buffer.concat(pieces,total);
}
function Seal(files,key,metadata={}){
 keyValid(key);let raw,compressed,derived;
 try{
  raw=Archive(files,metadata);compressed=zlib.deflateRawSync(raw,{level:6});
  if(compressed.length>MAX)fail('CUSTOM_PACKAGE_SIZE_LIMIT');
  const h=Buffer.alloc(HEADER);MAGIC.copy(h);h.writeUInt16LE(1,8);h.writeUInt16LE(1,10);h.writeUInt32LE(files.length,12);h.writeBigUInt64LE(BigInt(raw.length),16);h.writeBigUInt64LE(BigInt(compressed.length),24);
  crypto.randomBytes(32).copy(h,32);crypto.randomBytes(12).copy(h,64);sha(key).copy(h,80,0,16);
  derived=Buffer.from(crypto.hkdfSync('sha512',key,h.subarray(32,64),Buffer.from('GAME-CUSTOM-PACKAGE-V1'),32));
  const c=crypto.createCipheriv('aes-256-gcm',derived,h.subarray(64,76),{authTagLength:TAG});c.setAAD(h);
  return Buffer.concat([h,c.update(compressed),c.final(),c.getAuthTag()]);
 }finally{raw?.fill(0);compressed?.fill(0);derived?.fill(0);}
}
function Open(box,key){
 keyValid(key);let derived,compressed,raw;
 try{
  if(!Buffer.isBuffer(box)||box.length<HEADER+TAG||box.length>MAX+HEADER+TAG)fail('CUSTOM_PACKAGE_FORMAT_INVALID');
  const h=box.subarray(0,HEADER),count=h.readUInt32LE(12),rawN=h.readBigUInt64LE(16),n=h.readBigUInt64LE(24);
  if(!h.subarray(0,8).equals(MAGIC)||h.readUInt16LE(8)!==1||h.readUInt16LE(10)!==1||h.readUInt32LE(76)!==0||!count||count>MAX_FILES||rawN<4n||rawN>BigInt(MAX)||n>BigInt(MAX)||BigInt(box.length)!==BigInt(HEADER+TAG)+n)fail('CUSTOM_PACKAGE_FORMAT_INVALID');
  if(!crypto.timingSafeEqual(h.subarray(80,96),sha(key).subarray(0,16)))fail('CUSTOM_PACKAGE_KEY_MISMATCH');
  derived=Buffer.from(crypto.hkdfSync('sha512',key,h.subarray(32,64),Buffer.from('GAME-CUSTOM-PACKAGE-V1'),32));
  const d=crypto.createDecipheriv('aes-256-gcm',derived,h.subarray(64,76),{authTagLength:TAG});d.setAAD(h);d.setAuthTag(box.subarray(box.length-TAG));
  let first;try{first=d.update(box.subarray(HEADER,box.length-TAG));compressed=Buffer.concat([first,d.final()]);}catch(_){fail('CUSTOM_PACKAGE_AUTHENTICATION_FAILED');}finally{first?.fill(0);}
  // No decompression or entry parsing happens before the authentication tag.
  const inflated=zlib.inflateRawSync(compressed,{maxOutputLength:Number(rawN),info:true});raw=inflated.buffer;
  if(raw.length!==Number(rawN)||inflated.engine.bytesWritten!==compressed.length)fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');
  const metadataLength=raw.readUInt32LE(0);if(metadataLength>16384||metadataLength+4>raw.length)fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');
  const decode=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
  const metadata=JSON.parse(decode(raw.subarray(4,4+metadataLength)));let at=4+metadataLength;const seen=new Set(),files=[];
  try{
   for(let i=0;i<count;i++){
    if(at+70>raw.length)fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');const namelen=raw.readUInt16LE(at),size=raw.readUInt32LE(at+2),hash=raw.subarray(at+6,at+70);at+=70;
    if(namelen>1024||size>64*1024*1024||at+namelen+size>raw.length)fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');const name=decode(raw.subarray(at,at+namelen));at+=namelen;
    if(!nameValid(name)||seen.has(name.toLowerCase()))fail('CUSTOM_PACKAGE_ENTRY_INVALID');seen.add(name.toLowerCase());const bytes=Buffer.from(raw.subarray(at,at+size));at+=size;
    if(!crypto.timingSafeEqual(hash,sha(bytes))){bytes.fill(0);fail('CUSTOM_PACKAGE_DIGEST_INVALID');}files.push({name,bytes,sha512:hash.toString('hex')});
   }
   if(at!==raw.length)fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');return {files,metadata};
  }catch(e){for(const f of files)f.bytes.fill(0);throw e;}
 }catch(e){if(e.desktopError)throw e;fail('CUSTOM_PACKAGE_ARCHIVE_INVALID');}
 finally{derived?.fill(0);compressed?.fill(0);raw?.fill(0);}
}
module.exports={Seal,Open,Archive,nameValid,MAX,MAX_FILES,HEADER};
