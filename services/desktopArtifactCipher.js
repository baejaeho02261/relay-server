'use strict';
// Server-only authenticated storage. Wire payloads, release signatures and
// artifact hashes continue to describe the original approved PE bytes.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const MAGIC=Buffer.from('GACGCM01','ascii'),HEADER_SIZE=96,CHUNK_SIZE=262144,TAG_SIZE=16;
const DOMAIN='GAME-ARTIFACT-AT-REST-V1';
function Invalid(){throw Error('ARTIFACT_STORAGE_INVALID');}
function Parameters(id,size,digest,plugin){
 if(typeof id!=='string'||!/^(?:(?:DA|OP)-)?[A-F0-9]{24}$/.test(id)||typeof plugin!=='boolean'||!Number.isSafeInteger(size)||size<1||size>(plugin?16:64)*1024*1024||typeof digest!=='string'||!/^[a-f0-9]{64}$/.test(digest))Invalid();
}
function SameFile(a,b){return a.isFile()&&b.isFile()&&!a.isSymbolicLink()&&!b.isSymbolicLink()&&a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;}
function Directory(file){const stat=fs.lstatSync(path.dirname(file));if(!stat.isDirectory()||stat.isSymbolicLink())Invalid();}
function Open(file){
 Directory(file);
 const before=fs.lstatSync(file);if(!before.isFile()||before.isSymbolicLink())Invalid();
 const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
 try{const stat=fs.fstatSync(fd);if(!SameFile(before,stat))Invalid();return {fd,stat};}catch(error){fs.closeSync(fd);throw error;}
}
function ReadExact(fd,out,position){let done=0;while(done<out.length){const count=fs.readSync(fd,out,done,out.length-done,position+done);if(!count)Invalid();done+=count;}}
function SyncDirectory(file){if(process.platform==='win32')return;const fd=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function Key(secret,id,plugin,header){
 if(typeof secret!=='string'||!/^[a-f0-9]{64}$/.test(secret))Invalid();
 const material=Buffer.from(secret,'hex');
 try{return Buffer.from(crypto.hkdfSync('sha256',material,header.subarray(16,48),Buffer.from(DOMAIN+'\n'+id+'\n'+(plugin?'O':'AB'),'ascii'),32));}finally{material.fill(0);}
}
function Aad(id,plugin,header,index,length){
 const record=Buffer.alloc(8);record.writeUInt32LE(index,0);record.writeUInt32LE(length,4);
 return Buffer.concat([Buffer.from(DOMAIN+'\n'+id+'\n'+(plugin?'O':'AB')+'\n','ascii'),header,record]);
}
function Nonce(header,index){const nonce=Buffer.alloc(12);header.copy(nonce,0,48,56);nonce.writeUInt32BE(index,8);return nonce;}
function Header(size,digest,plugin){
 const header=Buffer.alloc(HEADER_SIZE);MAGIC.copy(header);header.writeUInt32LE(CHUNK_SIZE,8);header.writeUInt32LE(size,12);
 crypto.randomFillSync(header,16,40);Buffer.from(digest,'hex').copy(header,56);header[88]=plugin?1:0;return header;
}
function CheckHeader(header,size,digest,plugin,physicalSize){
 if(!header.subarray(0,8).equals(MAGIC)||header.readUInt32LE(8)!==CHUNK_SIZE||header.readUInt32LE(12)!==size||header.subarray(56,88).toString('hex')!==digest||header[88]!==Number(plugin)||header.subarray(89).some(value=>value!==0)||physicalSize!==HEADER_SIZE+size+Math.ceil(size/CHUNK_SIZE)*TAG_SIZE)Invalid();
}
function Publish(file,id,bytes,secret,plugin=false,previous){
 Directory(file);
 if(!Buffer.isBuffer(bytes))Invalid();const digest=crypto.createHash('sha256').update(bytes).digest('hex');Parameters(id,bytes.length,digest,plugin);
 const header=Header(bytes.length,digest,plugin),key=Key(secret,id,plugin,header),temporary=file+'.'+crypto.randomBytes(12).toString('hex')+'.tmp';let fd;
 try{
  fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,header);
  for(let offset=0,index=0;offset<bytes.length;offset+=CHUNK_SIZE,index++){
   const plain=bytes.subarray(offset,Math.min(offset+CHUNK_SIZE,bytes.length)),cipher=crypto.createCipheriv('aes-256-gcm',key,Nonce(header,index),{authTagLength:TAG_SIZE});
   cipher.setAAD(Aad(id,plugin,header,index,plain.length));
   const encrypted=cipher.update(plain),end=cipher.final();
   try{fs.writeFileSync(fd,encrypted);if(end.length)fs.writeFileSync(fd,end);fs.writeFileSync(fd,cipher.getAuthTag());}finally{encrypted.fill(0);end.fill(0);}
  }
  fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  if(previous){if(!SameFile(previous,fs.lstatSync(file)))Invalid();fs.renameSync(temporary,file);}
  else {fs.linkSync(temporary,file);fs.unlinkSync(temporary);}
  SyncDirectory(file);
 }finally{key.fill(0);if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(temporary);}catch(_){} }
}
function DecryptRecord(fd,id,plugin,header,key,index,size){
 const length=Math.min(CHUNK_SIZE,size-index*CHUNK_SIZE),encrypted=Buffer.alloc(length+TAG_SIZE);let clear,end;
 try{
  ReadExact(fd,encrypted,HEADER_SIZE+index*(CHUNK_SIZE+TAG_SIZE));
  const cipher=crypto.createDecipheriv('aes-256-gcm',key,Nonce(header,index),{authTagLength:TAG_SIZE});
  cipher.setAAD(Aad(id,plugin,header,index,length));cipher.setAuthTag(encrypted.subarray(length));
  clear=cipher.update(encrypted.subarray(0,length));end=cipher.final();
  if(clear.length!==length||end.length)Invalid();const result=clear;clear=undefined;return result;
 }finally{encrypted.fill(0);clear?.fill(0);end?.fill(0);}
}
function Read(file,id,size,digest,secret,plugin,offset,length,whole){
 Parameters(id,size,digest,plugin);
 if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<1||offset+length>size||!whole&&length>CHUNK_SIZE)Invalid();
 const opened=Open(file);let fd=opened.fd,key,result,legacy;
 try{
  // Bound physical allocation before reading any attacker-controlled bytes.
  const sealedSize=HEADER_SIZE+size+Math.ceil(size/CHUNK_SIZE)*TAG_SIZE;
  if(opened.stat.size!==size&&opened.stat.size!==sealedSize)Invalid();
  const prefix=Buffer.alloc(Math.min(HEADER_SIZE,opened.stat.size));ReadExact(fd,prefix,0);
  if(prefix.length>=8&&prefix.subarray(0,8).equals(MAGIC)){
   if(prefix.length!==HEADER_SIZE)Invalid();CheckHeader(prefix,size,digest,plugin,opened.stat.size);key=Key(secret,id,plugin,prefix);result=Buffer.alloc(length);
   const first=Math.floor(offset/CHUNK_SIZE),last=Math.floor((offset+length-1)/CHUNK_SIZE);
   for(let index=first;index<=last;index++){
    const clear=DecryptRecord(fd,id,plugin,prefix,key,index,size);
    try{const start=Math.max(offset,index*CHUNK_SIZE),end=Math.min(offset+length,(index+1)*CHUNK_SIZE);clear.copy(result,start-offset,start-index*CHUNK_SIZE,end-index*CHUNK_SIZE);}finally{clear.fill(0);}
   }
   if(!SameFile(opened.stat,fs.fstatSync(fd)))Invalid();
   if(whole&&crypto.createHash('sha256').update(result).digest('hex')!==digest)Invalid();
  }else{
   // Legacy files are never trusted by size alone. Verify the full approved
   // hash before returning a byte, then replace only that unchanged inode.
   if(opened.stat.size!==size)Invalid();legacy=Buffer.alloc(size);ReadExact(fd,legacy,0);
   if(crypto.createHash('sha256').update(legacy).digest('hex')!==digest||!SameFile(opened.stat,fs.fstatSync(fd)))Invalid();
   fs.closeSync(fd);fd=undefined;Publish(file,id,legacy,secret,plugin,opened.stat);
   if(whole){result=legacy;legacy=undefined;}else result=Buffer.from(legacy.subarray(offset,offset+length));
  }
  if(fd!==undefined){const closing=fd;fd=undefined;fs.closeSync(closing);}
  const output=result;result=undefined;return output;
 }finally{key?.fill(0);legacy?.fill(0);result?.fill(0);if(fd!==undefined)fs.closeSync(fd);}
}
function ReadBytes(file,id,size,digest,secret,plugin=false){return Read(file,id,size,digest,secret,plugin,0,size,true);}
function ReadChunk(file,id,size,digest,offset,length,secret,plugin=false){return Read(file,id,size,digest,secret,plugin,offset,length,false);}
module.exports={Publish,ReadBytes,ReadChunk};
