'use strict';
// Storage primitives for server-owned state. Callers must hold the single-writer
// lock. These functions do not claim cross-host fencing or Windows directory fsync.
const fs=require('node:fs'), path=require('node:path'), crypto=require('node:crypto');
function SyncDirectory(directory){
  if(process.platform==='win32')return;
  const fd=fs.openSync(directory,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function ReadRegular(file,maxBytes=64*1024*1024){
  const before=fs.lstatSync(file);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.size>maxBytes)throw Error('SERVER_STORAGE_PATH_INVALID');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  try{
    const st=fs.fstatSync(fd);
    if(st.dev!==before.dev||st.ino!==before.ino||st.size!==before.size||!st.isFile())throw Error('SERVER_STORAGE_CHANGED');
    const bytes=Buffer.alloc(st.size);let offset=0;
    while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(n<=0)throw Error('SERVER_STORAGE_SHORT_READ');offset+=n;}
    const end=fs.fstatSync(fd);
    if(end.size!==st.size||end.mtimeMs!==st.mtimeMs||end.ctimeMs!==st.ctimeMs)throw Error('SERVER_STORAGE_CHANGED');
    return bytes;
  }finally{fs.closeSync(fd);}
}
function Atomic(file,bytes,{createOnly=false}={}){
  const temporary=file+'.'+crypto.randomBytes(16).toString('hex')+'.tmp';let fd,published=false;
  try{
    fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    if(createOnly){fs.linkSync(temporary,file);published=true;fs.unlinkSync(temporary);}else{fs.renameSync(temporary,file);published=true;}
    SyncDirectory(path.dirname(file));
  }catch(error){error.published=published;throw error;}
  finally{if(fd!==undefined)try{fs.closeSync(fd);}catch(_){}try{fs.unlinkSync(temporary);}catch(_){} }
}
function SecretEqual(a,b){if(typeof a!=='string'||typeof b!=='string')return false;const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);}
module.exports={ReadRegular,Atomic,SyncDirectory,SecretEqual};
