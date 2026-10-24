'use strict';
const fs=require('node:fs');
// Allocate at most the original file size + one sentinel byte. Every read has an
// explicit offset. A growing file never turns readFileSync into unbounded work.
function Read(file,max=64*1024*1024){
 if(!Number.isSafeInteger(max)||max<1||max>64*1024*1024)throw Error('AUDIT_FILE_LIMIT_INVALID');
 const named=fs.lstatSync(file);if(!named.isFile()||named.isSymbolicLink()||named.nlink!==1||named.size<1||named.size>max)throw Error('AUDIT_FILE_INVALID');
 const fd=fs.openSync(file,'r');let bytes;
 const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;
 try{
  const before=fs.fstatSync(fd);if(!before.isFile()||before.nlink!==1||!same(named,before)||before.size<1||before.size>max)throw Error('AUDIT_FILE_CHANGED');
  bytes=Buffer.alloc(before.size+1);let total=0;
  while(total<bytes.length){const n=fs.readSync(fd,bytes,total,Math.min(1024*1024,bytes.length-total),total);if(!n)break;total+=n;}
  const after=fs.fstatSync(fd),current=fs.lstatSync(file);
  if(total!==before.size||!same(before,after)||!same(after,current)||!current.isFile()||current.isSymbolicLink()||after.nlink!==1||current.nlink!==1)throw Error('AUDIT_FILE_CHANGED');
  return bytes.subarray(0,total);
 }catch(error){bytes?.fill(0);throw error;}finally{fs.closeSync(fd);}
}
module.exports={Read};
