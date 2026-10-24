'use strict';
// Railway Linux secret provisioning. No private key is included in source or logs.
// Directory FDs anchor writes, so replacing an ancestor with a symlink cannot
// redirect a provisioned secret outside the configured private data directory.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const MAX=64*1024,ENCODED_MAX=4*Math.ceil(MAX/3),C=fs.constants;
function fail(code){throw Error('RUNTIME_PEM_'+code);}
function decode(raw,kind){
 if(typeof raw!=='string'||!raw.length||raw.length>ENCODED_MAX||raw.length%4!==0||!/^[A-Za-z0-9+/]*={0,2}$/.test(raw))fail('BASE64_INVALID');
 const bytes=Buffer.from(raw,'base64');
 try{
  if(!bytes.length||bytes.length>MAX||bytes.toString('base64')!==raw)fail('BASE64_INVALID');
  const text=bytes.toString('ascii');
  if(bytes.some(value=>value>127))fail('CONTENT_INVALID');
  if(kind==='KEY'){
   if(!/^-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END \1-----\r?\n?$/.test(text))fail('CONTENT_INVALID');
   crypto.createPrivateKey({key:bytes,format:'pem'});
  }else{
   if(!/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----\r?\n?$/.test(text))fail('CONTENT_INVALID');
   new crypto.X509Certificate(bytes);
  }
  return bytes;
 }catch(error){bytes.fill(0);if(/^RUNTIME_PEM_[A-Z0-9_]+$/.test(error.message))throw error;fail('CONTENT_INVALID');}
}
function target(root,file){
 if(typeof root!=='string'||!path.isAbsolute(root)||typeof file!=='string'||!path.isAbsolute(file)||/[\0\r\n]/.test(root+file)||root.split('/').includes('..')||file.split('/').includes('..'))fail('PATH_INVALID');
 root=path.resolve(root);file=path.resolve(file);
 if(root==='/'||!file.startsWith(root+'/'))fail('PATH_ESCAPE');
 return {root,file,parent:path.dirname(file),name:path.basename(file)};
}
function parentFd(item){
 let fd=fs.openSync('/',C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW),current='';
 try{
  for(const part of item.parent.split('/').filter(Boolean)){
   current+='/'+part;const anchored='/proc/self/fd/'+fd+'/'+part;
   let next;
   try{next=fs.openSync(anchored,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);}
   catch(error){if(error.code!=='ENOENT')throw error;fs.mkdirSync(anchored,{mode:0o700});next=fs.openSync(anchored,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);}
   fs.closeSync(fd);fd=next;
   if(current===item.root||current.startsWith(item.root+'/'))fs.fchmodSync(fd,0o700);
  }
  return fd;
 }catch(error){fs.closeSync(fd);throw error;}
}
function checkExisting(item){
 let fd;
 try{
  try{fd=fs.openSync(item.anchored,C.O_RDONLY|C.O_NOFOLLOW|C.O_NONBLOCK);}catch(error){if(error.code==='ENOENT')return false;throw error;}
  const stat=fs.fstatSync(fd);
  if(!stat.isFile()||stat.nlink!==1||stat.size>MAX)fail('FILE_INVALID');
  if(stat.size!==item.bytes.length)fail('EXISTING_MISMATCH');
  const actual=Buffer.alloc(stat.size);
  try{let offset=0;while(offset<actual.length){const n=fs.readSync(fd,actual,offset,actual.length-offset,offset);if(!n)break;offset+=n;}const after=fs.fstatSync(fd);if(offset!==actual.length||after.size!==stat.size||after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs||!crypto.timingSafeEqual(actual,item.bytes))fail('EXISTING_MISMATCH');}finally{actual.fill(0);}
  fs.fchmodSync(fd,0o600);return true;
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
function writeNew(item){
 const fd=fs.openSync(item.anchored,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600),identity=fs.fstatSync(fd);let complete=false;
 try{fs.writeFileSync(fd,item.bytes);fs.fchmodSync(fd,0o600);fs.fsyncSync(fd);complete=true;}
 finally{
  if(!complete){try{const actual=fs.lstatSync(item.anchored);if(actual.dev===identity.dev&&actual.ino===identity.ino)fs.unlinkSync(item.anchored);}catch(_){}}
  fs.closeSync(fd);
 }
 fs.fsyncSync(item.fd);
}
function provision(env,prefix,rootName){
 const names=['CA','CERT','KEY'].map(kind=>({kind,variable:prefix+'_'+kind+'_PEM_B64',fileVariable:prefix+'_'+kind+'_FILE'}));
 const selected=names.filter(item=>Object.hasOwn(env,item.variable));
 if(!selected.length)return {provisioned:0,existing:0};
 const items=[];
 try{
  if(process.platform!=='linux'||!C.O_NOFOLLOW||!C.O_DIRECTORY)fail('PLATFORM_UNSUPPORTED');
  // Validate every input before creating directories or writing any secret.
  for(const item of selected)items.push({...item,...target(env[rootName],env[item.fileVariable]),bytes:decode(env[item.variable],item.kind)});
  if(new Set(items.map(item=>item.file)).size!==items.length)fail('PATH_DUPLICATE');
  for(const item of items){item.fd=parentFd(item);item.anchored='/proc/self/fd/'+item.fd+'/'+item.name;item.exists=checkExisting(item);}
  let created=0;for(const item of items)if(!item.exists){writeNew(item);created++;}
  return {provisioned:created,existing:items.length-created};
 }catch(error){if(/^RUNTIME_PEM_[A-Z0-9_]+$/.test(error.message))throw error;fail('FILE_UNSAFE');}
 finally{
  for(const item of items){item.bytes.fill(0);if(item.fd!==undefined)fs.closeSync(item.fd);}
  for(const item of names)delete env[item.variable];
 }
}
function ProvisionAuthority(env=process.env){return provision(env,'DESKTOP_RECOVERY_WITNESS','DATA_DIR');}
function ProvisionWitness(env=process.env){return provision(env,'WITNESS','WITNESS_DATA_DIR');}
module.exports={ProvisionAuthority,ProvisionWitness};
