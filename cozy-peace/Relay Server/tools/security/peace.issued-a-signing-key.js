#!/usr/bin/env node
'use strict';
// Private material is written only to an explicitly named external file. It is
// never printed. Public JSON and a Pascal include contain verification data.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const signing=require('../../services/bootstrap/peace.issued-a-signing');
function Fail(code){throw Error(code);}
function PublicJSON(identity){return {version:1,algorithm:'RSA2048-PKCS1-SHA256',keyId:identity.keyId,publicBlob:identity.blob.toString('base64')};}
function ParsePublic(value){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='algorithm,keyId,publicBlob,version'||value.version!==1||value.algorithm!=='RSA2048-PKCS1-SHA256'||typeof value.publicBlob!=='string'||value.publicBlob.length!==380)Fail('ISSUED_A_PUBLIC_JSON_INVALID');
 const blob=Buffer.from(value.publicBlob,'base64');if(blob.toString('base64')!==value.publicBlob)Fail('ISSUED_A_PUBLIC_JSON_INVALID');const identity=signing.IdentityFromBlob(blob);if(identity.keyId!==value.keyId)Fail('ISSUED_A_PUBLIC_JSON_INVALID');return identity;
}
function Include(identity){
 const bytes=signing.AnchorBytes(identity.publicKey),lines=[];for(let i=0;i<bytes.length;i+=12)lines.push('  '+Array.from(bytes.subarray(i,i+12),v=>'$'+v.toString(16).toUpperCase().padStart(2,'0')).join(', ')+(i+12<bytes.length?',':''));
 return '\uFEFF'+['{ Public verification anchor only. Never put a private key in this file. }','{ Key ID: '+identity.keyId+' }','{$J-}','const','  CozyIssuedATrustAnchor: array[0..330] of Byte = (',...lines,'  );',''].join('\r\n');
}
function ValidateOutput(file){
 if(!file||!path.isAbsolute(file)||fs.existsSync(file))Fail('ISSUED_A_OUTPUT_NEW_ABSOLUTE_PATH_REQUIRED');
 let parent=path.dirname(file);while(!fs.existsSync(parent)){const next=path.dirname(parent);if(next===parent)Fail('ISSUED_A_OUTPUT_INVALID');parent=next;}
 if(!fs.lstatSync(parent).isDirectory()||fs.realpathSync(parent)!==path.resolve(parent))Fail('ISSUED_A_OUTPUT_SYMLINK_DENIED');
}
function RestrictDirectory(directory){
 const who=require('node:child_process').spawnSync('whoami',[],{encoding:'utf8',timeout:10000,windowsHide:true,maxBuffer:4096}),user=who.stdout?.trim();
 if(who.status!==0||!user||/[\r\n]/.test(user))Fail('ISSUED_A_PRIVATE_ACL_REQUIRED');
 const acl=require('node:child_process').spawnSync('icacls',[directory,'/inheritance:r','/grant:r',user+':(OI)(CI)F'],{encoding:'utf8',timeout:15000,windowsHide:true,maxBuffer:16384});
 if(acl.status!==0)Fail('ISSUED_A_PRIVATE_ACL_REQUIRED');
}
function WritePrivateWindows(file,bytes,created){
 // No private file exists while the new empty directory inherits its parent
 // ACL. Restrict that directory first, so no preexisting reader can retain a
 // handle to the private file across the ACL change.
 const directory=fs.mkdtempSync(path.join(path.dirname(file),'.cozy-issued-key-')),dirIdentity=fs.lstatSync(directory),staged=path.join(directory,'key.pending');let fd,identity;
 try{
  RestrictDirectory(directory);
  const dirNow=fs.lstatSync(directory);if(!dirNow.isDirectory()||dirNow.isSymbolicLink()||dirNow.dev!==dirIdentity.dev||dirNow.ino!==dirIdentity.ino)Fail('ISSUED_A_PRIVATE_ACL_REQUIRED');
  fd=fs.openSync(staged,'wx',0o600);identity=fs.fstatSync(fd);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  ValidateOutput(file);if(fs.realpathSync(path.dirname(file))!==path.resolve(path.dirname(file)))Fail('ISSUED_A_OUTPUT_SYMLINK_DENIED');
  // A hard link is create-only and retains the staged file's restricted DACL.
  // Unsupported filesystems fail closed instead of copying with inherited ACL.
  fs.linkSync(staged,file);created.push({file,dev:identity.dev,ino:identity.ino});
  const published=fs.lstatSync(file);if(!published.isFile()||published.isSymbolicLink()||published.dev!==identity.dev||published.ino!==identity.ino)Fail('ISSUED_A_PRIVATE_PUBLISH_FAILED');
 }finally{
  if(fd!==undefined)fs.closeSync(fd);
  if(identity)try{const st=fs.lstatSync(staged);if(st.isFile()&&!st.isSymbolicLink()&&st.dev===identity.dev&&st.ino===identity.ino)fs.unlinkSync(staged);}catch(_){}
  try{const st=fs.lstatSync(directory);if(st.isDirectory()&&!st.isSymbolicLink()&&st.dev===dirIdentity.dev&&st.ino===dirIdentity.ino)fs.rmdirSync(directory);}catch(_){}
 }
}
function WriteNew(file,bytes,mode=0o644,created=[]){
 ValidateOutput(file);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});if(fs.realpathSync(path.dirname(file))!==path.resolve(path.dirname(file)))Fail('ISSUED_A_OUTPUT_SYMLINK_DENIED');
 if(mode===0o600&&process.platform==='win32')return WritePrivateWindows(file,bytes,created);
 const fd=fs.openSync(file,'wx',mode);try{const st=fs.fstatSync(fd);created.push({file,dev:st.dev,ino:st.ino});fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function ReadPrivate(file){if(!path.isAbsolute(file))Fail('ISSUED_A_PRIVATE_PATH_REQUIRED');const bytes=require('../../services/artifacts/peace.bounded-artifact-read').Read(file,8192);try{return crypto.createPrivateKey(bytes);}finally{bytes.fill(0);}}
function ExternalPrivate(file){
 const relay=path.resolve(__dirname,'../..'),parent=path.dirname(relay),source=path.basename(parent).toLowerCase()==='cozy-peace'?path.dirname(parent):relay;
 const normalize=x=>process.platform==='win32'?x.toLowerCase():x,resolved=normalize(path.resolve(file)),root=normalize(source);if(!path.isAbsolute(file)||resolved===root||resolved.startsWith(root+path.sep))Fail('ISSUED_A_PRIVATE_KEY_OUTSIDE_SOURCE_REQUIRED');
}
function Cleanup(created){for(const row of created.reverse()){try{const st=fs.lstatSync(row.file);if(st.isFile()&&!st.isSymbolicLink()&&st.dev===row.dev&&st.ino===row.ino)fs.unlinkSync(row.file);}catch(_){}}}
function main(args){
 const options={};for(let i=0;i<args.length;i+=2){if(!/^--[a-z-]+$/.test(args[i]||'')||args[i+1]===undefined||Object.hasOwn(options,args[i]))Fail('ISSUED_A_KEY_USAGE');options[args[i]]=args[i+1];}
 if(Object.keys(options).some(k=>!['--action','--private-key-file','--public-json-file','--public-json-out','--include-out'].includes(k)))Fail('ISSUED_A_KEY_USAGE');
 const action=options['--action'];if(!['generate','export','include'].includes(action))Fail('ISSUED_A_KEY_USAGE');
 if(!options['--public-json-out']&&!options['--include-out'])Fail('ISSUED_A_KEY_OUTPUT_REQUIRED');
 if(action==='include'&&options['--private-key-file']||action!=='include'&&options['--public-json-file'])Fail('ISSUED_A_KEY_USAGE');
 const outputs=[options['--public-json-out'],options['--include-out'],...(action==='generate'?[options['--private-key-file']]:[])].filter(Boolean);
 if(new Set(outputs.map(x=>path.resolve(x))).size!==outputs.length)Fail('ISSUED_A_DUPLICATE_OUTPUT');
 for(const file of outputs)ValidateOutput(file);
 if(action==='generate')ExternalPrivate(options['--private-key-file']||'');
 const created=[];let identity;
 try{
 if(action==='generate'){
  const file=options['--private-key-file'];ExternalPrivate(file||'');
  const pair=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});identity=signing.PublicIdentity(pair.publicKey);const pem=pair.privateKey.export({type:'pkcs8',format:'pem'});
  WriteNew(file,pem,0o600,created);

 }else if(options['--action']==='export'){
  ExternalPrivate(options['--private-key-file']||'');const privateKey=ReadPrivate(options['--private-key-file']||'');identity=signing.PublicIdentity(crypto.createPublicKey(privateKey));
 }else if(options['--action']==='include'){
  const file=options['--public-json-file'];if(!file||!path.isAbsolute(file))Fail('ISSUED_A_PUBLIC_JSON_PATH_REQUIRED');const bytes=require('../../services/artifacts/peace.bounded-artifact-read').Read(file,4096);try{identity=ParsePublic(JSON.parse(bytes.toString('utf8')));}finally{bytes.fill(0);}
 }else Fail('ISSUED_A_KEY_USAGE');
 if(options['--public-json-out'])WriteNew(options['--public-json-out'],JSON.stringify(PublicJSON(identity),null,2)+'\n',0o644,created);
 if(options['--include-out'])WriteNew(options['--include-out'],Include(identity),0o644,created);
 return {ok:true,keyId:identity.keyId,publicJsonWritten:!!options['--public-json-out'],publicIncludeWritten:!!options['--include-out'],privateKeyPrinted:false};
 }catch(error){Cleanup(created);throw error;}
}
if(require.main===module){try{process.stdout.write(JSON.stringify(main(process.argv.slice(2)))+'\n');}catch(error){process.stderr.write(String(error.message&&/^[A-Z0-9_]+$/.test(error.message)?error.message:'ISSUED_A_KEY_OPERATION_FAILED')+'\n');process.exitCode=1;}}
module.exports={PublicJSON,ParsePublic,Include,main};
