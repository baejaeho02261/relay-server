'use strict';
// Offline tool. Does not execute EXEs, manufacture PASS, contact the server, or
// upload a private key. Generates exact-file release manifests only.
const fs=require('node:fs'),crypto=require('node:crypto');
const p=require("../../services/artifacts/peace.desktop-release-provenance");
function Read(file,max=65536) {
 try{return require("../../services/artifacts/peace.bounded-artifact-read").Read(file,max);}
 catch(error){if(error.message==='AUDIT_FILE_CHANGED')throw Error('PROVENANCE_FILE_CHANGED');if(/^AUDIT_FILE_/.test(error.message))throw Error('PROVENANCE_INPUT_INVALID');throw error;}
}
function Json(file) {const bytes=Read(file),bom=bytes.length>=3&&bytes[0]===239&&bytes[1]===187&&bytes[2]===191;return require("../../services/protocol/peace.strict-json").Parse(bom?bytes.subarray(3):bytes,{maxBytes:65536});}
function FileHash(file,max,allowEmpty=false) {
  const fd=fs.openSync(file,'r'),buffer=Buffer.alloc(65536);try{
    const before=fs.fstatSync(fd);if(!before.isFile()||before.size<(allowEmpty===true?0:1)||before.size>max)throw Error('PROVENANCE_INPUT_INVALID');
    const hash=crypto.createHash('sha512');let total=0,n;
    while((n=fs.readSync(fd,buffer,0,buffer.length,null))!==0){total+=n;if(total>max||total>before.size)throw Error('PROVENANCE_FILE_CHANGED');hash.update(buffer.subarray(0,n));}
    const after=fs.fstatSync(fd);if(total!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw Error('PROVENANCE_FILE_CHANGED');return hash.digest('hex');
  }finally{buffer.fill(0);fs.closeSync(fd);}
}
function MakeManifest(specFile,aFile,bFile,oFile,sourceFile,policyFile) {
  const spec=Json(specFile);
  if(!spec||Object.keys(spec).sort().join(',')!=='handoffVersion,hashVersion,protocol,releaseName,securityVersion,toolchain,version')throw Error('PROVENANCE_SPEC_INVALID');
  const manifest=p.ValidateManifest({...spec,artifacts:{A:FileHash(aFile,64*1024*1024),B:FileHash(bFile,64*1024*1024),O:FileHash(oFile,64*1024*1024)},sourceManifestSha512:FileHash(sourceFile,8*1024*1024),policySha512:p.PolicyDigest(Json(policyFile))});
  return{manifestId:p.ManifestId(manifest),manifest};
}
function LoadManifest(file) {
  const r=Json(file);if(!r||Object.keys(r).sort().join(',')!=='manifest,manifestId'||r.manifestId!==p.ManifestId(r.manifest))throw Error('PROVENANCE_MANIFEST_INVALID');return r;
}
function Write(file,value) {const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
if(require.main===module){try{
  const args=process.argv.slice(2),outIndex=args.indexOf('--out');let out;if(outIndex>=0){if(outIndex!==args.length-2)throw Error('PROVENANCE_ARGUMENT_INVALID');out=args.pop();args.pop();}
  let result;if(args[0]==='manifest'&&args.length===7)result=MakeManifest(...args.slice(1));
  else throw Error('Usage: peace.release-provenance.js manifest SPEC A.exe B.exe O.exe SOURCE_MANIFEST POLICY [--out NEW_FILE]');
  if(out){Write(out,result);process.stdout.write('PROVENANCE_OUTPUT_WRITTEN\n');}else process.stdout.write(JSON.stringify(result,null,2)+'\n');
}catch(e){console.error(e.message?.startsWith('Usage:')?e.message:'PROVENANCE_FAILED: check input, final artifact hashes, output path. No private key data was logged.');process.exitCode=1;}}
module.exports={MakeManifest,LoadManifest,FileHash,Write};
