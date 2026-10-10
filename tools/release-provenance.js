'use strict';
// Offline tool. Does not execute EXEs, manufacture PASS, contact the server, or
// upload a private key. Use a dedicated CI key, distinct from release approval.
const fs=require('node:fs'),crypto=require('node:crypto');
const p=require('../services/desktopReleaseProvenance');
function Read(file,max=65536) {
  const fd=fs.openSync(file,'r');try{
    const before=fs.fstatSync(fd);if(!before.isFile()||before.size<1||before.size>max)throw Error('PROVENANCE_INPUT_INVALID');
    const data=fs.readFileSync(fd),after=fs.fstatSync(fd);
    if(data.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw Error('PROVENANCE_FILE_CHANGED');
    return data;
  }finally{fs.closeSync(fd);}
}
function Json(file) {return JSON.parse(Read(file).toString('utf8').replace(/^\uFEFF/,''));}
function FileHash(file,max) {
  const fd=fs.openSync(file,'r'),buffer=Buffer.alloc(65536);try{
    const before=fs.fstatSync(fd);if(!before.isFile()||before.size<1||before.size>max)throw Error('PROVENANCE_INPUT_INVALID');
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
function PrivateKey(file) {const bytes=Read(file,16384);let key;try{key=crypto.createPrivateKey(bytes);}finally{bytes.fill(0);}if(key.asymmetricKeyType!=='ed25519')throw Error('CI_ED25519_KEY_REQUIRED');return key;}
function Sign(manifestFile,reportFile,keyFile,runId) {
  const r=LoadManifest(manifestFile),report=Json(reportFile),m=r.manifest;
  if(!report||report.version!==1||['A','B','O'].some(k=>report[k.toLowerCase()+'Sha512']!==m.artifacts[k])||report.sourceManifestSha512!==m.sourceManifestSha512)throw Error('CI_REPORT_MANIFEST_MISMATCH');
  const statement=p.ValidateStatement({version:1,purpose:p.CI_DOMAIN,manifestId:r.manifestId,runId,issuedAt:Date.now(),nativeBuild:report.nativeBuild,apiProbe:report.apiProbe,integration:report.integration,logsSha512:report.logsSha512});
  const key=PrivateKey(keyFile),publicKey=crypto.createPublicKey(key);
  return p.ValidateEnvelope({keyId:p.KeyId(publicKey),statement,signature:crypto.sign(null,Buffer.from(p.Canonical(statement)),key).toString('base64')});
}
function Verify(manifestFile,envelopeFile,publicKeyFile) {
  const manifest=LoadManifest(manifestFile),e=p.ValidateEnvelope(Json(envelopeFile)),key=p.PublicKey(Read(publicKeyFile,2048).toString('utf8'));
  if(e.statement.manifestId!==manifest.manifestId||e.keyId!==p.KeyId(key)||!crypto.verify(null,Buffer.from(p.Canonical(e.statement)),key,Buffer.from(e.signature,'base64')))throw Error('CI_SIGNATURE_INVALID');
  return{signatureVerified:true,manifestId:manifest.manifestId,keyId:e.keyId,serverTrustChecked:false,hardwareAttested:false,...Object.fromEntries(['nativeBuild','apiProbe','integration'].map(k=>[k,e.statement[k]]))};
}
function PublicRecord(keyFile,notBefore,notAfter) {
  const publicKey=crypto.createPublicKey(PrivateKey(keyFile));const k=p.ValidateKey({keyId:p.KeyId(publicKey),publicKey:publicKey.export({type:'spki',format:'pem'}).toString(),purpose:p.CI_DOMAIN,state:'ACTIVE',notBefore:Number(notBefore),notAfter:Number(notAfter),changedAt:Date.now(),changedBy:'OFFLINE_CI_PROVISIONING'});
  return{keyId:k.keyId,publicKey:k.publicKey,state:k.state,notBefore:k.notBefore,notAfter:k.notAfter};
}
function Write(file,value) {const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
if(require.main===module){try{
  const args=process.argv.slice(2),outIndex=args.indexOf('--out');let out;if(outIndex>=0){if(outIndex!==args.length-2)throw Error('PROVENANCE_ARGUMENT_INVALID');out=args.pop();args.pop();}
  let result;if(args[0]==='manifest'&&args.length===7)result=MakeManifest(...args.slice(1));
  else if(args[0]==='sign'&&args.length===5)result=Sign(...args.slice(1));
  else if(args[0]==='verify'&&args.length===4)result=Verify(...args.slice(1));
  else if(args[0]==='public-key'&&args.length===4)result=PublicRecord(...args.slice(1));
  else throw Error('Usage: release-provenance.js manifest SPEC A.exe B.exe O.exe SOURCE_MANIFEST POLICY | sign MANIFEST REPORT CI_KEY RUN_ID | verify MANIFEST ENVELOPE CI_PUBLIC_KEY | public-key CI_KEY NOT_BEFORE_MS NOT_AFTER_MS [--out NEW_FILE]');
  if(out){Write(out,result);process.stdout.write('PROVENANCE_OUTPUT_WRITTEN\n');}else process.stdout.write(JSON.stringify(result,null,2)+'\n');
}catch(e){console.error(e.message?.startsWith('Usage:')?e.message:'PROVENANCE_FAILED: check input, final artifact hashes, dedicated Ed25519 CI key and output path. No private key data was logged.');process.exitCode=1;}}
module.exports={MakeManifest,LoadManifest,FileHash,Sign,Verify,PublicRecord,Write};
