'use strict';
// Private Windows test preparation. This is not a compiler, production signer,
// hardware attestation or receipt-authenticity verifier. Never executes an EXE.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const reader=require('../../services/artifacts/peace.bounded-artifact-read');
const strict=require('../../services/protocol/peace.strict-json');
const receipts=require('../../services/artifacts/peace.desktop-packing-evidence');
const protection=require('../../services/artifacts/peace.cozy-protection-engine');
const provenance=require('../../services/artifacts/peace.desktop-release-provenance');
const ROLE=['A','B','O'],KIND='FINAL_WINDOWS_EXECUTION_INPUTS_V1';
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
function Fail(code){throw Error('CI_FINAL_'+code);}
function Exact(x,keys){if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).sort().join(',')!==keys.slice().sort().join(','))Fail('INPUT_INVALID');}
function Read(file,max){if(!path.isAbsolute(file))Fail('ABSOLUTE_INPUT_REQUIRED');file=path.resolve(file);let at=path.parse(file).root;for(const part of file.slice(at.length).split(path.sep).filter(Boolean)){at=path.join(at,part);if(fs.lstatSync(at).isSymbolicLink())Fail('INPUT_SYMLINK');}return reader.Read(file,max);}
function Json(file,max=65536){return strict.Parse(Read(file,max),{maxBytes:max,maxNodes:50000});}
function Write(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function Directory(directory){
 if(!path.isAbsolute(directory))Fail('ABSOLUTE_INPUT_REQUIRED');
 let at=path.parse(directory).root;
 for(const part of path.resolve(directory).slice(at.length).split(path.sep).filter(Boolean)){
  at=path.join(at,part);const stat=fs.lstatSync(at);if(stat.isSymbolicLink()||!stat.isDirectory())Fail('INPUT_SYMLINK');
 }
}
function CheckReceipts(records,artifacts){
 if(!Array.isArray(records)||records.length!==3)Fail('RECEIPT_COHORT_REQUIRED');
 const map=Object.fromEntries(records.map(r=>[receipts.ReceiptId(r),r]));
 if(Object.keys(map).length!==3||new Set(records.map(r=>r.jobId)).size!==1)Fail('RECEIPT_COHORT_REQUIRED');
 receipts.ValidateStore({artifacts:{},packingEvidence:map});
 for(const role of ROLE){const row=records.find(x=>x.component===role);if(row.outputSha512!==artifacts[role].sha512||row.size!==artifacts[role].size)Fail('RECEIPT_FILE_MISMATCH');}
 return records;
}
function Prepare(configFile,sourceRoot,output){
 Directory(sourceRoot);if(!path.isAbsolute(output))Fail('ABSOLUTE_INPUT_REQUIRED');Directory(path.dirname(output));
 sourceRoot=path.resolve(sourceRoot);output=path.resolve(output);
 const config=Json(configFile);Exact(config,['version','releaseVersion','artifacts','packingReceiptsFile','policyFile']);Exact(config.artifacts,ROLE);
 if(config.version!==1||!/^\d+(?:\.\d+){0,3}$/.test(config.releaseVersion)||config.releaseVersion.length>40)Fail('INPUT_INVALID');
 if(fs.existsSync(output))Fail('NEW_OUTPUT_REQUIRED');
 const blobs={},artifacts={};let created;
 try{
  for(const role of ROLE){const b=Read(config.artifacts[role],64*1024*1024);blobs[role]=b;const own=protection.Inspect(b);
   if(!own||own.engine!=='COZY_VM_V1'||own.state!=='SEALED'||own.role!==role)Fail('PROTECTED_ARTIFACTS_REQUIRED');
   if(role==='A'&&['GAMEA80CONFIG!','COZYA2CONFIG!'].some(x=>b.subarray(-x.length).equals(Buffer.from(x))))Fail('ISSUED_A_NOT_TEMPLATE');
   artifacts[role]={sha512:sha(b),size:b.length,embeddedClientKeyPresent:true};
  }
  const records=CheckReceipts(Json(config.packingReceiptsFile),artifacts);
  const authority=require('../../services/security/peace.desktop-security-authority');
  const supplied=authority.ValidatePolicy(Json(config.policyFile));
  if(supplied.mode!=='enforce'||!supplied.requireReadonlyApi||!supplied.requireCompleteCrcLayers||!supplied.requireReleaseSignature)Fail('ENFORCED_POLICY_REQUIRED');
  const source=Read(path.join(sourceRoot,'Relay Server','maintenance','source-manifest.json'),8*1024*1024);
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519'),keyId=provenance.KeyId(publicKey),publicPem=publicKey.export({type:'spki',format:'pem'}).toString();
  const policy={...supplied,trustedReleaseKeys:[{keyId,publicKey:publicPem}]};authority.ValidatePolicy(policy);
  const manifest={version:1,releaseName:'Isolated final-file execution '+config.releaseVersion,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,sourceManifestSha512:sha(source),policySha512:provenance.PolicyDigest(policy),toolchain:{delphi:'NOT_ATTESTED',cpp:'NOT_ATTESTED',windowsSdk:'NOT_ATTESTED',imgui:'NOT_ATTESTED'},artifacts:Object.fromEntries(ROLE.map(r=>[r,artifacts[r].sha512]))};
  const summary={version:1,kind:KIND,releaseVersion:config.releaseVersion,finalExecutionOnly:true,buildProvenance:'NOT_ATTESTED',productionApproved:false,windowsExecuted:false,receiptAuthenticity:'OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED',sourceManifestSha512:sha(source),reviewedPolicySha512:provenance.PolicyDigest(supplied),fixturePolicySha512:provenance.PolicyDigest(policy),artifacts};
  fs.mkdirSync(output,{mode:0o700});created=fs.lstatSync(output);
  for(const role of ROLE){fs.writeFileSync(path.join(output,role+'.exe'),blobs[role],{flag:'wx',mode:0o600});Write(path.join(output,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,config.releaseVersion,artifacts[role].sha512].join('\n')),privateKey).toString('base64')});}
  Write(path.join(output,'policy.json'),policy);Write(path.join(output,'manifest.json'),{manifestId:provenance.ManifestId(manifest),manifest});
  Write(path.join(output,'packing-receipts.json'),records);Write(path.join(output,'final-execution-inputs.json'),summary);
  return summary;
 }catch(error){
  // Never remove a path merely because it exists after an error. It may have
  // been created/replaced by another caller while the inputs were inspected.
  if(created){
   try{Directory(path.dirname(output));const now=fs.lstatSync(output);
    if(now.isDirectory()&&!now.isSymbolicLink()&&now.dev===created.dev&&now.ino===created.ino)fs.rmSync(output,{recursive:true,force:true});
   }catch(cleanup){if(cleanup.code!=='ENOENT')Fail('OWNED_CLEANUP_FAILED');}
  }
  throw error;
 }finally{for(const b of Object.values(blobs))b.fill(0);}
}
function Verify(output){
 const summary=Json(path.join(output,'final-execution-inputs.json'));
 if(summary.version!==1||summary.kind!==KIND||summary.finalExecutionOnly!==true||summary.buildProvenance!=='NOT_ATTESTED'||summary.productionApproved!==false)Fail('CONTEXT_INVALID');
 for(const role of ROLE){const b=Read(path.join(output,role+'.exe'),64*1024*1024);try{if(sha(b)!==summary.artifacts[role].sha512||b.length!==summary.artifacts[role].size)Fail('ARTIFACT_CHANGED');}finally{b.fill(0);}}
 CheckReceipts(Json(path.join(output,'packing-receipts.json')),summary.artifacts);
 if(provenance.PolicyDigest(Json(path.join(output,'policy.json')))!==summary.fixturePolicySha512)Fail('POLICY_CHANGED');
 return summary;
}
if(require.main===module){try{const[cmd,...args]=process.argv.slice(2);let value;if(cmd==='prepare'&&args.length===3)value=Prepare(...args);else if(cmd==='verify'&&args.length===1)value=Verify(args[0]);else Fail('ARGUMENTS_INVALID');process.stdout.write(JSON.stringify(value)+'\n');}catch(error){process.stderr.write(/^CI_FINAL_[A-Z_]+$/.test(error.message)?error.message+'\n':'CI_FINAL_INPUTS_REJECTED\n');process.exitCode=1;}}
module.exports={KIND,Prepare,Verify,CheckReceipts};
