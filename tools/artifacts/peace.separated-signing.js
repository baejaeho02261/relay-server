'use strict';
// Offline release approval for operator-reviewed final Windows observations.
// No submitted script or executable is run. A signed observation is not proof
// of compiler authenticity, hardware trust, or independently witnessed testing.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const p=require('../../services/artifacts/peace.desktop-release-provenance');
const strict=require('../../services/protocol/peace.strict-json');
const bounded=require('../../services/artifacts/peace.bounded-artifact-read');
const provenance=require('./peace.release-provenance');
const PURPOSE='GAME-FINAL-RELEASE-TEST-BINDING-V2';
const OBSERVATION_KIND='FINAL_WINDOWS_EXECUTION_OBSERVATION';
const INPUT=['A.exe','B.exe','O.exe','source-manifest.json','policy.json','spec.json','manifest.json','final-windows-result.json'];
const REPLACED=new Set(['policy.json','manifest.json']);
const OUTPUT=[...INPUT,'A.approval.json','B.approval.json','O.approval.json','release-test-binding.json','reviewed/policy.json','reviewed/manifest.json','reviewed/bundle-index.json'];
const HASH=/^[a-f0-9]{128}$/,hash=b=>crypto.createHash('sha512').update(b).digest('hex');
function Fail(code){throw Error(code);}
function Root(root){const r=path.resolve(root);if(fs.realpathSync(r)!==r||!fs.lstatSync(r).isDirectory()||fs.lstatSync(r).isSymbolicLink())Fail('SIGNING_BUNDLE_DIRECTORY_INVALID');return r;}
function File(root,name){if(![...OUTPUT,'bundle-index.json','bundle-review-sha512.txt'].includes(name))Fail('SIGNING_BUNDLE_PATH_INVALID');let at=Root(root);for(const part of name.split('/')){at=path.join(at,part);if(fs.existsSync(at)&&fs.lstatSync(at).isSymbolicLink())Fail('SIGNING_BUNDLE_SYMLINK');}return at;}
function SameDirectory(file,expected){try{const stat=fs.lstatSync(file);return stat.isDirectory()&&!stat.isSymbolicLink()&&fs.realpathSync(file)===path.resolve(file)&&stat.dev===expected.dev&&stat.ino===expected.ino&&stat.birthtimeMs===expected.birthtimeMs;}catch(_){return false;}}
function Read(file,max=16*1024*1024){return bounded.Read(file,max);}
function Json(file,max=16*1024*1024){return strict.Parse(Read(file,max),{maxBytes:max,maxNodes:4000000});}
function Write(file,value){fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function EquivalentPolicy(a,b){const x={...a},y={...b};delete x.trustedReleaseKeys;delete y.trustedReleaseKeys;return p.Stable(x)===p.Stable(y);}
function NoProductionEnvironment(){if(process.env.GAME_RELEASE_APPROVAL_KEY_B64)Fail('SIGNING_KEY_ENVIRONMENT_FORBIDDEN');}
function CheckFinalExposure(root){for(const role of ['A','B','O']){const bytes=Read(File(root,role+'.exe'),64*1024*1024);try{
 if(require('../../services/artifacts/peace.release-exposure').ScanBytes(bytes).status!=='PASS')Fail('ARTIFACT_EXPOSURE_BLOCKED');
 if(require('../security/peace.audit-client-secrets').InspectBytes(bytes,role).status!=='PASS')Fail('CLIENT_SECRET_OR_EXPOSURE_BLOCKED');
 }finally{bytes.fill(0);}}}
function ValidateWindows(root,resolveName=n=>n){
 const file=n=>File(root,resolveName(n)),result=Json(file('final-windows-result.json')),record=provenance.LoadManifest(file('manifest.json')),manifest=record.manifest;
 const policy=require('../../services/security/peace.desktop-security-authority').ValidatePolicy(Json(file('policy.json'),65536));
 if(policy.mode!=='enforce'||!policy.requireReadonlyApi||!policy.requireCompleteCrcLayers||!policy.requireReleaseSignature)Fail('SIGNING_REQUIRED_PROTECTIONS_MISSING');
 const stages=['snapshot','dependencies','prepare','client-secrets','integration','verify'];
 if(result.version!==1||result.kind!==OBSERVATION_KIND||result.outcome!=='PASS'||result.finalExecutionOnly!==true||result.buildProvenance!=='NOT_ATTESTED'||result.productionApproved!==false||result.finalExecutionVerified!==true||result.integrationAttempted!==true||result.integration!=='PASS'||result.cleanup!=='PASS'||result.secretBoundary!=='PASS'||result.secretScanGuaranteesAbsenceOfSecrets!==false||result.fixtureClaimObservationBarrierUsed!==true||!/^\d+(?:\.\d+){0,3}$/.test(result.releaseVersion||'')||stages.some(name=>result.stages?.[name]?.outcome!=='PASS'||result.stages[name].exitCode!==0))Fail('SIGNING_FINAL_WINDOWS_OBSERVATION_REQUIRED');
 if(result.protectionEngine==='COZY_SERVER_POLICY_V2'&&result.fixtureEnrollmentApprovalUsed!==true)Fail('SIGNING_FINAL_WINDOWS_APPROVAL_MISSING');
 if(result.sourceManifestSha512!==manifest.sourceManifestSha512||hash(Read(file('source-manifest.json'),8*1024*1024))!==manifest.sourceManifestSha512||result.reviewedPolicySha512!==p.PolicyDigest(policy)||manifest.policySha512!==p.PolicyDigest(policy))Fail('SIGNING_REPORT_BINDING_INVALID');
 const spec=Json(file('spec.json'),65536),wanted={...manifest};delete wanted.artifacts;delete wanted.sourceManifestSha512;delete wanted.policySha512;
 if(p.Stable(spec)!==p.Stable(wanted))Fail('SIGNING_SPEC_MANIFEST_MISMATCH');
 if(!result.artifacts||Object.keys(result.artifacts).sort().join(',')!=='A,B,O')Fail('SIGNING_FINAL_FILE_MISMATCH');
 for(const role of ['A','B','O']){const b=Read(file(role+'.exe'),64*1024*1024),r=result.artifacts[role];if(!r||r.sha512!==hash(b)||r.size!==b.length||manifest.artifacts[role]!==hash(b))Fail('SIGNING_FINAL_FILE_MISMATCH');}
 return{result,manifest:record,policy,spec};
}
function Names(root,prefix=''){
 const names=[];for(const entry of fs.readdirSync(root,{withFileTypes:true})){
  const n=prefix+entry.name;if(n==='reviewed'&&entry.isDirectory()&&!entry.isSymbolicLink())names.push(...Names(path.join(root,n),'reviewed/'));
  else if(['bundle-index.json','bundle-review-sha512.txt'].includes(n)){if(!entry.isFile()||entry.isSymbolicLink())Fail('SIGNING_BUNDLE_FILE_INVALID');}
  else {if(!OUTPUT.includes(n)||!entry.isFile()||entry.isSymbolicLink())Fail('SIGNING_BUNDLE_FILE_INVALID');names.push(n);}
 }return names.sort();
}
function Seal(root,kind='UNSIGNED_WINDOWS_TEST_BUNDLE'){
 if(!['UNSIGNED_WINDOWS_TEST_BUNDLE','RELEASE_APPROVED_TESTED_BUNDLE'].includes(kind))Fail('SIGNING_BUNDLE_KIND');Root(root);
 const names=Names(root),expected=(kind==='UNSIGNED_WINDOWS_TEST_BUNDLE'?INPUT:OUTPUT).slice().sort();if(names.join('\n')!==expected.join('\n'))Fail('SIGNING_BUNDLE_FILES_REQUIRED');
 if(fs.existsSync(File(root,'bundle-index.json'))||fs.existsSync(File(root,'bundle-review-sha512.txt')))Fail('SIGNING_OUTPUT_ALREADY_EXISTS');
 const files={};let total=0;for(const name of names){const b=Read(File(root,name),name.endsWith('.exe')?64*1024*1024:16*1024*1024);total+=b.length;if(total>256*1024*1024)Fail('SIGNING_BUNDLE_TOTAL_LIMIT');if(/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(b.toString('utf8')))Fail('SIGNING_SECRET_IN_OUTPUT');files[name]={sha512:hash(b),bytes:b.length};}
 Write(File(root,'bundle-index.json'),{version:1,kind,files});const sha512=hash(Read(File(root,'bundle-index.json')));fs.writeFileSync(File(root,'bundle-review-sha512.txt'),sha512+'\n',{flag:'wx',mode:0o600});return{kind,sha512,files:names.length,buildProvenance:'NOT_ATTESTED',publicationPerformed:false};
}
function VerifyIndex(root,expected,kind){
 if(!HASH.test(expected||''))Fail('SIGNING_REVIEWED_DIGEST_REQUIRED');const b=Read(File(root,'bundle-index.json'));if(hash(b)!==expected)Fail('SIGNING_REVIEWED_DIGEST_MISMATCH');const index=Json(File(root,'bundle-index.json'));
 const names=(kind==='UNSIGNED_WINDOWS_TEST_BUNDLE'?INPUT:OUTPUT).slice().sort();if(index.version!==1||index.kind!==kind||!index.files||Object.keys(index.files).sort().join('\n')!==names.join('\n')||Names(root).join('\n')!==names.join('\n'))Fail('SIGNING_BUNDLE_INDEX_INVALID');
 for(const [n,r]of Object.entries(index.files)){if(!r||Object.keys(r).sort().join(',')!=='bytes,sha512'||!HASH.test(r.sha512||'')||!Number.isSafeInteger(r.bytes)||r.bytes<1)Fail('SIGNING_BUNDLE_INDEX_INVALID');const b=Read(File(root,n),n.endsWith('.exe')?64*1024*1024:16*1024*1024);if(b.length!==r.bytes||hash(b)!==r.sha512)Fail('SIGNING_BUNDLE_CHANGED');}return index;
}
function PrivateKey(file,root,out){const actual=fs.realpathSync(file);for(const directory of [root,out])if(actual===path.resolve(directory)||actual.startsWith(path.resolve(directory)+path.sep))Fail('SIGNING_KEY_INSIDE_BUNDLE');const bytes=Read(file,16384);try{const key=crypto.createPrivateKey(bytes);if(key.asymmetricKeyType!=='ed25519')Fail('SIGNING_ED25519_REQUIRED');return key;}finally{bytes.fill(0);}}
function Release(root,digest,out,keyFile,policyFile){
 require('../../services/security/peace.service-isolation').Check('release-signer');NoProductionEnvironment();const index=VerifyIndex(root,digest,'UNSIGNED_WINDOWS_TEST_BUNDLE'),old=ValidateWindows(root);CheckFinalExposure(root);
 const policy=require('../../services/security/peace.desktop-security-authority').ValidatePolicy(Json(policyFile,65536));if(!EquivalentPolicy(old.policy,policy))Fail('SIGNING_TESTED_POLICY_CHANGED');
 const resolved=path.resolve(out);if(fs.existsSync(resolved))Fail('SIGNING_NEW_OUTPUT_REQUIRED');Root(path.dirname(resolved));
 const key=PrivateKey(keyFile,root,resolved),pub=crypto.createPublicKey(key),keyId=p.KeyId(pub);if(!policy.trustedReleaseKeys.some(k=>k.keyId===keyId&&p.KeyId(crypto.createPublicKey(k.publicKey))===keyId))Fail('SIGNING_APPROVAL_KEY_NOT_TRUSTED');
 const parent=path.dirname(resolved),parentIdentity=fs.lstatSync(parent);fs.mkdirSync(resolved,{mode:0o700});const ownedIdentity=fs.lstatSync(resolved);try{
  for(const [n,row]of Object.entries(index.files)){const bytes=Read(File(root,n),n.endsWith('.exe')?64*1024*1024:16*1024*1024);if(hash(bytes)!==row.sha512||bytes.length!==row.bytes)Fail('SIGNING_BUNDLE_CHANGED_DURING_COPY');const dest=File(resolved,REPLACED.has(n)?'reviewed/'+n:n);fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o700});fs.writeFileSync(dest,bytes,{flag:'wx',mode:0o600});}
  const originalIndex=Read(File(root,'bundle-index.json'));if(hash(originalIndex)!==digest)Fail('SIGNING_BUNDLE_CHANGED_DURING_COPY');fs.writeFileSync(File(resolved,'reviewed/bundle-index.json'),originalIndex,{flag:'wx',mode:0o600});
  ValidateWindows(resolved,n=>REPLACED.has(n)?'reviewed/'+n:n);CheckFinalExposure(resolved);
  Write(File(resolved,'policy.json'),policy);const manifest=p.ValidateManifest({...old.manifest.manifest,policySha512:p.PolicyDigest(policy)}),manifestId=p.ManifestId(manifest);Write(File(resolved,'manifest.json'),{manifestId,manifest});
  for(const role of ['A','B','O'])Write(File(resolved,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,old.result.releaseVersion,manifest.artifacts[role]].join('\n')),key).toString('base64')});
  const statement={version:2,purpose:PURPOSE,issuedAt:Date.now(),reviewedWindowsBundleSha512:digest,reviewedManifestId:old.manifest.manifestId,manifestId,reportSha512:hash(Read(File(resolved,'final-windows-result.json'))),sourceManifestSha512:manifest.sourceManifestSha512,policyDifference:'TRUSTED_RELEASE_KEYS_ONLY',windowsEvidence:'OPERATOR_REVIEWED_NOT_INDEPENDENT_ATTESTATION',buildProvenance:'NOT_ATTESTED'};
  Write(File(resolved,'release-test-binding.json'),{keyId,statement,signature:crypto.sign(null,Buffer.from(p.Stable(statement)),key).toString('base64')});VerifyRelease(resolved,Buffer.from(pub.export({type:'spki',format:'pem'})));return Seal(resolved,'RELEASE_APPROVED_TESTED_BUNDLE');
 }catch(error){
  // Never delete a replacement directory after an operator/process moves output.
  if(!SameDirectory(parent,parentIdentity)||!SameDirectory(resolved,ownedIdentity))Fail('SIGNING_OUTPUT_OWNERSHIP_CHANGED');
  try{fs.rmSync(resolved,{recursive:true,force:true});}catch(_){Fail('SIGNING_OUTPUT_CLEANUP_FAILED');}throw error;
 }
}
function VerifyRelease(root,publicFile){
 const bytes=Buffer.isBuffer(publicFile)?publicFile:Read(publicFile,65536);if(bytes.length>65536)Fail('SIGNING_PUBLIC_KEY_INVALID');let key;try{key=crypto.createPublicKey(bytes);}catch(_){key=crypto.createPublicKey(strict.Parse(bytes,{maxBytes:65536}).publicKey);}
 const binding=Json(File(root,'release-test-binding.json')),s=binding?.statement;if(!s||key.asymmetricKeyType!=='ed25519'||binding.keyId!==p.KeyId(key)||typeof binding.signature!=='string'||!crypto.verify(null,Buffer.from(p.Stable(s)),key,Buffer.from(binding.signature,'base64')))Fail('SIGNING_RELEASE_BINDING_SIGNATURE_INVALID');
 if(s.version!==2||s.purpose!==PURPOSE||s.policyDifference!=='TRUSTED_RELEASE_KEYS_ONLY'||s.windowsEvidence!=='OPERATOR_REVIEWED_NOT_INDEPENDENT_ATTESTATION'||s.buildProvenance!=='NOT_ATTESTED'||!Number.isSafeInteger(s.issuedAt)||s.issuedAt>Date.now()||!HASH.test(s.reviewedWindowsBundleSha512||''))Fail('SIGNING_RELEASE_BINDING_INVALID');
 const originalBytes=Read(File(root,'reviewed/bundle-index.json')),original=Json(File(root,'reviewed/bundle-index.json'));if(hash(originalBytes)!==s.reviewedWindowsBundleSha512||original.version!==1||original.kind!=='UNSIGNED_WINDOWS_TEST_BUNDLE'||Object.keys(original.files||{}).sort().join('\n')!==INPUT.slice().sort().join('\n'))Fail('SIGNING_ORIGINAL_INDEX_MISMATCH');
 const resolveName=n=>REPLACED.has(n)?'reviewed/'+n:n;for(const [n,r]of Object.entries(original.files)){const b=Read(File(root,resolveName(n)),n.endsWith('.exe')?64*1024*1024:16*1024*1024);if(b.length!==r.bytes||hash(b)!==r.sha512)Fail('SIGNING_ORIGINAL_EVIDENCE_CHANGED');}
 const old=ValidateWindows(root,resolveName),m=provenance.LoadManifest(File(root,'manifest.json')),policy=require('../../services/security/peace.desktop-security-authority').ValidatePolicy(Json(File(root,'policy.json'),65536));
 if(s.reviewedManifestId!==old.manifest.manifestId||s.manifestId!==m.manifestId||s.sourceManifestSha512!==m.manifest.sourceManifestSha512||s.reportSha512!==hash(Read(File(root,'final-windows-result.json')))||!EquivalentPolicy(old.policy,policy)||m.manifest.policySha512!==p.PolicyDigest(policy)||!policy.trustedReleaseKeys.some(k=>k.keyId===binding.keyId&&p.KeyId(crypto.createPublicKey(k.publicKey))===binding.keyId))Fail('SIGNING_RELEASE_BINDING_INVALID');
 const expected={...old.manifest.manifest,policySha512:p.PolicyDigest(policy)};if(p.Stable(expected)!==p.Stable(m.manifest))Fail('SIGNING_FINAL_MANIFEST_CHANGED');
 for(const role of ['A','B','O']){const a=Json(File(root,role+'.approval.json'));if(a.keyId!==binding.keyId||!crypto.verify(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,old.result.releaseVersion,m.manifest.artifacts[role]].join('\n')),key,Buffer.from(a.signature,'base64')))Fail('SIGNING_FINAL_APPROVAL_INVALID');}
 if(Names(root).join('\n')!==OUTPUT.slice().sort().join('\n'))Fail('SIGNING_UNREVIEWED_ATTACHMENT');
 return{keyId:binding.keyId,manifestId:m.manifestId,buildProvenance:'NOT_ATTESTED',windowsEvidence:s.windowsEvidence,publicationPerformed:false};
}
if(require.main===module){try{const [command,...args]=process.argv.slice(2);let result;if(command==='seal'&&args.length===1){ValidateWindows(args[0]);CheckFinalExposure(args[0]);result=Seal(args[0]);}else if(command==='release'&&args.length===5)result=Release(...args);else if(command==='verify'&&args.length===2)result=VerifyRelease(...args);else if(command==='--help'){console.log('seal INPUT | release INPUT REVIEW_SHA512 NEW_OUTPUT PRIVATE_KEY POLICY | verify OUTPUT PUBLIC_KEY');process.exit(0);}else Fail('SIGNING_ARGUMENTS_INVALID');console.log(JSON.stringify(result));}catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'SIGNING_FAILED');process.exitCode=1;}}
module.exports={OBSERVATION_KIND,ValidateWindows,Seal,VerifyIndex,Release,VerifyRelease,EquivalentPolicy,NoProductionEnvironment};
