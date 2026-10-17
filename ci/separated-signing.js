'use strict';
// Trusted offline tool: NEVER require/execute scripts or executables from a
// submitted bundle. Hash review is an operator trust decision, not attestation
// of a compromised Windows runner. Production keys are never sent to a builder.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const artifacts=require('./ci-artifacts'),provenance=require('../tools/release-provenance');
const p=require('../services/desktopReleaseProvenance'),strict=require('../services/strictJson');
const PURPOSE='GAME-FINAL-RELEASE-TEST-BINDING-V1';
const MAX=512*1024*1024,hash=b=>crypto.createHash('sha512').update(b).digest('hex');
const PUBLIC=new Set(['A.exe','B.exe','O.exe','A.approval.json','B.approval.json','O.approval.json',
 'source-manifest.json','toolchain.json','observed-build-inputs.json','build-inputs.json','build-inputs-after.json',
 'final-artifact-audit.json','cfg-evidence.json','sdk-probe-inputs.json','runner-results.json','integration-result.json',
 'integration-profile-observe-result.json','integration-profile-prohibit-result.json','compatibility-observations.json',
 'compatibility-statements.json','policy.json','deployment-policy.json','spec.json','manifest.json','report.json','logs-index.json',
 'security-authority-result.json','fixture-policy-purpose.json','release-test-binding.json','ci-evidence.json','ci-public-key.pem',
 'mitigation-A-observe.json','mitigation-B-observe.json','mitigation-O-observe.json',
 'mitigation-A-prohibit.json','mitigation-B-prohibit.json','mitigation-O-prohibit.json']);
const REPLACED=new Set(['A.approval.json','B.approval.json','O.approval.json','policy.json','spec.json','manifest.json','report.json','compatibility-statements.json']);
function Allowed(n){return PUBLIC.has(n)||/^logs\/[a-z0-9-]+\.log$/.test(n)||n==='fixture/bundle-index.json'||n.startsWith('fixture/')&&REPLACED.has(n.slice(8));}
function File(root,n){if(!Allowed(n))throw Error('SIGNING_BUNDLE_PATH_INVALID');let at=path.resolve(root);
 if(fs.lstatSync(at).isSymbolicLink())throw Error('SIGNING_BUNDLE_SYMLINK');
 for(const part of n.split('/')){at=path.join(at,part);if(fs.existsSync(at)&&fs.lstatSync(at).isSymbolicLink())throw Error('SIGNING_BUNDLE_SYMLINK');}return at;}
function Read(file,max=16*1024*1024){
 // A silent subprocess may legitimately produce an empty log, but no other
 // required input may be empty. Preserve inode and no-symlink checks here too.
 if(file.endsWith('.log')){const st=fs.lstatSync(file);if(st.size===0){
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)throw Error('SIGNING_LOG_INVALID');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  try{const b=fs.fstatSync(fd),n=fs.readSync(fd,Buffer.alloc(1),0,1,0),a=fs.fstatSync(fd),named=fs.lstatSync(file);
   if(n!==0||[b,a,named].some(x=>!x.isFile()||x.isSymbolicLink()||x.nlink!==1||x.dev!==st.dev||x.ino!==st.ino||x.size!==0||x.mtimeMs!==st.mtimeMs||x.ctimeMs!==st.ctimeMs))throw Error('SIGNING_LOG_CHANGED');return Buffer.alloc(0);
  }finally{fs.closeSync(fd);}
 }}
 return require('../services/boundedArtifactRead').Read(file,max);
}
function Json(file,max=16*1024*1024){const b=Read(file,max);return strict.Parse(b.subarray(b[0]===239&&b[1]===187&&b[2]===191?3:0),{maxBytes:max,maxNodes:4000000});}
function Write(file,v){fs.writeFileSync(file,JSON.stringify(v,null,2)+'\n',{flag:'wx',mode:0o600});}
function NoProductionEnvironment(){for(const k of ['GAME_RELEASE_APPROVAL_KEY_B64','GAME_CI_ATTESTATION_KEY_B64'])if(process.env[k])throw Error('SIGNING_KEY_ENVIRONMENT_FORBIDDEN');}
function Fixture(out,privateDirectory,version,securityVersion,policyFile){
 NoProductionEnvironment();const pair=crypto.generateKeyPairSync('ed25519'),pem=pair.privateKey.export({type:'pkcs8',format:'pem'}),pub=pair.publicKey.export({type:'spki',format:'pem'}).toString(),keyId=p.KeyId(pair.publicKey);
 const original=policyFile?require('../services/desktopSecurityAuthority').ValidatePolicy(Json(policyFile,65536)):null;
 const key=path.join(privateDirectory,'isolated-fixture-only.pem'),selected=path.join(privateDirectory,'isolated-policy.json');
 try{fs.writeFileSync(key,pem,{flag:'wx',mode:0o600});
  if(original){Write(path.join(out,'deployment-policy.json'),original);Write(selected,{...original,trustedReleaseKeys:[{keyId,publicKey:pub}]});}
  artifacts.Prepare(out,key,version,Number(securityVersion),path.join(out,'toolchain.json'),path.join(out,'source-manifest.json'),original?selected:undefined);
  Write(path.join(out,'fixture-policy-purpose.json'),{version:1,kind:'EPHEMERAL_TEST_KEY_NOT_DEPLOYMENT_APPROVAL',testKeyId:keyId,basePolicySha512:original?p.PolicyDigest(original):null});
 }finally{for(const f of [key,selected])try{fs.unlinkSync(f);}catch(e){if(e.code!=='ENOENT')throw e;}}
 return {fixtureOnly:true,productionApproval:false};
}
function ValidateWindows(root,resolveName=n=>n){
 const file=n=>File(root,resolveName(n)),j=n=>Json(file(n)),result=j('runner-results.json');
 const stages=['self-test','snapshot','dependencies','build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration','security-authority','report'];
 if(result.version!==1||result.windowsExecuted!==true||result.productionKeysPresent!==false||result.signed!==false||result.cleanupFailed||result.error||!/^\d+(?:\.\d+){0,3}$/.test(result.releaseVersion||'')||!Number.isSafeInteger(result.securityVersion)||result.securityVersion<1||stages.some(n=>result.stages?.[n]?.outcome!=='PASS'||result.stages[n].exitCode!==0)||['nativeBuild','apiProbe','integration'].some(n=>result[n]!=='PASS'))throw Error('SIGNING_ACTUAL_WINDOWS_PASS_REQUIRED');
 const report=j('report.json'),m=provenance.LoadManifest(file('manifest.json')),policy=j('policy.json');
 if(['nativeBuild','apiProbe','integration'].some(k=>report[k]!=='PASS')||m.manifest.policySha512!==p.PolicyDigest(policy)||report.sourceManifestSha512!==m.manifest.sourceManifestSha512||hash(Read(file('source-manifest.json'),8*1024*1024))!==m.manifest.sourceManifestSha512)throw Error('SIGNING_REPORT_BINDING_INVALID');
 const audit=j('final-artifact-audit.json');
 if(audit.kind!=='FINAL_FILE_INSPECTION_NOT_RUNTIME_ATTESTATION'||audit.artifacts?.O?.overlayManifest?.status!=='EXACT_SOURCE_BYTES_MATCH')throw Error('SIGNING_FINAL_AUDIT_INVALID');
 for(const role of ['A','B','O']){
  const digest=hash(Read(file(role+'.exe'),64*1024*1024));
  if(digest!==m.manifest.artifacts[role]||digest!==report[role.toLowerCase()+'Sha512']||audit.artifacts?.[role]?.sha512!==digest)throw Error('SIGNING_FINAL_FILE_MISMATCH');
  const a=j(role+'.approval.json'),k=policy.trustedReleaseKeys.find(x=>x.keyId===a.keyId);
  if(!k||!crypto.verify(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,result.releaseVersion,digest].join('\n')),crypto.createPublicKey(k.publicKey),Buffer.from(a.signature,'base64')))throw Error('SIGNING_FIXTURE_APPROVAL_INVALID');
 }
 const before=j('build-inputs.json'),after=j('build-inputs-after.json');
 if(before.status!=='PASS'||after.status!=='PASS'||before.inputSha512!==after.inputSha512||before.sdkHeaderSha512!==after.sdkHeaderSha512)throw Error('SIGNING_BUILD_INPUT_MISMATCH');
 const integration=j('integration-result.json');
 if(integration.outcome!=='PASS'||['ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed'].some(k=>integration[k]!==true))throw Error('SIGNING_INTEGRATION_INCOMPLETE');
 const index=j('logs-index.json');
 if(index.version!==1||!Array.isArray(index.files)||index.files.length>128||new Set(index.files.map(x=>x.name)).size!==index.files.length||hash(Read(file('logs-index.json'),8*1024*1024))!==report.logsSha512)throw Error('SIGNING_LOG_INDEX_INVALID');
 for(const row of index.files)if(!/^[a-z0-9-]+\.log$/.test(row.name)||hash(Read(file('logs/'+row.name),64*1024*1024))!==row.sha512)throw Error('SIGNING_LOG_MISMATCH');
 for(const name of stages.filter(n=>!['report'].includes(n)))if(!index.files.some(x=>x.name===name+'.log'))throw Error('SIGNING_STAGE_LOG_MISSING');
 const security=j('security-authority-result.json');require('../tools/security-authority-contract').Validate(security,m.manifest.artifacts,m.manifest.sourceManifestSha512,policy);
 return {result,report,manifest:m,policy};
}
function Names(root,prefix=''){
 const names=[];for(const entry of fs.readdirSync(root,{withFileTypes:true})){
  const n=prefix+entry.name;if(entry.isDirectory()&&['logs','fixture'].includes(n))names.push(...Names(path.join(root,entry.name),n+'/'));
  else if(Allowed(n)){if(!entry.isFile()||entry.isSymbolicLink())throw Error('SIGNING_BUNDLE_FILE_INVALID');names.push(n);}
 }return names.sort();
}
function Seal(root,kind){
 if(!['UNSIGNED_WINDOWS_TEST_BUNDLE','RELEASE_APPROVED_TESTED_BUNDLE','CI_SIGNED_TESTED_BUNDLE'].includes(kind))throw Error('SIGNING_BUNDLE_KIND');
 const files={};let total=0;
 for(const name of Names(root)){const b=Read(File(root,name),name.endsWith('.exe')||name.endsWith('.log')?64*1024*1024:16*1024*1024);total+=b.length;
  if(total>MAX)throw Error('SIGNING_BUNDLE_TOTAL_LIMIT');
  if(!name.endsWith('.exe')&&/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/.test(b.toString('utf8')))throw Error('SIGNING_SECRET_IN_OUTPUT');
  files[name]={sha512:hash(b),bytes:b.length};
 }
 Write(path.join(root,'bundle-index.json'),{version:1,kind,files});const sha512=hash(Read(path.join(root,'bundle-index.json')));
 fs.writeFileSync(path.join(root,'bundle-review-sha512.txt'),sha512+'\n',{flag:'wx',mode:0o600});return {kind,sha512,files:Object.keys(files).length};
}
function VerifyIndex(root,expected,kind){
 if(!/^[a-f0-9]{128}$/.test(expected))throw Error('SIGNING_REVIEWED_DIGEST_REQUIRED');
 const b=Read(path.join(root,'bundle-index.json'));if(hash(b)!==expected)throw Error('SIGNING_REVIEWED_DIGEST_MISMATCH');const index=Json(path.join(root,'bundle-index.json'));
 if(index.version!==1||index.kind!==kind||!index.files||Object.keys(index.files).length<10||Object.keys(index.files).length>256)throw Error('SIGNING_BUNDLE_INDEX_INVALID');let total=0;
 for(const [n,row]of Object.entries(index.files)){if(!row||Object.keys(row).sort().join(',')!=='bytes,sha512'||!Number.isSafeInteger(row.bytes)||row.bytes<0||!/^[a-f0-9]{128}$/.test(row.sha512))throw Error('SIGNING_BUNDLE_INDEX_INVALID');
  const bytes=Read(File(root,n),n.endsWith('.exe')||n.endsWith('.log')?64*1024*1024:16*1024*1024);total+=bytes.length;
  if(total>MAX||bytes.length!==row.bytes||hash(bytes)!==row.sha512)throw Error('SIGNING_BUNDLE_CHANGED');
 }
 // Reject extra allowed files too: no unreviewed report/profile substitution.
 if(Names(root).join('\n')!==Object.keys(index.files).sort().join('\n'))throw Error('SIGNING_UNREVIEWED_ATTACHMENT');
 return index;
}
function Copy(root,out,index,rename=n=>n){for(const [n,row] of Object.entries(index.files)){
 // Bind the exact copied bytes too: the submitting directory may change after
 // its initial validation. Never produce an approval for a changed copy.
 const bytes=Read(File(root,n),64*1024*1024);if(bytes.length!==row.bytes||hash(bytes)!==row.sha512)throw Error('SIGNING_BUNDLE_CHANGED_DURING_COPY');
 const dest=File(out,rename(n));fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o700});fs.writeFileSync(dest,bytes,{flag:'wx',mode:0o600});
}}
function PrivateKey(file,root,out){
 for(const directory of [root,out])if(path.resolve(file).startsWith(path.resolve(directory)+path.sep))throw Error('SIGNING_KEY_INSIDE_BUNDLE');
 const bytes=Read(file,16384);try{const key=crypto.createPrivateKey(bytes);if(key.asymmetricKeyType!=='ed25519')throw Error('SIGNING_ED25519_REQUIRED');return key;}finally{bytes.fill(0);}
}
function EquivalentPolicy(a,b){const x={...a},y={...b};delete x.trustedReleaseKeys;delete y.trustedReleaseKeys;return p.Stable(x)===p.Stable(y);}
function Release(root,digest,out,keyFile,policyFile){
 NoProductionEnvironment();const index=VerifyIndex(root,digest,'UNSIGNED_WINDOWS_TEST_BUNDLE'),old=ValidateWindows(root);
 const policy=require('../services/desktopSecurityAuthority').ValidatePolicy(Json(policyFile,65536));
 if(!EquivalentPolicy(old.policy,policy))throw Error('SIGNING_TESTED_POLICY_CHANGED');
 if(policy.trustedReleaseKeys.some(k=>k.keyId===Json(path.join(root,'fixture-policy-purpose.json')).testKeyId))throw Error('SIGNING_TEST_KEY_TRUST_FORBIDDEN');
 const key=PrivateKey(keyFile,root,out),pub=crypto.createPublicKey(key),keyId=p.KeyId(pub);
 if(!policy.trustedReleaseKeys.some(k=>k.keyId===keyId&&p.KeyId(crypto.createPublicKey(k.publicKey))===keyId))throw Error('SIGNING_TESTED_POLICY_CHANGED');
 const resolved=path.resolve(out);if(fs.existsSync(resolved))throw Error('SIGNING_NEW_OUTPUT_REQUIRED');fs.mkdirSync(resolved,{mode:0o700});
 try{
  Copy(root,resolved,index,n=>REPLACED.has(n)?'fixture/'+n:n);
  const originalIndex=Read(path.join(root,'bundle-index.json'));
  if(hash(originalIndex)!==digest)throw Error('SIGNING_BUNDLE_CHANGED_DURING_COPY');
  fs.writeFileSync(path.join(resolved,'fixture/bundle-index.json'),originalIndex,{flag:'wx',mode:0o600});
  ValidateWindows(resolved,n=>REPLACED.has(n)?'fixture/'+n:n);
  // Policy was checked before any private-key operation. All inputs below are
  // the copied, bounded files; no untrusted script is imported or executed.
  const scratch=path.join(resolved,'.reviewed-policy.json');Write(scratch,policy);
  try{artifacts.Prepare(resolved,keyFile,old.result.releaseVersion,old.result.securityVersion,path.join(resolved,'toolchain.json'),path.join(resolved,'source-manifest.json'),scratch);}finally{fs.unlinkSync(scratch);}
  const m=provenance.LoadManifest(path.join(resolved,'manifest.json')),report={...old.report};
  if(report.version===2){const prior=Json(path.join(resolved,'fixture/compatibility-statements.json')),profile=require('../services/desktopMitigationProfiles');
   if(profile.CompatibilityHash(prior.compatibility)!==old.report.compatibilitySha512)throw Error('SIGNING_COMPATIBILITY_MISMATCH');
   const statements=prior.statements.map(s=>{if(s.manifestId!==old.manifest.manifestId||s.artifactSha512!==old.manifest.manifest.artifacts[s.component]||s.logsSha512!==old.report.logsSha512)throw Error('SIGNING_COMPATIBILITY_MISMATCH');return profile.Statement({...s,manifestId:m.manifestId});});
   const compatibility={version:1,profileIds:statements.map(s=>profile.Id({statement:s})).sort()};report.compatibilitySha512=profile.CompatibilityHash(compatibility);Write(path.join(resolved,'compatibility-statements.json'),{version:1,compatibility,statements});
  }
  Write(path.join(resolved,'report.json'),report);
  const statement={version:1,purpose:PURPOSE,issuedAt:Date.now(),reviewedWindowsBundleSha512:digest,fixtureManifestId:old.manifest.manifestId,manifestId:m.manifestId,reportSha512:hash(Read(path.join(resolved,'report.json'))),sourceManifestSha512:m.manifest.sourceManifestSha512,policyDifference:'TRUSTED_RELEASE_KEYS_ONLY',windowsEvidence:'OPERATOR_REVIEWED_NOT_HARDWARE_ATTESTATION'};
  Write(path.join(resolved,'release-test-binding.json'),{keyId,statement,signature:crypto.sign(null,Buffer.from(p.Stable(statement)),key).toString('base64')});
  return Seal(resolved,'RELEASE_APPROVED_TESTED_BUNDLE');
 }catch(error){fs.rmSync(resolved,{recursive:true,force:true});throw error;}
}
function VerifyRelease(root,releasePublicFile){
 const record=Buffer.isBuffer(releasePublicFile)?releasePublicFile:Read(releasePublicFile,65536);if(record.length>65536)throw Error('SIGNING_PUBLIC_KEY_INVALID');let publicKey;try{publicKey=crypto.createPublicKey(record);}catch(_){publicKey=crypto.createPublicKey(strict.Parse(record,{maxBytes:65536}).publicKey);}
 const binding=Json(File(root,'release-test-binding.json'));
 if(publicKey.asymmetricKeyType!=='ed25519'||binding.keyId!==p.KeyId(publicKey)||!crypto.verify(null,Buffer.from(p.Stable(binding.statement)),publicKey,Buffer.from(binding.signature,'base64')))throw Error('SIGNING_RELEASE_BINDING_SIGNATURE_INVALID');
 const s=binding.statement;if(s.version!==1||s.purpose!==PURPOSE||s.policyDifference!=='TRUSTED_RELEASE_KEYS_ONLY'||!Number.isSafeInteger(s.issuedAt)||s.issuedAt>Date.now())throw Error('SIGNING_RELEASE_BINDING_INVALID');
 const original=Json(File(root,'fixture/bundle-index.json'));
 if(hash(Read(File(root,'fixture/bundle-index.json')))!==s.reviewedWindowsBundleSha512||original.kind!=='UNSIGNED_WINDOWS_TEST_BUNDLE'||original.version!==1||Object.keys(original.files||{}).length>256)throw Error('SIGNING_ORIGINAL_INDEX_MISMATCH');
 const resolveName=n=>REPLACED.has(n)?'fixture/'+n:n;
 for(const [n,row]of Object.entries(original.files)){const b=Read(File(root,resolveName(n)),64*1024*1024);if(b.length!==row.bytes||hash(b)!==row.sha512)throw Error('SIGNING_ORIGINAL_EVIDENCE_CHANGED');}
 const old=ValidateWindows(root,resolveName),m=provenance.LoadManifest(File(root,'manifest.json')),policy=Json(File(root,'policy.json')),report=Json(File(root,'report.json'));
 if(s.fixtureManifestId!==old.manifest.manifestId||s.manifestId!==m.manifestId||s.sourceManifestSha512!==m.manifest.sourceManifestSha512||s.reportSha512!==hash(Read(File(root,'report.json')))||!EquivalentPolicy(old.policy,policy)||m.manifest.policySha512!==p.PolicyDigest(policy)||!policy.trustedReleaseKeys.some(k=>k.keyId===binding.keyId&&p.KeyId(crypto.createPublicKey(k.publicKey))===binding.keyId))throw Error('SIGNING_RELEASE_BINDING_INVALID');
 for(const role of ['A','B','O']){if(m.manifest.artifacts[role]!==old.manifest.manifest.artifacts[role]||report[role.toLowerCase()+'Sha512']!==m.manifest.artifacts[role])throw Error('SIGNING_FINAL_FILE_MISMATCH');
  const a=Json(File(root,role+'.approval.json'));if(a.keyId!==binding.keyId||!crypto.verify(null,Buffer.from(['GAME-RELEASE-APPROVAL-V2',role,old.result.releaseVersion,m.manifest.artifacts[role]].join('\n')),publicKey,Buffer.from(a.signature,'base64')))throw Error('SIGNING_FINAL_APPROVAL_INVALID');
 }
 const expected={...old.report};if(expected.version===2)expected.compatibilitySha512=report.compatibilitySha512;
 if(p.Stable(expected)!==p.Stable(report))throw Error('SIGNING_TEST_REPORT_CHANGED');
 if(report.version===2){const before=Json(File(root,'fixture/compatibility-statements.json')),after=Json(File(root,'compatibility-statements.json'));
  const wanted=before.statements.map(x=>({...x,manifestId:m.manifestId}));if(p.Stable(wanted)!==p.Stable(after.statements))throw Error('SIGNING_TEST_OBSERVATION_CHANGED');}
 return {keyId:binding.keyId,manifestId:m.manifestId};
}
function Attest(root,digest,out,keyFile,expectedReleasePublicFile){
 NoProductionEnvironment();const index=VerifyIndex(root,digest,'RELEASE_APPROVED_TESTED_BUNDLE');VerifyRelease(root,expectedReleasePublicFile);
 const key=PrivateKey(keyFile,root,out),pub=crypto.createPublicKey(key),policy=Json(File(root,'policy.json'));
 if(policy.trustedReleaseKeys.some(k=>k.keyId===p.KeyId(pub)))throw Error('SIGNING_KEY_PURPOSE_CONFLICT');
 const resolved=path.resolve(out);if(fs.existsSync(resolved))throw Error('SIGNING_NEW_OUTPUT_REQUIRED');fs.mkdirSync(resolved,{mode:0o700});
 try{Copy(root,resolved,index);VerifyRelease(resolved,expectedReleasePublicFile);artifacts.Sign(resolved,keyFile,Json(File(resolved,'runner-results.json')).runId);return Seal(resolved,'CI_SIGNED_TESTED_BUNDLE');}catch(error){fs.rmSync(resolved,{recursive:true,force:true});throw error;}
}
if(require.main===module){try{const [cmd,...args]=process.argv.slice(2);let r;
 if(cmd==='fixture'&&[4,5].includes(args.length))r=Fixture(...args);
 else if(cmd==='seal'&&args.length===1){ValidateWindows(args[0]);r=Seal(args[0],'UNSIGNED_WINDOWS_TEST_BUNDLE');}
 else if(cmd==='release'&&args.length===5)r=Release(...args);
 else if(cmd==='attest'&&args.length===5)r=Attest(...args);
 else throw Error('SIGNING_ARGUMENTS_INVALID');console.log(JSON.stringify(r));
 }catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'SIGNING_FAILED');process.exitCode=1;}}
module.exports={Fixture,ValidateWindows,Seal,VerifyIndex,Release,VerifyRelease,Attest,EquivalentPolicy,NoProductionEnvironment};
