'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Execution-only A/B/O fault runner. A PASS is scoped to observed fault cases;
// no build, CI, hardware, physical GPU or publication attestation is produced.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ROOT=path.resolve(MODULE_RESOURCE_ROOT,'../..');
const HANDOFF=['handoff-body-interrupt-ab','handoff-body-interrupt-bo','handoff-parent-exit-ab','handoff-parent-exit-bo','handoff-child-exit-ab','handoff-child-exit-bo'];
const GPU=['gpu-create-e-outofmemory','gpu-resize-device-removed','gpu-present-device-reset'];
const RESPONSE=Object.keys(require("../../ci/fixtures/peace.product-fault-adapter").TARGETS),REPLACEMENT=['signed-exe-replacement','signed-json-replacement'];
const TLS=['tls-session-record-authentication-failure'];
const LEASE=['overlay-lease-expiry'];
const AUTHORITY=['authority-measurement-skipped','authority-report-stopped','authority-local-stop-held'];
const LIFECYCLE_FAULT=['lifecycle-cleanup-refused','lifecycle-cleanup-scheduled'];
const LIFECYCLE=['lifecycle-cleanup-success',...LIFECYCLE_FAULT];
const SCENARIOS=Object.freeze([...HANDOFF,...RESPONSE,...REPLACEMENT,...GPU,...TLS,...LEASE,...AUTHORITY,...LIFECYCLE]);
const MARKER='GAME-PRODUCT-FAULT-TEST-V1';
const read=(file,max=64*1024*1024)=>require("../../services/artifacts/peace.bounded-artifact-read").Read(file,max);
const json=file=>JSON.parse(read(file,8*1024*1024).toString('utf8').replace(/^\uFEFF/,''));
const sha=b=>crypto.createHash('sha512').update(b).digest('hex');
const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
function Config(c){
 if(!c||c.version!==1||Object.keys(c).some(k=>!['version','releaseVersion','artifacts','faultArtifacts','scenarios','nativeReceiveProbe','verificationContext','policyFile'].includes(k))||!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(c.releaseVersion||''))throw Error('PRODUCT_FAULT_INPUT_INVALID');
 for(const group of ['artifacts','faultArtifacts'])if(c[group]!==undefined){if(!c[group]||Object.keys(c[group]).sort().join(',')!=='A,B,O')throw Error('PRODUCT_FAULT_A_B_O_REQUIRED');for(const file of Object.values(c[group]))if(typeof file!=='string'||!path.isAbsolute(file))throw Error('PRODUCT_FAULT_ABSOLUTE_PATH_REQUIRED');}
 if(c.policyFile!==undefined&&(typeof c.policyFile!=='string'||!path.isAbsolute(c.policyFile)))throw Error('PRODUCT_FAULT_POLICY_PATH_INVALID');
 if(c.verificationContext!==undefined&&(typeof c.verificationContext!=='string'||!path.isAbsolute(c.verificationContext)))throw Error('PRODUCT_FAULT_CONTEXT_ABSOLUTE_PATH_REQUIRED');
 if(c.nativeReceiveProbe!==undefined&&(typeof c.nativeReceiveProbe!=='string'||!path.isAbsolute(c.nativeReceiveProbe)))throw Error('PRODUCT_FAULT_ABSOLUTE_PATH_REQUIRED');
 if(c.scenarios!==undefined&&(!Array.isArray(c.scenarios)||!c.scenarios.length||new Set(c.scenarios).size!==c.scenarios.length||c.scenarios.some(x=>!SCENARIOS.includes(x))))throw Error('PRODUCT_FAULT_SCENARIO_INVALID');
 return {...c,scenarios:c.scenarios||[...SCENARIOS]};
}
function Marker(bytes){
 require('./peace.manual-windows-tests').Pe64(bytes);const pe=bytes.readUInt32LE(0x3c),count=bytes.readUInt16LE(pe+6),table=pe+24+bytes.readUInt16LE(pe+20);if(count<1||count>96||table>bytes.length-count*40)throw Error('PRODUCT_FAULT_PE_INVALID');
 for(let i=0;i<count;i++){const p=table+i*40,size=bytes.readUInt32LE(p+16),offset=bytes.readUInt32LE(p+20);if(offset>bytes.length-size)throw Error('PRODUCT_FAULT_PE_INVALID');if(!(bytes.readUInt32LE(p+36)&0x40000000))continue;const section=bytes.subarray(offset,offset+size);if(section.includes(Buffer.from(MARKER))||section.includes(Buffer.from(MARKER,'utf16le')))return true;}
 return false;
}
function PrepareSet(sources,out,version,testBuild,basePolicy){
 fs.mkdirSync(out);const inputs={};
 for(const role of ['A','B','O']){const bytes=read(sources[role]);if(Marker(bytes)!==testBuild)throw Error(testBuild?'PRODUCT_FAULT_TESTBUILD_MARKER_REQUIRED':'PRODUCT_FAULT_FINAL_MUST_NOT_CONTAIN_HOOKS');const copy=path.join(out,role+'.exe');fs.writeFileSync(copy,bytes,{flag:'wx',mode:0o600});inputs[role]={source:sources[role],executedCopy:copy,beforeSha512:sha(bytes)};}
 require("../artifacts/peace.audit-final-artifacts").Audit(['A','B','O'].map(r=>inputs[r].executedCopy));
 const authority=require("../../services/security/peace.desktop-security-authority"),provenance=require("../../services/artifacts/peace.desktop-release-provenance"),delegation=require("../../services/bootstrap/peace.desktop-handoff-delegation");
 const buffers=['A','B','O'].map(r=>read(inputs[r].executedCopy));if(buffers.some(b=>delegation.ArtifactVersion(b)!==3))throw Error('PRODUCT_FAULT_HANDOFF_V3_REQUIRED');
 if(buffers.some(b=>require("../../services/artifacts/peace.pe-build-configuration").ReadBuildConfiguration(b).configuration!=='RELEASE'))throw Error('PRODUCT_FAULT_OPTIMIZED_RELEASE_CONFIGURATION_REQUIRED');
 const pair=crypto.generateKeyPairSync('ed25519'),keyId=provenance.KeyId(pair.publicKey),publicKey=pair.publicKey.export({type:'spki',format:'pem'}).toString();
 const policy=authority.ValidatePolicy({...(basePolicy||authority.Defaults()),requireReleaseSignature:true,trustedReleaseKeys:[{keyId,publicKey}]});
 const artifacts={};for(const role of ['A','B','O']){artifacts[role]=inputs[role].beforeSha512;write(path.join(out,role+'.approval.json'),{keyId,signature:crypto.sign(null,Buffer.from(authority.ReleaseCanonical(role,version,artifacts[role])),pair.privateKey).toString('base64')});}
 const manifest=provenance.ValidateManifest({version:1,releaseName:version,securityVersion:1,protocol:'GAME-CONNECT-4',hashVersion:3,handoffVersion:3,sourceManifestSha512:sha(read(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'),8*1024*1024)),policySha512:provenance.PolicyDigest(policy),toolchain:{delphi:testBuild?'IDE_PREBUILT_PRODUCT_FAULT_TESTBUILD':'IDE_PREBUILT_FINAL_NOT_OBSERVED',cpp:'NOT_OBSERVED',windowsSdk:'NOT_OBSERVED',imgui:'NOT_OBSERVED'},artifacts});
 write(path.join(out,'policy.json'),policy);write(path.join(out,'manifest.json'),{manifest,manifestId:provenance.ManifestId(manifest)});return inputs;
}
function Prepare(input,run,privateRoot){
 const c=Config(json(input));for(const root of [run,privateRoot])if(!fs.existsSync(path.join(root,'ci-owned-marker')))throw Error('PRODUCT_FAULT_OWNED_ROOT_REQUIRED');
 const policyService=require("../../services/security/peace.desktop-security-authority"),selectedPolicy=c.policyFile?policyService.ValidatePolicy(json(c.policyFile)):policyService.Defaults();
 if(c.policyFile&&selectedPolicy.requireReleaseSignature!==true)throw Error('PRODUCT_FAULT_SIGNED_POLICY_REQUIRED');
 const basePolicy={...selectedPolicy,requireReleaseSignature:true};
 const effectivePolicy={...basePolicy};delete effectivePolicy.trustedReleaseKeys;const testPolicySha512=sha(require("../../services/artifacts/peace.desktop-release-provenance").Stable(effectivePolicy));
 const inputs={},sets={},errors={};for(const [group,test] of [['artifacts',false],['faultArtifacts',true]])if(c[group]){sets[group]=path.join(privateRoot,group);try{inputs[group]=PrepareSet(c[group],sets[group],c.releaseVersion,test,basePolicy);}catch(e){errors[group]=/^[A-Z0-9_]+$/.test(e.message)?e.message:'PRODUCT_FAULT_PREPARATION_FAILED';}}
 const plan={version:1,testPolicySha512,policyScope:'EXACT_SETTINGS_EXCEPT_DISPOSABLE_TEST_TRUST_KEYS',kind:'PRODUCT_FAULT_EXECUTION',runId:crypto.randomUUID(),startedAt:new Date().toISOString(),sourceManifestSha512:sha(read(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'),8*1024*1024)),releaseVersion:c.releaseVersion,inputs,scenarios:c.scenarios.map(id=>{const testBuild=HANDOFF.includes(id)||GPU.includes(id)||LEASE.includes(id)||AUTHORITY.includes(id)||LIFECYCLE_FAULT.includes(id),group=testBuild?'faultArtifacts':'artifacts';return {id,testBuild,artifacts:sets[group],scope:testBuild?'DEDICATED_PRODUCT_TESTBUILD':'SELECTED_FINAL_RELEASE',...(!sets[group]?{skip:'A_B_O_PATHS_REQUIRED'}:{}),...(errors[group]?{skip:errors[group],preparationFailed:true}:{})};})};
 if(c.verificationContext){
  plan.verificationBinding=require("../artifacts/peace.verification-report").Binding(json(c.verificationContext));
  if(plan.verificationBinding.sourceManifestSha512!==plan.sourceManifestSha512)throw Error('PRODUCT_FAULT_CONTEXT_SOURCE_MISMATCH');
  for(const role of ['A','B','O'])if(inputs.artifacts?.[role]?.beforeSha512!==plan.verificationBinding.artifacts[role])throw Error('PRODUCT_FAULT_CONTEXT_ARTIFACT_MISMATCH');
 }
 if(c.nativeReceiveProbe){const destination=path.join(privateRoot,'cozy.TlsReceiveProbe.exe'),bytes=read(c.nativeReceiveProbe);require('./peace.manual-windows-tests').Pe64(bytes);fs.writeFileSync(destination,bytes,{flag:'wx'});plan.nativeReceiveProbe=destination;plan.inputs.tls={probe:{source:c.nativeReceiveProbe,executedCopy:destination,beforeSha512:sha(bytes)}};}
 write(path.join(run,'plan.json'),plan);return plan;
}
function Evaluate(id,r){
 if(!r||r.nativeExecuted!==true)return {outcome:'NOT_RUN',reason:r?.reason||'NATIVE_EXECUTION_NOT_OBSERVED'};
 const fail=reason=>({outcome:'FAIL',reason});
 if(r.error)return fail(r.error);
 if(r.scenario!==id||r.fixture?.scenario!==id||r.fixture.runId!==r.runId)return fail('PRODUCT_FAULT_RUN_BINDING_MISMATCH');
 if(!r.ownedProcessesVerified||!r.noOwnedProcessesRemain||!r.serverStopped||!r.privateFilesRemoved)return fail('PRODUCT_FAULT_CLEANUP_INCOMPLETE');
 if(!r.fixture.allAuthorityTerminal||!r.fixture.allRuntimeSecretsRetired||r.fixture.proof?.reuseDenied!==true||r.fixture.proof.reuseChecks<1)return fail('PRODUCT_FAULT_TERMINAL_REUSE_PROOF_MISSING');
 if(RESPONSE.includes(id)){
  const p=r.fixture.proof;if(p.requested!==id||p.observed!==true||p.droppedResponses!==1||['retryObserved','sameBusinessRequest','sameCommittedResult','noDoubleConsumption','noDuplicateDelegation','distinctChildren'].some(k=>p[k]!==true)||r.fixture.consumedCount!==1||r.overlayObserved!==true||r.parentCleanupObserved!==true)return fail('PRODUCT_FAULT_COMMIT_RETRY_PROOF_MISSING');
 }else if(REPLACEMENT.includes(id)){
  if(!r.fixture.replacementObserved||!r.fixture.replacementDenied||r.fixture.flowCount!==0||r.fixture.overlayCount!==0||r.fixture.consumedCount!==0)return fail('PRODUCT_FAULT_REPLACEMENT_REJECTION_MISSING');
 }else if(TLS.includes(id)){
  if(r.parentCleanupObserved!==true||r.tlsArmRequestedAfterParentExit!==true||r.overlayObserved!==true||r.fixture.tlsArmedAfterTransfer!==true||r.fixture.tlsRecordCorrupted!==true||r.fixture.tlsMutationCount!==1||r.fixture.consumedCount!==1)return fail('PRODUCT_FAULT_TLS_SESSION_FAULT_MISSING');
 }else if(LEASE.includes(id)){
  const event=(r.nativeEvents||[]).find(e=>e.version===1&&e.runId===r.runId&&e.scenario===id&&e.stage===id&&e.event==='fault-observed'&&e.pid===r.overlayPid&&r.verifiedPids?.includes(e.pid));
  const lease=r.fixture.lease,window=r.leaseWindow;
  if(!event||['deadlineTick','observedTick','requestStartedTick','leaseMs'].some(k=>!Number.isSafeInteger(event[k])||event[k]<1)||event.leaseMs>120000||event.requestStartedTick>event.observedTick||event.requestStartedTick+event.leaseMs!==event.deadlineTick||event.observedTick>=event.deadlineTick)return fail('LEASE_NATIVE_DEADLINE_BINDING_MISSING');
  if(!lease||['authorizedAt','expiresAt','grantObservedAt','serverObservedAt','prunedAt','prunedElapsedMs','monotonicElapsedMs'].some(k=>!Number.isSafeInteger(lease[k])||lease[k]<1)||lease.grantObserved!==true||lease.renewalAcceptedAfterGrant!==false||lease.serverExpired!==true||lease.serverTerminal!==true||lease.runtimeSecretsRetired!==true||lease.deviceRuntimeAuthorityRetired!==true||lease.oldAuthorityRejected!==true||lease.expiresAt-lease.authorizedAt!==event.leaseMs||lease.grantObservedAt<lease.authorizedAt||lease.grantObservedAt>=lease.expiresAt||lease.serverObservedAt<lease.expiresAt||lease.prunedAt<lease.expiresAt||lease.prunedElapsedMs+2<lease.expiresAt-lease.grantObservedAt||lease.monotonicElapsedMs<lease.prunedElapsedMs)return fail('LEASE_ACTUAL_EXPIRY_RETIREMENT_MISSING');
  if(!r.overlayObserved||!r.parentCleanupObserved||r.fixture.consumedCount!==1||r.fixture.transferCommitted!==true||r.automaticExitObservedBeforeCleanup!==true)return fail('LEASE_SAME_ABO_LIFETIME_MISSING');
  if(!window||['pid','windowHandle','visibleTick','hiddenTick'].some(k=>!Number.isSafeInteger(window[k])||window[k]<1)||!Number.isSafeInteger(r.overlayExitTick)||window.pid!==r.overlayPid||window.failed!==false||window.hiddenWhileAlive!==true||window.reappeared!==false||window.visibleTick>=event.deadlineTick||window.hiddenTick<event.deadlineTick||window.hiddenTick>event.deadlineTick+3000||window.hiddenTick<window.visibleTick||r.overlayExitTick<window.hiddenTick||r.overlayExitTick>window.hiddenTick+7000)return fail('LEASE_AUTOMATIC_HIDE_BEFORE_EXIT_MISSING');
 }else if(AUTHORITY.includes(id)){
  const verdict=require("../security/peace.security-authority-contract").EvaluateCase(id,r);if(verdict.outcome!=='PASS')return verdict;
 }else if(LIFECYCLE.includes(id)){
  if(r.fixture.consumedCount!==1||r.fixture.flowCount!==1||r.fixture.overlayCount!==1||r.fixture.transferCommitted!==true)return fail('LIFECYCLE_PRODUCT_FLOW_INCOMPLETE');
 }else{
  const expectedStage=HANDOFF.includes(id)?'handoff-body-'+id.slice(-2):id;
  const events=(r.nativeEvents||[]).filter(e=>e.stage===expectedStage&&e.version===1&&e.runId===r.runId&&e.scenario===id&&Number.isSafeInteger(e.pid)&&r.verifiedPids?.includes(e.pid));
  if(!events.some(e=>e.event==='fault-observed'))return fail('PRODUCT_FAULT_REQUESTED_FAULT_NOT_OBSERVED');
  if(HANDOFF.includes(id)&&(r.fixture.transferCommitted!==false||r.fixture.overlayAuthorized!==false||r.fixture.flowCount!==1||r.fixture.overlayCount!==(id.endsWith('-ab')?0:1)||r.fixture.consumedCount!==(id.endsWith('-ab')?0:1)))return fail('PRODUCT_FAULT_HANDOFF_FAIL_CLOSED_MISSING');
  if(GPU.includes(id)&&(r.fixture.consumedCount!==1||r.fixture.overlayCount!==1))return fail('PRODUCT_FAULT_RENDERER_PRODUCT_SESSION_MISSING');
  if(HANDOFF.includes(id)&&!events.some(e=>e.event==='handoff-body-written'&&e.bytesWritten>4&&e.bytesWritten<e.totalBytes))return fail('PRODUCT_FAULT_PARTIAL_BODY_NOT_OBSERVED');
  if(id.includes('child-exit')&&r.ownedChildTerminated!==true)return fail('PRODUCT_FAULT_OWNED_CHILD_EXIT_NOT_OBSERVED');
  if(id.includes('parent-exit')&&(r.parentExitObserved!==true||r.parentExitCode!==197))return fail('PRODUCT_FAULT_PARENT_EXIT_NOT_OBSERVED');
 }
 if(LEASE.includes(id)||LIFECYCLE.includes(id)){const lifecycle=require('./peace.lifecycle-test-contract').Evaluate(id,r);if(lifecycle.outcome!=='PASS')return lifecycle;}
 return {outcome:'PASS',scope:HANDOFF.includes(id)||GPU.includes(id)||LEASE.includes(id)||AUTHORITY.includes(id)||LIFECYCLE_FAULT.includes(id)?'DEDICATED_PRODUCT_TESTBUILD':'SELECTED_FINAL_RELEASE'};
}
function EvaluateReceive(result,expectedSha){
 if(!result)return {outcome:'NOT_RUN',reason:'PREBUILT_TLS_RECEIVE_PROBE_REQUIRED'};
 if(result.outcome!=='PASS')return result;
 const cases=require("../integrity/peace.native-receive-fixture").Cases();
 if(result.nativeExecuted!==true||result.inputsUnchanged!==true||result.scope!=='ISOLATED_NATIVE_RECEIVE_BOUNDARIES_ONLY'||!expectedSha||result.probeSha512!==expectedSha||!Array.isArray(result.cases)||result.cases.length!==cases.length||new Set(result.cases.map(x=>x.id)).size!==cases.length||cases.some(c=>!result.cases.some(x=>x.id===c.id&&x.outcome==='PASS'&&x.observed?.nativeReceiveExecuted===true)))return {...result,outcome:'FAIL',reason:'PRODUCT_FAULT_RECEIVE_PROOF_INCOMPLETE'};
 return result;
}
function BuildVerification(plan,result,evidenceSha512){
 const binding=plan.verificationBinding;if(!binding)return null;
 if(result.environment?.platform!=='win32'||result.environment?.architecture!=='x64'||!Number.isFinite(Date.parse(plan.startedAt)))return null;
 const checks=[];
 for(const row of result.cases){
  if(!LEASE.includes(row.id)&&!LIFECYCLE.includes(row.id))continue;
  const group=row.id==='lifecycle-cleanup-success'?'artifacts':'faultArtifacts',subjectArtifacts=Object.fromEntries(['A','B','O'].map(role=>[role,result.inputs[group]?.[role]?.sha512]));
  if(Object.values(subjectArtifacts).some(x=>typeof x!=='string'||!/^[a-f0-9]{128}$/.test(x)))continue;
  const actual=row.evidence?.nativeExecuted===true,changed=['A','B','O'].some(role=>result.inputs[group][role].unchanged!==true),outcome=actual?(changed?'FAIL':row.outcome):'NOT_RUN';
  checks.push({id:row.id,outcome,scope:group==='artifacts'?'SELECTED_FINAL_ABO':'DEDICATED_PRODUCT_TESTBUILD',execution:actual?'WINDOWS_EXECUTED':'NOT_EXECUTED',evidenceSha512:actual?evidenceSha512:null,reasonCode:outcome==='PASS'?'':actual&&changed?'PRODUCT_FAULT_INPUT_CHANGED':row.reason||'NATIVE_EXECUTION_NOT_OBSERVED',subjectArtifacts});
 }
 if(!checks.length)return null;
 return require("../../services/runtime/peace.desktop-manual-verification").ValidateReport({version:3,kind:'MANUAL_VERIFICATION',runId:result.runId+'-lifecycle',startedAt:plan.startedAt,finishedAt:result.finishedAt,platform:'win32',architecture:'x64',manifestId:binding.manifestId,sourceManifestSha512:plan.sourceManifestSha512,sourceManifestUnchanged:result.sourceManifestUnchanged,artifacts:Object.fromEntries(['A','B','O'].map(role=>[role,{sha512:binding.artifacts[role],unchanged:result.inputs.artifacts?.[role]?.unchanged===true&&result.inputs.artifacts[role].sha512===binding.artifacts[role]}])),policy:binding.policy,domains:[{id:'9',checks}],nativeBuild:'NOT_RUN',hardwareAttested:false,ciEvidenceCreated:false,publicationApproval:false});
}
function Finalize(run,resultFile,publicResultFile=resultFile){
 const plan=json(path.join(run,'plan.json')),execution=json(path.join(run,'execution.json'));const cases=plan.scenarios.map(s=>{const r=execution.scenarios.find(x=>x.scenario===s.id);return {id:s.id,...(s.skip?{outcome:s.preparationFailed?'FAIL':'NOT_RUN',reason:s.skip}:r&&r.runId!==plan.runId?{outcome:'FAIL',reason:'PRODUCT_FAULT_RUN_BINDING_MISMATCH'}:Evaluate(s.id,r)),...(r?{evidence:r}:{})};});
 const inputs=Object.fromEntries(Object.entries(plan.inputs).map(([set,rows])=>[set,Object.fromEntries(Object.entries(rows).map(([role,row])=>{let unchanged=false;try{unchanged=sha(read(row.source))===row.beforeSha512&&sha(read(row.executedCopy))===row.beforeSha512;}catch(_){}return [role,{sha512:row.beforeSha512,unchanged}];}))]));
 let sourceManifestUnchanged=false;try{sourceManifestUnchanged=sha(read(path.join(ROOT,'Relay Server/maintenance/source-manifest.json'),8*1024*1024))===plan.sourceManifestSha512;}catch(_){}
 const unchanged=Object.values(inputs).every(rows=>Object.values(rows).every(x=>x.unchanged));
 const result={version:1,testPolicySha512:plan.testPolicySha512,policyScope:plan.policyScope,kind:'PRODUCT_FAULT_EXECUTION',runId:plan.runId,startedAt:plan.startedAt||null,finishedAt:new Date().toISOString(),sourceManifestSha512:plan.sourceManifestSha512,sourceManifestUnchanged,environment:execution.environment||{},nativeBuild:'NOT_RUN',ciEvidenceCreated:false,hardwareAttested:false,publicationApproval:false,inputs,inputsUnchanged:unchanged,cases,nativeReceive:EvaluateReceive(execution.nativeReceive,plan.inputs.tls?.probe?.beforeSha512),scope:'Only observed cases. Dedicated test builds are never final release artifacts. TLS receive corpus is an isolated real SChannel boundary test, not A/B/O session proof. Physical GPU/driver removal and native signed-file TOCTOU remain separate.',outcome:!unchanged||!sourceManifestUnchanged||cases.some(x=>x.outcome==='FAIL')?'FAIL':cases.some(x=>x.outcome!=='PASS')?'INCOMPLETE':'PASS'};
 if(result.nativeReceive.outcome==='FAIL')result.outcome='FAIL';else if(result.nativeReceive.outcome!=='PASS'&&result.outcome==='PASS'&&!plan.scenarios.every(s=>LEASE.includes(s.id)||AUTHORITY.includes(s.id)||LIFECYCLE.includes(s.id)))result.outcome='INCOMPLETE';
 const candidate=BuildVerification(plan,result,'0'.repeat(128));
 if(candidate)result.publicVerificationFile=path.join(path.dirname(publicResultFile),path.basename(publicResultFile,'.json')+'-verification.json');
 write(resultFile,result);
 if(candidate){const evidenceSha512=sha(read(resultFile,16*1024*1024));write(path.join(path.dirname(resultFile),path.basename(resultFile,'.json')+'-verification.json'),BuildVerification(plan,result,evidenceSha512));}
 return result;
}
if(require.main===module){try{const [action,...args]=process.argv.slice(2);let result;if(action==='prepare'&&args.length===3)result=Prepare(...args);else if(action==='finalize'&&[2,3].includes(args.length))result=Finalize(...args);else throw Error('PRODUCT_FAULT_ARGUMENTS_INVALID');console.log(JSON.stringify({outcome:result.outcome||'PREPARED',ciEvidenceCreated:false}));if(result.outcome==='FAIL')process.exitCode=1;}catch(e){console.error(/^[A-Z0-9_]+$/.test(e.message)?e.message:'PRODUCT_FAULT_TOOL_FAILED');process.exitCode=1;}}
module.exports={SCENARIOS,HANDOFF,GPU,TLS,LEASE,AUTHORITY,LIFECYCLE,LIFECYCLE_FAULT,RESPONSE,REPLACEMENT,MARKER,Config,Marker,PrepareSet,Prepare,Evaluate,EvaluateReceive,BuildVerification,Finalize};
