'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Portable evaluator/adapter regression, not Windows execution evidence.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const tool=require("../../tools/runtime/peace.product-fault-tests"),manual=require("../../tools/runtime/peace.manual-windows-tests");
let count=0;const test=async(name,run)=>{await run();count++;console.log('PASS '+name);};
function Result(){return require("../fixtures/runtime/peace.lifecycle-test-fixture").Attach({scenario:'overlay-lease-expiry',runId:'validator-only',nativeExecuted:true,ownedProcessesVerified:true,noOwnedProcessesRemain:true,serverStopped:true,privateFilesRemoved:true,overlayObserved:true,parentCleanupObserved:true,automaticExitObservedBeforeCleanup:true,overlayPid:13,overlayExitTick:220100,verifiedPids:[11,12,13],nativeEvents:[{version:1,runId:'validator-only',scenario:'overlay-lease-expiry',stage:'overlay-lease-expiry',event:'fault-observed',pid:13,observedTick:100500,requestStartedTick:100000,leaseMs:120000,deadlineTick:220000}],leaseWindow:{pid:13,windowHandle:12345,visibleTick:100200,hiddenTick:220030,hiddenWhileAlive:true,reappeared:false,failed:false},fixture:{scenario:'overlay-lease-expiry',runId:'validator-only',allAuthorityTerminal:true,allRuntimeSecretsRetired:true,consumedCount:1,transferCommitted:true,proof:{reuseDenied:true,reuseChecks:4},lease:{grantObserved:true,authorizedAt:1000000,grantObservedAt:1000001,expiresAt:1120000,serverObservedAt:1120100,monotonicElapsedMs:120099,prunedElapsedMs:120050,prunedAt:1120051,renewalAcceptedAfterGrant:false,cleanupCloseWithheld:true,serverExpired:true,serverTerminal:true,runtimeSecretsRetired:true,deviceRuntimeAuthorityRetired:true,oldAuthorityRejected:true}}});}
async function Main(){
 await test('all lease proof dimensions required, scoped only to dedicated product builds',()=>{assert.equal(tool.Evaluate('overlay-lease-expiry',Result()).outcome,'PASS');assert.equal(tool.Evaluate('overlay-lease-expiry',Result()).scope,'DEDICATED_PRODUCT_TESTBUILD');assert(tool.LEASE.includes('overlay-lease-expiry'));});
 const mutations={
  earlyDeadline:r=>{r.nativeEvents[0].deadlineTick=100600;r.leaseWindow.hiddenTick=100630;r.overlayExitTick=100700;},shortGrant:r=>r.nativeEvents[0].leaseMs=100,reappeared:r=>r.leaseWindow.reappeared=true,foreignPid:r=>r.nativeEvents[0].pid=99,otherWindowProcess:r=>r.leaseWindow.pid=99,windowMissing:r=>r.leaseWindow.windowHandle=0,hiddenAfterExit:r=>r.leaseWindow.hiddenWhileAlive=false,
  hiddenBeforeDeadline:r=>r.leaseWindow.hiddenTick=219990,noDeadline:r=>delete r.nativeEvents[0].deadlineTick,expiredBeforeGrant:r=>r.nativeEvents[0].observedTick=220001,
  forgedServerTime:r=>r.fixture.lease.prunedAt=1119999,noActualWait:r=>r.fixture.lease.prunedElapsedMs=10,missingActualWait:r=>delete r.fixture.lease.prunedElapsedMs,
  acceptedOldAuthority:r=>r.fixture.lease.oldAuthorityRejected=false,secretsRemain:r=>r.fixture.lease.runtimeSecretsRetired=false,deviceAuthorityRemains:r=>r.fixture.lease.deviceRuntimeAuthorityRetired=false,
  renewedLease:r=>r.fixture.lease.renewalAcceptedAfterGrant=true,serverNotExpired:r=>r.fixture.lease.serverExpired=false,notSameAbo:r=>r.parentCleanupObserved=false,
  forcedCleanup:r=>r.automaticExitObservedBeforeCleanup=false,windowNeverVisible:r=>r.leaseWindow.visibleTick=0,observerFailed:r=>r.leaseWindow.failed=true,
  slowHide:r=>r.leaseWindow.hiddenTick=224000,processDoesNotExit:r=>r.overlayExitTick=229000,missingExit:r=>delete r.overlayExitTick,
  lifetimeReused:r=>r.fixture.proof.reuseDenied=false,missingNonceRetirement:r=>r.fixture.allRuntimeSecretsRetired=false,wrongRun:r=>r.nativeEvents[0].runId='other-run'
 };
 for(const [name,mutate]of Object.entries(mutations))await test('reject '+name,()=>{const bad=Result();mutate(bad);assert.equal(tool.Evaluate('overlay-lease-expiry',bad).outcome,'FAIL');});
 await test('unexecuted native stays NOT_RUN',()=>{const r=Result();r.nativeExecuted=false;assert.equal(tool.Evaluate(r.scenario,r).outcome,'NOT_RUN');});
 await test('manual binding compares exact testbuild hashes, source, platform and underlying case',()=>{
  const hashes={A:'a'.repeat(128),B:'b'.repeat(128),O:'c'.repeat(128)},source='d'.repeat(128),evidence=Result();
  const report={version:1,runId:'validator-only',kind:'PRODUCT_FAULT_EXECUTION',environment:{platform:'win32',architecture:'x64'},sourceManifestSha512:source,sourceManifestUnchanged:true,inputsUnchanged:true,inputs:{faultArtifacts:Object.fromEntries(Object.entries(hashes).map(([role,sha512])=>[role,{sha512,unchanged:true}]))},cases:[{id:'overlay-lease-expiry',outcome:'PASS',evidence}],outcome:'PASS'};
  assert.equal(manual.EvaluateLeaseResult(report,hashes,source).outcome,'PASS');
  for(const mutate of [r=>r.version=2,r=>r.runId='wrong-run',r=>r.environment.platform='linux',r=>r.inputs.faultArtifacts.O.sha512='e'.repeat(128),r=>r.inputs.faultArtifacts.A.unchanged=false,r=>r.sourceManifestUnchanged=false,r=>r.cases[0].evidence.leaseWindow.hiddenWhileAlive=false,r=>r.outcome='FAIL']){const bad=structuredClone(report);mutate(bad);assert.equal(manual.EvaluateLeaseResult(bad,hashes,source).outcome,'FAIL');}
 });
 await test('manual V2 survives and optional V3 preserves target/testbuild distinction and changed inputs',()=>{
  const root=path.resolve(MODULE_RESOURCE_ROOT,'../..'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'lease-report-schema-')),hash=b=>crypto.createHash('sha512').update(b).digest('hex');
  try{
   const artifactFiles={},faultFiles={},hashes={};
   for(const [i,role]of ['A','B','O'].entries())for(const fault of [false,true]){const bytes=Buffer.alloc(512);bytes.writeUInt16LE(0x5a4d);bytes.writeUInt32LE(0x80,0x3c);bytes.writeUInt32LE(0x4550,0x80);bytes.writeUInt16LE(0x8664,0x84);bytes.writeUInt16LE(0x20b,0x98);bytes[300]=i+(fault?4:1);const file=path.join(temp,(fault?'fault-':'')+role+'.exe');fs.writeFileSync(file,bytes);(fault?faultFiles:artifactFiles)[role]=file;if(!fault)hashes[role]=hash(bytes);}
   const run=path.join(temp,'manual-lease-validator'),priv=path.join(temp,'private');for(const dir of [run,priv]){fs.mkdirSync(dir);fs.writeFileSync(path.join(dir,'ci-owned-marker'),'schema-only');}
   const source=hash(fs.readFileSync(path.join(root,'Relay Server/maintenance/source-manifest.json'))),context={version:1,kind:'MANUAL_VERIFICATION_CONTEXT',manifestId:'f'.repeat(128),sourceManifestSha512:source,artifacts:hashes,policy:{authorityRevision:1,authoritySha512:'a'.repeat(128),operationsRevision:1,deviceIdentityRevision:0,tlsPinGeneration:0,deploymentConfigurationSha512:'b'.repeat(128)},catalog:require("../../services/runtime/peace.desktop-verification-catalog").CATALOG,readOnly:true,usedForPublicationAuthorization:false};
   const contextFile=path.join(temp,'context.json'),input=path.join(temp,'inputs.json');fs.writeFileSync(contextFile,JSON.stringify(context));fs.writeFileSync(input,JSON.stringify({version:1,probeDirectory:temp,releaseVersion:'1.0.0',runIntegration:false,artifacts:artifactFiles,faultArtifacts:faultFiles,verificationContext:contextFile}));
   const plan=manual.Prepare(input,run,priv,process.execPath,'pwsh',true);plan.environment.nodePlatform='win32';plan.environment.nodeArchitecture='x64';fs.writeFileSync(path.join(run,'plan.json'),JSON.stringify(plan));
   assert.deepEqual(plan.stages.map(x=>x.id),require("../../services/runtime/peace.desktop-manual-verification").CURRENT_STAGES);
   const caseResult=Result(),faultHashes=Object.fromEntries(['A','B','O'].map(role=>[role,plan.inputs['fault'+role].beforeSha512]));
   const report={version:1,runId:'validator-only',kind:'PRODUCT_FAULT_EXECUTION',environment:{platform:'win32',architecture:'x64'},sourceManifestSha512:source,sourceManifestUnchanged:true,inputsUnchanged:true,inputs:{faultArtifacts:Object.fromEntries(Object.entries(faultHashes).map(([role,sha512])=>[role,{sha512,unchanged:true}]))},cases:[{id:'overlay-lease-expiry',outcome:'PASS',evidence:caseResult}],outcome:'PASS'};
   fs.writeFileSync(plan.overlayLeaseExpiry.resultFile,JSON.stringify(report));fs.writeFileSync(path.join(run,'execution.json'),JSON.stringify({startedAt:'2026-01-01T00:00:00.000Z',environment:{},stages:[],overlayLeaseExpiry:{outcome:'EXECUTED',exitCode:0}}));
   const value=manual.Finalize(run,path.join(temp,'schema-result.json')),v3=JSON.parse(fs.readFileSync(value.leaseVerificationFile)),v2=JSON.parse(fs.readFileSync(value.publicVerificationFile));
   assert.equal(v2.version,2);assert.equal(v3.version,3);assert.equal(v3.domains[0].checks[0].scope,'DEDICATED_PRODUCT_TESTBUILD');assert.deepEqual(v3.domains[0].checks[0].subjectArtifacts,faultHashes);assert.equal(v3.artifacts.O.sha512,hashes.O);assert.notEqual(v3.artifacts.O.sha512,faultHashes.O);assert.equal(v3.domains[0].checks[0].evidenceSha512,hash(fs.readFileSync(plan.overlayLeaseExpiry.resultFile)));assert.deepEqual(fs.readFileSync(value.leaseEvidenceFile),fs.readFileSync(plan.overlayLeaseExpiry.resultFile));
   const changed=fs.readFileSync(faultFiles.O);changed[400]=1;fs.writeFileSync(faultFiles.O,changed);const failed=manual.Finalize(run,path.join(temp,'changed-schema-result.json'));assert.equal(failed.overlayLeaseExpiry.outcome,'FAIL');assert.equal(failed.overlayLeaseExpiry.reason,'LEASE_TESTBUILD_CHANGED');assert.equal(JSON.parse(fs.readFileSync(failed.leaseVerificationFile)).domains[0].checks[0].outcome,'FAIL');
   const binding=plan.verificationBinding;delete plan.verificationBinding;fs.writeFileSync(path.join(run,'plan.json'),JSON.stringify(plan));const local=manual.Finalize(run,path.join(temp,'local-schema-result.json'));assert.equal(local.leaseVerificationFile,undefined);
   changed[400]=0;fs.writeFileSync(faultFiles.O,changed);plan.verificationBinding=binding;fs.writeFileSync(path.join(run,'plan.json'),JSON.stringify(plan));for(const dir of [run,priv])fs.writeFileSync(path.join(dir,'ci-owned-marker'),'GAME_WINDOWS_CI_V1');
   const pending=path.join(run,'pending.json'),output=path.join(temp,'clean-public.json'),staged=manual.Finalize(run,pending,output);require("../../tools/runtime/peace.test-evidence-cleanup").Publish(run,priv,pending,output);
   assert(!fs.existsSync(run));assert(!fs.existsSync(priv));const finalV3=JSON.parse(fs.readFileSync(staged.leaseVerificationFile));assert.equal(finalV3.domains[0].checks[0].evidenceSha512,hash(fs.readFileSync(staged.leaseEvidenceFile)));assert.equal(finalV3.domains[0].checks[0].outcome,'PASS');
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
 });
 await test('fixture observer cannot renew or synthesize leases and tests exact captured token retirement',async()=>{
  let calls=0,reject=true;const db={flows:{p:{status:'CLOSED',deviceId:'parent',machineId:'machine'}},overlays:{o:{status:'CLAIMED',sessionId:'session',deviceId:'child',machineId:'machine',sessionNonce:'nonce',ticketNonce:'ticket'}}};
  const fail=()=>{const e=Error('BOOTSTRAP_EXPIRED');e.desktopError=true;throw e;};
  const service={Execute(body){calls++;const row=db.overlays.o;if(row.status==='EXPIRED')fail();if(body.action==='overlayVerify'){const at=Date.now();row.lastVerifiedAt=at;row.sessionExpiresAt=at+40;return {status:'ACTIVE',serverTime:at,expiresAt:at+40,leaseExpiresAt:at+40,transferConfirmed:true};}return {status:'CLOSED'};}};
  const original=service.Execute,overlay={Prune(){const row=db.overlays.o;if(row.status==='CLAIMED'&&row.sessionExpiresAt<=Date.now()){row.status='EXPIRED';row.retiredAt=Date.now();delete row.sessionNonce;delete row.ticketNonce;}},AuthenticateIntegrityReport(body){assert.equal(body.sessionToken,'actual-captured-token');if(reject)fail();return {};}},adapter=require("../../ci/fixtures/peace.overlay-lease-fixture").Install({service,overlay,store:{Load:()=>db}});
  try{
   const body={action:'overlayVerify',sessionId:'session',sessionToken:'actual-captured-token',machineId:'machine'},answer=service.Execute(body),row=structuredClone(db.overlays.o);
   assert.equal(answer.leaseExpiresAt,row.sessionExpiresAt);assert.equal(answer.serverTime,row.lastVerifiedAt);assert.equal(adapter.Status().serverExpired,false);assert.deepEqual(db.overlays.o,row);
   assert.throws(()=>adapter.CheckReuse(),/BEFORE_REAL_EXPIRY/);
   assert.throws(()=>service.Execute({...body,action:'overlayClose'}),/CONNECT_DEADLINE/);assert.equal(calls,1);assert.equal(adapter.Status().cleanupCloseWithheld,true);assert.equal(db.overlays.o.status,'CLAIMED');
   await new Promise(resolve=>setTimeout(resolve,55));const status=adapter.Status();assert.equal(status.serverExpired,true);assert(status.prunedAt>=answer.leaseExpiresAt);assert(status.prunedElapsedMs>=35);assert.equal(status.runtimeSecretsRetired,true);assert.equal(adapter.CheckReuse().oldAuthorityRejected,true);
   reject=false;assert.equal(adapter.CheckReuse().oldAuthorityRejected,false);
  }finally{adapter.Dispose();assert.equal(service.Execute,original);}
 });
 await test('production startup has no lease hold and harness never closes lease O window',()=>{
  const root=path.resolve(MODULE_RESOURCE_ROOT,'../..'),native=fs.readFileSync(path.join(root,"Railway/Cozy.Source/Cozy.Overlay/Cozy.Overlay.pas"),'utf8'),observer=fs.readFileSync(path.join(root,"Relay Server/ci/fixtures/OverlayLeaseObserver.cs"),'utf8');
  assert(native.includes("{$IFDEF GAME_PRODUCT_FAULT_TESTS}"));assert(native.includes("ProductFaultLeaseGranted(FClient.LeaseRequestTick, UInt64(Lease), Deadline)"));assert(native.includes('if FLeaseRenewalHeld then'));assert(observer.includes('window==observedWindow'));assert(observer.includes('GetWindowThreadProcessId'));assert(observer.includes('WaitForSingleObject(process,0)==0x102'));assert(!/SetWindowPos|ShowWindow|SendMessage/.test(observer));
 });
 console.log(JSON.stringify({suite:'OVERLAY_LEASE_EXPIRY_CONTRACTS',checks:count,status:'PASS',windowsExecuted:false,actualLeaseIntegration:'NOT_RUN'}));
}
if(require.main===module)Main().catch(error=>{console.error(error);process.exitCode=1;});
module.exports={Result};
