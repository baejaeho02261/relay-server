'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Portable protocol/service checks only. Native KSP and actual A/B/O remain
// Windows execution evidence; these synthetic keys never generate such PASS.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const temporary=process.env.RECOVERY_WINDOWS_CONTRACT_ROOT||fs.mkdtempSync(path.join(os.tmpdir(),'game-recovery-windows-contract-'));
if(!process.env.RECOVERY_WINDOWS_CONTRACT_ROOT){
 const child=require('node:child_process').spawnSync(process.execPath,[__filename],{env:{...process.env,RECOVERY_WINDOWS_CONTRACT_ROOT:temporary},stdio:'inherit',timeout:120000});
 fs.rmSync(temporary,{recursive:true,force:true});process.exit(child.status===null?1:child.status);
}
process.env.DATA_DIR=path.join(temporary,'data');process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
for(const key of ['DESKTOP_RECOVERY_WITNESS_DIR','DESKTOP_RECOVERY_WITNESS_REQUIRED','CONNECT_TLS_CERT_FILE','CONNECT_TLS_KEY_FILE'])delete process.env[key];
const originalLog=console.log;console.log=(...args)=>{if(!String(args[0]).startsWith('[EVENT]'))originalLog(...args);};
let count=0;async function Check(name,fn){await fn();count++;console.log('PASS '+name);}
async function Main(){
 const tool=require("../../tools/recovery/peace.recovery-windows"),native=require("../../tools/recovery/peace.recovery-windows-fixture"),worker=require("../../tools/recovery/peace.recovery-drill-worker");
 await Check('backup inputs require a real original enrollment, explicit isolated unlock and separate witness',()=>{
  const backup=path.join(temporary,'backup'),witness=path.join(temporary,'witness');fs.mkdirSync(backup);fs.mkdirSync(witness);fs.mkdirSync(path.join(backup,'desktop-bootstrap'));fs.writeFileSync(path.join(backup,'desktop-bootstrap','authority.json'),'{}');fs.writeFileSync(path.join(backup,'relay-identities.json'),'{}');
  const c={version:1,backupDirectory:backup,witnessSnapshotDirectory:witness,storageEngine:'json',enrollmentId:'a'.repeat(64),machineId:'B'.repeat(64),provider:'SOFTWARE',nativeProbe:path.join(temporary,'probe.exe'),artifacts:{A:path.join(temporary,'A.exe'),B:path.join(temporary,'B.exe'),O:path.join(temporary,'O.exe')},allowIsolatedPcUnlock:true};assert.equal(tool.Config(c).provider,'SOFTWARE');
  for(const patch of [{allowIsolatedPcUnlock:false},{provider:'FALLBACK'},{enrollmentId:'unknown'},{machineId:'not-a-device'},{extra:true},{witnessSnapshotDirectory:backup},{nativeProbe:'relative.exe'},{verificationContextFile:'relative.json'}])assert.throws(()=>tool.Config({...c,...patch}));
  const without={...c};delete without.witnessSnapshotDirectory;assert.throws(()=>tool.Config(without),/WITNESS_SNAPSHOT_REQUIRED/);
 });
 await Check('canonical owned roots are accepted and symlinks never establish ownership',()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'game-recovery-drill-test-'));fs.writeFileSync(path.join(root,'test-owned-marker'),'GAME_WINDOWS_TEST_V1');try{assert.equal(tool.Root(root+path.sep+'.'),fs.realpathSync(root));if(process.platform!=='win32'){const link=path.join(temporary,'linked');fs.symlinkSync(root,link);assert.throws(()=>tool.Root(link),/PRIVATE_ROOT_REQUIRED/);}}finally{fs.rmSync(root,{recursive:true,force:true});}
 });
 await Check('report validation rejects missing real execution, swapped builds, failed cleanup and scoped provider downgrade',()=>{
  const plan={runId:'a'.repeat(32),config:{provider:'SOFTWARE'},files:Object.fromEntries(['A','B','O'].map((r,i)=>[r,{sha512:String(i).repeat(128)}]))};
  const status={runId:plan.runId,artifacts:Object.fromEntries(Object.entries(plan.files).map(([r,v])=>[r,v.sha512])),recovery:{originalProofAccepted:true,originalReplayDenied:true,oldKeyChallengeDenied:true,originalKeyStillPresent:true,originalKeyDeleted:false,replacementDeleted:true,replacementExclusiveCreated:true,replacementPrivateExportBlocked:true,originalPrivateExportBlocked:true,policyUnchanged:true,oldLicensesUnchanged:true,spentLicenseIssueRejected:true,recoveryEpochBefore:1,recoveryEpochAfter:2,nativeCleanup:{processExited:true,processExitCode:0,forcedTermination:false,gracefulInputClosed:true}},product:{machineBindingMatched:true,replacementEnrollmentMatched:true,allRolesProvedReplacement:true,runtimeRetired:true,epoch:2,consumedNewLicense:true}};
  const execution={cleanupHadToTerminateOwnedProcess:false,runId:plan.runId,windowsExecuted:true,platform:'win32',architecture:'x64',...Object.fromEntries(tool.PRODUCT_CHECKS.map(k=>[k,true]))};assert.equal(tool.Evaluate(plan,status,execution),'PASS');
  for(const key of tool.PRODUCT_CHECKS)assert.throws(()=>tool.Evaluate(plan,status,{...execution,[key]:false}));
  for(const key of Object.keys(status.recovery).filter(k=>status.recovery[k]===true))assert.throws(()=>tool.Evaluate(plan,{...status,recovery:{...status.recovery,[key]:false}},execution));
  for(const key of Object.keys(status.product).filter(k=>status.product[k]===true))assert.throws(()=>tool.Evaluate(plan,{...status,product:{...status.product,[key]:false}},execution));
  assert.throws(()=>tool.Evaluate(plan,status,{...execution,runId:'b'.repeat(32)}),/RUN_BINDING/);assert.throws(()=>tool.Evaluate(plan,status,{...execution,windowsExecuted:false}),/EXECUTION_REQUIRED/);assert.throws(()=>tool.Evaluate(plan,status,{...execution,cleanupHadToTerminateOwnedProcess:true}),/PRODUCT_FLOW_INCOMPLETE/);
  assert.throws(()=>tool.Evaluate(plan,{...status,artifacts:{...status.artifacts,O:'f'.repeat(128)}},execution),/ARTIFACT_BINDING/);
  assert.throws(()=>tool.Evaluate({...plan,config:{provider:'PLATFORM'}},status,execution),/TPM_ATTESTATION_REQUIRED/);
  assert.throws(()=>tool.Evaluate(plan,{...status,recovery:{...status.recovery,originalKeyDeleted:true}},execution),/ORIGINAL_DEVICE_PROOF/);
  for(const patch of [{processExited:false},{processExitCode:1},{forcedTermination:true},{gracefulInputClosed:false}])assert.throws(()=>tool.Evaluate(plan,{...status,recovery:{...status.recovery,nativeCleanup:{...status.recovery.nativeCleanup,...patch}}},execution),/NATIVE_CLEANUP_UNCONFIRMED/);
 });
 const childFixture=path.join(temporary,'native-cleanup-contract.js');fs.writeFileSync(childFixture,`
  const mode=process.argv[2],rl=require('node:readline').createInterface({input:process.stdin});let last=0;
  const reply=row=>process.stdout.write(JSON.stringify({version:1,requestId:last,...row})+'\\n');
  const hold=setInterval(()=>{},1000);
  rl.on('line',line=>{const r=JSON.parse(line);last=r.requestId;if(mode==='normal')reply({ok:true,originalKeyDeleted:false,originalKeyStillPresent:true,replacementDeleted:true});});
  rl.on('close',()=>{if(mode==='hang')return;clearInterval(hold);if(mode==='eof')reply({ok:false,error:'RECOVERY_PROBE_PIPE_CLOSED',originalKeyDeleted:false,replacementCleanup:'DELETED'});process.exitCode=mode==='eof'?1:0;});
 `);
 const childProbe=mode=>new native.NativeProbe('portable-test-child',temporary,{spawn:(_file,_args,options)=>require('node:child_process').spawn(process.execPath,[childFixture,mode],options),callTimeoutMs:1500,closeTimeoutMs:1500,abortGraceMs:1500});
 await Check('native close waits for process exit and duplicate close joins the same cleanup',async()=>{
  const probe=childProbe('normal'),first=probe.Close();assert.equal(probe.Close(),first);assert.equal((await first).replacementDeleted,true);assert.deepEqual(probe.CleanupState(),{gracefulInputClosed:true,forcedTermination:false,processExited:true,processExitCode:0,originalKeyDeleted:false,originalKeyStillPresent:true,replacementDeleted:true});
 });
 await Check('native request timeout sends EOF and lets finally cleanup finish before returning failure',async()=>{
  const probe=childProbe('eof');await assert.rejects(()=>probe.Call('waiting'),/RECOVERY_NATIVE_TIMEOUT/);await assert.rejects(()=>probe.Close(),/RECOVERY_NATIVE_TIMEOUT/);const state=probe.CleanupState();assert.equal(state.processExited,true);assert.equal(state.forcedTermination,false);assert.equal(state.replacementDeleted,true);assert.equal(state.originalKeyDeleted,false);assert.equal(state.processExitCode,1);
 });
 await Check('unresponsive native cleanup is bounded and forced exit cannot report replacement deletion',async()=>{
  const probe=childProbe('hang');await assert.rejects(()=>probe.Close(),/RECOVERY_NATIVE_TIMEOUT/);const state=probe.CleanupState();assert.equal(state.processExited,true);assert.equal(state.forcedTermination,true);assert.equal(state.replacementDeleted,undefined);
 });
 await Check('failed finalization removes isolated files but preserves only minimal unconfirmed key cleanup identity',()=>{
  const owned=path.join(temporary,'game-recovery-drill-failed'),backup=path.join(temporary,'backup'),witness=path.join(temporary,'witness'),output=path.join(temporary,'failed-recovery-result.json');fs.mkdirSync(owned);fs.writeFileSync(path.join(owned,'test-owned-marker'),'GAME_WINDOWS_TEST_V1');
  const runId='e'.repeat(32),token=crypto.randomBytes(32).toString('hex'),identity={runId,provider:'PLATFORM',namespace:'a'.repeat(64),creation:'EXCLUSIVE_CREATED',publicKeySha512:'b'.repeat(128),deletion:'UNCONFIRMED',manualReviewRequired:true};fs.writeFileSync(path.join(owned,'owner'),token);
  const plan={version:1,kind:'RECOVERY_WINDOWS_PRODUCT_DRILL',runId,token,data:path.join(owned,'server-data'),witness:path.join(owned,'witness'),rollback:path.join(owned,'rollback'),config:{provider:'PLATFORM',backupDirectory:backup,witnessSnapshotDirectory:witness,storageEngine:'json'},backup:require("../../tools/recovery/peace.recovery-drill").Tree(backup),witnessSnapshot:require("../../tools/recovery/peace.recovery-drill").Tree(witness),sourceManifestSha512:'0'.repeat(128),files:Object.fromEntries(['A','B','O','probe'].map(role=>[role,{source:path.join(temporary,role+'.exe'),executedCopy:path.join(owned,role==='probe'?'cozy.RecoveryDeviceProbe.exe':role+'.template.exe'),sha512:'0'.repeat(128)}]))};
  tool.Write(path.join(owned,'plan.json'),plan);tool.Write(path.join(owned,'status.json'),{runId,error:'RECOVERY_NATIVE_TIMEOUT',recovery:{replacementDeleted:false,replacementCleanup:identity,nativeCleanup:{forcedTermination:true}}});tool.Write(path.join(owned,'execution.json'),{runId,windowsExecuted:true,error:'RECOVERY_NATIVE_TIMEOUT'});
  const result=tool.Finalize(owned,output);assert.equal(result.outcome,'FAIL');assert.equal(result.isolatedCopiesRemoved,true);assert.equal(fs.existsSync(owned),false);assert.deepEqual(result.checks.replacementCleanup,identity);assert.equal(result.checks.replacementDeleted,false);assert.equal(fs.readFileSync(output,'utf8').includes(token),false);
 });
 await Check('single-stage publication removes helper logs before releasing exact report and companion bytes',()=>{
  const cleanup=require("../../tools/runtime/peace.test-evidence-cleanup"),stage=path.join(temporary,'report-stage'),output=path.join(temporary,'published-recovery.json'),companion=path.join(temporary,'published-recovery-verification.json');fs.mkdirSync(stage);fs.writeFileSync(path.join(stage,'test-owned-marker'),'GAME_WINDOWS_TEST_V1');
  const pending=path.join(stage,path.basename(output)),bytes=Buffer.from(JSON.stringify({outcome:'PASS',publicVerificationFile:companion})),proof=Buffer.from(JSON.stringify({evidenceSha512:tool.SHA(bytes)}));fs.writeFileSync(pending,bytes);fs.writeFileSync(path.join(stage,path.basename(companion)),proof);fs.writeFileSync(path.join(stage,'finalize.log'),'private helper output');
  assert.equal(cleanup.Publish(stage,null,pending,output).privateScratchRemoved,true);assert.equal(fs.existsSync(stage),false);assert.deepEqual(fs.readFileSync(output),bytes);assert.deepEqual(fs.readFileSync(companion),proof);
 });
 await Check('single-stage cleanup failure exposes neither PASS report nor PASS companion',()=>{
  const cleanup=require("../../tools/runtime/peace.test-evidence-cleanup"),stage=path.join(temporary,'report-stage-fail'),output=path.join(temporary,'unpublished-recovery.json'),companion=path.join(temporary,'unpublished-recovery-verification.json');fs.mkdirSync(stage);fs.writeFileSync(path.join(stage,'test-owned-marker'),'GAME_WINDOWS_TEST_V1');
  const pending=path.join(stage,path.basename(output));fs.writeFileSync(pending,JSON.stringify({outcome:'PASS',publicVerificationFile:companion}));fs.writeFileSync(path.join(stage,path.basename(companion)),JSON.stringify({outcome:'PASS'}));const outside=path.join(temporary,'untouched-source');fs.writeFileSync(outside,'preserve');fs.linkSync(outside,path.join(stage,'unexpected-hardlink'));
  assert.throws(()=>cleanup.Publish(stage,null,pending,output),/CLEANUP_FAILED/);assert.equal(fs.existsSync(output),false);assert.equal(fs.existsSync(companion),false);assert.equal(fs.readFileSync(outside,'utf8'),'preserve');fs.unlinkSync(path.join(stage,'unexpected-hardlink'));cleanup.Remove(stage);
 });
 worker.Load();const f=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture"),boot=require("../../services/bootstrap/peace.desktop-bootstrap"),identity=require("../../services/devices/peace.desktop-device-identity"),store=require("../../services/bootstrap/peace.desktop-bootstrap-store"),licenses=require("../../services/licensing/peace.desktop-licenses");f.Publish();boot.Publish('O','80.0.0',f.PE('O'));
 const machine=f.Device(),old=f.Device(),replacement=f.Device();let context,proved;
 const softwareProbe=key=>({Call:async(command,body)=>{assert.equal(command,'sign-original');return {signature:f.Sign(key,body.canonical)};}});
 await Check('original persistent key proof uses the real identity challenge and RSA verifier, not accepted JSON status',async()=>{
  context=native.BeginProof(machine.machineId);proved=await native.OriginalProof(softwareProbe(old),context.context,context.app,old.publicKey,'SOFTWARE');assert.equal(proved.reply.status,'ENROLLED');assert.equal(proved.reply.tpmAttested,false);assert.equal(identity.State().enrollments[proved.reply.enrollmentId].status,'ACTIVE');identity.AssertSession(store.Load().flows[context.begin.flowId],'A');
  const other=native.BeginProof(machine.machineId);await assert.rejects(()=>native.OriginalProof(softwareProbe(replacement),other.context,other.app,old.publicKey,'SOFTWARE'),/DEVICE_PROOF_INVALID/);boot.Execute({action:'abort',flowId:other.begin.flowId,downloadTicket:other.begin.downloadTicket});
 });
 await Check('recovery rejects the exact formerly accepted device signature and preserves original license rows',()=>{
  const before=structuredClone(licenses.DB().licenses),epoch=require("../../services/recovery/peace.desktop-recovery").Epoch();const recovered=worker.Recover(false,true);assert.equal(recovered.epoch,epoch+1);assert.deepEqual(licenses.DB().licenses,before);assert.throws(()=>identity.Handle(proved.body),/SERVER_SESSION_EPOCH_REVOKED|BOOTSTRAP_REVOKED/);
 });
 await Check('exclusive replacement namespace equals real product policy, old key is denied and new proof enrolls',async()=>{
  const original=identity.State().enrollments[proved.reply.enrollmentId],priorNamespace=identity.Policy().keyNamespace,generation=(identity.State().keyGenerations?.[original.bindingId]||0)+1,expected=native.Namespace(store.Load(),original.bindingId,generation);
  assert.notEqual(expected,priorNamespace);identity.Revoke({enrollmentId:original.id,expectedRevision:identity.State().revision,requestId:crypto.randomUUID(),reasonCode:'ADMIN_RECOVERY',replacementPublicKey:replacement.publicKey},'ISOLATED_TEST');
  const fresh=native.BeginProof(machine.machineId);assert.equal(identity.Handle({...fresh.context,action:'policy'}).keyNamespace,expected);assert.throws(()=>identity.Handle({...fresh.context,action:'challenge',requestId:crypto.randomUUID(),publicKey:old.publicKey,keyProvider:'SOFTWARE'}),/DEVICE_KEY_REVOKED/);
  const next=await native.OriginalProof(softwareProbe(replacement),fresh.context,fresh.app,replacement.publicKey,'SOFTWARE');assert.equal(next.reply.status,'ENROLLED');assert.equal(identity.State().enrollments[original.id].status,'RETIRED');assert.equal(identity.State().enrollments[next.reply.enrollmentId].bindingId,original.bindingId);identity.AssertSession(store.Load().flows[fresh.begin.flowId],'A');
 });
 await Check('service identity context handles protected V3 templates and automatic assigned-license B without legacy downgrade',()=>{
  for(const role of ['A','B','O'])boot.Publish(role,'81.0.0',f.PE(role,'GAME-HANDOFF-V3 SERVER_ASSIGNED_V1'));
  const fresh=native.BeginProof(machine.machineId),flow=store.Load().flows[fresh.begin.flowId];assert.equal(flow.handoffVersion,3);assert.ok(store.Load().launchers[flow.launcherId].assignedLicenseId);assert.equal(store.Load().artifacts[flow.releaseId].backgroundVersion,1);boot.Execute({action:'abort',flowId:fresh.begin.flowId,downloadTicket:fresh.begin.downloadTicket});
 });
 await Check('actual Windows fixture retains protected policy, owns jobs, finalizes after exit and never launches external host',()=>{
  const source=fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT,"../tools/recovery/peace.recovery-windows-fixture.js"),'utf8'),runner=fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT,"../tools/runtime/recovery-windows.ps1"),'utf8');
  assert.match(source,/listener\.listen\(0,'127\.0\.0\.1'/);assert.match(source,/original\.status!=='ACTIVE'/);assert.match(source,/row\.sha512!==plan\.files\[role\]\.sha512/);assert.match(source,/probe\.Call\('create-replacement'/);assert.match(source,/identity\.Revoke/);assert.match(source,/replacementPublicKey:replacement\.publicKey/);assert.match(source,/RememberCleanup\(closed\)/);assert.doesNotMatch(source,/AssertProductionConfiguration\s*=|syntheticRegression|Policy\(\)\s*=(?!=)/);
  assert.match(runner,/OwnsProcess\(\$p\.Handle\)/);assert.match(runner,/\$status\.product\.allRolesProvedReplacement/);assert.match(runner,/\$Arguments\[1\] -eq 'finalize'\)\{\$PSScriptRoot\}/);assert.match(runner,/\$server\.ExitCode -ne 0/);assert.doesNotMatch(runner,/dcc64|MSBuild|ci-evidence/);
  assert.match(source,/automaticLicense\?\{\}:\{licenseKey:license\.licenseKey\}/);assert.match(source,/license\.licenseKey=''/);assert.match(source,/publicKeySha512:tool\.SHA\(Buffer\.from\(replacement\.publicKey\)\)/);assert.match(source,/creation:'REQUESTED',publicKeySha512:null,deletion:'UNCONFIRMED'/);
  assert.match(runner,/\$stage=\[GameWindowsTests\.LifecycleFileObserver\]::CanonicalDirectory\(\$stage\)/);assert.match(runner,/CanonicalDirectory\(\[IO\.Path\]::GetDirectoryName\(\$report\)\)/);
  assert.match(runner,/'finalize',\$private,\$pending,\$report/);assert.match(runner,/publish-one \$stage \$pending \$report/);assert.match(runner,/if\(\$partial\.outcome -ne 'FAIL'\)\{throw\}/);assert.match(runner,/if\(\$failureIdentity\)\{\$failed\.checks=@\{replacementCleanup=\$failureIdentity\}\}/);assert.match(runner,/if\(\$failureCode\)\{\$exitCode=1\}/);assert(runner.indexOf("'finalize',$private,$pending,$report")<runner.indexOf('publish-one $stage $pending $report'));
  assert.match(runner,/if\(-not \$input\.automaticLicense/);assert.match(runner,/if\(\$status\.licenseUsed\)[^\n]*Remove-Item/);assert.match(runner,/\$wait\.Elapsed\.TotalSeconds -lt 20/);
 });
 console.log('RECOVERY WINDOWS CONTRACT PASS '+count+' groups; synthetic service contracts only. Actual Windows/CNG/TPM/product execution NOT_RUN.');
}
Main().catch(e=>{console.error(e);process.exitCode=1;});
