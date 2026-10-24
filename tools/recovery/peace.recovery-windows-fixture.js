'use strict';
// Own-process fixture only. Uses the restored stores and their protected active
// release; it never substitutes synthetic PE files, keys, trust or PASS reports.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const tool=require('./peace.recovery-windows'),drill=require('./peace.recovery-drill');
function Fail(code){throw Error(code);}
class NativeProbe {
 constructor(executable,root,options={}){
  this.id=0;this.buffer='';this.pending=null;this.done=false;this.forced=false;this.inputClosed=false;this.cleanup={};this.callTimeoutMs=options.callTimeoutMs||90000;this.closeTimeoutMs=options.closeTimeoutMs||5000;this.abortGraceMs=options.abortGraceMs||5000;
  this.child=(options.spawn||cp.spawn)(executable,[],{cwd:root,stdio:['pipe','pipe','ignore'],windowsHide:true});
  this.exited=new Promise(resolve=>this.child.once('close',(code,signal)=>{this.done=true;this.exitCode=code;this.exitSignal=signal;clearTimeout(this.abortTimer);if(this.pending)this.Abort('RECOVERY_NATIVE_EARLY_EXIT');this.buffer='';resolve();}));
  this.child.stdout.setEncoding('utf8');this.child.stdout.on('data',text=>{
   this.buffer+=text;if(Buffer.byteLength(this.buffer)>65536){this.buffer='';return this.Abort('RECOVERY_NATIVE_RESPONSE_LIMIT');}let end;
   while((end=this.buffer.indexOf('\n'))>=0){const line=this.buffer.slice(0,end).replace(/\r$/,'');this.buffer=this.buffer.slice(end+1);let row;try{row=JSON.parse(line);}catch(_){return this.Abort('RECOVERY_NATIVE_RESPONSE_INVALID');}
    // After EOF the native error reply may confirm its finally cleanup. It is
    // diagnostic only: a failed/forced run can never become a successful run.
    if(row.version===1&&row.requestId===this.id)this.ObserveCleanup(row);
    if(this.failure)continue;
    const p=this.pending;if(!p||row.version!==1||row.requestId!==p.id)return this.Abort('RECOVERY_NATIVE_RESPONSE_BINDING');clearTimeout(p.timer);this.pending=null;
    if(row.ok!==true){const code=/^[A-Z0-9_]{3,100}$/.test(row.error||'')?row.error:'RECOVERY_NATIVE_FAILED';p.reject(Error(code));this.Abort(code);}else p.resolve(row);
   }
  });
  this.child.on('error',()=>this.Abort('RECOVERY_NATIVE_LAUNCH_FAILED'));this.child.stdin.on('error',()=>this.Abort('RECOVERY_NATIVE_WRITE_FAILED'));
 }
 ObserveCleanup(row){for(const key of ['originalKeyDeleted','originalKeyStillPresent','replacementDeleted'])if(typeof row[key]==='boolean')this.cleanup[key]=row[key];if(row.replacementCleanup==='DELETED')this.cleanup.replacementDeleted=true;}
 EndInput(){if(this.inputClosed)return;this.inputClosed=true;try{this.child.stdin.end();}catch(_){}}
 Force(){if(this.done||this.forced)return;this.forced=true;try{this.child.kill();}catch(_){}}
 Abort(code){if(this.pending){clearTimeout(this.pending.timer);this.pending.reject(Error(code));this.pending=null;}this.failure=this.failure||code;this.EndInput();if(!this.done&&!this.abortTimer)this.abortTimer=setTimeout(()=>this.Force(),this.abortGraceMs);}
 Call(command,body={},timeout=this.callTimeoutMs){if(this.pending||this.failure||this.done||this.inputClosed||this.child.exitCode!==null)return Promise.reject(Error('RECOVERY_NATIVE_NOT_READY'));const id=++this.id;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.Abort('RECOVERY_NATIVE_TIMEOUT'),timeout);this.pending={id,timer,resolve,reject};try{this.child.stdin.write(JSON.stringify({version:1,requestId:id,command,...body})+'\n',error=>{if(error)this.Abort('RECOVERY_NATIVE_WRITE_FAILED');});}catch(_){this.Abort('RECOVERY_NATIVE_WRITE_FAILED');}});}
 async WaitForExit(){let timer;try{await Promise.race([this.exited,new Promise(resolve=>{timer=setTimeout(resolve,this.abortGraceMs+1000);})]);}finally{clearTimeout(timer);}if(!this.done){this.Force();let last;try{await Promise.race([this.exited,new Promise(resolve=>{last=setTimeout(resolve,1000);})]);}finally{clearTimeout(last);}}}
 Close(){if(!this.closing)this.closing=(async()=>{let answer,error;try{if(this.failure)throw Error(this.failure);answer=await this.Call('close',{},this.closeTimeoutMs);}catch(e){error=e;this.Abort(e.message);}finally{this.EndInput();await this.WaitForExit();}if(error)throw error;if(this.failure||!this.done||this.forced||this.exitCode!==0)Fail(this.failure||'RECOVERY_NATIVE_CLOSE_FAILED');return answer;})();return this.closing;}
 CleanupState(){return {gracefulInputClosed:this.inputClosed,forcedTermination:this.forced,processExited:this.done,processExitCode:this.done?this.exitCode:null,...this.cleanup};}
}
function Namespace(db,binding,generation){return crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update('GAME-DEVICE-KEY-NAMESPACE-V2'+(generation?'\n'+binding+'\n'+generation:'')).digest('hex');}
function ProtectedPolicy(){const i=require("../../services/devices/peace.desktop-device-identity").State();return tool.SHA(Buffer.from(JSON.stringify([require("../../services/security/peace.desktop-security-authority").Policy(),i.mode,i.requireForEnrolled,i.trust||null])));}
function BeginProof(machineId){
 const f=require("../../tests/fixtures/bootstrap/peace.desktop-bootstrap-fixture"),boot=require("../../services/bootstrap/peace.desktop-bootstrap"),licenses=require("../../services/licensing/peace.desktop-licenses"),store=require("../../services/bootstrap/peace.desktop-bootstrap-store");
 const app=f.Device();app.machineId=machineId;const license=licenses.Create({requestId:crypto.randomUUID(),label:'Isolated recovery identity challenge'},'ISOLATED_RECOVERY');
 const issue=boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Isolated recovery identity challenge',licenseId:license.license.id},'ISOLATED_RECOVERY');
 const bytes=boot.LauncherBytes(issue.launcherId),config=f.Config(bytes),code=f.CodeImage(bytes),version=store.Load().artifacts[store.Load().active.A].handoffVersion||1;
 const begin=boot.Execute({action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:config.launcherTicket,launcherSha512:f.sha512(bytes),launcherCrc64:f.Crc64(bytes),aCodeSha512:code.sha512,aCodeCrc64:code.crc64,machineId,publicKey:app.publicKey,deviceId:app.deviceId,handoffVersion:version});
 return {app,begin,context:{stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId}};
}
async function OriginalProof(probe,context,app,key,provider,which='original'){
 if(!['original','replacement'].includes(which))Fail('RECOVERY_PROBE_KEY_INVALID');
 const identity=require("../../services/devices/peace.desktop-device-identity"),f=require("../../tests/fixtures/bootstrap/peace.desktop-bootstrap-fixture");
 const challenge=identity.Handle({...context,action:'challenge',requestId:crypto.randomUUID(),publicKey:key,keyProvider:provider});
 const signature=(await probe.Call('sign-'+which,{canonical:challenge.canonical})).signature;
 const body={...context,action:'complete',challengeId:challenge.challengeId,signature,appSignature:f.Sign(app,challenge.canonical)};
 if(challenge.requireTpm)body.tpmEvidence=(await probe.Call('evidence-'+which,{nonce:challenge.nonce})).evidence;
 let reply=identity.Handle(body);if(reply.status==='TPM_ACTIVATION_REQUIRED'){
  const activated=await probe.Call('activate-'+which,{activationBlob:reply.activationBlob});
  reply=identity.Handle({...context,action:'tpmActivate',challengeId:reply.challengeId,secret:activated.secret,signature:(await probe.Call('sign-'+which,{canonical:reply.activationCanonical})).signature,appSignature:f.Sign(app,reply.activationCanonical)});
 }
 if(reply.status!=='ENROLLED')Fail('RECOVERY_ORIGINAL_PROOF_NOT_ACCEPTED');
 return {body,reply};
}
async function Main(root){
 let plan,probe,listener,timer,stopping=false;const status={version:1,ready:false,phase:'load',runId:'',recovery:{}};
 const Write=()=>{const target=path.join(root,'status.json'),tmp=target+'.next';fs.writeFileSync(tmp,JSON.stringify(status),{mode:0o600});try{fs.renameSync(tmp,target);}catch(e){if(!['EPERM','EBUSY','EACCES'].includes(e.code))throw e;}};
 function RememberCleanup(closed){
  const state=probe?.CleanupState()||{};status.recovery.nativeCleanup=state;
  for(const key of ['originalKeyDeleted','originalKeyStillPresent','replacementDeleted'])if(typeof closed?.[key]==='boolean')status.recovery[key]=closed[key];else if(typeof state[key]==='boolean')status.recovery[key]=state[key];
  if(status.recovery.replacementCleanup){status.recovery.replacementCleanup.deletion=status.recovery.replacementDeleted===true?'CONFIRMED':'UNCONFIRMED';status.recovery.replacementCleanup.manualReviewRequired=status.recovery.replacementDeleted!==true;}
 }
 try{
  if(process.platform!=='win32'||process.arch!=='x64')Fail('RECOVERY_WINDOWS_X64_REQUIRED');root=tool.Root(root);plan=tool.LoadPlan(root);status.runId=plan.runId;
  if(fs.readFileSync(path.join(root,'owner'),'utf8')!==plan.token)Fail('RECOVERY_WINDOWS_OWNER_REQUIRED');
  for(const key of Object.keys(process.env))if(/SECRET|TOKEN|KEY|RAILWAY|CONNECT_TLS|VAPID|DESKTOP_|WEB_ADMIN_|DATA_DIR|HA_|GAME_/.test(key))delete process.env[key];
  Object.assign(process.env,drill.ChildEnvironment(root,plan.token,plan.data,plan.witness,plan.config.storageEngine),{WEB_ADMIN_PORT:'0',CONNECT_TCP_PORT:'1',HEALTH_PORT:'0',ENABLE_LEGACY_TCP_ADMIN:'0',DESKTOP_PUBLIC_PORT:'1'});
  console.log=()=>{};console.error=()=>{};Write();
  const worker=require('./peace.recovery-drill-worker');worker.Load();
  const store=require("../../services/bootstrap/peace.desktop-bootstrap-store"),boot=require("../../services/bootstrap/peace.desktop-bootstrap"),identity=require("../../services/devices/peace.desktop-device-identity"),licenses=require("../../services/licensing/peace.desktop-licenses"),recovery=require("../../services/recovery/peace.desktop-recovery"),machine=require("../../services/devices/peace.desktop-machine-policy");
  const original=structuredClone(identity.State().enrollments[plan.config.enrollmentId]);
  if(!original||original.status!=='ACTIVE'||require("../../services/devices/peace.desktop-device-registry").BindingId(plan.config.machineId)!==original.bindingId)Fail('RECOVERY_ORIGINAL_ENROLLMENT_MISMATCH');
  if((original.assurance==='TPM_KEY_ATTESTED'||identity.State().mode==='TPM_ATTESTED')&&plan.config.provider!=='PLATFORM')Fail('RECOVERY_ORIGINAL_TPM_PROVIDER_REQUIRED');
  const policyBefore=ProtectedPolicy(),oldLicenses=structuredClone(licenses.DB().licenses),spent=Object.values(oldLicenses).filter(r=>r.consumed&&r.machineId===plan.config.machineId);
  if(!spent.length)Fail('RECOVERY_ORIGINAL_SPENT_LICENSE_REQUIRED');
  status.artifacts={};for(const role of ['A','B','O']){const row=store.Load().artifacts[store.Load().active[role]];if(!row||row.sha512!==plan.files[role].sha512||tool.SHA(boot.ReadArtifactBytes(row))!==row.sha512)Fail('RECOVERY_ACTIVE_ARTIFACT_MISMATCH');require("../../services/artifacts/peace.pe-build-configuration").AssertProductionConfiguration(boot.ReadArtifactBytes(row));status.artifacts[role]=row.sha512;}
  if(plan.verification){const db=store.Load(),pair=require("../../services/security/peace.desktop-security-operations").PreviewPair({aId:db.active.A,bId:db.active.B,oId:db.active.O});if(!pair.eligible||pair.release.manifestId!==plan.verification.binding.manifestId)Fail('RECOVERY_WINDOWS_ACTIVE_MANIFEST_MISMATCH');}
  const selected=Object.fromEntries(['A','B','O'].map(r=>[r,store.Load().active[r]]));
  if(machine.Public(plan.config.machineId).blocked)machine.Set(plan.config.machineId,false,{requestId:crypto.randomUUID(),reason:'Isolated backup recovery drill only'},'ISOLATED_RECOVERY');
  listener=require("../../services/network/peace.desktop-connect").CreateServer();await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(0,'127.0.0.1',resolve);});process.env.DESKTOP_PUBLIC_PORT=String(listener.address().port);
  const originalContext=BeginProof(plan.config.machineId),policy=identity.Handle({...originalContext.context,action:'policy'});
  probe=new NativeProbe(plan.files.probe.executedCopy,root);status.phase='original-device-proof';Write();
  const opened=await probe.Call('init',{namespace:policy.keyNamespace,provider:plan.config.provider,expectedPublicKey:original.publicKey,runId:plan.runId});
  if(opened.namespace!==policy.keyNamespace||opened.publicKey!==original.publicKey||opened.privateExportBlocked!==true||opened.provider!==plan.config.provider)Fail('RECOVERY_ORIGINAL_NATIVE_KEY_MISMATCH');
  const proved=await OriginalProof(probe,originalContext.context,originalContext.app,original.publicKey,plan.config.provider);
  if(proved.reply.enrollmentId!==original.id||plan.config.provider==='PLATFORM'&&proved.reply.tpmAttested!==true)Fail('RECOVERY_ORIGINAL_ENROLLMENT_MISMATCH');
  Object.assign(status.recovery,{originalEnrollmentId:original.id,originalProofAccepted:true,originalProofScope:'NATIVE_PERSISTENT_KEY_WITH_SERVICE_CREATED_A_CONTEXT',originalPrivateExportBlocked:true,originalTpmAttested:proved.reply.tpmAttested===true,recoveryEpochBefore:recovery.Epoch()});
  status.phase='recovery';Write();const recovered=worker.Recover(false,true);status.recovery.recoveryEpochAfter=recovered.epoch;
  worker.Denied(()=>identity.Handle(proved.body),['SERVER_SESSION_EPOCH_REVOKED','BOOTSTRAP_FLOW_INVALID','BOOTSTRAP_REVOKED','BOOTSTRAP_SESSION_INVALID','DEVICE_CHALLENGE_EXPIRED']);status.recovery.originalReplayDenied=true;
  worker.Denied(()=>boot.IssueLauncher({requestId:crypto.randomUUID(),licenseId:spent[0].id},'ISOLATED_RECOVERY'),['DESKTOP_KEY_USED']);status.recovery.spentLicenseIssueRejected=true;status.recovery.spentLicenseProofScope='PRESERVED_ROWS_AND_PRODUCTION_LAUNCHER_ISSUANCE_GATE';status.recovery.originalSignedRedeemReplay='NOT_RUN';
  status.phase='replacement-key';Write();const generation=(identity.State().keyGenerations?.[original.bindingId]||0)+1,newNamespace=Namespace(store.Load(),original.bindingId,generation);
  if(newNamespace===policy.keyNamespace)Fail('RECOVERY_KEY_NAMESPACE_NOT_ROTATED');
  // Preserve only an identity for manual investigation if the OS kills a
  // provider operation. A namespace alone never grants deletion authority.
  status.recovery.replacementCleanup={runId:plan.runId,provider:plan.config.provider,namespace:newNamespace,creation:'REQUESTED',publicKeySha512:null,deletion:'UNCONFIRMED',manualReviewRequired:true};Write();
  const replacement=await probe.Call('create-replacement',{namespace:newNamespace});
  if(replacement.namespace!==newNamespace||replacement.created!==true||replacement.privateExportBlocked!==true||replacement.publicKey===original.publicKey||replacement.provider!==plan.config.provider)Fail('RECOVERY_REPLACEMENT_NATIVE_KEY_INVALID');
  Object.assign(status.recovery.replacementCleanup,{creation:'EXCLUSIVE_CREATED',publicKeySha512:tool.SHA(Buffer.from(replacement.publicKey))});Write();
  identity.Revoke({enrollmentId:original.id,expectedRevision:identity.State().revision,requestId:crypto.randomUUID(),reasonCode:'ADMIN_RECOVERY',replacementPublicKey:replacement.publicKey},'ISOLATED_RECOVERY');
  const deniedContext=BeginProof(plan.config.machineId);
  if(identity.Handle({...deniedContext.context,action:'policy'}).keyNamespace!==newNamespace)Fail('RECOVERY_PRODUCT_NAMESPACE_MISMATCH');
  worker.Denied(()=>identity.Handle({...deniedContext.context,action:'challenge',requestId:crypto.randomUUID(),publicKey:original.publicKey,keyProvider:plan.config.provider}),['DEVICE_KEY_REVOKED']);
  const replacementProof=await OriginalProof(probe,deniedContext.context,deniedContext.app,replacement.publicKey,plan.config.provider,'replacement');
  if(replacementProof.reply.enrollmentId!==identity.EnrollmentId(replacement.publicKey)||plan.config.provider==='PLATFORM'&&replacementProof.reply.tpmAttested!==true)Fail('RECOVERY_REPLACEMENT_ATTESTATION_REQUIRED');
  // Enrollment retains the explicitly attested provider even if the original
  // policy is COMPATIBLE; unchanged A/B/O must open this exact replacement.
  boot.Execute({action:'abort',flowId:deniedContext.begin.flowId,downloadTicket:deniedContext.begin.downloadTicket});
  Object.assign(status.recovery,{oldKeyChallengeDenied:true,replacementNamespace:newNamespace,replacementEnrollmentId:replacementProof.reply.enrollmentId,replacementExclusiveCreated:true,replacementPrivateExportBlocked:true,originalKeyDeleted:false,replacementDeleted:false});
  const replacementId=identity.EnrollmentId(replacement.publicKey),license=licenses.Create({requestId:crypto.randomUUID(),label:'Recovered product positive execution'},'ISOLATED_RECOVERY');
  const issue=boot.IssueLauncher({requestId:crypto.randomUUID(),label:'Recovered product positive execution',licenseId:license.license.id},'ISOLATED_RECOVERY');
  const execution=path.join(root,'execution');fs.mkdirSync(execution,{mode:0o700});const launcher=path.join(execution,issue.downloadName);fs.writeFileSync(launcher,boot.LauncherBytes(issue.launcherId),{flag:'wx',mode:0o600});
  const automaticLicense=store.Load().artifacts[store.Load().active.B].backgroundVersion===1;
  tool.Write(path.join(root,'input.json'),{launcher,automaticLicense,...(automaticLicense?{}:{licenseKey:license.licenseKey})});license.licenseKey='';
  function Current(){
   boot.Overview();const db=store.Load(),flow=Object.values(db.flows).find(r=>r.launcherId===issue.launcherId),overlay=Object.values(db.overlays||{}).find(r=>r.parentFlowId===flow?.id),enrolled=identity.State().enrollments[replacementId];
   const proof=(r,stage)=>r?.deviceIdentityProofs?.[stage]?.enrollmentId===replacementId&&r.deviceIdentityProofs[stage].epoch===recovery.Epoch();
   Object.assign(status,{ready:true,phase:'product',flowStatus:flow?.status||'',overlayStatus:overlay?.status||'',overlayAuthorized:!!overlay?.authorizedAt,transferCommitted:flow?.closedByOverlay===true&&overlay?.transferVersion===1,retiredParent:!!flow?.retiredAt,retiredOverlay:!!overlay?.retiredAt,licenseUsed:licenses.DB().licenses[license.license.id]?.consumed===true});
   status.product={epoch:recovery.Epoch(),machineBindingMatched:flow?.machineId===plan.config.machineId&&overlay?.machineId===plan.config.machineId,replacementEnrollmentMatched:enrolled?.status==='ACTIVE'&&enrolled.bindingId===original.bindingId,replacementTpmAttested:enrolled?.assurance==='TPM_KEY_ATTESTED',allRolesProvedReplacement:proof(flow,'A')&&proof(flow,'B')&&proof(overlay,'O'),consumedNewLicense:status.licenseUsed,runtimeRetired:!!flow&&!!overlay&&[flow,overlay].every(r=>['CLOSED','REVOKED','EXPIRED'].includes(r.status)&&['sessionNonce','ticketNonce','downloadNonce','handoffNonce','finishNonce','claimNonce'].every(k=>r[k]===undefined))};
   status.recovery.oldLicensesUnchanged=Object.entries(oldLicenses).every(([id,row])=>JSON.stringify(licenses.DB().licenses[id])===JSON.stringify(row));
   status.recovery.policyUnchanged=ProtectedPolicy()===policyBefore&&['A','B','O'].every(r=>db.active[r]===selected[r]);
  }
  Current();Write();timer=setInterval(async()=>{try{if(stopping)return;Current();Write();if(fs.existsSync(path.join(root,'stop.request'))){stopping=true;clearInterval(timer);status.phase='cleanup';Write();const closed=await probe.Close();RememberCleanup(closed);probe=null;Current();status.phase='finished';Write();require("../../storage/snapshots/peace.database.js").SaveDatabase();listener.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();}}catch(e){await Failed(e);}},150);
  setTimeout(()=>Failed(Error('RECOVERY_WINDOWS_PRODUCT_TIMEOUT')),480000).unref();
 }catch(e){await Failed(e);}
 async function Failed(e){if(stopping&&status.error)return;stopping=true;clearInterval(timer);status.error=tool.CODE(e);status.ready=false;if(probe)try{const closed=await probe.Close();RememberCleanup(closed);}catch(_){RememberCleanup();if(status.recovery.replacementDeleted!==true)status.recovery.replacementDeleted=false;}finally{probe=null;}try{fs.rmSync(path.join(root,'input.json'),{force:true});Write();}catch(_){}if(listener)listener.close();process.exitCode=1;setTimeout(()=>process.exit(1),2000).unref();}
}
if(require.main===module)Main(process.argv[2]);
module.exports={NativeProbe,Namespace,BeginProof,OriginalProof,ProtectedPolicy,Main};
