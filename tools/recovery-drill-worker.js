'use strict';
// Internal child process: only an owner-marked temporary tree from the parent
// tool is accepted. No production module is loaded before path validation.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {Inside}=require('./recovery-drill');
function Fail(code){throw Error(code);}
function SafePath(root,value){if(typeof value!=='string'||!path.isAbsolute(value)||!Inside(root,value)||value===root)Fail('DRILL_WORKER_PATH_INVALID');let p=path.dirname(value);while(p!==root){if(fs.existsSync(p)&&fs.lstatSync(p).isSymbolicLink())Fail('DRILL_WORKER_PATH_INVALID');p=path.dirname(p);}if(fs.existsSync(value)&&fs.lstatSync(value).isSymbolicLink())Fail('DRILL_WORKER_PATH_INVALID');return value;}
function Load(){
 require('../services/desktopSingleWriter').Acquire(process.env.DATA_DIR,{haEnabled:false});
 require('../core/utils').EnsureDirs();
 const journal=require('../services/desktopJournal');journal.Load();
 require('../services/desktopMachinePolicy').Load();
 const store=require('../services/desktopBootstrapStore');store.Load();
 require('../services/desktopIntegrityReports').List();
 const database=require('../storage/database');
 if(process.env.STORAGE_ENGINE==='json'&&fs.existsSync(path.join(process.env.DATA_DIR,'relay-identities.json'))){
  let snapshot;try{snapshot=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(path.join(process.env.DATA_DIR,'relay-identities.json'),64*1024*1024),{maxBytes:64*1024*1024,maxNodes:4000000});}catch(_){Fail('DRILL_BACKUP_DATABASE_INVALID');}
  if(!database.ImportDatabaseObject(snapshot))Fail('DRILL_BACKUP_DATABASE_INVALID');
 }
 database.LoadDatabase();require('../storage/audit').LoadRecentAudit();
 const licenses=require('../services/desktopLicenses'),reconciliation=licenses.ReconcileOperations();
 require('../services/desktopOperationAudit').Drain({reconcile:true});
 const audit=require('../storage/audit').VerifyAuditChain();if(!audit.ok)Fail('DRILL_AUDIT_CHAIN_INVALID');
 const db=licenses.DB();return {epoch:require('../services/desktopRecovery').Epoch(store.Load()),licenseRevision:db.revision,consumedLicenses:Object.values(db.licenses).filter(r=>r.consumed).length,bootstrapRevision:store.Load().revision,reconciledOperations:reconciliation.reconciled,auditChainVerified:true};
}
function Head(file){const row=require('../services/strictJson').Parse(require('../services/durableFile').ReadRegular(file,4096),{maxBytes:4096});if(row.body.pending)Fail('DRILL_HEAD_UNSETTLED');return row.body.current;}
function Enroll(directory){
 const j=require('../services/desktopJournal'),m=require('../services/desktopMachinePolicy'),s=require('../services/desktopBootstrapStore'),i=require('../services/desktopIntegrityReports');
 const heads={DESKTOP_JOURNAL:fs.existsSync(j.FILE+'.head')?Head(j.FILE+'.head'):{seq:0,hash:'0'.repeat(64)},DESKTOP_MACHINE_POLICY:Head(m.FILE+'.head'),DESKTOP_BOOTSTRAP:Head(path.join(s.DIR,'authority.json.head')),DESKTOP_INTEGRITY:Head(i.FILE+'.head')};
 require('../services/desktopSingleWriter').AcquireWitness(directory,{haEnabled:false});new (require('../services/recoveryWitnessFile').WitnessFile)(directory).enroll(heads);
 return {ok:true};
}
function Denied(fn,allowed){try{fn();}catch(error){if(allowed.includes(error.message))return error.message;throw error;}Fail('DRILL_EXPECTED_REJECTION_MISSING');}
function Proof(device,action,payload){
 const f=require('../scripts/desktop-bootstrap-fixture'),licenses=require('../services/desktopLicenses'),requestId=crypto.randomUUID(),payloadJSON=JSON.stringify(payload),payloadHash=crypto.createHash('sha512').update(payloadJSON).digest('hex');
 const body={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash},challenge=licenses.Challenge(body);f.ObserveLicense(device,action,requestId,payloadHash,payload);
 return {...body,payloadJSON,challengeId:challenge.challengeId,signature:f.Sign(device,challenge.canonical)};
}
function Seed(){
 Load();const f=require('../scripts/desktop-bootstrap-fixture'),licenses=require('../services/desktopLicenses');
 const device=f.Device(),issued=licenses.Create({requestId:crypto.randomUUID(),label:'ISOLATED RECOVERY DRILL FIXTURE'},'DRILL'),session=f.Session(device),payload={...f.Evidence(device,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,licenseKey:issued.licenseKey};
 const activated=licenses.Execute(Proof(device,'redeem',payload));assert.equal(activated.status,'USED');
 require('../storage/database').SaveDatabase();return {ok:true};
}
function ExistingSessionProbes(db){
 const probes=[];
 for(const [stage,rows,domain]of [['B',db.flows,'SESSION'],['O',db.overlays||{},'OVERLAY-SESSION']])for(const row of Object.values(rows)){
  if(row.status!=='CLAIMED'||!row.sessionNonce)continue;
  const sessionToken=crypto.createHmac('sha256',Buffer.from(db.secret,'hex')).update(['GAME-A80',domain,row.sessionId,row.sessionNonce].join('|')).digest('base64url');
  // Reconstruct only a backup-stored capability, not a device private key.
  if(crypto.createHash('sha256').update(sessionToken).digest('hex')!==row.sessionHash)Fail('DRILL_SESSION_CAPABILITY_MISMATCH');
  const body={stage,sessionId:row.sessionId,sessionToken,machineId:row.machineId};
  let preflight;try{require('../services/desktopBootstrap').AuthenticateIntegrityReport(body);preflight='ACCEPTED';}catch(e){preflight=/^[A-Z0-9_]+$/.test(e.message)?e.message:'DENIED';}
  probes.push({row:structuredClone(row),body,preflight});
 }
 return probes;
}
function DeviceLifecycle(){
 const f=require('../scripts/desktop-bootstrap-fixture'),boot=require('../services/desktopBootstrap'),identity=require('../services/desktopDeviceIdentity'),store=require('../services/desktopBootstrapStore');
 const app=f.Device(),oldKey=f.Device(),newKey=f.Device();
 function Context(session){return {stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:app.machineId};}
 function Register(context,key){const c=identity.Handle({...context,action:'challenge',requestId:crypto.randomUUID(),publicKey:key.publicKey,keyProvider:'SOFTWARE'});return identity.Handle({...context,action:'complete',challengeId:c.challengeId,signature:f.Sign(key,c.canonical),appSignature:f.Sign(app,c.canonical)});}
 const session=f.Session(app),context=Context(session),registered=Register(context,oldKey);
 assert.equal(registered.assurance,'PERSISTENT_KEY_POSSESSION');
 const revocation=identity.Revoke({enrollmentId:registered.enrollmentId,expectedRevision:identity.State().revision,requestId:crypto.randomUUID(),reasonCode:'ADMIN_RECOVERY',replacementPublicKey:newKey.publicKey},'DRILL');
 assert.equal(revocation.status,'RETIRED');assert.ok(revocation.closed>=1);assert.equal(revocation.licenseCarryOver,false);
 Denied(()=>boot.AuthenticateIntegrityReport(context),['BOOTSTRAP_SESSION_CLOSED','BOOTSTRAP_REVOKED','BOOTSTRAP_SESSION_INVALID']);
 // New A must prove the approved replacement before finish because the binding
 // already has an enrollment. Use production begin/challenge/complete/finish.
 const {begin}=f.Begin(app),a={stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:app.machineId};
 Denied(()=>identity.Handle({...a,action:'challenge',requestId:crypto.randomUUID(),publicKey:oldKey.publicKey,keyProvider:'SOFTWARE'}),['DEVICE_KEY_REVOKED']);
 const replacement=Register(a,newKey);assert.equal(replacement.status,'ENROLLED');
 f.Download(begin);const fresh=f.Claim(app,begin,f.Finish(app,begin));Register(Context(fresh),newKey);
 assert.equal(identity.State().enrollments[registered.enrollmentId].status,'RETIRED');
 assert.equal(identity.State().enrollments[replacement.enrollmentId].status,'ACTIVE');
 identity.AssertSession(Object.values(store.Load().flows).find(r=>r.sessionId===fresh.sessionId),'B');
 return {name:'device_key_revoke_and_reregister',status:'PASS',scope:'SYNTHETIC_SOFTWARE_RSA_PROOFS_REAL_STORES',oldKeyDenied:true,newKeyRegistered:true,licenseCarryOver:false,hardwareTpm:'NOT_TESTED',windowsCng:'NOT_TESTED'};
}
function Recover(synthetic,alreadyLoaded=false){
 if(!alreadyLoaded)Load();const boot=require('../services/desktopBootstrap'),store=require('../services/desktopBootstrapStore'),licenses=require('../services/desktopLicenses'),recovery=require('../services/desktopRecovery'),checks=[];
 const before=structuredClone(licenses.DB()),epoch=recovery.Epoch(),probes=ExistingSessionProbes(store.Load()),oldRows=[...Object.values(store.Load().flows),...Object.values(store.Load().overlays||{})].map(r=>structuredClone(r));
 const request={requestId:crypto.randomUUID(),expectedEpoch:epoch,reasonCode:'RECOVERY_DRILL'},applied=recovery.Apply(request,'DRILL');assert.equal(applied.epoch,epoch+1);assert.equal(recovery.Apply(request,'DRILL').duplicate,true);
 checks.push({name:'recovery_epoch_apply_and_retry',status:'PASS',from:epoch,to:applied.epoch});
 for(const row of oldRows)Denied(()=>recovery.Assert(row),['SERVER_SESSION_EPOCH_REVOKED']);
 const errors={};let acceptedBefore=0;
 for(const probe of probes){const error=Denied(()=>boot.AuthenticateIntegrityReport(probe.body),['SERVER_SESSION_EPOCH_REVOKED','BOOTSTRAP_SESSION_INVALID','BOOTSTRAP_SESSION_CLOSED','BOOTSTRAP_REVOKED']);errors[error]=(errors[error]||0)+1;if(probe.preflight==='ACCEPTED')acceptedBefore++;}
 checks.push({name:'old_session_rejection',status:probes.length?'PASS':'NOT_TESTED',credentialProbes:probes.length,acceptedBeforeRecovery:acceptedBefore,epochRowsRejected:oldRows.length,errors,...(!probes.length?{reason:'BACKUP_HAS_NO_RECONSTRUCTABLE_CLAIMED_SESSION'}:{})});
 assert.deepEqual(licenses.DB().licenses,before.licenses,'recovery must not change any license row');assert.deepEqual(licenses.DB().receipts,before.receipts);
 const spent=Object.values(before.licenses).filter(r=>r.consumed);
 if(spent.length){const attempted=structuredClone(licenses.DB());attempted.revision++;attempted.licenses[spent[0].id].consumed=false;Denied(()=>require('../services/desktopJournal').Commit(licenses.DB(),attempted),['DESKTOP_JOURNAL_CORRUPT']);}
 checks.push({name:'spent_license_preservation_and_unconsume_refusal',status:spent.length?'PASS':'NOT_TESTED',consumedLicenses:spent.length,scope:'REAL_JOURNAL_INVARIANT',...(!spent.length?{reason:'BACKUP_HAS_NO_SPENT_LICENSE'}:{})});
 if(synthetic){
  assert.ok(spent.length&&probes.length&&acceptedBefore,'synthetic fixture must exercise live pre-recovery authority');
  // Derive the fixture's own deterministic issued key in memory. No credential
  // appears in the report or leaves the owned temporary process tree.
  const row=spent[0],key=crypto.createHmac('sha256',Buffer.from(before.signingSecret,'hex')).update('GAME-DESKTOP-KEY-V2|'+row.id+'|'+row.issuanceNonce).digest('hex').toUpperCase();
  const f=require('../scripts/desktop-bootstrap-fixture'),app=f.Device(),session=f.Session(app),payload={...f.Evidence(app,session),bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken,licenseKey:key};
  Denied(()=>licenses.Execute(Proof(app,'redeem',payload)),['DESKTOP_KEY_USED']);
  checks.push({name:'spent_license_signed_redeem_rejection',status:'PASS',scope:'SYNTHETIC_CREDENTIAL_REAL_LICENSE_SERVICE',error:'DESKTOP_KEY_USED'});
  checks.push(DeviceLifecycle());
 }else{
  checks.push({name:'spent_license_signed_redeem_rejection',status:'NOT_TESTED',reason:'ORIGINAL_DEVICE_AND_REDEEM_CREDENTIAL_NOT_IMPORTED',supplement:'syntheticRegression'});
  checks.push({name:'device_key_revoke_and_reregister',status:'NOT_TESTED',reason:'ORIGINAL_DEVICE_PRIVATE_KEY_NOT_IMPORTED',supplement:'syntheticRegression'});
 }
 assert.equal(require('../storage/audit').VerifyAuditChain().ok,true);checks.push({name:'audit_chain_after_recovery',status:'PASS'});
 return {ok:true,epoch:applied.epoch,consumedLicenses:spent.length,checks};
}
function Main(){
let job,result,authorizedOutput;
try{
 const root=process.env.RECOVERY_DRILL_ROOT,token=process.env.RECOVERY_DRILL_TOKEN;
 if(!root||!/^game-recovery-drill-/.test(path.basename(root))||!token||!/^[a-f0-9]{64}$/.test(token)||fs.lstatSync(root).isSymbolicLink()||fs.realpathSync(root)!==root||fs.readFileSync(path.join(root,'owner'),'utf8')!==token)Fail('DRILL_WORKER_OWNER_REQUIRED');
 job=JSON.parse(fs.readFileSync(0,'utf8'));for(const key of ['data','output','witness','enrollWitness'])if(job[key])SafePath(root,job[key]);
 authorizedOutput=job.output;
 if(process.env.DATA_DIR!==job.data||job.witness!==(process.env.DESKTOP_RECOVERY_WITNESS_DIR||null))Fail('DRILL_WORKER_ENV_INVALID');
 switch(job.command){case 'seed':result=Seed();break;case 'inspect':result={ok:true,details:Load()};break;case 'enroll':Load();result=Enroll(job.enrollWitness);break;case 'recover':result=Recover(job.synthetic===true);break;default:Fail('DRILL_WORKER_COMMAND_INVALID');}
}catch(error){result={ok:false,error:/^[A-Z][A-Z0-9_]{2,100}$/.test(error.message)?error.message:'DRILL_ASSERTION_FAILED'};}
if(authorizedOutput)fs.writeFileSync(authorizedOutput,JSON.stringify(result),{flag:'wx',mode:0o600});
process.exitCode=result?.ok?0:1;

}
if(require.main===module)Main();
module.exports={Load,Enroll,Denied,Proof,ExistingSessionProbes,Recover,SafePath};
