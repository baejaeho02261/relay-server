'use strict';
// Recovery is server authority, never a client-provided epoch. Changing it
// does NOT unconsume licenses or un-revoke deployments. External witness keeps
// the epoch and all its dependent stores from being restored independently.
const crypto=require('node:crypto'),store=require('./desktopBootstrapStore');
const TERMINAL=['CLOSED','REVOKED','EXPIRED'];
function Fail(code,status=409){const e=Error(code);e.desktopError=true;e.status=status;throw e;}
function Epoch(db=store.Load()){return db.serverRecovery?.epoch||0;}
function Assert(row,db=store.Load()){
 if(!row||(row.serverEpoch||0)!==Epoch(db))Fail('SERVER_SESSION_EPOCH_REVOKED',403);
}
function Validate(db){
 const r=db.serverRecovery;
 if(!r||r.version!==1||!Number.isSafeInteger(r.epoch)||r.epoch<1||!r.receipts||Array.isArray(r.receipts)||Object.keys(r.receipts).length>4096)throw Error('SERVER_RECOVERY_STORAGE_INVALID');
 for(const [id,row]of Object.entries(r.receipts))if(!/^[a-f0-9]{64}$/.test(id)||!row||!Number.isSafeInteger(row.epoch)||row.epoch<1||row.epoch>r.epoch||!/^[a-f0-9]{64}$/.test(row.fingerprint)||!Number.isSafeInteger(row.at)||row.at<1)throw Error('SERVER_RECOVERY_STORAGE_INVALID');
 for(const rows of [db.launchers,db.flows,db.overlays||{}])for(const row of Object.values(rows))if(row.serverEpoch!==undefined&&(!Number.isSafeInteger(row.serverEpoch)||row.serverEpoch<0||row.serverEpoch>r.epoch))throw Error('SERVER_RECOVERY_STORAGE_INVALID');
}
function Apply(body,actor='ADMIN'){
 if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).some(k=>!['requestId','expectedEpoch','reasonCode'].includes(k))||!/^[-A-Za-z0-9_]{8,80}$/.test(body.requestId||'')||!Number.isSafeInteger(body.expectedEpoch)||body.expectedEpoch<0||!['BACKUP_RESTORE','SECURITY_INCIDENT','CREDENTIAL_ROTATION','RECOVERY_DRILL'].includes(body.reasonCode))Fail('SERVER_RECOVERY_INPUT_INVALID',400);
 const fingerprint=crypto.createHash('sha256').update(JSON.stringify({expectedEpoch:body.expectedEpoch,reasonCode:body.reasonCode})).digest('hex'),key=crypto.createHash('sha256').update('GAME-RECOVERY-REQUEST-V1\n'+String(actor)+'\n'+body.requestId).digest('hex');
 const db=store.Load(),old=db.serverRecovery?.receipts[key];
 if(old){if(old.fingerprint!==fingerprint)Fail('SERVER_RECOVERY_REQUEST_REUSED');require('./desktopOperationAudit').BestEffortDrain();return {...old,duplicate:true};}
 if(Epoch(db)!==body.expectedEpoch)Fail('SERVER_RECOVERY_EPOCH_CONFLICT');
 if(Object.keys(db.serverRecovery?.receipts||{}).length>=4096)Fail('SERVER_RECOVERY_RECEIPT_CAPACITY',503);
 const result=require('./desktopOperationAudit').Run('RECOVERY_EPOCH',actor,{epoch:body.expectedEpoch+1,reasonCode:body.reasonCode},next=>{
  if(Epoch(next)!==body.expectedEpoch)Fail('SERVER_RECOVERY_EPOCH_CONFLICT');
  const boot=require('./desktopBootstrap'),at=Date.now();let launchers=0,flows=0,overlays=0;
  next.serverRecovery={version:1,epoch:body.expectedEpoch+1,receipts:next.serverRecovery?.receipts||{}};
  for(const row of Object.values(next.launchers))if(row.status==='AVAILABLE'){row.status='EXPIRED';row.expiresAt=Math.min(row.expiresAt,at);delete row.ticketNonce;delete row.profile;row.retiredAt=at;launchers++;}
  // Expiry time itself must remain > issuedAt for historic record validation.
  for(const row of Object.values(next.launchers))if(row.retiredAt===at&&row.expiresAt<=row.issuedAt)row.expiresAt=row.issuedAt+1;
  for(const row of Object.values(next.overlays||{}))if(!TERMINAL.includes(row.status)){row.status='REVOKED';row.revokedAt=at;row.reason='SERVER_RECOVERY';row.retiredAt=at;delete row.ticketNonce;delete row.sessionNonce;delete row.claimRecoveryUntil;delete row.claimFingerprint;row.chunkOffsets=[];overlays++;}
  for(const row of Object.values(next.flows))if(!TERMINAL.includes(row.status)){row.status='REVOKED';row.revokedAt=at;row.reason='SERVER_RECOVERY';const launcher=next.launchers[row.launcherId];if(launcher){launcher.status='REVOKED';delete launcher.ticketNonce;delete launcher.profile;launcher.retiredAt||=at;}boot.RetireFlow(row,next);flows++;}
  const receipt={epoch:next.serverRecovery.epoch,fingerprint,at,launchers,flows,overlays,reasonCode:body.reasonCode};next.serverRecovery.receipts[key]=receipt;return receipt;
 });
 require('./desktopSecurityAuthority').InvalidateAll();
 require('./desktopLicenses').InvalidateVolatile();
 require('./desktopIntegrityReports').InvalidateVolatile();
 require('./desktopDeviceRegistry').ClearChallenges();
 require('../web/webAuth').RevokeAllSessions();
 return result;
}
function Status(){const db=store.Load(),identity=require('./desktopCapabilities').DeviceState(db);return {epoch:Epoch(db),licenseRevision:require('./desktopLicenses').DB().revision,witness:require('./desktopRecoveryWitness').Status(),localPolicyCache:false,offlineAuthorization:false,auditPending:Object.values(db.serverAuditOutbox||{}).filter(x=>!x.acked).length,clientPersistence:identity.clientPersistence,tpmAttestation:identity.tpmAttestation,deviceIdentity:identity};}
module.exports={Epoch,Assert,Validate,Apply,Status};
