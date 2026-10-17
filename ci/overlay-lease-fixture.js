'use strict';
const {performance}=require('node:perf_hooks');
// Installed only inside the disposable product-fault fixture. This observer
// never edits clocks, leases, credentials or accepted service responses.
function Install({service,overlay,store,onEvent=()=>{},allowEarlyTerminal=false}={}){
 service||=require('../services/desktopBootstrap');overlay||=require('../services/desktopOverlay');store||=require('../services/desktopBootstrapStore');
 const execute=service.Execute;let grant=null,acceptedBody=null,replay=null,renewed=false,closeWithheld=false,prunedElapsedMs=0;
 service.Execute=function(body){
  if(grant&&body?.action==='overlayClose'&&body.sessionId===acceptedBody.sessionId&&body.sessionToken===acceptedBody.sessionToken){
   // Client deadlines are intentionally conservative (request-start + grant).
   // Its best-effort close could otherwise precede server expiry by one RTT.
   // Withhold this exact owned cleanup request, never forge a successful close,
   // and let unchanged Prune retire the actual lease at the actual timestamp.
   closeWithheld=true;onEvent({event:'lease-close-request-withheld'});
   const error=Error('CONNECT_DEADLINE');error.desktopError=true;throw error;
  }
  const result=execute.apply(this,arguments);
  if(body?.action==='overlayVerify'&&result?.status==='ACTIVE'&&result.transferConfirmed===true){
   if(grant)renewed ||= result.leaseExpiresAt!==grant.expiresAt||result.serverTime!==grant.authorizedAt||body.sessionId!==grant.sessionId;
   else{
    const row=Object.values(store.Load().overlays||{}).find(x=>x.sessionId===body.sessionId);
    if(!row||row.status!=='CLAIMED'||row.sessionExpiresAt!==result.leaseExpiresAt||result.expiresAt!==result.leaseExpiresAt||result.serverTime!==row.lastVerifiedAt)throw Error('LEASE_REAL_GRANT_BINDING_MISMATCH');
    grant={authorizedAt:result.serverTime,expiresAt:result.leaseExpiresAt,observedAt:Date.now(),monotonic:performance.now(),sessionId:row.sessionId,deviceId:row.deviceId,machineId:row.machineId};acceptedBody=structuredClone(body);
    onEvent({event:'lease-real-grant',authorizedAt:grant.authorizedAt,expiresAt:grant.expiresAt});
   }
  }
  return result;
 };
 function Status(){
  // Actual production pruning with the real server clock, not direct row edits.
  overlay.Prune();
  const db=store.Load(),row=grant&&Object.values(db.overlays||{}).find(x=>x.sessionId===grant.sessionId),at=Date.now(),elapsed=grant?Math.floor(performance.now()-grant.monotonic):0;
  const expired=!!row&&row.status==='EXPIRED'&&at>=grant.expiresAt;
  if(expired&&!prunedElapsedMs)prunedElapsedMs=elapsed;
  return {grantObserved:!!grant,authorizedAt:grant?.authorizedAt||0,grantObservedAt:grant?.observedAt||0,expiresAt:grant?.expiresAt||0,serverObservedAt:at,monotonicElapsedMs:elapsed,prunedElapsedMs,prunedAt:expired?row.retiredAt:0,renewalAcceptedAfterGrant:renewed,cleanupCloseWithheld:closeWithheld,serverExpired:expired,serverTerminal:!!row&&['EXPIRED','CLOSED','REVOKED'].includes(row.status),runtimeSecretsRetired:!!row&&!!row.retiredAt&&['sessionNonce','ticketNonce','verifyReceipt','claimRecoveryUntil','claimFingerprint'].every(k=>row[k]===undefined),deviceRuntimeAuthorityRetired:!!grant&&[...Object.values(db.flows),...Object.values(db.overlays||{})].filter(x=>x.deviceId===grant.deviceId||x.machineId===grant.machineId).every(x=>['EXPIRED','CLOSED','REVOKED'].includes(x.status)),oldAuthorityRejected:replay===true};
 }
 function CheckReuse(){
  if(!acceptedBody||Date.now()<grant.expiresAt&&!allowEarlyTerminal)throw Error('LEASE_REUSE_BEFORE_REAL_EXPIRY');
  const before=Status();if(!before.serverTerminal||!before.runtimeSecretsRetired)throw Error('LEASE_REUSE_BEFORE_TERMINAL');
  let serviceDenied=false,reportDenied=false;
  try{execute.call(service,acceptedBody);}catch(error){serviceDenied=error.desktopError===true;}
  try{overlay.AuthenticateIntegrityReport({sessionId:acceptedBody.sessionId,sessionToken:acceptedBody.sessionToken,machineId:acceptedBody.machineId});}catch(error){reportDenied=error.desktopError===true;}
  const after=Status();replay=serviceDenied&&reportDenied&&after.serverTerminal&&after.runtimeSecretsRetired&&!renewed;return Status();
 }
 return {Status,CheckReuse,Dispose(){service.Execute=execute;acceptedBody=null;grant=null;}};
}
module.exports={Install};
