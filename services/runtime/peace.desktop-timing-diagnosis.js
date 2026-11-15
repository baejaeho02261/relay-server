'use strict';
// Never infer heartbeat, process exit, or causal order from a duration alone.
// 'at' is the server receipt time, not the client's event-occurrence time.
function Describe(events){
 const facts=[];
 for(const e of Array.isArray(events)?events:[]){
  if(e.source==='SERVER_CONFIRMED'&&['LEASE_EXPIRED','AUTHORITY_ENDED'].includes(e.event))
   facts.push({eventId:e.id,role:e.role,recordedAt:e.at,kind:e.event,status:e.status,scope:'SERVER_AUTHORITY_ONLY'});
  else if(e.source==='CLIENT_REPORTED'&&e.event==='DOWNLOAD_DEADLINE'&&e.status==='OBSERVED'&&e.role==='A'&&e.reporterRole==='A')
   facts.push({eventId:e.id,role:'A',recordedAt:e.at,kind:'BOOTSTRAP_DOWNLOAD_DEADLINE',elapsedMs:e.elapsedMs,scope:'AUTHENTICATED_CLIENT_REPORT_NOT_OS_ATTESTATION'});
 }
 return {facts,heartbeatInferred:false,processExitCause:'NOT_DETERMINED',ordering:'RECEIPT_ORDER_NOT_CAUSAL_ORDER',downloadLimitMs:290000};
}
module.exports={Describe};
