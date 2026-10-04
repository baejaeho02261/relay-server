'use strict';
// Server-side facts only. No stack traces, private keys, proof payloads or tokens.
// A context is attached only after the existing session token is authenticated.
const recent=new Map();
function Record(operation,body,code){
 try{
  if(!['bootstrap','execute','security','report'].includes(operation)||!body||!/^[A-Z0-9_]{1,80}$/.test(code))return;
  let context;
  if(operation==='execute'){
   const raw=body.payloadJSON??body.payloadJson;if(typeof raw!=='string'||Buffer.byteLength(raw)>4096)return;
   const p=JSON.parse(raw);context={stage:'B',sessionId:p.bootstrapSessionId,sessionToken:p.bootstrapSessionToken,machineId:p.machineId};
  }else if(operation==='bootstrap'&&['chunk','finish'].includes(body.action))context={stage:'A',sessionId:body.flowId,sessionToken:body.downloadTicket};
  else if(operation==='bootstrap')context={stage:'B',sessionId:body.sessionId,sessionToken:body.sessionToken};
  else context={stage:body.stage||'B',sessionId:body.sessionId,sessionToken:body.sessionToken,machineId:body.machineId};
  const row=require('./desktopBootstrap').AuthenticateIntegrityReport(context),at=Date.now(),key=row.reportContextId+':'+operation+':'+code;
  if(at-(recent.get(key)||0)<10000)return;
  recent.delete(key);recent.set(key,at);if(recent.size>4096)recent.delete(recent.keys().next().value);
  const record={stage:row.stage,sessionId:row.sessionId,flowId:row.id,releaseId:row.integrityArtifact.id,operation,reason:code,association:'SESSION_TOKEN_BOUND_REQUEST_FAILURE',allProofChecksPassed:false};
  require('../storage/audit').LogEvent('DESKTOP_RUNTIME_REQUEST_FAILED',JSON.stringify(record));
 }catch(_){/* Diagnostics must not turn a rejected operation into success. */}
}
module.exports={Record};
