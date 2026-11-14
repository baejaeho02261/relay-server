"use strict";
const {ActionStore,Hash}=require('./peace.admin-action-store');
// Exclude volatile traffic/audit counters: an unrelated heartbeat must not
// invalidate a reviewed policy change. Actual route-specific optimistic locks
// still apply at commit. Never hash/export authority secrets or session tokens.
function PolicyFence(){
 const db=require("../bootstrap/peace.desktop-bootstrap-store").Load(),state=require("../../core/peace.runtime-state");
 const reports=require("../integrity/peace.desktop-integrity-reports");
 const credentials=[...state.production.passkeyCredentials.values()].map(x=>({id:x.credentialId||x.id||'',role:x.role||'',revokedAt:x.revokedAt||0,publicKey:x.publicKeySpki||x.publicKey||x.publicKeyPem||''})).sort((a,b)=>a.id.localeCompare(b.id));
 return Hash({version:1,active:db.active||{},recoveryEpoch:db.serverRecovery?.epoch||0,
  authority:db.securityAuthorityPolicy||null,operations:db.securityOperations||null,
  safetyRevision:db.releaseSafety?.revision||0,integrity:reports.Policy(),baselines:reports.Baselines().items,
  credentials,revocations:db.adminCredentialRevocations||{},production:state.production.deploymentManifest||null});
}
const store=new ActionStore({active:s=>require("../../web/authentication/peace.web-auth").IsSessionActive(s),fence:PolicyFence});
function Guard(session,method,path,body,id){try{
 if(id){const consumed=store.consume(session,id,method,path,body);return {ok:true,action:consumed};}
 const action=store.issue(session,method,path,body,JSON.parse(JSON.stringify(require('./peace.desktop-admin-guard').Summary(path,body))));
 return {ok:false,status:428,reason:'ADMIN_ACTION_REQUIRED',action};
 }catch(e){return {ok:false,status:e.desktopError?e.status:503,reason:e.desktopError?e.message:'ADMIN_ACTION_STATE_UNAVAILABLE'};}}
function Deny(res,result){require("../../web/http/peace.api-context").Json(res,result.status||428,{ok:false,error:result.reason,...(result.action?{action:result.action}:{}),...(result.ticketId?{detail:result.ticketId}:{})});}
module.exports={Guard,Deny,PolicyFence,Pending:(s,id)=>store.pending(s,id),Approve:(s,id)=>store.approve(s,id),Cancel:(s,id)=>store.cancel(s,id)};
