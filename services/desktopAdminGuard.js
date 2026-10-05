'use strict';
// Stable operator identities are provisioned on the SERVER, never supplied by
// request bodies or inferred from an admin session ID / browser name.
const state=require('../core/state');
// One-use server-only capability; never serialized to a browser or stored as an approval.
const singleAuthorizations=new WeakMap();
const TTL=5*60000;
function IsMutation(pathname) {
  return /^\/api\/production\/(?:dual-policy|passkeys\/revoke)$/.test(pathname) || /^\/api\/desktop\/bootstrap\/(?:security-authority|integrity-policy|artifacts|module-baselines)$/.test(pathname) || /^\/api\/desktop\/bootstrap\/security-operations\/(?:controls|contracts|signers|rollout|test-evidence|activate|enable-all)$/.test(pathname);
}
function Identities() {
  const text=process.env.DESKTOP_APPROVER_IDENTITIES_JSON||'{}';
  let map;try{map=JSON.parse(text);}catch(_){return null;}
  if(!map||Array.isArray(map)||Object.getPrototypeOf(map)!==Object.prototype||Object.keys(map).length>128)return null;
  if(Object.entries(map).some(([k,v])=>!/^[A-F0-9]{24}$/.test(k)||typeof v!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/.test(v)))return null;
  return map;
}
function DualRequired(){return state.production.deploymentManifest.dualApprovalRequired===true;}
function StepUpRequired(){return process.env.DESKTOP_SECURITY_STEP_UP_REQUIRED==='1'||DualRequired();}
function Credential(session){return session?.passkeyCredentialId&&state.production.passkeyCredentials.get(session.passkeyCredentialId);}
function Recent(session){const c=Credential(session);return !!c&&!c.revokedAt&&c.role==='admin'&&session.role==='admin'&&Number.isSafeInteger(session.securityVerifiedAt)&&session.securityVerifiedAt<=Date.now()&&Date.now()-session.securityVerifiedAt<TTL;}
function ProvisionedCredential(id,principal){const c=state.production.passkeyCredentials.get(id);return !!c&&!c.revokedAt&&c.role==='admin'&&Identities()?.[id]===principal;}
function Identity(session){if(!Recent(session))return '';return Identities()?.[session.passkeyCredentialId]||'';}
function MarkVerified(session,credentialId){session.passkeyCredentialId=credentialId;session.securityVerifiedAt=Date.now();}
// This edition is explicitly configured for a single desktop operator. Do not
// change other applications' optional global two-person policy or stored keys.
function SingleOperatorPath(pathname) {
  return typeof pathname==='string' && (pathname.startsWith('/api/desktop/bootstrap/') || pathname.startsWith('/api/desktop/workspace/') ||
    pathname==='/api/production/passkeys/revoke');
}
function CheckSession(session, pathname='') {
  if(!session||session.role!=='admin'||typeof session.id!=='string'||!session.id)
    return {ok:false,status:403,reason:'ADMIN_REQUIRED'};
  if(Object.hasOwn(session,'expiresAt')&&(!Number.isSafeInteger(session.expiresAt)||session.expiresAt<=Date.now()))
    return {ok:false,status:401,reason:'ADMIN_SESSION_EXPIRED'};
  if(!pathname||SingleOperatorPath(pathname))return {ok:true,mode:'SINGLE_ADMIN'};
  if(StepUpRequired()&&!Recent(session))return {ok:false,status:428,reason:'SECURITY_ADMIN_STEP_UP_REQUIRED'};
  if(DualRequired()&&!Identity(session))return {ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
  return {ok:true};
}
function Status(){return {mode:'SINGLE_ADMIN',stepUpRequired:false,dualApprovalRequired:false,
  identityConfigurationValid:true,provisionedPrincipalCount:0,stepUpLifetimeMs:0,
  identitySource:'EXISTING_ADMIN_SESSION',humanIdentityProof:false};}
function Begin(session,req){const check=CheckSession(session);return check.ok?{ok:false,reason:'SECURITY_DESKTOP_PASSKEY_NOT_USED'}:check;}
function Finish(session,req,body){return Begin(session,req);}
function SinglePermit(session,method,path,body){
  const ticket=Object.freeze({mode:'SINGLE_ADMIN'});
  singleAuthorizations.set(ticket,{session,id:session.id,method,path,
    digest:require('./privilegedApproval').Digest(method,path,body),expiresAt:Date.now()+30000});
  return ticket;
}
function ConsumeSingleAuthorization(ticket,session,method,path,body){
  const grant=ticket&&singleAuthorizations.get(ticket);
  if(grant)singleAuthorizations.delete(ticket);
  return !!grant&&CheckSession(session,path).ok&&grant.session===session&&grant.id===session.id&&
    grant.method===method&&grant.path===path&&grant.expiresAt>Date.now()&&
    grant.digest===require('./privilegedApproval').Digest(method,path,body);
}
function Summary(path,body){
  // No raw request / PE bytes or private key material in an approval ticket.
  const out={path};
  for(const k of ['profile','expectedActivationRevision','aSha256','bSha256','targetHash','expectedRevision','expectedPolicyRevision','expectedOperationsRevision','component','version','sha256','aId','bId','artifactId','keyId','state','mode','enforceLegacy','requireReadonlyApi','dynamicCode','requireCfg','requireReleaseSignature','minVersionA','minVersionB','requireBuildContract','requireTestEvidence'])if(['string','number','boolean'].includes(typeof body?.[k]))out[k]=body[k];
  if(Array.isArray(body?.trustedReleaseKeys))out.trustedSignerKeyIds=body.trustedReleaseKeys.map(x=>x.keyId).slice(0,8);
  if(Array.isArray(body?.revokedSha256))out.revokedReleaseHashes=body.revokedSha256.slice(0,512);
  if(body?.contract)out.contract=Object.fromEntries(['version','evidenceVersion','minApiSlots','maxApiSlots'].filter(k=>Number.isSafeInteger(body.contract[k])).map(k=>[k,body.contract[k]]));
  if(body?.rollout)out.rollout={enabled:body.rollout.enabled===true,artifactKeys:Array.isArray(body.rollout.artifactKeys)?body.rollout.artifactKeys.filter(x=>typeof x==='string'&&/^[AB]:[a-f0-9]{64}$/.test(x)).slice(0,128):[],patch:Object.fromEntries(['mode','dynamicCode','requireReadonlyApi','requireCfg'].filter(k=>['string','boolean'].includes(typeof body.rollout.patch?.[k])).map(k=>[k,String(body.rollout.patch[k]).slice(0,20)]))};
  if(path==='/api/desktop/bootstrap/security-operations/enable-all')out.activationTargets={profile:body?.profile,targetHash:body?.targetHash,stepUpRequired:false,dualApprovalRequired:false,adminMode:'SINGLE_ADMIN',windows:body?.profile==='ALL'?'dynamicCode=prohibit; requireCfg=true':'UNCHANGED'};
  if(body?.report)out.testEvidence={aSha256:body.report.aSha256,bSha256:body.report.bSha256,nativeBuild:body.report.nativeBuild,apiProbe:body.report.apiProbe,integration:body.report.integration,logsSha256:body.report.logsSha256};
  return out;
}
function Authorize(session,method,path,body,ticketId){
  const check=CheckSession(session,path);if(!check.ok)return check;
  if(path==='/api/desktop/bootstrap/security-operations/enable-all'){
    try{require('./desktopSecurityActivation').CheckRequest(body,session);}
    catch(e){return{ok:false,status:e.desktopError?e.status:503,reason:e.desktopError?e.message:'SECURITY_ACTIVATION_CHECK_FAILED'};}
  }
  if(SingleOperatorPath(path))return {ok:true,mode:'SINGLE_ADMIN',
    ...(path==='/api/desktop/bootstrap/security-operations/enable-all'?{ticket:SinglePermit(session,method,path,body)}:{})};
  if(path==='/api/production/dual-policy'&&body?.required===true){
    if(!Identity(session))return{ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
    if(new Set(Object.entries(Identities()||{}).filter(([id,principal])=>ProvisionedCredential(id,principal)).map(([,principal])=>principal)).size<2)return{ok:false,status:409,reason:'SECURITY_SECOND_OPERATOR_REQUIRED'};
  }
  const dual=require('./privilegedApproval');if(!dual.Required(path))return{ok:true};
  const used=dual.Consume(ticketId,session,method,path,body);if(used.ok)return used;
  if(used.reason==='DUAL_APPROVAL_REQUIRED'){
    const requested=dual.Request(session,method,path,body,'DESKTOP_SECURITY_CHANGE');
    return{ok:false,status:428,reason:requested.ok?used.reason:requested.reason,ticketId:requested.ticket?.ticketId||''};
  }
  return{ok:false,status:428,reason:used.reason};
}
module.exports={SingleOperatorPath,ConsumeSingleAuthorization,ProvisionedCredential,IsMutation,Identity,Recent,MarkVerified,CheckSession,Status,Begin,Finish,Summary,Authorize};
