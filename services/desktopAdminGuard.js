'use strict';
// Stable operator identities are provisioned on the SERVER, never supplied by
// request bodies or inferred from an admin session ID / browser name.
const state=require('../core/state');
const stepUps=new Map();
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
function DualRequired(){return state.production.deploymentManifest.dualApprovalRequired===true||require('./desktopSecurityActivation').AdminEnforced();}
function StepUpRequired(){return process.env.DESKTOP_SECURITY_STEP_UP_REQUIRED==='1'||DualRequired();}
function Credential(session){return session?.passkeyCredentialId&&state.production.passkeyCredentials.get(session.passkeyCredentialId);}
function Recent(session){const c=Credential(session);return !!c&&!c.revokedAt&&c.role==='admin'&&session.role==='admin'&&Number.isSafeInteger(session.securityVerifiedAt)&&session.securityVerifiedAt<=Date.now()&&Date.now()-session.securityVerifiedAt<TTL;}
function ProvisionedCredential(id,principal){const c=state.production.passkeyCredentials.get(id);return !!c&&!c.revokedAt&&c.role==='admin'&&Identities()?.[id]===principal;}
function Identity(session){if(!Recent(session))return '';return Identities()?.[session.passkeyCredentialId]||'';}
function MarkVerified(session,credentialId){session.passkeyCredentialId=credentialId;session.securityVerifiedAt=Date.now();}
function CheckSession(session){
  if(!session||session.role!=='admin')return{ok:false,status:403,reason:'ADMIN_REQUIRED'};
  if(StepUpRequired()&&!Recent(session))return{ok:false,status:428,reason:'SECURITY_ADMIN_STEP_UP_REQUIRED'};
  if(DualRequired()&&!Identity(session))return{ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
  return{ok:true};
}
function Status(){const m=Identities(),valid=Object.keys(m||{}).filter(k=>state.production.passkeyCredentials.has(k)&&state.production.passkeyCredentials.get(k).role==='admin'&&!state.production.passkeyCredentials.get(k).revokedAt);return{stepUpRequired:StepUpRequired(),dualApprovalRequired:DualRequired(),identityConfigurationValid:m!==null,provisionedPrincipalCount:new Set(valid.map(k=>m[k])).size,stepUpLifetimeMs:TTL,identitySource:'SERVER_ENV_MAPPING_OF_VERIFIED_PASSKEY',humanIdentityProof:false};}
function Prune(){for(const[id,v]of stepUps)if(v.expiresAt<=Date.now())stepUps.delete(id);}
function Begin(session,req){
  if(!session||session.role!=='admin')return{ok:false,reason:'ADMIN_REQUIRED'};Prune();
  if(stepUps.size>=1024)return{ok:false,reason:'SECURITY_ADMIN_CAPACITY'};
  for(const[id,v]of stepUps)if(v.sessionId===session.id)stepUps.delete(id);
  const out=require('./passkeyAuth').LoginBegin('admin',req);
  if(out.ok)stepUps.set(out.challengeId,{sessionId:session.id,expiresAt:Date.now()+TTL});return out;
}
function Finish(session,req,body){
  Prune();const pending=stepUps.get(body?.challengeId);
  if(!session||session.role!=='admin'||!pending||pending.sessionId!==session.id)return{ok:false,reason:'SECURITY_ADMIN_CHALLENGE_INVALID'};
  stepUps.delete(body.challengeId);
  const out=require('./passkeyAuth').LoginFinish(req,body);
  if(!out.ok||out.role!=='admin')return{ok:false,reason:out.reason||'ADMIN_REQUIRED'};
  MarkVerified(session,out.credentialId);
  return{ok:true,verifiedUntil:session.securityVerifiedAt+TTL,principalConfigured:!!Identity(session)};
}
function Summary(path,body){
  // No raw request / PE bytes or private key material in an approval ticket.
  const out={path};
  for(const k of ['profile','expectedActivationRevision','aSha256','bSha256','expectedRevision','expectedPolicyRevision','expectedOperationsRevision','component','version','sha256','aId','bId','artifactId','keyId','state','mode','enforceLegacy','requireReadonlyApi','dynamicCode','requireCfg','requireReleaseSignature','minVersionA','minVersionB','requireBuildContract','requireTestEvidence'])if(['string','number','boolean'].includes(typeof body?.[k]))out[k]=body[k];
  if(Array.isArray(body?.trustedReleaseKeys))out.trustedSignerKeyIds=body.trustedReleaseKeys.map(x=>x.keyId).slice(0,8);
  if(Array.isArray(body?.revokedSha256))out.revokedReleaseHashes=body.revokedSha256.slice(0,512);
  if(body?.contract)out.contract=Object.fromEntries(['version','evidenceVersion','minApiSlots','maxApiSlots'].filter(k=>Number.isSafeInteger(body.contract[k])).map(k=>[k,body.contract[k]]));
  if(body?.rollout)out.rollout={enabled:body.rollout.enabled===true,artifactKeys:Array.isArray(body.rollout.artifactKeys)?body.rollout.artifactKeys.filter(x=>typeof x==='string'&&/^[AB]:[a-f0-9]{64}$/.test(x)).slice(0,128):[],patch:Object.fromEntries(['mode','dynamicCode','requireReadonlyApi','requireCfg'].filter(k=>['string','boolean'].includes(typeof body.rollout.patch?.[k])).map(k=>[k,String(body.rollout.patch[k]).slice(0,20)]))};
  if(path==='/api/desktop/bootstrap/security-operations/enable-all')out.activationTargets={mode:'enforce',enforceLegacy:true,requireReadonlyApi:true,requireReleaseSignature:true,requireBuildContract:true,requireTestEvidence:true,stepUpRequired:true,dualApprovalRequired:true,rollout:'DISABLED',windows:body?.profile==='ALL'?'dynamicCode=prohibit; requireCfg=true':'UNCHANGED'};
  if(body?.report)out.testEvidence={aSha256:body.report.aSha256,bSha256:body.report.bSha256,nativeBuild:body.report.nativeBuild,apiProbe:body.report.apiProbe,integration:body.report.integration,logsSha256:body.report.logsSha256};
  return out;
}
function Authorize(session,method,path,body,ticketId){
  const check=CheckSession(session);if(!check.ok)return check;
  if(path==='/api/desktop/bootstrap/security-operations/enable-all'){
    try{require('./desktopSecurityActivation').CheckRequest(body,session);}
    catch(e){return{ok:false,status:e.desktopError?e.status:503,reason:e.desktopError?e.message:'SECURITY_ACTIVATION_CHECK_FAILED'};}
  }
  if(path==='/api/production/dual-policy'&&body?.required===true){
    if(!Identity(session))return{ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
    if(Status().provisionedPrincipalCount<2)return{ok:false,status:409,reason:'SECURITY_SECOND_OPERATOR_REQUIRED'};
  }
  const dual=require('./privilegedApproval');if(!dual.Required(path))return{ok:true};
  const used=dual.Consume(ticketId,session,method,path,body);if(used.ok)return used;
  if(used.reason==='DUAL_APPROVAL_REQUIRED'){
    const requested=dual.Request(session,method,path,body,'DESKTOP_SECURITY_CHANGE');
    return{ok:false,status:428,reason:requested.ok?used.reason:requested.reason,ticketId:requested.ticket?.ticketId||''};
  }
  return{ok:false,status:428,reason:used.reason};
}
module.exports={ProvisionedCredential,IsMutation,Identity,Recent,MarkVerified,CheckSession,Status,Begin,Finish,Summary,Authorize};
