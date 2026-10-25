'use strict';
// Stable operator identities are provisioned on the SERVER, never supplied by
// request bodies or inferred from an admin session ID / browser name.
const state=require("../../core/peace.runtime-state");
// One-use server-only capability; never serialized to a browser or stored as an approval.
const singleAuthorizations=new WeakMap();
const TTL=5*60000;
function SecurityCenterMutation(pathname){return /^\/api\/desktop\/bootstrap\/security-center\/(?:parser-tests|artifact-scan|respond)$/.test(pathname||'');}
function IsMutation(pathname) {
  if(pathname==='/api/desktop/bootstrap/security-operations/registration-reset')return true;
  if(SecurityCenterMutation(pathname))return true;
  if(AdditionalCritical(pathname)||(pathname==='/api/desktop/bootstrap/packing/jobs'||pathname==='/api/desktop/bootstrap/packing/custom/jobs'))return true;
  if(/^\/api\/desktop\/bootstrap\/server-state\/(?:recover-sessions|device-identity-policy|device-key-revoke|storage-maintenance|device-replacement|orphan-quarantine|orphan-delete|journal-checkpoint|manual-verification)$/.test(pathname))return true;
  return /^\/api\/production\/(?:dual-policy|passkeys\/(?:revoke|register\/(?:begin|finish)))$/.test(pathname) || /^\/api\/desktop\/bootstrap\/(?:security-authority|integrity-policy|artifacts|module-baselines)$/.test(pathname) || /^\/api\/desktop\/bootstrap\/security-operations\/(?:baseline-pin|retire-cohort|controls|contracts|signers|rollout|test-evidence|activate|enable-all|release-governance|release-manifests|ci-signers|ci-evidence|mitigation-compatibility|mitigation-profiles|tls-pin-transition|plan-release|recovery\/(?:prepare|apply))$/.test(pathname);
}
function Identities() {
  const text=process.env.DESKTOP_APPROVER_IDENTITIES_JSON||'{}';
  let map;try{map=require("../protocol/peace.strict-json").Parse(text,{maxBytes:65536});}catch(_){return null;}
  if(!map||Array.isArray(map)||Object.getPrototypeOf(map)!==Object.prototype||Object.keys(map).length>128)return null;
  if(Object.entries(map).some(([k,v])=>!/^[A-F0-9]{24}$/.test(k)||typeof v!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/.test(v)))return null;
  return map;
}
function DualRequired(){return state.production.deploymentManifest.dualApprovalRequired===true;}
function StepUpRequired(){return process.env.DESKTOP_SECURITY_STEP_UP_REQUIRED==='1'||DualRequired();}
function Credential(session){return session?.passkeyCredentialId&&state.production.passkeyCredentials.get(session.passkeyCredentialId);}
// Passkey identity remains separate from the single-operator authentication choice.
function Recent(session){return require("../../web/authentication/peace.web-auth").HasRecentPasskey(session);}
function RecentAuthentication(session){return require("../../web/authentication/peace.web-auth").HasRecentAuthentication(session);}
function ProvisionedCredential(id,principal){const c=state.production.passkeyCredentials.get(id);return !!c&&!c.revokedAt&&c.role==='admin'&&Identities()?.[id]===principal;}
function Identity(session){if(!Recent(session))return '';return Identities()?.[session.passkeyCredentialId]||'';}
function MarkVerified(session,credentialId){session.passkeyCredentialId=credentialId;session.securityVerifiedAt=Date.now();}
// This edition is explicitly configured for a single desktop operator. Do not
// change other applications' optional global two-person policy or stored keys.
function SingleOperatorPath(pathname) {
  return typeof pathname==='string' && (pathname.startsWith('/api/desktop/bootstrap/') || pathname.startsWith('/api/desktop/workspace/') ||
    pathname==='/api/production/passkeys/revoke' || pathname==='/api/production/passkeys/register/begin' || pathname==='/api/production/passkeys/register/finish');
}
// Mandatory trust-changing operations. Candidate uploads, read-only previews,
// release planning and normal launcher/license operations are NOT step-up gates.
// Replacing trust policy/measurement baselines, publishing an execution cohort,
// changing evidence used by live authorization and recovery always are.
function AdditionalCritical(pathname){return /^\/api\/backups\/[^/]+\/restore$/.test(pathname||'') || /^\/api\/production\/(?:config\/apply|transport|update\/(?:policy|rollback))$/.test(pathname||'');}
function CriticalMutation(pathname) {
  if(pathname==='/api/desktop/bootstrap/security-operations/registration-reset')return true;
  if(SecurityCenterMutation(pathname))return true;
  if(AdditionalCritical(pathname)||(pathname==='/api/desktop/bootstrap/packing/jobs'||pathname==='/api/desktop/bootstrap/packing/custom/jobs'))return true;
  if (typeof pathname !== 'string') return false;
  return /^\/api\/production\/(?:dual-policy|passkeys\/(?:revoke|register\/(?:begin|finish)))$/.test(pathname) ||
    /^\/api\/desktop\/bootstrap\/(?:security-authority|integrity-policy|module-baselines)$/.test(pathname) ||
    /^\/api\/desktop\/bootstrap\/security-operations\/(?:baseline-pin|retire-cohort|controls|contracts|signers|rollout|test-evidence|activate|enable-all|release-governance|ci-signers|ci-evidence|mitigation-compatibility|mitigation-profiles|tls-pin-transition|recovery\/(?:prepare|apply))$/.test(pathname) ||
    /^\/api\/desktop\/bootstrap\/server-state\/(?:recover-sessions|device-identity-policy|device-key-revoke|storage-maintenance|device-replacement|orphan-quarantine|orphan-delete|journal-checkpoint|manual-verification)$/.test(pathname);
}
function ReauthenticationRequired(pathname, method = 'POST') {
  if (['GET', 'HEAD', 'OPTIONS'].includes(String(method).toUpperCase())) return false;
  // The legacy flag may extend the gate; 0/unset can never disable its floor.
  return CriticalMutation(pathname) || process.env.DESKTOP_ADMIN_REAUTH_REQUIRED==='1' && IsMutation(pathname);
}
function CheckSession(session, pathname='', method='POST') {
  if(!session||session.role!=='admin'||typeof session.id!=='string'||!session.id)
    return {ok:false,status:403,reason:'ADMIN_REQUIRED'};
  const webAuth=require("../../web/authentication/peace.web-auth");
  if(webAuth.IsManagedSession(session)&&!webAuth.IsSessionActive(session))
    return {ok:false,status:401,reason:'ADMIN_SESSION_EXPIRED'};
  if(Object.hasOwn(session,'expiresAt')&&(!Number.isSafeInteger(session.expiresAt)||session.expiresAt<=Date.now()))
    return {ok:false,status:401,reason:'ADMIN_SESSION_EXPIRED'};
  // Both password and passkey verification use private, live server session metadata.
  // Never derive freshness from browser flags or a client-supplied timestamp.
  if(ReauthenticationRequired(pathname,method)&&!RecentAuthentication(session))
    return {ok:false,status:428,reason:'ADMIN_REAUTH_REQUIRED'};
  if(!pathname||SingleOperatorPath(pathname))return {ok:true,mode:'SINGLE_ADMIN'};
  if(StepUpRequired()&&!RecentAuthentication(session))return {ok:false,status:428,reason:'ADMIN_REAUTH_REQUIRED'};
  if(DualRequired()&&!Identity(session))return {ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
  return {ok:true};
}
function Status(){return {mode:'SINGLE_ADMIN',stepUpRequired:true,dualApprovalRequired:false,
  identityConfigurationValid:true,provisionedPrincipalCount:0,stepUpLifetimeMs:require("../../web/authentication/peace.web-auth").REAUTH_MS,
  identitySource:'SERVER_VERIFIED_RECENT_AUTHENTICATION',humanIdentityProof:false,
  recentReauthenticationRequired:true,
  reauthenticationScope:process.env.DESKTOP_ADMIN_REAUTH_REQUIRED==='1'?'ALL_DECLARED_MUTATIONS':'CRITICAL_MUTATIONS',
  criticalReauthenticationMandatory:true,criticalAuthenticationMethod:'PASSWORD_OR_PASSKEY',
  enrollmentAuthentication:'PASSWORD_OR_PASSKEY',
  enrollmentRecovery:'OPTIONAL_ONE_USE_SERVER_ISSUED_SESSION_BOUND_APPROVAL',
  reauthenticationLifetimeMs:require("../../web/authentication/peace.web-auth").REAUTH_MS,operationBound:true,operationApprovalOneUse:true,operationApprovalLifetimeMs:30000};}
function Begin(session,req){const check=CheckSession(session);return check.ok?{ok:false,reason:'SECURITY_DESKTOP_PASSKEY_NOT_USED'}:check;}
function Finish(session,req,body){return Begin(session,req);}
function SinglePermit(session,method,path,body){
  const ticket=Object.freeze({mode:'SINGLE_ADMIN'});
  singleAuthorizations.set(ticket,{session,id:session.id,method,path,
    digest:require('./peace.privileged-approval').Digest(method,path,body),expiresAt:Date.now()+30000});
  return ticket;
}
function ConsumeSingleAuthorization(ticket,session,method,path,body){
  const grant=ticket&&singleAuthorizations.get(ticket);
  if(grant)singleAuthorizations.delete(ticket);
  return !!grant&&CheckSession(session,path,method).ok&&grant.session===session&&grant.id===session.id&&
    grant.method===method&&grant.path===path&&grant.expiresAt>Date.now()&&
    grant.digest===require('./peace.privileged-approval').Digest(method,path,body);
}
function Summary(path,body){
  // No raw request / PE bytes or private key material in an approval ticket.
  const out={path};
  for(const k of ['action','alertId','seed','iterations','id','machineId','expectedGeneration','manifestId','credentialId','requestId','expectedEpoch','reasonCode','reason','note','profile','expectedActivationRevision','aSha512','bSha512','oSha512','targetHash','expectedRevision','expectedPolicyRevision','expectedOperationsRevision','component','version','sha512','aId','bId','oId','artifactId','keyId','state','mode','enforceLegacy','requireReadonlyApi','dynamicCode','requireCfg','requireReleaseSignature','deviceSignalsRequested','minVersionA','minVersionB','minVersionO','requireBuildContract','requireTestEvidence'])if(['string','number','boolean'].includes(typeof body?.[k]))out[k]=body[k];
  if(SecurityCenterMutation(path)&&Array.isArray(body?.artifactIds))out.artifactIds=body.artifactIds.filter(x=>typeof x==='string'&&/^[A-F0-9]{24}$/.test(x)).slice(0,3);
  if(Array.isArray(body?.trustedReleaseKeys))out.trustedSignerKeyIds=body.trustedReleaseKeys.map(x=>x.keyId).slice(0,8);
  if(Array.isArray(body?.revokedSha512))out.revokedReleaseHashes=body.revokedSha512.slice(0,512);
  if(body?.contract)out.contract=Object.fromEntries(['version','evidenceVersion','minApiSlots','maxApiSlots'].filter(k=>Number.isSafeInteger(body.contract[k])).map(k=>[k,body.contract[k]]));
  if(body?.rollout)out.rollout={enabled:body.rollout.enabled===true,artifactKeys:Array.isArray(body.rollout.artifactKeys)?body.rollout.artifactKeys.filter(x=>typeof x==='string'&&/^[ABO]:[a-f0-9]{128}$/.test(x)).slice(0,128):[],patch:Object.fromEntries(['mode','dynamicCode','requireReadonlyApi','requireCfg'].filter(k=>['string','boolean'].includes(typeof body.rollout.patch?.[k])).map(k=>[k,String(body.rollout.patch[k]).slice(0,20)]))};
  if(path==='/api/desktop/bootstrap/security-operations/enable-all')out.activationTargets={profile:body?.profile,targetHash:body?.targetHash,stepUpRequired:true,dualApprovalRequired:false,adminMode:'SINGLE_ADMIN',windows:body?.profile==='ALL'?'dynamicCode=prohibit; requireCfg=true':'UNCHANGED'};
  if(path==='/api/desktop/bootstrap/security-operations/registration-reset')out.reset={scope:body?.scope,confirmation:body?.confirmation,expectedEpoch:body?.expectedEpoch,requestId:body?.requestId,preserves:'SERVER_KEYS_ADMIN_LOGIN_SECURITY_FLOORS_AUDIT'};
  if(body?.report)out.testEvidence={aSha512:body.report.aSha512,bSha512:body.report.bSha512,...(body.report.oSha512?{oSha512:body.report.oSha512}:{}),nativeBuild:body.report.nativeBuild,apiProbe:body.report.apiProbe,integration:body.report.integration,logsSha512:body.report.logsSha512};
  return out;
}
function EnrollmentPath(path){return /^\/api\/production\/passkeys\/register\/(?:begin|finish)$/.test(path||'');}
function Authorize(session,method,path,body,ticketId,enrollmentToken='',actionId=''){
  if(EnrollmentPath(path)){
    const enrollment=require('./peace.desktop-admin-enrollment');
    // Optional console recovery remains one-use/session-bound. An explicitly
    // supplied token must validate: never silently fall back after token failure.
    if(enrollmentToken||enrollment.HasPending(session)){
      const base=CheckSession(session);if(!base.ok)return base;
      return enrollment.Authorize(session,method,path,body,enrollmentToken);
    }
    // Ordinary first/additional enrollment uses the same recent password OR
    // passkey gate as other sensitive writes. No SSH approval is mandatory.
  }
  if(ReauthenticationRequired(path,method)){
    const base=CheckSession(session);if(!base.ok)return base;
    const bound=require('./peace.desktop-action-approval').Guard(session,method,path,body,actionId);if(!bound.ok)return bound;
  }
  const check=CheckSession(session,path,method);if(!check.ok)return check;
  if(path==='/api/desktop/bootstrap/security-operations/enable-all'){
    try{require("../security/peace.desktop-security-activation").CheckRequest(body,session);}
    catch(e){return{ok:false,status:e.desktopError?e.status:503,reason:e.desktopError?e.message:'SECURITY_ACTIVATION_CHECK_FAILED'};}
  }
  if(SingleOperatorPath(path))return {ok:true,mode:'SINGLE_ADMIN',
    ...((path==='/api/desktop/bootstrap/security-operations/enable-all'||path==='/api/desktop/bootstrap/security-operations/registration-reset'||SecurityCenterMutation(path))?{ticket:SinglePermit(session,method,path,body)}:{})};
  if(path==='/api/production/dual-policy'&&body?.required===true){
    if(!Identity(session))return{ok:false,status:428,reason:'SECURITY_ADMIN_IDENTITY_REQUIRED'};
    if(new Set(Object.entries(Identities()||{}).filter(([id,principal])=>ProvisionedCredential(id,principal)).map(([,principal])=>principal)).size<2)return{ok:false,status:409,reason:'SECURITY_SECOND_OPERATOR_REQUIRED'};
  }
  const dual=require('./peace.privileged-approval');if(!dual.Required(path))return{ok:true};
  const used=dual.Consume(ticketId,session,method,path,body);if(used.ok)return used;
  if(used.reason==='DUAL_APPROVAL_REQUIRED'){
    const requested=dual.Request(session,method,path,body,'DESKTOP_SECURITY_CHANGE');
    return{ok:false,status:428,reason:requested.ok?used.reason:requested.reason,ticketId:requested.ticket?.ticketId||''};
  }
  return{ok:false,status:428,reason:used.reason};
}
module.exports={CriticalMutation,ReauthenticationRequired,SingleOperatorPath,ConsumeSingleAuthorization,ProvisionedCredential,IsMutation,Identity,Recent,MarkVerified,CheckSession,Status,Begin,Finish,Summary,Authorize};
