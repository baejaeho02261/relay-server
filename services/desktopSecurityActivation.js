'use strict';
// Single-operator desktop edition. An existing authenticated administrator and
// CSRF-protected dispatcher authorize changes. No fabricated passkey/second
// person, trusted key, test PASS, CFG flag or client attestation is created.
const crypto = require('node:crypto');
const store = require('./desktopBootstrapStore');
const PATH = '/api/desktop/bootstrap/security-operations/enable-all';
const PROFILES = ['READY', 'SERVER', 'ALL'];
const HASH = /^[a-f0-9]{128}$/;
const REQUEST_FIELDS = ['profile', 'expectedPolicyRevision', 'expectedOperationsRevision',
  'expectedActivationRevision', 'aId', 'bId', 'aSha512', 'bSha512', 'targetHash'];
const OVERLAY_REQUEST_FIELDS = [...REQUEST_FIELDS,'oId','oSha512'];
function Fail(code, status = 409) {
  const e = Error(code); e.desktopError = true; e.status = status; throw e;
}
function Plain(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}
function Profile(profile) {
  if (!PROFILES.includes(profile)) Fail('SECURITY_ACTIVATION_PROFILE_INVALID', 400);
  return profile;
}
function Exact(value, fields) {
  return Plain(value) && Object.keys(value).length === fields.length &&
    fields.every(k => Object.hasOwn(value, k));
}
function TargetHash(value) {
  return crypto.createHash('sha512').update(JSON.stringify(value)).digest('hex');
}
function ValidateRecord(value) {
  // Preserve/validate old records as history without making them a new 2-person
  // requirement. Do not migrate or delete saved data merely by reading it.
  if (value?.version === 1) {
    const fields = ['version', 'revision', 'adminEnforced', 'profile', 'activatedAt',
      'activatedBy', 'approvedBy', 'aSha512', 'bSha512'];
    if (!Exact(value, fields) || value.adminEnforced !== true ||
        !['ALL','SERVER'].includes(value.profile) ||
        ['activatedBy','approvedBy'].some(k => typeof value[k] !== 'string' ||
          !/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/.test(value[k])) ||
        value.activatedBy === value.approvedBy) Fail('SECURITY_ACTIVATION_STORAGE_INVALID', 503);
  } else if (value?.version === 2) {
    const fields = ['version', 'revision', 'adminMode', 'profile', 'activatedAt',
      'activatedBy', 'aSha512', 'bSha512', 'targetHash'];
    if (!(Exact(value, fields) || Exact(value,[...fields,'oSha512']) && typeof value.oSha512==='string' && HASH.test(value.oSha512)) || value.adminMode !== 'SINGLE_ADMIN' ||
        !PROFILES.includes(value.profile) || typeof value.activatedBy!=='string' ||
        !/^admin-[a-f0-9]{24}$/.test(value.activatedBy) || typeof value.targetHash!=='string' ||
        !HASH.test(value.targetHash)) Fail('SECURITY_ACTIVATION_STORAGE_INVALID', 503);
  } else Fail('SECURITY_ACTIVATION_STORAGE_INVALID', 503);
  if (!Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Number.isSafeInteger(value.activatedAt) || value.activatedAt < 1 ||
      typeof value.aSha512!=='string' || typeof value.bSha512!=='string' ||
      !HASH.test(value.aSha512) || !HASH.test(value.bSha512)) Fail('SECURITY_ACTIVATION_STORAGE_INVALID', 503);
  return value;
}
function Record() {
  const value = store.Load().securityActivation;
  return value === undefined ? null : structuredClone(ValidateRecord(value));
}
// Kept for older internal callers. This dedicated edition does not enforce
// passkey/independent co-approval on desktop mutations, even for a legacy record.
function AdminEnforced() { return false; }
function Status() {
  const p = require('./desktopSecurityAuthority').Policy();
  const s = require('./desktopSecurityOperations').State();
  const settings = {
    mode:p.mode, enforceLegacy:p.enforceLegacy, requireReadonlyApi:p.requireReadonlyApi,
    requireReleaseSignature:p.requireReleaseSignature, requireBuildContract:s.requireBuildContract,
    requireTestEvidence:s.requireTestEvidence, stepUpRequired:false, dualApprovalRequired:false,
    adminMode:'SINGLE_ADMIN', rolloutDisabled:!s.rollout.enabled,
    dynamicCode:p.dynamicCode, requireCfg:p.requireCfg
  };
  const baselineEnabled = p.mode === 'enforce' && p.enforceLegacy &&
    p.requireReadonlyApi && p.requireReleaseSignature && !s.rollout.enabled;
  const serverEnabled = baselineEnabled && s.requireBuildContract && s.requireTestEvidence;
  return {settings,baselineEnabled,serverEnabled,allEnabled:serverEnabled &&
    p.dynamicCode === 'prohibit' && p.requireCfg,activation:Record(),
    adminMode:'SINGLE_ADMIN',defaultProfile:'READY',
    alreadyWired:['policyUI','candidatePublication','boundedRetry','incidentAudit','sourceAndTestRecords'],
    storage:'SERVER_ONLY',isRuntimeAttestation:false};
}
function Targets(profile) {
  Profile(profile);
  const p = require('./desktopSecurityAuthority').Policy();
  return {...p,mode:'enforce',enforceLegacy:true,requireReadonlyApi:true,requireReleaseSignature:true,
    ...(profile === 'ALL' ? {dynamicCode:'prohibit',requireCfg:true} : {})};
}
function Preview(profile, session) {
  Profile(profile);
  if (!require('./desktopAdminGuard').CheckSession(session,PATH).ok) Fail('ADMIN_REQUIRED',403);
  const auth=require('./desktopSecurityAuthority'),ops=require('./desktopSecurityOperations');
  const db=store.Load(),p=auth.Policy(),s=ops.State(),record=Record();
  const target=Targets(profile),issues=[],pending=[];
  const add=(code,detail,component='')=>issues.push({code,detail,component});
  const defer=(code,detail,component='')=>pending.push({code,detail,component});
  const a=db.artifacts[db.active.A],b=db.artifacts[db.active.B],o=db.artifacts[db.active.O];
  const pair=[['A',a],['B',b],...(db.active.O?[['O',o]]:[])];
  for (const [component,artifact] of pair) {
    if (!artifact || artifact.component !== component) {
      add('SECURITY_ACTIVE_PAIR_REQUIRED','후보 등록 후 운영 A/B 및 선택한 O 게시를 먼저 완료하세요.',component);continue;
    }
    const reason=auth.ArtifactReason(artifact,target);
    if (reason) add(reason,'현재 운영 파일의 서명·버전·철회·현재 필수 정책을 확인하세요.',component);
    try {
      const bytes=require('./desktopBootstrap').ReadArtifactBytes(artifact);
      const actual=auth.PeCapabilities(bytes);
      if (actual.authorityVersion !== 1) add('SECURITY_CLIENT_UPGRADE_REQUIRED','실제 저장 EXE가 서버 관측 프로토콜을 지원해야 합니다.',component);
      if (target.requireCfg && !actual.compiledCfg) add('SECURITY_CFG_BUILD_REQUIRED','현재 필수 CFG 정책을 저장된 EXE가 충족하지 않습니다. 기존 요구를 자동 해제하지 않습니다.',component);
    } catch (e) {
      add(e.desktopError?e.message:'SECURITY_RELEASE_READ_FAILED','서버의 실제 운영 파일을 다시 검증하지 못했습니다.',component);
    }
  }
  const samples=auth.ActivationObservations(target,pair.map(([,row])=>row?.id).filter(Boolean));
  const allObserved=pair.every(([,row])=>row && samples.some(x=>x.artifactId===row.id&&x.status==='PASS'));
  const allContracts=pair.every(([,row])=>row && s.contracts[ops.BuildKey(row)]);
  let evidenceReady=false;
  if (a&&b&&(!db.active.O||o)) { try {ops.RequirePairEvidence(a,b,s,o);evidenceReady=true;} catch (_) {} }
  const strict=profile!=='READY';
  const controls={
    requireBuildContract:s.requireBuildContract || strict || !!(allContracts && allObserved),
    requireTestEvidence:s.requireTestEvidence || strict || evidenceReady
  };
  for (const [component,row] of pair) {
    if (!row) continue;
    if (!s.contracts[ops.BuildKey(row)]) {
      (controls.requireBuildContract?add:defer)('SECURITY_BUILD_CONTRACT_REQUIRED',
        '빌드 규격은 미등록 상태입니다. 슬롯 수를 추정하지 않으며, 준비된 뒤 별도로 등록할 수 있습니다.',component);
    }
    const recent=samples.find(x=>x.artifactId===row.id);
    if (!recent) {
      (strict?add:defer)('SECURITY_RECENT_OBSERVATION_REQUIRED',
        '최근 실제 관측이 없습니다. 기본 보호 설정은 적용할 수 있으나 실행 검증 완료로 표시하지 않습니다.',component);
    } else if (recent.status!=='PASS') {
      // A known failure is not treated as an absent optional measurement.
      add('SECURITY_TARGET_OBSERVATION_FAILED','최근 실제 관측이 목표 정책과 불일치합니다: '+recent.reason,component);
    }
  }
  if (!evidenceReady) (controls.requireTestEvidence?add:defer)('SECURITY_TEST_EVIDENCE_REQUIRED',
    '정확한 A/B 및 선택한 O 시험 기록이 없습니다. PASS를 자동 생성하지 않으며, 준비 전에는 신규 필수 요구를 켜지 않습니다.');
  if (profile==='READY') {
    if (allContracts && !allObserved && !s.requireBuildContract)
      defer('SECURITY_BUILD_CONTRACT_ACTIVATION_PENDING','등록된 규격의 실제 정상 관측을 확인한 뒤 규격 필수를 적용합니다.');
    if (!target.requireCfg) defer('SECURITY_CFG_NOT_ENABLED','CFG는 새로 강제하지 않습니다. 현재 서버 설정을 유지합니다.');
    if (target.dynamicCode!=='prohibit') defer('SECURITY_DYNAMIC_CODE_NOT_ENFORCED','Windows 동적 코드 제한은 새로 강제하지 않습니다. 현재 관찰 설정을 유지합니다.');
  }
  const health=require('../storage/audit').WriteHealth();
  if (health.status==='DEGRADED') add('SECURITY_AUDIT_UNAVAILABLE','서버 감사 저장 오류를 먼저 해결하세요.');
  if (require('../core/state').production.auditChain.lastError) add('SECURITY_AUDIT_CHAIN_INVALID','감사 체인의 기존 오류를 먼저 확인하세요.');
  const targetView={policy:target,controls,admin:{mode:'SINGLE_ADMIN',stepUpRequired:false,dualApprovalRequired:false},rollout:'DISABLED'};
  const plan={profile,expectedPolicyRevision:p.revision,expectedOperationsRevision:s.revision,
    expectedActivationRevision:record?.revision||0,aId:a?.id||'',bId:b?.id||'',
    aSha512:a?.sha512||'',bSha512:b?.sha512||'',oId:o?.id||'',oSha512:o?.sha512||'',targetHash:TargetHash(targetView)};
  const unique=[...new Map(issues.map(x=>[x.code+':'+x.component,x])).values()];
  return {profile,ready:unique.length===0,issues:unique,pending,plan,target:targetView,
    current:Status(),recentObservations:samples,readOnly:true,observationsAreNotAttestation:true,
    approvalRequiredBeforeFirstActivation:false,adminMode:'SINGLE_ADMIN',
    warning:'기존 관리자 로그인과 CSRF 검증으로 적용합니다. 준비되지 않은 추가 보호는 별도 표시하며 기존 필수 정책은 자동으로 끄지 않습니다. 라이선스·키·정리 경로는 유지합니다.'};
}
function CheckRequest(body,session) {
  if (!(Exact(body,REQUEST_FIELDS)||Exact(body,OVERLAY_REQUEST_FIELDS))) Fail('SECURITY_ACTIVATION_INPUT_INVALID',400);
  Profile(body.profile);
  if (typeof body.targetHash!=='string' || !HASH.test(body.targetHash)) Fail('SECURITY_ACTIVATION_INPUT_INVALID',400);
  for (const k of ['expectedPolicyRevision','expectedOperationsRevision','expectedActivationRevision'])
    if (!Number.isSafeInteger(body[k])||body[k]<0) Fail('SECURITY_ACTIVATION_INPUT_INVALID',400);
  const auth=require('./desktopSecurityAuthority'),ops=require('./desktopSecurityOperations');
  if(body.expectedPolicyRevision!==auth.Policy().revision)Fail('SECURITY_POLICY_CONFLICT');
  if(body.expectedOperationsRevision!==ops.Revision())Fail('SECURITY_OPERATIONS_CONFLICT');
  if(body.expectedActivationRevision!==(Record()?.revision||0))Fail('SECURITY_ACTIVATION_CONFLICT');
  const db=store.Load();
  if(['aId','bId','aSha512','bSha512'].some(k=>typeof body[k]!=='string')||
    body.aId!==db.active.A||body.bId!==db.active.B||body.aSha512!==db.artifacts[body.aId]?.sha512||
    body.bSha512!==db.artifacts[body.bId]?.sha512)Fail('SECURITY_ACTIVE_PAIR_CHANGED');
  // Legacy A/B previews remain usable only when no O is selected. An omitted O
  // must never approve a newly activated overlay between preview and commit.
  if (Object.hasOwn(body,'oId') ? typeof body.oId!=='string'||typeof body.oSha512!=='string'||body.oId!==(db.active.O||'')||body.oSha512!==(db.artifacts[db.active.O]?.sha512||'') : !!db.active.O) Fail('SECURITY_ACTIVE_PAIR_CHANGED');
  const view=Preview(body.profile,session);
  if(!view.ready)Fail(view.issues[0].code);
  // New evidence can arrive without a policy revision. Never silently apply a
  // different set of optional requirements from the one shown in the preview.
  if(view.plan.targetHash!==body.targetHash)Fail('SECURITY_ACTIVATION_PREVIEW_CHANGED');
  return view;
}
function Apply(body,session,ticket) {
  const guard=require('./desktopAdminGuard');
  if(!guard.ConsumeSingleAuthorization(ticket,session,'POST',PATH,body))
    Fail('SECURITY_ACTIVATION_AUTHORIZATION_REQUIRED',403);
  const view=CheckRequest(body,session);
  const auth=require('./desktopSecurityAuthority'),ops=require('./desktopSecurityOperations');
  const nextPolicy=auth.ValidatePolicy({...view.target.policy,revision:body.expectedPolicyRevision+1});
  const nextOperations=ops.State();nextOperations.revision++;
  Object.assign(nextOperations,view.target.controls);
  nextOperations.rollout={enabled:false,artifactKeys:[],patch:{}};ops.ValidateState(nextOperations);
  const actor='admin-'+crypto.createHash('sha256').update(session.id).digest('hex').slice(0,24);
  const activation=ValidateRecord({version:2,revision:body.expectedActivationRevision+1,
    adminMode:'SINGLE_ADMIN',profile:body.profile,activatedAt:Date.now(),activatedBy:actor,
    aSha512:body.aSha512,bSha512:body.bSha512,...(body.oId?{oSha512:body.oSha512}:{}),targetHash:body.targetHash});
  ops.AuditIntent('SINGLE_ADMIN_ENABLE_'+body.profile,actor);
  store.Atomic(db=>{
    if((db.securityAuthorityPolicy||auth.Defaults()).revision!==body.expectedPolicyRevision||
      (db.securityOperations||ops.Defaults()).revision!==body.expectedOperationsRevision||
      (db.securityActivation?.revision||0)!==body.expectedActivationRevision||
      db.active.A!==body.aId||db.active.B!==body.bId||(db.active.O||'')!==(body.oId||''))Fail('SECURITY_ACTIVATION_CONFLICT');
    db.securityAuthorityPolicy=nextPolicy;db.securityOperations=nextOperations;db.securityActivation=activation;
  });
  auth.InvalidateAll();
  require('../storage/audit').LogEvent('DESKTOP_SECURITY_ACTIVATED',JSON.stringify({
    profile:body.profile,revision:activation.revision,actor,adminMode:'SINGLE_ADMIN',
    aSha512:body.aSha512,bSha512:body.bSha512,...(body.oId?{oSha512:body.oSha512}:{}),targetHash:body.targetHash}));
  const current=Status();
  if(!current.baselineEnabled||body.profile==='SERVER'&&!current.serverEnabled||body.profile==='ALL'&&!current.allEnabled)
    Fail('SECURITY_ACTIVATION_RECHECK_FAILED',503);
  return {activated:true,profile:body.profile,current,pending:view.pending,clientChanged:false,
    note:'1인 운영 보호 설정을 서버에 저장했습니다. 미준비 추가 보호와 실제 Windows 실행 검증은 별도입니다.'};
}
module.exports={PATH,ValidateRecord,Record,AdminEnforced,Status,Preview,CheckRequest,Apply};
