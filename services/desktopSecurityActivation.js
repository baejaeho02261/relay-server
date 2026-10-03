'use strict';
// Administrative policy activation only. No client files, runtime attestation,
// operating-system settings or private signing keys are created here.
const store = require('./desktopBootstrapStore');
const PATH = '/api/desktop/bootstrap/security-operations/enable-all';
const PROFILES = ['ALL', 'SERVER'];
const HASH = /^[a-f0-9]{64}$/;
const REQUEST_FIELDS = ['profile', 'expectedPolicyRevision', 'expectedOperationsRevision',
  'expectedActivationRevision', 'aId', 'bId', 'aSha256', 'bSha256'];
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
function ValidateRecord(value) {
  const fields = ['version', 'revision', 'adminEnforced', 'profile', 'activatedAt',
    'activatedBy', 'approvedBy', 'aSha256', 'bSha256'];
  if (!Plain(value) || Object.keys(value).length !== fields.length ||
      fields.some(k => !Object.hasOwn(value, k)) || value.version !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      value.adminEnforced !== true || !PROFILES.includes(value.profile) ||
      !Number.isSafeInteger(value.activatedAt) || value.activatedAt < 1 ||
      !HASH.test(value.aSha256) || !HASH.test(value.bSha256) ||
      ['activatedBy', 'approvedBy'].some(k => typeof value[k] !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/.test(value[k])) ||
      value.activatedBy === value.approvedBy) Fail('SECURITY_ACTIVATION_STORAGE_INVALID', 503);
  return value;
}
function Record() {
  const value = store.Load().securityActivation;
  return value === undefined ? null : structuredClone(ValidateRecord(value));
}
function AdminEnforced() { return Record()?.adminEnforced === true; }
function Status() {
  const p = require('./desktopSecurityAuthority').Policy();
  const s = require('./desktopSecurityOperations').State();
  const g = require('./desktopAdminGuard').Status();
  const record = Record();
  const settings = {
    mode: p.mode, enforceLegacy: p.enforceLegacy,
    requireReadonlyApi: p.requireReadonlyApi, requireReleaseSignature: p.requireReleaseSignature,
    requireBuildContract: s.requireBuildContract, requireTestEvidence: s.requireTestEvidence,
    stepUpRequired: g.stepUpRequired, dualApprovalRequired: g.dualApprovalRequired,
    rolloutDisabled: !s.rollout.enabled, dynamicCode: p.dynamicCode, requireCfg: p.requireCfg
  };
  const serverEnabled = settings.mode === 'enforce' && settings.enforceLegacy &&
    settings.requireReadonlyApi && settings.requireReleaseSignature &&
    settings.requireBuildContract && settings.requireTestEvidence &&
    settings.stepUpRequired && settings.dualApprovalRequired && settings.rolloutDisabled;
  return {settings, serverEnabled, allEnabled: serverEnabled &&
    p.dynamicCode === 'prohibit' && p.requireCfg, activation: record,
    alreadyWired: ['policyUI', 'candidatePublication', 'boundedRetry', 'incidentAudit', 'sourceAndTestRecords'],
    storage: 'SERVER_ONLY', isRuntimeAttestation: false};
}
function Targets(profile) {
  Profile(profile);
  const p = require('./desktopSecurityAuthority').Policy();
  return {...p, mode: 'enforce', enforceLegacy: true, requireReadonlyApi: true,
    requireReleaseSignature: true,
    ...(profile === 'ALL' ? {dynamicCode: 'prohibit', requireCfg: true} : {})};
}
function Preview(profile, session) {
  Profile(profile);
  if (!session || session.role !== 'admin') Fail('ADMIN_REQUIRED', 403);
  const auth = require('./desktopSecurityAuthority');
  const ops = require('./desktopSecurityOperations');
  const guard = require('./desktopAdminGuard');
  const db = store.Load(), p = auth.Policy(), s = ops.State(), record = Record();
  const target = Targets(profile), issues = [];
  const add = (code, detail, component = '') => issues.push({code, detail, component});
  const admin = guard.Status();
  if (!admin.identityConfigurationValid) add('SECURITY_ADMIN_IDENTITY_CONFIG_INVALID', '서버 운영자 매핑 JSON 형식을 확인하세요.');
  if (!guard.Recent(session)) add('SECURITY_ADMIN_STEP_UP_REQUIRED', '관리자 패스키 재인증을 먼저 완료하세요.');
  if (!guard.Identity(session)) add('SECURITY_ADMIN_IDENTITY_REQUIRED', '현재 관리자 패스키를 서버의 실제 운영자 신원에 매핑하세요.');
  if (admin.provisionedPrincipalCount < 2) add('SECURITY_SECOND_OPERATOR_REQUIRED', '서로 다른 실제 운영자 2명의 유효한 관리자 패스키가 필요합니다.');
  const a = db.artifacts[db.active.A], b = db.artifacts[db.active.B];
  for (const [component, artifact] of [['A', a], ['B', b]]) {
    if (!artifact || artifact.component !== component) {
      add('SECURITY_ACTIVE_PAIR_REQUIRED', '후보 등록 후 운영 A/B 게시를 먼저 완료하세요.', component); continue;
    }
    const reason = auth.ArtifactReason(artifact, target);
    if (reason) add(reason, '현재 운영 파일이 목표 정책을 충족하지 않습니다. 서명·버전·프로토콜·CFG 상태를 확인하세요.', component);
    if (!s.contracts[ops.BuildKey(artifact)]) add('SECURITY_BUILD_CONTRACT_REQUIRED', '실제 정상 실행에서 확인한 이 빌드의 검사 규격을 등록하세요.', component);
    try {
      const bytes = require('./desktopBootstrap').ReadArtifactBytes(artifact);
      // Compute capabilities from the current server file, not just old metadata.
      const actual = auth.PeCapabilities(bytes);
      if (actual.authorityVersion !== 1) add('SECURITY_CLIENT_UPGRADE_REQUIRED', '저장된 EXE가 현재 관측 프로토콜을 포함하지 않습니다.', component);
      if (target.requireCfg && !actual.compiledCfg) add('SECURITY_CFG_BUILD_REQUIRED', '실제 저장 EXE에 필요한 CFG 메타데이터가 없습니다. 플래그만 위조하지 마세요.', component);
    } catch (e) {
      add(e.desktopError ? e.message : 'SECURITY_RELEASE_READ_FAILED', '서버의 실제 운영 파일을 다시 검증하지 못했습니다.', component);
    }
  }
  if (a && b) {
    try { ops.RequirePairEvidence(a, b, s); }
    catch (_) { add('SECURITY_TEST_EVIDENCE_REQUIRED', '정확한 운영 A/B 조합의 nativeBuild·apiProbe·integration PASS 기록이 필요합니다. 실행하지 않은 시험을 PASS로 만들지 마세요.'); }
  }
  const samples = auth.ActivationObservations(target, [a?.id, b?.id].filter(Boolean));
  for (const [component, artifact] of [['A', a], ['B', b]]) {
    if (!artifact) continue;
    const recent = samples.filter(x => x.artifactId === artifact.id);
    if (!recent.length) add('SECURITY_RECENT_OBSERVATION_REQUIRED', '최근 10분 내 실제 A/B 실행 관측이 필요합니다. 서버 재시작 후에는 새로 실행하세요.', component);
    else if (recent.some(x => x.status !== 'PASS')) add('SECURITY_TARGET_OBSERVATION_FAILED', '최근 관측이 목표 설정을 충족하지 않습니다. 아래 관측 사유를 확인하세요.', component);
  }
  const health = require('../storage/audit').WriteHealth();
  if (health.status === 'DEGRADED') add('SECURITY_AUDIT_UNAVAILABLE', '서버 감사 저장 오류를 해결한 뒤 다시 점검하세요.');
  if (require('../core/state').production.auditChain.lastError) add('SECURITY_AUDIT_CHAIN_INVALID', '감사 체인의 기존 오류를 확인하세요. 활성화가 과거 로그 오류를 지우지는 않습니다.');
  const plan = {profile, expectedPolicyRevision: p.revision,
    expectedOperationsRevision: s.revision, expectedActivationRevision: record?.revision || 0,
    aId: a?.id || '', bId: b?.id || '', aSha256: a?.sha256 || '', bSha256: b?.sha256 || ''};
  const unique = [...new Map(issues.map(x => [x.code + ':' + x.component, x])).values()];
  return {profile, ready: unique.length === 0, issues: unique, plan,
    target: {policy: target, controls: {requireBuildContract: true, requireTestEvidence: true},
      admin: {stepUpRequired: true, dualApprovalRequired: true}, rollout: 'DISABLED'},
    current: Status(), recentObservations: samples, readOnly: true,
    observationsAreNotAttestation: true, approvalRequiredBeforeFirstActivation: true,
    warning: '구버전·무서명·규격/시험 기록 없는 배포는 이후 작업에서 거절됩니다. 기존 설정을 끄는 시험 적용은 종료됩니다. 정리/해제 경로는 유지합니다.'};
}
function CheckRequest(body, session) {
  if (!Plain(body) || Object.keys(body).length !== REQUEST_FIELDS.length ||
      REQUEST_FIELDS.some(k => !Object.hasOwn(body, k))) Fail('SECURITY_ACTIVATION_INPUT_INVALID', 400);
  Profile(body.profile);
  for (const key of ['expectedPolicyRevision', 'expectedOperationsRevision', 'expectedActivationRevision']) {
    if (!Number.isSafeInteger(body[key]) || body[key] < 0) Fail('SECURITY_ACTIVATION_INPUT_INVALID', 400);
  }
  const auth = require('./desktopSecurityAuthority'), ops = require('./desktopSecurityOperations');
  if (body.expectedPolicyRevision !== auth.Policy().revision) Fail('SECURITY_POLICY_CONFLICT');
  if (body.expectedOperationsRevision !== ops.Revision()) Fail('SECURITY_OPERATIONS_CONFLICT');
  if (body.expectedActivationRevision !== (Record()?.revision || 0)) Fail('SECURITY_ACTIVATION_CONFLICT');
  const db = store.Load();
  if (['aId','bId','aSha256','bSha256'].some(k => typeof body[k] !== 'string') ||
      body.aId !== db.active.A || body.bId !== db.active.B ||
      body.aSha256 !== db.artifacts[body.aId]?.sha256 || body.bSha256 !== db.artifacts[body.bId]?.sha256) Fail('SECURITY_ACTIVE_PAIR_CHANGED');
  const preview = Preview(body.profile, session);
  if (!preview.ready) Fail(preview.issues[0].code, preview.issues[0].code.includes('ADMIN') ? 428 : 409);
  return preview;
}
function Apply(body, session, ticket) {
  const guard = require('./desktopAdminGuard'), dual = require('./privilegedApproval');
  const live = ticket && require('../core/state').production.privilegedApprovals.get(ticket.ticketId);
  if (!ticket || live !== ticket || ticket.status !== 'CONSUMED' || ticket.pathname !== PATH ||
      ticket.consumedBy !== session?.id || ticket.requestedBy !== session?.id ||
      ticket.payloadHash !== dual.Digest('POST', PATH, body) || ticket.expiresAt <= Date.now() ||
      !guard.Identity(session) || ticket.requestedPrincipal !== guard.Identity(session) ||
      ticket.approvedPrincipal === ticket.requestedPrincipal ||
      !guard.ProvisionedCredential(ticket.approvedCredentialId, ticket.approvedPrincipal)) {
    Fail('SECURITY_ACTIVATION_APPROVAL_REQUIRED', 428);
  }
  const view = CheckRequest(body, session);
  const auth = require('./desktopSecurityAuthority'), ops = require('./desktopSecurityOperations');
  const nextPolicy = auth.ValidatePolicy({...view.target.policy, revision: body.expectedPolicyRevision + 1});
  const nextOperations = ops.State();
  nextOperations.revision++;
  nextOperations.requireBuildContract = true;
  nextOperations.requireTestEvidence = true;
  nextOperations.rollout = {enabled: false, artifactKeys: [], patch: {}};
  ops.ValidateState(nextOperations);
  const activation = ValidateRecord({version: 1, revision: body.expectedActivationRevision + 1,
    adminEnforced: true, profile: body.profile, activatedAt: Date.now(),
    activatedBy: guard.Identity(session), approvedBy: ticket.approvedPrincipal,
    aSha256: body.aSha256, bSha256: body.bSha256});
  ops.AuditIntent('ENABLE_ALL_' + body.profile, activation.activatedBy);
  // One writer, one durable authority file. Never commit the policy first and
  // the test/admin requirements later, or publish a weaker fallback on failure.
  store.Atomic(db => {
    if ((db.securityAuthorityPolicy || auth.Defaults()).revision !== body.expectedPolicyRevision ||
        (db.securityOperations || ops.Defaults()).revision !== body.expectedOperationsRevision ||
        (db.securityActivation?.revision || 0) !== body.expectedActivationRevision ||
        db.active.A !== body.aId || db.active.B !== body.bId) Fail('SECURITY_ACTIVATION_CONFLICT');
    db.securityAuthorityPolicy = nextPolicy;
    db.securityOperations = nextOperations;
    db.securityActivation = activation;
  });
  auth.InvalidateAll();
  require('../storage/audit').LogEvent('DESKTOP_SECURITY_ACTIVATED', JSON.stringify({
    profile: body.profile, revision: activation.revision, actor: activation.activatedBy,
    approvedBy: activation.approvedBy, aSha256: body.aSha256, bSha256: body.bSha256
  }));
  const current = Status();
  if (!current.serverEnabled || body.profile === 'ALL' && !current.allEnabled) Fail('SECURITY_ACTIVATION_RECHECK_FAILED', 503);
  return {activated: true, profile: body.profile, current, clientChanged: false,
    note: '서버 강제 설정 저장 완료. 실행 중 클라이언트의 새 측정은 다음 서버 작업에서 요구됩니다.'};
}
module.exports = {PATH, ValidateRecord, Record, AdminEnforced, Status, Preview, CheckRequest, Apply};
