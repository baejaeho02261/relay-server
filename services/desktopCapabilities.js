'use strict';
// Read-only capability projection. Source implementation, active configuration
// and deployment verification are separate facts. A policy switch, an enrolled
// key or a synthetic regression never creates a Windows test PASS.
const crypto=require('node:crypto'),store=require('./desktopBootstrapStore');
function DeviceState(db=store.Load(),now=Date.now()){
 const state=require('./desktopDeviceIdentity').State(db),active=Object.values(state.enrollments).filter(x=>x.status==='ACTIVE');
 const trustConfigured=!!state.trust&&state.trust.validUntil>now;
 const tpmRows=active.filter(x=>x.assurance==='TPM_KEY_ATTESTED'),unexpired=tpmRows.filter(x=>x.attestedUntil>now);
 const currentRoots=new Set(),revoked=new Set(state.trust?.revokedCertificateSha256||[]);
 if(trustConfigured)for(const pem of state.trust.roots||[]){
  const cert=new crypto.X509Certificate(pem),id=crypto.createHash('sha256').update(cert.raw).digest('hex');
  if(cert.ca&&!revoked.has(id)&&Date.parse(cert.validFrom)<=now&&now<Date.parse(cert.validTo))currentRoots.add(id);
 }
 // This count compares persisted enrollment metadata with current root policy.
 // It does not revalidate an EK chain or authorize a particular live session.
 const currentRootEnrollments=unexpired.filter(x=>currentRoots.has(x.rootSha256)).length;
 const persistentAll=state.mode!=='COMPATIBLE',persistentEnrolled=persistentAll||state.requireForEnrolled;
 const required=state.mode==='TPM_ATTESTED';
 return {mode:state.mode,revision:state.revision,requireForEnrolled:state.requireForEnrolled,proofRetentionDays:state.proofRetentionDays,
  persistentKeyImplemented:true,persistentKeyRequired:persistentAll,persistentKeyRequiredForEnrolled:persistentEnrolled,
  persistentKeyRequirementScope:persistentAll?'ALL_DEVICES':persistentEnrolled?'ENROLLED_DEVICES':'OPTIONAL',legacyFlowGraceAvailable:state.mode==='COMPATIBLE',activeEnrollments:active.length,
  tpmImplemented:true,tpmRequired:required,trustConfigured,tpmCurrentRoots:currentRoots.size,tpmActiveEnrollments:tpmRows.length,tpmUnexpiredEnrollments:unexpired.length,tpmCurrentRootEnrollments:currentRootEnrollments,
  clientPersistence:state.mode!=='COMPATIBLE'?'OS_CNG_NAMED_DEVICE_KEY_REQUIRED':active.length?'OS_CNG_NAMED_DEVICE_KEY_ENROLLED':'OS_CNG_NAMED_DEVICE_KEY_OPTIONAL',
  tpmAttestation:required?(currentRoots.size?'REQUIRED_BY_POLICY':'REQUIRED_TRUST_UNAVAILABLE'):
   tpmRows.length?(currentRootEnrollments?'ENROLLED_OPTIONAL':'ENROLLED_REQUIRES_REVALIDATION'):currentRoots.size?'AVAILABLE_TRUST_CONFIGURED':'AVAILABLE_TRUST_NOT_CONFIGURED',
  verification:{status:'NOT_RECORDED',scope:'DEPLOYMENT_WINDOWS_TPM_TEST',enrollmentIsDeploymentTest:false}};
}
function Status(){
 const db=store.Load(),ops=require('./desktopSecurityOperations').State(),authority=require('./desktopSecurityAuthority').Policy();
 const manualVerification=require('./desktopManualVerification').Status(db);
 const device=DeviceState(db),publication=require('./desktopSecurityOperations').ProductionStatus(ops),admin=require('./desktopAdminGuard').Status();
 const witness=require('./desktopRecoveryWitness').Status(),pin=require('./desktopTlsPinTransition').Status();
 const profiles=Object.values(db.mitigationProfiles?.entries||{}),enabledProfiles=profiles.filter(x=>x.enabled).length;
 const artifactRoles=['A','B','O'].map(role=>{const row=db.artifacts[db.active[role]];return {role,present:!!row,handoffVersion:row?.handoffVersion||0,measurementPlanVersion:row?.measurementPlanVersion||0};});
 const verification=(id,scope)=>{
  const domain=manualVerification.domains.find(x=>x.id===id);
  return {...domain,scope,evidenceCreated:false,currentPolicy:manualVerification.currentPolicy};
 };
 device.verification=verification('12','DEPLOYMENT_WINDOWS_TPM_TEST');
 const item=(id,name,implementation,configured,scope,limitations=[])=>({id,name,implementation,configured,verification:verification(id,scope),limitations});
 const features=[
  item('1','관리자 인증','IMPLEMENTED',{criticalReauthenticationRequired:admin.criticalReauthenticationMandatory,reauthenticationScope:admin.reauthenticationScope,reauthenticationLifetimeMs:admin.reauthenticationLifetimeMs,absoluteSessionMs:require('../web/webAuth').ABSOLUTE_SESSION_MS},'DEPLOYMENT_PROXY_AND_AUTH_TEST',['PROXY_CONFIGURATION_REQUIRES_OPERATOR_REVIEW']),
  item('2','Challenge · 라이선스','IMPLEMENTED',{authorityMode:authority.mode,singleWriterRequired:true},'DEPLOYMENT_RESTART_AND_FAULT_TEST',['NO_DISTRIBUTED_EXACTLY_ONCE_CLAIM']),
  item('3','A/B/O 인수인계','IMPLEMENTED',{roles:artifactRoles.map(({role,handoffVersion})=>({role,handoffVersion}))},'DEPLOYMENT_WINDOWS_HANDOFF_TEST',['LEGACY_V1_COHORTS_REMAIN_COMPATIBLE']),
  item('4','수동 배포 · 승인','IMPLEMENTED',{requirements:publication.requirements,runtime:publication.runtime,sourceHashPreflightAvailable:true,compilerProvenanceAttested:false},'DEPLOYMENT_RELEASE_DRILL',['CI_NOT_REQUIRED','MANUAL_PUBLICATION_IS_NOT_CI_PASS']),
  item('5','네이티브 ABI · 메모리','PARTIAL',{abiComparisonAvailable:true,managedStringCopiesRemain:true},'DEPLOYMENT_WINDOWS_ABI_AND_LIFETIME_TEST',['NO_COMPLETE_MEMORY_ERASURE_GUARANTEE']),
  item('6','파일 · PE 측정','IMPLEMENTED',{serverFinalFileRecheck:true,explicitDebugBuildRejected:true,legacyUnmarkedBuildCompatible:true},'DEPLOYMENT_WINDOWS_FILE_FAULT_TEST',['OS_IO_COMPLETION_REQUIRES_REAL_TEST','SOURCE_MARKER_IS_NOT_COMPILER_AUTHENTICITY_PROOF']),
  item('7','측정 계획 · 범위','IMPLEMENTED',{requireCompleteCrcLayers:authority.requireCompleteCrcLayers,roles:artifactRoles.map(({role,measurementPlanVersion})=>({role,measurementPlanVersion}))},'DEPLOYMENT_WINDOWS_MEASUREMENT_TEST',['DECLARATION_IS_NOT_RUNTIME_ATTESTATION']),
  item('8','TLS · 요청 수명','PARTIAL',{pinTransitionEnabled:pin.enabled,pinGeneration:pin.generation},'DEPLOYMENT_WINDOWS_TLS_TEST',['PIN_TRANSITION_STATE_IS_MEMORY_AND_HANDOFF_ONLY']),
  item('9','오버레이 · 종료','PARTIAL',{boundedAdmission:true,forcedThreadTermination:false,capturePrivacyRequested:require('../config/config').OVERLAY_CAPTURE_PRIVACY===true,capturePrivacyVersion:1,capturePrivacyScope:'OWN_OVERLAY_WINDOW',captureBlockingGuaranteed:false},'DEPLOYMENT_WINDOWS_GPU_AND_SHUTDOWN_TEST',['KERNEL_IO_COMPLETION_HAS_NO_UNCONDITIONAL_TIME_BOUND']),
  item('10','완화 정책 · 빌드 격리','IMPLEMENTED',{dynamicCode:authority.dynamicCode,requireCfg:authority.requireCfg,enabledCompatibilityProfiles:enabledProfiles},'DEPLOYMENT_WINDOWS_MITIGATION_TEST',['CONFIGURATION_IS_NOT_OS_READBACK']),
  item('11','복구 · 보존','IMPLEMENTED',{witnessConfigured:witness.status!=='NOT_CONFIGURED',witnessRequired:witness.required===true,outboxCompactionImplemented:true,spentLicenseTombstones:'RETAINED'},'DEPLOYMENT_STORAGE_RESTORE_DRILL',['WITNESS_VOLUME_INDEPENDENCE_NOT_ATTESTED','MULTI_SERVER_CONSENSUS_NOT_IMPLEMENTED']),
  item('12','영속 장치키 · TPM','IMPLEMENTED',{...device,deviceSignalsRequested:authority.deviceSignalsRequested===true,deviceSignalsScope:'SERVER_REQUESTED_DIAGNOSTIC_ONLY',rawHardwareIdentifiersReported:false,spoofResistanceAttested:false},'DEPLOYMENT_WINDOWS_TPM_TEST',['TPM_TRUST_ROOTS_AND_REAL_DEVICE_TEST_REQUIRED']),
  item('13','Windows 실기 시나리오','PARTIAL',{manualDiagnosticsAvailable:true,requiredForPublication:false},'DEPLOYMENT_WINDOWS_SCENARIOS',['TEST_TOOL_AVAILABLE_DOES_NOT_MEAN_EXECUTED']),
  item('14','독립 비교 · 장애 주입','IMPLEMENTED',{serverTestsAvailable:true,nativeProbesAvailable:true},'DEPLOYMENT_INDEPENDENT_AND_FAILURE_TEST',['PORTABLE_TEST_IS_NOT_WINDOWS_TEST'])
 ];
 return {version:1,readOnly:true,generatedAt:Date.now(),source:'LIVE_SERVER_POLICY_AND_SOURCE_CAPABILITIES',
  evidencePolicy:'NO_AUTOMATIC_PASS',windowsVerification:manualVerification.status,manualVerification,deviceIdentity:device,features};
}
module.exports={DeviceState,Status};
