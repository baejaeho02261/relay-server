'use strict';
// These are coverage contracts, not an authorization policy. A reported PASS
// covers one named check in one declared environment, never an entire product.
const SERVER=['ISOLATED_SERVICE','DEPLOYMENT_SERVER'];
const NATIVE=['WINDOWS_PROBE','SELECTED_FINAL_ABO'];
const PHYSICAL=['PHYSICAL_ENVIRONMENT'];
const rows=[
 ['1','관리자 인증','DEPLOYMENT_PROXY_AND_AUTH_TEST',[
  ['trusted-proxy',SERVER],['login-throttle',SERVER],['session-lifetime',SERVER],['critical-reauthentication',SERVER],['session-revocation',SERVER],['role-denial',SERVER]]],
 ['2','Challenge · 라이선스','DEPLOYMENT_RESTART_AND_FAULT_TEST',[
  ['challenge-expiry',SERVER],['purpose-binding',SERVER],['receipt-retry',SERVER],['license-consumption',SERVER],['single-writer',SERVER],['restart-replay',SERVER]]],
 ['3','A/B/O 인수인계','DEPLOYMENT_WINDOWS_HANDOFF_TEST',[
  ['handoff-crypto',NATIVE],['handoff-kdf',NATIVE],['handoff-pipe',NATIVE],['handoff-process',NATIVE],['abo-integration',['SELECTED_FINAL_ABO']]]],
 ['4','수동 배포 · 승인','DEPLOYMENT_RELEASE_DRILL',[
  ['final-artifact-approval',SERVER],['manifest-tuple',SERVER],['signer-rotation',SERVER],['minimum-security-version',SERVER],['publication-policy',SERVER]]],
 ['5','네이티브 ABI · 메모리','DEPLOYMENT_WINDOWS_ABI_AND_LIFETIME_TEST',[
  ['abi-layout',NATIVE],['abi-sdk-compare',NATIVE],['native-api',NATIVE],['memory-lifetime',NATIVE]]],
 ['6','파일 · PE 측정','DEPLOYMENT_WINDOWS_FILE_FAULT_TEST',[
  ['pe-corpus',NATIVE],['independent-pe',NATIVE],['memory-lifetime',NATIVE]]],
 ['7','측정 계획 · 범위','DEPLOYMENT_WINDOWS_MEASUREMENT_TEST',[
  ['hash-reference',NATIVE],['independent-crc',NATIVE],['independent-crc-pe',NATIVE],['module-generation',NATIVE],['thread-inventory',NATIVE]]],
 ['8','TLS · 요청 수명','DEPLOYMENT_WINDOWS_TLS_TEST',[
  ['schannel-handshake',NATIVE],['pin-transition',NATIVE],['receive-bounds',NATIVE],['request-timeout',NATIVE]]],
 ['9','오버레이 · 종료','DEPLOYMENT_WINDOWS_GPU_AND_SHUTDOWN_TEST',[
  ['overlay-first-frame',NATIVE],['overlay-privacy',NATIVE],['overlay-shutdown',NATIVE],['overlay-gpu-faults',NATIVE],['abo-integration',['SELECTED_FINAL_ABO']],['overlay-lease-expiry',['SELECTED_FINAL_ABO','DEDICATED_PRODUCT_TESTBUILD']],['lifecycle-cleanup-success',['SELECTED_FINAL_ABO']],['lifecycle-cleanup-refused',['DEDICATED_PRODUCT_TESTBUILD']],['lifecycle-cleanup-scheduled',['DEDICATED_PRODUCT_TESTBUILD']],['physical-dpi-monitor',PHYSICAL],['physical-rdp-focus',PHYSICAL]]],
 ['10','완화 정책 · 빌드 격리','DEPLOYMENT_WINDOWS_MITIGATION_TEST',[
  ['mitigation-readback',NATIVE],['product-policy-compatibility',['SELECTED_FINAL_ABO']],['final-cfg-instrumentation',['SELECTED_FINAL_ABO']],['windows-cfg-enforcement',['SELECTED_FINAL_ABO']]]],
 ['11','복구 · 보존','DEPLOYMENT_STORAGE_RESTORE_DRILL',[
  ['backup-restore',SERVER],['old-session-rejection',SERVER],['spent-license-rejection',SERVER],['witness-rollback',SERVER],['device-key-rotation',SERVER],['original-device-recovery',['WINDOWS_PROBE']],['recovered-abo-integration',['SELECTED_FINAL_ABO']]]],
 ['12','영속 장치키 · TPM','DEPLOYMENT_WINDOWS_TPM_TEST',[
  ['persistent-device-key',NATIVE],['tpm-manufacturer-chain',PHYSICAL],['key-possession',NATIVE],['revoke-reenroll',NATIVE]]],
 ['13','Windows 실기 시나리오','DEPLOYMENT_WINDOWS_SCENARIOS',[
  ...['probe-build-output-contracts','startup','abi-layout','hash-contracts','handoff-kdf','blake3-parallel','handoff-crypto','handoff-pipe','handoff-process','memory-lifetime','thread-inventory','device-signals','module-generation','native-api','device-key-construction','hardening-contracts','deterministic-state-core','pe-corpus','independent-pe','independent-crc','hash-reference','deterministic-state','abi-sdk-compare','overlay-first-frame','overlay-privacy','overlay-shutdown','overlay-gpu-faults','mitigation-readback','independent-crc-pe'].map(id=>[id,NATIVE]),['abo-integration',['SELECTED_FINAL_ABO']]]],
 ['14','독립 비교 · 장애 주입','DEPLOYMENT_INDEPENDENT_AND_FAILURE_TEST',[
  ...['independent-pe','independent-crc','independent-crc-pe','hash-reference','deterministic-state','blake3-parallel'].map(id=>[id,NATIVE]),['float-json-reference',['ISOLATED_SERVICE','WINDOWS_PROBE']]]]
];
const CATALOG=rows.map(([id,name,scope,checks])=>Object.freeze({id,name,scope,checks:Object.freeze(checks.map(([check,allowedScopes])=>Object.freeze({id:check,allowedScopes:Object.freeze([...allowedScopes])})))}));
Object.freeze(CATALOG);
const EXECUTION=Object.freeze({ISOLATED_SERVICE:'SERVICE_EXECUTED',DEPLOYMENT_SERVER:'SERVICE_EXECUTED',WINDOWS_PROBE:'WINDOWS_EXECUTED',SELECTED_FINAL_ABO:'WINDOWS_EXECUTED',DEDICATED_PRODUCT_TESTBUILD:'WINDOWS_EXECUTED',PHYSICAL_ENVIRONMENT:'PHYSICAL_EXECUTED'});
const OUTCOMES=Object.freeze(['PASS','FAIL','PARTIAL','NOT_RUN']);
module.exports={CATALOG,EXECUTION,OUTCOMES};
