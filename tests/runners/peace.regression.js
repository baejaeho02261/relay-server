'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs'), os = require('node:os');
const checks = [
  ["artifacts/peace.test-cozy-protection-engine.js"],
  ["bootstrap/peace.test-launcher-config.js"],
  ["artifacts/peace.test-packing-evidence.js"],
  ["security/peace.test-packed-release-pair.js"],
  ["cryptography/peace.test-native-contract-vectors.js"],
  ["authentication/peace.test-admin-https-security.js"], ["authentication/peace.test-passkey-validation-security.js"], ["network/peace.test-tcp-admission-security.js"],
  ["observability/peace.test-performance-metrics.js"], ["observability/peace.test-performance-dashboard-ui.js"], ["runtime/peace.test-lifecycle-windows.js"], ["recovery/peace.test-recovery-device-probe.js"], ["recovery/peace.test-recovery-windows.js"],
  ["runtime/peace.test-manual-verification-v3.js"], ["observability/peace.test-lifecycle-trace.js"],
  ["web/peace.test-server-state-read-routes.js"], ["observability/peace.test-server-state-dashboard-ui.js"], ["web/peace.test-server-state-service-ui.js"],
  ["overlay/peace.test-overlay-lease-expiry.js"], ["runtime/peace.test-native-lifecycle-contract.js"],
  ["recovery/peace.test-recovery-drill.js"], ["runtime/peace.test-product-fault-tests.js"], ["runtime/peace.test-product-fault-wire.js"],
  ["fixtures/integrity/peace.test-native-receive-fixture.js"], ["network/peace.test-product-fault-tls-proxy.js"],
  ["build/peace.test-ide-build-observation.js"], ["storage/peace.test-etcd-consensus-store.js"],
  ["build/peace.test-cfg-callsite-audit.js"], ["fixtures/build/peace.cfg-runtime-enforcement-fixture.js"], ["overlay/peace.test-overlay-environment.js"], ["security/peace.test-mitigation-compatibility.js"], ["artifacts/peace.test-crc-pe-comparison.js"],
  ["artifacts/peace.test-pe-build-configuration.js"], ["artifacts/peace.test-manual-release-check.js"], ["runtime/peace.test-manual-windows-tests.js"], ["artifacts/peace.test-server-capabilities.js"], ["runtime/peace.test-manual-verification.js"], ["cryptography/peace.test-kmac256.js"], ["cryptography/peace.test-blake3-ownership.js"],
  ["web/peace.test-key-console.js"], ["web/peace.test-history-outcomes.js"],
  ["authentication/peace.test-passkey-lifetime.js"], ["network/peace.test-network-lifecycle-upgrade.js"], ["web/peace.test-server-state-ui.js"],
  ["observability/peace.test-work-queue-observability.js"],
  ["protocol/peace.test-remaining-auth-protocol.js"], ["network/peace.test-transport-key-rotation.js"],
  ["integrity/peace.test-remaining-own-measurement.js"], ["devices/peace.test-desktop-device-identity.js"], ["devices/peace.test-device-identity-handoff.js"],
  ["storage/peace.test-storage-retention-remaining.js"], ["build/peace.test-build-input-lock.js"], ["security/peace.test-mitigation-profiles.js"], ["fixtures/build/peace.test-ci-profile-fixture.js"],
  ["web/peace.test-desktop-workspace.js"], ["web/peace.test-workspace-http.js"],
  ["security/peace.test-security-activation.js"],
  ["authentication/peace.test-web-auth-hardening.js"], ["runtime/peace.test-desktop-deadlines.js"], ["storage/peace.test-desktop-single-writer.js"],
  ["recovery/peace.test-desktop-license-recovery.js"], ["bootstrap/peace.test-handoff-delegation.js"], ["artifacts/peace.test-release-provenance.js"],
  ["bootstrap/peace.test-handoff-native-contract.js"], ["artifacts/peace.test-release-provenance-ui.js"], ["artifacts/peace.test-release-tools-split.js"], ["build/peace.test-ci-workflow-tools.js"], ["web/peace.test-admin-modal-isolation.js"],
  ["storage/peace.test-desktop-audit-append.js"], ["storage/peace.test-desktop-audit-outbox.js"], ["runtime/peace.test-desktop-request-receipts.js"],
  ["recovery/peace.test-handoff-recovery.js"], ["bootstrap/peace.test-handoff-completion-contract.js"],
  ["security/peace.test-key-purposes.js"], ["artifacts/peace.test-release-governance-complete.js"], ["build/peace.test-windows-ci.js"],
  ["security/peace.test-security-operations.js"], ["security/peace.test-security-admin.js"], ["security/peace.test-security-evidence.js"], ["security/peace.test-security-native-contract.js"],
  ["security/peace.test-security-authority.js"], ["security/peace.test-security-tools.js"], ["security/peace.test-security-wire.js"],
  ["runners/peace.check-modules.js"], ["web/peace.check-web-ui.js"], ["network/peace.check-connect-project.js"],
  ["cryptography/peace.test-extended-hashes.js"], ["security/peace.test-security-v4.js"], ["overlay/peace.test-desktop-overlay.js"], ["overlay/peace.test-overlay-transfer.js"], ["overlay/peace.test-overlay-start-diagnostics.js"], ["overlay/peace.test-overlay-parent-sharing.js"], ["overlay/peace.test-overlay-imgui.js"], ["overlay/peace.test-overlay-web-policy.js"], ["cryptography/peace.test-crc-layers.js"], ["cryptography/peace.test-crc-checker-ranges.js"],
  ["integrity/peace.test-desktop-extended-integrity.js"], ["integrity/peace.test-desktop-extended-integrity.js", '--sqlite'],
  ["storage/peace.test-sqlite-driver.js"], ["network/peace.test-connect-tls.js"], ["artifacts/peace.test-desktop-pe-exports.js"], ["runtime/peace.test-native-report-budget.js"],
  ["integrity/peace.test-desktop-integrity-policy.js"], ["integrity/peace.test-desktop-integrity-policy.js", '--sqlite'],
  ["devices/peace.test-desktop-machine-policy.js"], ["devices/peace.test-desktop-machine-policy.js",'--sqlite'],
  ["licensing/peace.test-desktop-licenses.js"], ["licensing/peace.test-desktop-licenses.js", '--sqlite'],
  ["licensing/peace.test-desktop-license-migration.js"], ["licensing/peace.test-desktop-license-migration.js", '--sqlite'],
  ["bootstrap/peace.test-desktop-bootstrap.js"], ["bootstrap/peace.test-desktop-bootstrap.js", '--sqlite'],
  ["integrity/peace.test-desktop-code-integrity.js"], ["runtime/peace.test-native-code-contract.js"], ["runtime/peace.test-native-crc-metadata-contract.js"], ["artifacts/peace.test-crc-release-eligibility.js"],
  ["integrity/peace.test-desktop-integrity-reports.js"], ["integrity/peace.test-integrity-rejection-reasons.js"], ["integrity/peace.test-desktop-integrity-reports.js", '--sqlite'],
  ["licensing/peace.test-desktop-retirement.js"], ["runtime/peace.test-desktop-http.js"], ["network/peace.test-connect-deployment.js"],
  ["network/peace.test-desktop-connect.js"], ["network/peace.test-desktop-connect.js", '--sqlite'],
  ["web/peace.test-desktop-admin-ui.js"], ["integrity/peace.test-integrity-display.js"], ["overlay/peace.test-overlay-admin-ui.js"], ["web/peace.test-web-ui-cache.js"],
  ["protocol/peace.test-hardening-protocol.js"], ["runtime/peace.test-hardening-work-queue.js"], ["integrity/peace.test-hardening-measurement.js"], ["artifacts/peace.test-hardening-pe-corpus.js"], ["runtime/peace.test-review-corrections.js"], ["storage/peace.test-server-storage-11-14.js"], ["protocol/peace.test-independent-contracts-14.js"], ["runtime/peace.test-production-boundaries-1-5.js"], ["runtime/peace.test-native-abi-field-contract.js"],
  ["protocol/peace.test-completion-protocol-6-10.js"], ["integrity/peace.test-completion-measurement-6-10.js"], ["protocol/peace.test-completion-artifacts-6-10.js"], ["protocol/peace.test-completion-pin-6-10.js"]
];
module.exports=checks;
if(require.main===module){
 const suiteData=fs.mkdtempSync(path.join(os.tmpdir(),'game-full-regression-'));
 process.env.DATA_DIR=suiteData;process.env.HA_ENABLED='0';
 process.on('exit',()=>fs.rmSync(suiteData,{recursive:true,force:true}));
for (const [name, ...args] of checks) {
  const data=fs.mkdtempSync(path.join(suiteData,'suite-'));
  const result = spawnSync(process.execPath, [path.join(MODULE_RESOURCE_ROOT, name), ...args], {
    cwd: path.resolve(MODULE_RESOURCE_ROOT, '..'), stdio: 'inherit', timeout: 120000,
    env:{...process.env,DATA_DIR:data}
  });
  fs.rmSync(data,{recursive:true,force:true});
  if (result.error) console.error(result.error.message);
  if (result.status !== 0 || result.error) process.exit(result.status || 1);
  console.log('SUITE PASS '+[name,...args].join(' '));
}
console.log('SERVER / SOURCE REGRESSION PASS: '+checks.length+' suites');

}
