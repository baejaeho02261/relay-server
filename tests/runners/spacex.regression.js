'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs'), os = require('node:os');
const checks = [
  ["security/spacex.test-module-baseline-space.js"],
  ["web/spacex.test-resource-disk-error-ui.js"],
  ["network/spacex.test-download-size-recovery.js"],
  ["bootstrap/spacex.test-issued-a-keyring.js"],
  ["bootstrap/spacex.test-keyless-tpm-recovery.js"],
  ["source/spacex.test-native-string-contract-reader.js"],
  ["web/spacex.test-issued-a-keyring-ui.js"],
  ["security/spacex.test-release-audit-runner.js"],
  ["security/spacex.test-release-audit-file-races.js"],
  ["security/spacex.test-release-readiness-route-lifetime.js"],
  ["security/spacex.test-server-operation-results.js"],
  ["source/spacex.test-sensitive-copy-lifetime.js"],
  ["integrity/spacex.test-pointer-general-probe.js"],
  ["protocol/spacex.test-native-policy-contract-vectors.js"],
  ["source/spacex.test-native-startup-observations.js"],
  ["source/spacex.test-device-security-owned.js"],
  ["security/spacex.test-server-operation-transcript-validation.js"],
  ["security/spacex.test-server-operation-arguments.js"],
  ["security/spacex.test-release-readiness.js"],
  ["security/spacex.test-release-readiness-http.js"],
  ["web/spacex.test-cfg-policy-readiness-ui.js"],
  ["network/spacex.test-connect-tls-flush.js"],
  ["network/spacex.test-tls-transport-boundaries.js"],
  ["source/spacex.test-native-tls-ownership.js"],
  ["network/spacex.test-transport-owned-contract.js"],
  ["bootstrap/spacex.test-handoff-owned-crypto.js"],
  ["source/spacex.test-native-device-identity-priorities.js"],
  ["observability/spacex.test-lifecycle-event-contract.js"],
  ["network/spacex.test-server-profile-contract.js"],
  ["integrity/spacex.test-owned-runtime-measurement.js"],
  ["source/spacex.test-own-runtime-wiring.js"],
  ["web/spacex.test-owned-runtime-graph-ui.js"],
  ["source/spacex.test-native-hash-lifecycle-source.js"],
  ["security/spacex.test-native-keyless-contract.js"],
  ["web/spacex.test-keyless-approval-ui.js"],
  ["security/spacex.test-native-quiet-boundary.js"],
  ["storage/spacex.test-retired-support-storage.js"],
  ["web/spacex.test-retired-support-http.js"],
  ["bootstrap/spacex.test-handoff-pipe-fragments.js"],
  ["cryptography/spacex.test-crc-collision-vectors.js"],

  ["protocol/spacex.test-document-schema.js"],
  ["licensing/spacex.test-desktop-members.js"],
  ["licensing/spacex.test-license-products.js"],
  ["overlay/spacex.test-overlay-products.js"],
  ["web/spacex.test-desktop-member-ui.js"],
  ["overlay/spacex.test-overlay-text-input.js"],
  ["overlay/spacex.test-overlay-parent-startup-lease.js"],
  ["bootstrap/spacex.test-keyless-bootstrap.js"],
  ["bootstrap/spacex.test-keyless-legacy-receipts.js"],
  ["bootstrap/spacex.test-repeat-approval-legacy.js"],

  ["cryptography/spacex.test-code-page-sha512.js"],
  ["integrity/spacex.test-pointer-graph-lifecycle.js"],
  ["network/spacex.test-native-socket-priorities.js"],
  ["bootstrap/spacex.test-issued-a-signing.js"],
  ["bootstrap/spacex.test-issued-a-native-contract.js"],
  ["protocol/spacex.test-packet-schema.js"],
  ["protocol/spacex.test-native-json-differential.js"],
  ["bootstrap/spacex.test-handoff-restricted-contract.js"],
  ["security/spacex.test-retired-governance-migration.js"],
  ["storage/spacex.test-registration-reset-journal.js"],
  ["runtime/spacex.test-registration-reset-bootstrap.js"],
  ["storage/spacex.test-registration-reset-stores.js"],
  ["runtime/spacex.test-registration-reset-startup.js"],
  ["runtime/spacex.test-registration-reset-web.js"],
  ["security/spacex.test-registration-reset-authorization.js"],
  ["web/spacex.test-registration-reset-ui.js"],
  ["artifacts/spacex.test-protection-engine.js"],
  ["bootstrap/spacex.test-launcher-config.js"],
  ["artifacts/spacex.test-packing-evidence.js"],
  ["artifacts/spacex.test-packed-release-manifest.js"],
  ["artifacts/spacex.test-packed-manifest-flow.js"],
  ["artifacts/spacex.test-packed-release-http.js"],
  ["web/spacex.test-packed-release-ui.js"],
  ["security/spacex.test-packed-release-pair.js"],
  ["cryptography/spacex.test-native-contract-vectors.js"],
  ["authentication/spacex.test-admin-https-security.js"], ["authentication/spacex.test-passkey-validation-security.js"], ["network/spacex.test-tcp-admission-security.js"],
  ["observability/spacex.test-performance-metrics.js"], ["observability/spacex.test-performance-dashboard-ui.js"], ["runtime/spacex.test-lifecycle-windows.js"], ["recovery/spacex.test-recovery-device-probe.js"], ["recovery/spacex.test-recovery-windows.js"],
  ["runtime/spacex.test-manual-verification-v3.js"], ["observability/spacex.test-lifecycle-trace.js"],
  ["web/spacex.test-server-state-read-routes.js"], ["observability/spacex.test-server-state-dashboard-ui.js"], ["web/spacex.test-server-state-service-ui.js"],
  ["overlay/spacex.test-overlay-lease-expiry.js"], ["overlay/spacex.test-overlay-startup-failure.js"], ["runtime/spacex.test-native-lifecycle-contract.js"],
  ["recovery/spacex.test-recovery-drill.js"], ["runtime/spacex.test-product-fault-tests.js"], ["runtime/spacex.test-product-fault-wire.js"],
  ["fixtures/integrity/spacex.test-native-receive-fixture.js"], ["network/spacex.test-product-fault-tls-proxy.js"],
  ["build/spacex.test-ide-build-observation.js"], ["storage/spacex.test-etcd-consensus-store.js"],
  ["build/spacex.test-cfg-callsite-audit.js"], ["fixtures/build/spacex.cfg-runtime-enforcement-fixture.js"], ["overlay/spacex.test-overlay-environment.js"], ["security/spacex.test-mitigation-compatibility.js"], ["artifacts/spacex.test-crc-pe-comparison.js"],
  ["artifacts/spacex.test-pe-build-configuration.js"], ["artifacts/spacex.test-manual-release-check.js"], ["runtime/spacex.test-manual-windows-tests.js"], ["artifacts/spacex.test-server-capabilities.js"], ["runtime/spacex.test-manual-verification.js"], ["cryptography/spacex.test-kmac256.js"], ["cryptography/spacex.test-blake3-ownership.js"],
  ["web/spacex.test-key-console.js"], ["web/spacex.test-history-outcomes.js"],
  ["authentication/spacex.test-passkey-lifetime.js"], ["network/spacex.test-network-lifecycle-upgrade.js"], ["web/spacex.test-server-state-ui.js"],
  ["observability/spacex.test-work-queue-observability.js"],
  ["protocol/spacex.test-remaining-auth-protocol.js"], ["network/spacex.test-transport-key-rotation.js"],
  ["integrity/spacex.test-remaining-own-measurement.js"], ["devices/spacex.test-desktop-device-identity.js"], ["devices/spacex.test-device-identity-handoff.js"],
  ["storage/spacex.test-storage-retention-remaining.js"], ["build/spacex.test-build-input-lock.js"], ["build/spacex.test-source-snapshot.js"], ["build/spacex.test-separated-signing-security.js"], ["security/spacex.test-mitigation-profiles.js"], ["fixtures/build/spacex.test-profile-fixture.js"],
  ["web/spacex.test-desktop-workspace.js"], ["web/spacex.test-workspace-http.js"],
  ["security/spacex.test-security-activation.js"],
  ["authentication/spacex.test-web-auth-hardening.js"], ["runtime/spacex.test-desktop-deadlines.js"], ["storage/spacex.test-desktop-single-writer.js"],
  ["recovery/spacex.test-desktop-license-recovery.js"], ["bootstrap/spacex.test-handoff-delegation.js"], ["artifacts/spacex.test-release-provenance.js"],
  ["bootstrap/spacex.test-handoff-native-contract.js"], ["artifacts/spacex.test-release-provenance-ui.js"], ["artifacts/spacex.test-release-tools-split.js"], ["web/spacex.test-admin-modal-isolation.js"],
  ["storage/spacex.test-desktop-audit-append.js"], ["storage/spacex.test-desktop-audit-outbox.js"], ["runtime/spacex.test-desktop-request-receipts.js"],
  ["recovery/spacex.test-handoff-recovery.js"], ["bootstrap/spacex.test-handoff-completion-contract.js"],
  ["security/spacex.test-key-purposes.js"], ["artifacts/spacex.test-release-governance-complete.js"],
  ["security/spacex.test-security-operations.js"], ["security/spacex.test-security-admin.js"], ["security/spacex.test-security-evidence.js"], ["security/spacex.test-security-native-contract.js"],
  ["security/spacex.test-security-authority.js"], ["security/spacex.test-security-tools.js"], ["security/spacex.test-security-wire.js"],
  ["runners/spacex.check-modules.js"], ["web/spacex.check-web-ui.js"], ["network/spacex.check-connect-project.js"],
  ["cryptography/spacex.test-extended-hashes.js"], ["security/spacex.test-security-v4.js"], ["overlay/spacex.test-desktop-overlay.js"], ["overlay/spacex.test-overlay-transfer.js"], ["overlay/spacex.test-overlay-start-diagnostics.js"], ["overlay/spacex.test-overlay-parent-sharing.js"], ["overlay/spacex.test-overlay-imgui.js"], ["overlay/spacex.test-overlay-web-policy.js"], ["cryptography/spacex.test-crc-layers.js"], ["cryptography/spacex.test-crc-checker-ranges.js"],
  ["integrity/spacex.test-desktop-extended-integrity.js"], ["integrity/spacex.test-desktop-extended-integrity.js", '--sqlite'],
  ["storage/spacex.test-sqlite-driver.js"], ["network/spacex.test-connect-tls.js"], ["artifacts/spacex.test-desktop-pe-exports.js"], ["runtime/spacex.test-native-report-budget.js"],
  ["integrity/spacex.test-desktop-integrity-policy.js"], ["integrity/spacex.test-desktop-integrity-policy.js", '--sqlite'],
  ["devices/spacex.test-desktop-machine-policy.js"], ["devices/spacex.test-desktop-machine-policy.js",'--sqlite'],
  ["licensing/spacex.test-desktop-licenses.js"], ["licensing/spacex.test-desktop-licenses.js", '--sqlite'],
  ["licensing/spacex.test-desktop-license-migration.js"], ["licensing/spacex.test-desktop-license-migration.js", '--sqlite'],
  ["bootstrap/spacex.test-desktop-bootstrap.js"], ["bootstrap/spacex.test-desktop-bootstrap.js", '--sqlite'],
  ["integrity/spacex.test-desktop-code-integrity.js"], ["runtime/spacex.test-native-code-contract.js"], ["runtime/spacex.test-native-crc-metadata-contract.js"], ["artifacts/spacex.test-crc-release-eligibility.js"],
  ["integrity/spacex.test-desktop-integrity-reports.js"], ["integrity/spacex.test-integrity-rejection-reasons.js"], ["integrity/spacex.test-desktop-integrity-reports.js", '--sqlite'],
  ["licensing/spacex.test-desktop-retirement.js"], ["runtime/spacex.test-desktop-http.js"], ["network/spacex.test-connect-deployment.js"],
  ["network/spacex.test-desktop-connect.js"], ["network/spacex.test-desktop-connect.js", '--sqlite'],
  ["web/spacex.test-desktop-admin-ui.js"], ["integrity/spacex.test-integrity-display.js"], ["overlay/spacex.test-overlay-admin-ui.js"], ["web/spacex.test-web-ui-cache.js"],
  ["protocol/spacex.test-hardening-protocol.js"], ["runtime/spacex.test-hardening-work-queue.js"], ["integrity/spacex.test-hardening-measurement.js"], ["artifacts/spacex.test-hardening-pe-corpus.js"], ["runtime/spacex.test-review-corrections.js"], ["storage/spacex.test-server-storage-11-14.js"], ["protocol/spacex.test-independent-contracts-14.js"], ["runtime/spacex.test-production-boundaries-1-5.js"], ["runtime/spacex.test-native-abi-field-contract.js"],
  ["protocol/spacex.test-completion-protocol-6-10.js"], ["integrity/spacex.test-completion-measurement-6-10.js"], ["protocol/spacex.test-completion-artifacts-6-10.js"], ["protocol/spacex.test-completion-pin-6-10.js"]
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
