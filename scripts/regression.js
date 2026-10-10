'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs'), os = require('node:os');
// A forgotten per-suite override must never fall back to operating/source data.
const suiteData = fs.mkdtempSync(path.join(os.tmpdir(), 'game-full-regression-'));
process.env.DATA_DIR = suiteData;
process.env.HA_ENABLED = '0';
process.on('exit', () => fs.rmSync(suiteData, {recursive:true,force:true}));
const checks = [
  ['test-key-console.js'], ['test-history-outcomes.js'],
  ['test-desktop-workspace.js'], ['test-workspace-http.js'],
  ['test-security-activation.js'],
  ['test-web-auth-hardening.js'], ['test-desktop-deadlines.js'], ['test-desktop-single-writer.js'],
  ['test-desktop-license-recovery.js'], ['test-handoff-delegation.js'], ['test-release-provenance.js'],
  ['test-handoff-native-contract.js'], ['test-release-provenance-ui.js'], ['test-release-tools-split.js'], ['test-admin-modal-isolation.js'],
  ['test-desktop-audit-append.js'], ['test-desktop-audit-outbox.js'], ['test-desktop-request-receipts.js'],
  ['test-handoff-recovery.js'], ['test-handoff-completion-contract.js'],
  ['test-key-purposes.js'], ['test-release-governance-complete.js'], ['test-windows-ci.js'],
  ['test-security-operations.js'], ['test-security-admin.js'], ['test-security-evidence.js'], ['test-security-native-contract.js'],
  ['test-security-authority.js'], ['test-security-tools.js'], ['test-security-wire.js'],
  ['check-modules.js'], ['check-web-ui.js'], ['check-connect-project.js'],
  ['test-extended-hashes.js'], ['test-security-v4.js'], ['test-desktop-overlay.js'], ['test-overlay-transfer.js'], ['test-overlay-start-diagnostics.js'], ['test-overlay-parent-sharing.js'], ['test-overlay-imgui.js'], ['test-overlay-web-policy.js'], ['test-crc-layers.js'], ['test-crc-checker-ranges.js'],
  ['test-desktop-extended-integrity.js'], ['test-desktop-extended-integrity.js', '--sqlite'],
  ['test-sqlite-driver.js'], ['test-connect-tls.js'], ['test-desktop-pe-exports.js'], ['test-native-report-budget.js'],
  ['test-desktop-integrity-policy.js'], ['test-desktop-integrity-policy.js', '--sqlite'],
  ['test-desktop-machine-policy.js'], ['test-desktop-machine-policy.js','--sqlite'],
  ['test-desktop-licenses.js'], ['test-desktop-licenses.js', '--sqlite'],
  ['test-desktop-license-migration.js'], ['test-desktop-license-migration.js', '--sqlite'],
  ['test-desktop-bootstrap.js'], ['test-desktop-bootstrap.js', '--sqlite'],
  ['test-desktop-code-integrity.js'], ['test-native-code-contract.js'], ['test-native-crc-metadata-contract.js'], ['test-crc-release-eligibility.js'],
  ['test-desktop-integrity-reports.js'], ['test-integrity-rejection-reasons.js'], ['test-desktop-integrity-reports.js', '--sqlite'],
  ['test-desktop-retirement.js'], ['test-desktop-http.js'], ['test-connect-deployment.js'],
  ['test-desktop-connect.js'], ['test-desktop-connect.js', '--sqlite'],
  ['test-desktop-admin-ui.js'], ['test-integrity-display.js'], ['test-overlay-admin-ui.js'], ['test-web-ui-cache.js'],
  ['test-hardening-protocol.js'], ['test-hardening-work-queue.js'], ['test-hardening-measurement.js'], ['test-hardening-pe-corpus.js']
];
for (const [name, ...args] of checks) {
  const result = spawnSync(process.execPath, [path.join(__dirname, name), ...args], {
    cwd: path.resolve(__dirname, '..'), stdio: 'inherit', timeout: 120000
  });
  if (result.error) console.error(result.error.message);
  if (result.status !== 0 || result.error) process.exit(result.status || 1);
  console.log('SUITE PASS '+[name,...args].join(' '));
}
console.log('WINDOWS LICENSE REGRESSION PASS: '+checks.length+' suites');
