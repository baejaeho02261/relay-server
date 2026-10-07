'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const checks = [
  ['test-key-console.js'], ['test-history-outcomes.js'],
  ['test-desktop-workspace.js'], ['test-workspace-http.js'],
  ['test-security-activation.js'],
  ['test-security-operations.js'], ['test-security-admin.js'], ['test-security-evidence.js'], ['test-security-native-contract.js'],
  ['test-security-authority.js'], ['test-security-tools.js'], ['test-security-wire.js'],
  ['check-modules.js'], ['check-web-ui.js'], ['check-connect-project.js'],
  ['test-extended-hashes.js'], ['test-security-v4.js'], ['test-desktop-overlay.js'], ['test-overlay-web-policy.js'], ['test-crc-layers.js'], ['test-crc-checker-ranges.js'],
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
  ['test-desktop-admin-ui.js'], ['test-integrity-display.js'], ['test-overlay-admin-ui.js'], ['test-web-ui-cache.js']
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
