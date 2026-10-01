'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const checks = [
  ['check-modules.js'], ['check-web-ui.js'], ['check-connect-project.js'],
  ['test-desktop-machine-policy.js'], ['test-desktop-machine-policy.js','--sqlite'],
  ['test-desktop-licenses.js'], ['test-desktop-licenses.js', '--sqlite'],
  ['test-desktop-license-migration.js'], ['test-desktop-license-migration.js', '--sqlite'],
  ['test-desktop-bootstrap.js'], ['test-desktop-bootstrap.js', '--sqlite'],
  ['test-desktop-code-integrity.js'], ['test-native-code-contract.js'],
  ['test-desktop-integrity-reports.js'], ['test-desktop-integrity-reports.js', '--sqlite'],
  ['test-desktop-retirement.js'], ['test-desktop-http.js'], ['test-connect-deployment.js'],
  ['test-desktop-connect.js'], ['test-desktop-connect.js', '--sqlite'],
  ['test-desktop-admin-ui.js'], ['test-web-ui-cache.js']
];
for (const [name, ...args] of checks) {
  const result = spawnSync(process.execPath, [path.join(__dirname, name), ...args], {
    cwd: path.resolve(__dirname, '..'), stdio: 'inherit', timeout: 120000
  });
  if (result.error) console.error(result.error.message);
  if (result.status !== 0 || result.error) process.exit(result.status || 1);
}
console.log('WINDOWS LICENSE REGRESSION PASS');
