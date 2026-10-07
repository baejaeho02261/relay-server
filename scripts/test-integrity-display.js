'use strict';
// Exercise the real report/session renderers: matching digests must not hide
// missing CRC coverage, nor must a rejected report erase independent results.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<main id="content"></main>', { runScripts: 'outside-only' });
const w = dom.window;
vm.runInContext(`
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtTime(x){return String(x);}
`, dom.getInternalVMContext());
new vm.Script(fs.readFileSync(path.join(__dirname, '../public/admin-desktop-licenses.js'), 'utf8')).runInContext(dom.getInternalVMContext());
const content = w.document.getElementById('content');
const row = {
  id: 'CRC_REPORT', stage: 'A', check: 'OWN_CODE', status: 'REJECTED',
  reason: 'CRC_COVERAGE_INCOMPLETE',
  expectedSha512: 'a'.repeat(128), observedSha512: 'a'.repeat(128),
  expectedCrc64: '54A7C41BEA233BC6', observedCrc64: '54A7C41BEA233BC6',
  expectedFileXxh3_128: 'b'.repeat(32), observedFileXxh3_128: 'b'.repeat(32),
  expectedFileBlake3: 'c'.repeat(64), observedFileBlake3: 'c'.repeat(64),
  expectedXxh3_128: 'd'.repeat(32), observedXxh3_128: 'd'.repeat(32),
  expectedBlake3: 'e'.repeat(64), observedBlake3: 'e'.repeat(64),
  fileExtendedVerified: true, codeExtendedVerified: true, extendedHashesVerified: true,
  crcComparison: { complete: false, signals: [
    { role: 'ecma182', status: 'MATCH' }, { role: 'nvme', status: 'PARTIAL' },
    { role: 'jones', status: 'UNAVAILABLE' }, { role: 'iso', status: 'UNAVAILABLE' }
  ] }
};
function render(value) {
  content.innerHTML = w.desktopIntegrityMarkup({ items: [value] }, { items: [] }, null);
  return [...content.querySelectorAll('.desktop-extended-hashes strong')].map(el => el.textContent);
}
try {
  let digests = render(row);
  assert.match(content.querySelector('summary').textContent, /A · 검사 범위 부족 · 거부/);
  assert.ok(content.querySelector('.desktop-integrity-rejected'));
  assert.match(content.textContent, /CRC_COVERAGE_INCOMPLETE/);
  assert.match(content.textContent, /일부 범위만 측정/);
  assert.equal(digests.length, 2);
  for (const value of digests) assert.match(value, /서버 확장 해시 기준 일치/);

  digests = render({ ...row, fileExtendedVerified: false, extendedHashesVerified: true });
  assert.match(digests[0], /서버 검증 안 됨/);
  assert.match(digests[1], /서버 확장 해시 기준 일치/);
  const legacy = { ...row, extendedHashesVerified: false };
  delete legacy.fileExtendedVerified;
  delete legacy.codeExtendedVerified;
  for (const value of render(legacy)) assert.match(value, /서버 검증 안 됨/);
  for (const value of render({ ...legacy, extendedHashesVerified: true })) assert.match(value, /서버 확장 해시 기준 일치/);

  digests = render({ ...row, reason: 'CODE_EXTENDED_HASH_MISMATCH', observedBlake3: 'f'.repeat(64), codeExtendedVerified: false });
  assert.match(content.querySelector('summary').textContent, /불일치 · 거부/);
  assert.match(digests[1], /서버 기준 불일치/);

  content.innerHTML = w.desktopBootstrapMarkup({ sessions: [{
    id: 'SESSION', status: 'REVOKED', codeIntegrityStatus: 'REJECTED', reason: 'INTEGRITY_CRC_COVERAGE_INCOMPLETE'
  }] });
  assert.match(content.querySelector('#desktop-bootstrap-sessions').textContent, /필수 CRC 검사 범위 부족 · 실행 거부/);
  assert.match(content.querySelector('#desktop-bootstrap-sessions').textContent, /INTEGRITY_CRC_COVERAGE_INCOMPLETE/);
  console.log('PASS integrity display distinguishes incomplete CRC coverage, independent digest results, legacy records and real mismatches');
} finally { dom.window.close(); }
