'use strict';
// Execute the production modal/upload/security/deployment handlers against a DOM
// and a fake server. This does not claim a real browser or Windows execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');
const errors = [], calls = [], vc = new VirtualConsole();
vc.on('jsdomError', error => errors.push(error.message));
const dom = new JSDOM('<main id="content"></main><div id="modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-body"></div><button id="modal-confirm"></button><button id="modal-cancel"></button></div>', {
  url: 'https://fixture.invalid/', runScripts: 'outside-only', virtualConsole: vc
});
const w = dom.window, document = w.document;
vm.runInContext(`
const content=document.getElementById('content'),modalEl=document.getElementById('modal'),modalBody=document.getElementById('modal-body'),modalTitle=document.getElementById('modal-title'),modalConfirm=document.getElementById('modal-confirm'),modalCancel=document.getElementById('modal-cancel');
let session={csrf:'ADMIN_SESSION',role:'admin'},currentView='desktop-licenses';
function roleIsAdmin(){return session?.role==='admin';}
function esc(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmtTime(x){return String(x);}
function toast(){}
async function renderCurrent(){}
`, dom.getInternalVMContext());
const byId = id => document.getElementById(id);
const candidates = ['A', 'B', 'O', 'O'].map((component, i) => ({ id: component + (i + 1), component, version: '3.2.1', sha512: String(i + 1).repeat(128) }));
let active = { A: 'A1', B: 'B2', O: 'O3' }, uploadError = true;
let policy = { revision: 8, mode: 'enforce', dynamicCode: 'observe', freshnessMs: 45000, challengeMs: 15000, minVersionA: '1', minVersionB: '2', minVersionO: '3.2.1', enforceLegacy: false, requireReadonlyApi: true, requireCfg: false, requireReleaseSignature: false, trustedReleaseKeys: [], revokedSha512: [] };
const operations = { revision: 12, requireBuildContract: false, requireTestEvidence: false, rollout: { enabled: false, artifactKeys: [], patch: {} }, activations: [], signerStates: {} };
const listing = () => ({ active: { ...active }, candidates: candidates.map(a => ({ ...a, active: active[a.component] === a.id })), operations: { ...operations }, auditHealth: { status: 'HEALTHY', failedWrites: 0 } });
const clone = x => JSON.parse(JSON.stringify(x));
const base = '/api/desktop/bootstrap/security-operations';
w.api = async (url, options = {}) => {
  const body = options.body && clone(options.body);
  calls.push({ url, body, rawBody: options.rawBody, method: options.method || 'GET' });
  if (url.startsWith('/api/desktop/bootstrap/artifacts?')) {
    assert.equal(new URL(url, 'https://fixture.invalid').searchParams.get('component'), 'O');
    if (uploadError) {
      uploadError = false;
      throw Object.assign(Error('요청을 완료하지 못했습니다. <img src=x onerror=bad()>'), { code: 'BOOTSTRAP_COMPONENT_INVALID' });
    }
    return { artifact: candidates[2] };
  }
  if (url === '/api/desktop/bootstrap/security-authority/preview') return { preview: { readOnly: true } };
  if (url === '/api/desktop/bootstrap/security-authority') {
    if (body) policy = { ...policy, ...body, revision: policy.revision + 1 };
    return { policy: clone(policy), operations: listing(), recentBuildObservations: [], events: [] };
  }
  if (url === base) return listing();
  if (url === base + '/activation') return { status: {} };
  if (url === base + '/preview-pair') return { preview: { ...body, eligible: true, reasons: [], policyRevision: policy.revision, operationsRevision: operations.revision } };
  if (url === base + '/activate') {
    active = { A: body.aId, B: body.bId, O: body.oId };
    operations.revision++;
    return { ok: true };
  }
  if (url === base + '/test-evidence' || url === '/api/desktop/workspace/deployment-note') return { ok: true };
  throw Error('Unexpected endpoint: ' + url);
};
for (const name of ['admin-modal.js', 'admin-desktop-licenses.js', 'admin-desktop-workflow.js', 'admin-desktop-security.js']) {
  new vm.Script(fs.readFileSync(path.join(__dirname, '../public', name), 'utf8'), { filename: name }).runInContext(dom.getInternalVMContext());
}
async function waitFor(check, label) {
  const end = Date.now() + 2500;
  while (Date.now() < end) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw Error('Timeout: ' + label + '; ' + errors.join('; '));
}
const count = url => calls.filter(c => c.url === url && c.method === 'POST').length;
const last = url => calls.filter(c => c.url === url).at(-1);
function file(id, value) { Object.defineProperty(byId(id), 'files', { configurable: true, value: [value] }); }
async function securityAction(action) {
  const button = document.querySelector('[data-security-action="' + action + '"]');
  button.click();
  await waitFor(() => !button.isConnected || !button.disabled, action);
}
async function close(pending) { byId('modal-cancel').click(); await pending; }

(async () => {
  try {
    const contentMarkup = w.desktopBootstrapMarkup({ artifacts: {}, sessions: [], launchers: [] });
    byId('content').innerHTML = contentMarkup;
    assert.ok(document.querySelector('[data-component="O"]'));
    assert.match(byId('desktop-bootstrap-panel').textContent, /A \/ B \/ O 실행 파일 배포/);
    const upload = w.showDesktopArtifactUpload('O');
    const exe = new w.File(['MZ_OVERLAY'], 'GameOverlay.exe');
    file('desktop-artifact-file', exe);
    document.querySelector('[data-modal-field="version"]').value = '3.2.1';
    await byId('modal-confirm').onclick();
    assert.match(byId('desktop-artifact-status').textContent, /BOOTSTRAP_COMPONENT_INVALID/);
    assert.match(byId('desktop-artifact-status').textContent, /<img src=x/);
    assert.equal(byId('desktop-artifact-status').querySelector('img'), null);
    assert.equal(byId('desktop-artifact-file').files[0], exe);
    assert.equal(byId('modal-confirm').disabled, false);
    assert.equal(byId('modal').classList.contains('hidden'), false);
    await byId('modal-confirm').onclick();
    await upload;
    assert.equal(calls.filter(c => c.rawBody === exe).length, 2);
    assert.equal(count(base + '/activate'), 0, 'Candidate upload must not publish');
    console.log('PASS Overlay upload preserves server error code, escapes text, and retries the selected file without publishing');

    const security = w.showDesktopSecurityOperations();
    await waitFor(() => byId('sec-min-o'), 'security modal');
    assert.equal(byId('sec-min-o').value, '3.2.1');
    assert.equal(byId('sec-o').value, 'O3');
    assert.deepEqual([...byId('sec-o').options].map(x => x.value), ['', 'O3', 'O4']);
    byId('sec-min-o').value = '4.0';
    await securityAction('preview-policy');
    assert.equal(last('/api/desktop/bootstrap/security-authority/preview').body.minVersionO, '4.0');
    byId('sec-min-o').value = '4.1';
    await securityAction('save-policy');
    assert.equal(count('/api/desktop/bootstrap/security-authority'), 0, 'Changed O policy requires a new preview');
    await securityAction('preview-policy');
    await securityAction('save-policy');
    assert.equal(last('/api/desktop/bootstrap/security-authority').method, 'GET');
    assert.equal(policy.minVersionO, '4.1');
    byId('sec-o').value = 'O4';
    await securityAction('preview-pair');
    assert.equal(last(base + '/preview-pair').body.oId, 'O4');
    byId('sec-o').value = 'O3';
    await securityAction('activate');
    assert.equal(count(base + '/activate'), 0, 'Changed O candidate requires a new preview');
    byId('sec-o').value = 'O4';
    await securityAction('preview-pair');
    await securityAction('activate');
    assert.equal(last(base + '/activate').body.oId, 'O4');
    file('sec-evidence-file', { size: 18, text: async () => '{"nativeBuild":"NOT_RUN"}' });
    await securityAction('record-evidence');
    assert.equal(last(base + '/test-evidence').body.oId, 'O4');
    await close(security);
    console.log('PASS O minimum version preview/save, O candidate preview/publication and evidence preserve revisions and selection guards');

    for (const selectedO of ['O3', '']) {
      const wizard = w.showDesktopDeploymentWizard();
      await waitFor(() => byId('desktop-pair-preview'), 'deployment wizard');
      const select = document.querySelector('[data-candidate="O"]');
      select.value = selectedO;
      select.dispatchEvent(new w.Event('change', { bubbles: true }));
      byId('desktop-release-notes').value = 'Overlay selection ' + (selectedO || 'disabled');
      await byId('desktop-pair-preview').onclick();
      assert.equal(last(base + '/preview-pair').body.oId, selectedO);
      assert.equal(byId('desktop-pair-publish').disabled, false);
      select.dispatchEvent(new w.Event('change', { bubbles: true }));
      assert.equal(byId('desktop-pair-publish').disabled, true);
      await byId('desktop-pair-preview').onclick();
      await byId('desktop-pair-publish').onclick();
      assert.equal(last('/api/desktop/workspace/deployment-note').body.oId, selectedO);
      assert.equal(last(base + '/activate').body.oId, selectedO);
      await close(wizard);
    }
    console.log('PASS Deployment notes and publication bind the selected O, including explicit no-Overlay selection');
    w.desktopWorkflowError(byId('content'), { code: 'OVERLAY_ERROR', problem: { code: 'REQUEST_FAILED', title: '<script>bad()</script>', current: 'state', next: 'retry' } });
    assert.equal(byId('content').querySelector('code').textContent, 'OVERLAY_ERROR');
    assert.equal(byId('content').querySelector('script'), null);
    assert.deepEqual(errors, []);
    console.log('PASS Workflow errors retain the specific server code and escape server text');
  } finally { w.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
