'use strict';
// Focused browser behavior checks. Loads production modal logic and HTTP helpers;
// HTTP replies and the common modal host are fixtures, not a real browser/server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { JSDOM, VirtualConsole } = require('jsdom');
const root = path.resolve(__dirname, '..');
const source = name => fs.readFileSync(path.join(root, 'public', name), 'utf8');
const endpoint = '/api/desktop/bootstrap/overlay';
const pluginEndpoint = endpoint + '/plugins';
const errors = [], calls = [];
const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', error => errors.push(error.message));
const dom = new JSDOM('<!doctype html><main id="modal-host"></main>', {
  url: 'https://fixture.invalid/', runScripts: 'outside-only', virtualConsole, pretendToBeVisual: true
});
const w = dom.window;
Object.defineProperty(w.crypto, 'subtle', { value: crypto.webcrypto.subtle });
const intervals = new Map(); let nextInterval = 1;
w.setInterval = (callback, delay) => { const id = nextInterval++; intervals.set(id, { callback, delay }); return id; };
w.clearInterval = id => intervals.delete(id);
function poll() { assert.equal(intervals.size, 1); const item = intervals.values().next().value; assert.equal(item.delay, 4000); return item.callback(); }
let modalResolve, modalOptions, responder, pluginResponder, checks = 0;
const malicious = '<img src=x onerror="window.injected=true">';
const recordId = 'id\" onclick=\"window.injected=true';
const model = (version = 7) => ({
  ok: true, version, enabled: true, documentSha256: 'a'.repeat(64),
  document: { schema: 1, format: 'GAME-OVERLAY-DATA-1', title: malicious,
    lines: ['</textarea><script>window.injected=true</script>', '두 번째 줄'], theme: 'dark' },
  sessions: [{ id: recordId, licenseId: malicious, status: 'ACTIVE', lastSeenAt: Date.now() },
    { id: 'second', licenseId: 'license', status: malicious, lastSeenAt: 0 }]
});
const nativeBytes = Buffer.from('fixture: native overlay module');
const nativeHash = crypto.createHash('sha256').update(nativeBytes).digest('hex');
const pluginArtifact = (extra = {}) => ({ id: 'PLUGIN_ONE', component: 'O', version: '1.0.0',
  sha256: nativeHash, codeSha256: 'b'.repeat(64), exportTableSha256: 'c'.repeat(64), size: nativeBytes.length,
  active: false, signaturePresent: false, signatureValid: false, eligible: true, reason: '', ...extra });
const pluginModel = (extra = {}) => ({ ok: true, revision: 3, activeId: '', ready: false,
  maxBytes: 16777216, artifacts: [pluginArtifact()], ...extra });
function chooseFile(selector, file) {
  Object.defineProperty(w.document.querySelector(selector), 'files', { value: file ? [file] : [], configurable: true });
}
const nativeFile = (extra = {}) => ({ name: 'overlay.bin', size: nativeBytes.length,
  arrayBuffer: async () => nativeBytes.buffer.slice(nativeBytes.byteOffset, nativeBytes.byteOffset + nativeBytes.byteLength), ...extra });
function response(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(data) };
}
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
async function until(predicate) {
  for (let n = 0; n < 100; n++) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  throw Error('UI fixture timed out');
}
function passed(name) { checks++; console.log('PASS ' + name); }
function session(role = 'admin', csrf = 'OVERLAY_UI_CSRF') {
  w.session = role ? { role, csrf } : null;
}
function input(selector, value) { w.document.querySelector(selector).value = value; }
const editor = () => w.document.querySelector('#desktop-overlay-editor');
const status = () => w.document.querySelector('#overlay-status').textContent;
const postCalls = () => calls.filter(item => item.method === 'POST');
async function close(pending) {
  if (modalResolve) { const resolve = modalResolve; modalResolve = null; resolve({}); }
  await pending;
  w.document.querySelector('#modal-host').replaceChildren();
}
async function open(reply = model()) {
  responder = () => response(reply);
  pluginResponder = () => response(pluginModel());
  const pending = w.showDesktopOverlay();
  await until(() => editor());
  return { pending };
}
w.fetch = async (url, options) => {
  const item = { url, method: options.method, headers: options.headers,
    credentials: options.credentials, signal: options.signal,
    body: typeof options.body === 'string' ? JSON.parse(options.body) : undefined,
    rawBody: typeof options.body === 'string' ? undefined : options.body };
  calls.push(item);
  const result = Promise.resolve().then(() => url.startsWith(pluginEndpoint) ? pluginResponder(item) : responder(item));
  if (!options.signal) return result;
  return new Promise((resolve, reject) => {
    const abort = () => reject(new w.DOMException('Request aborted', 'AbortError'));
    if (options.signal.aborted) { abort(); return; }
    options.signal.addEventListener('abort', abort, { once: true });
    result.then(resolve, reject).finally(() => options.signal.removeEventListener('abort', abort));
  });
};
w.openModal = options => {
  modalOptions = options;
  w.document.querySelector('#modal-host').innerHTML = options.html;
  return new Promise(resolve => { modalResolve = resolve; });
};
w.showLogin = () => { session(null); };
w.readableApiError = code => code;
w.dirtyViews = new Set();
w.currentView = 'desktop';
w.content = w.document.body;
session();
const admin = source('admin.js');
// Import the real escaping/time helpers and the real CSRF HTTP wrapper without
// starting unrelated dashboard timers or fetches in this focused fixture.
const execute = text => vm.runInContext(text, dom.getInternalVMContext());
execute(admin.slice(admin.indexOf('function esc('), admin.indexOf('function fmtDuration(')));
execute(admin.slice(admin.indexOf('async function api('), admin.indexOf('function showLogin(')));
execute(admin.match(/^function roleIsAdmin\(\).*$/m)[0]);
execute(source('admin-desktop-licenses.js').match(/^function desktopDate\(value\).*$/m)[0]);
execute(source('admin-desktop-workflow.js'));

(async () => {
  try {
    responder = () => { throw Error('Unauthorized UI must not request'); };
    session('viewer'); await w.showDesktopOverlay();
    session(null); await w.showDesktopOverlay();
    assert.equal(calls.length, 0); assert.equal(editor(), null);
    passed('Viewer and signed-out sessions cannot open the overlay editor');

    session(); let view = await open();
    assert.ok(modalOptions.title.includes('오버레이'));
    assert.equal(w.document.querySelector('#overlay-title').value, malicious);
    assert.equal(w.document.querySelector('#overlay-lines').value, model().document.lines.join('\n'));
    assert.equal(editor().querySelectorAll('img,script,[onclick]').length, 0);
    assert.equal(w.injected, undefined);
    assert.equal(editor().querySelector('[data-overlay-revoke]').dataset.overlayRevoke, recordId);
    assert.ok(editor().textContent.includes(malicious));
    passed('Display text, session IDs, license IDs and statuses cannot inject HTML');

    input('#overlay-title', '편집 중 제목'); input('#overlay-lines', '저장 전 내용');
    input('#overlay-theme', 'light'); w.document.querySelector('#overlay-enabled').checked = false;
    responder = () => response({ ...model(99), document: { ...model().document, title: 'another admin changed this' },
      sessions: [{ id: 'NEW_GRANT', licenseId: 'NEW_LICENSE', status: 'ACTIVE', lastSeenAt: Date.now() }] });
    await poll();
    assert.equal(w.document.querySelector('#overlay-title').value, '편집 중 제목');
    assert.equal(w.document.querySelector('#overlay-lines').value, '저장 전 내용');
    assert.equal(w.document.querySelector('#overlay-theme').value, 'light');
    assert.equal(w.document.querySelector('#overlay-enabled').checked, false);
    assert.match(w.document.querySelector('#overlay-version').textContent, /버전 7/);
    assert.equal(editor().querySelector('[data-overlay-revoke]').dataset.overlayRevoke, 'NEW_GRANT');
    passed('Four-second automatic polling updates grants while preserving every draft field and its version');

    const slowPoll = deferred(); responder = () => slowPoll.promise;
    const beforePoll = calls.length, pendingPoll = poll();
    await poll(); await w.document.querySelector('#overlay-reload').onclick(); await w.document.querySelector('#overlay-save').onclick();
    assert.equal(calls.length, beforePoll + 2); assert.equal(calls.at(-1).signal.aborted, false);
    assert.equal(w.document.querySelector('#overlay-title').disabled, false);
    input('#overlay-title', '조회 중에도 편집');
    slowPoll.resolve(response(model(99))); await pendingPoll;
    assert.equal(w.document.querySelector('#overlay-title').value, '조회 중에도 편집');
    assert.equal(w.document.querySelector('#overlay-save').disabled, false);
    passed('Slow automatic reads never overlap polls or mutations and keep form fields editable');

    responder = () => { throw Error('temporary network failure'); }; await poll();
    assert.match(w.document.querySelector('#overlay-session-status').textContent, /다음 확인/);
    responder = () => response({ ...model(99), sessions: [] }); await poll();
    assert.match(w.document.querySelector('#overlay-session-status').textContent, /4초/);
    assert.match(editor().textContent, /라이선스 완료 요청/); assert.match(editor().textContent, /A의 실행 흐름은 유지/); assert.match(editor().textContent, /B 갱신과 .bin/);
    assert.doesNotMatch(editor().textContent, /최신 A\/B|새 A를 발급/);
    assert.equal(w.document.querySelector('#overlay-title').value, '조회 중에도 편집');
    passed('Transient poll errors recover and empty grants preserve A while explaining B/plugin publication');

    input('#overlay-title', '인증 완료'); input('#overlay-lines', '첫째\n둘째');
    input('#overlay-theme', 'light'); w.document.querySelector('#overlay-enabled').checked = false;
    responder = request => {
      assert.equal(request.url, endpoint); assert.equal(request.method, 'POST');
      assert.equal(request.credentials, 'same-origin');
      assert.equal(request.headers['X-CSRF-Token'], 'OVERLAY_UI_CSRF');
      assert.deepEqual(request.body, { expectedVersion: 7, enabled: false, document: {
        schema: 1, format: 'GAME-OVERLAY-DATA-1', title: '인증 완료', lines: ['첫째', '둘째'], theme: 'light' } });
      return response({ ...model(8), enabled: false, document: request.body.document });
    };
    await w.document.querySelector('#overlay-save').onclick();
    assert.match(status(), /저장했습니다/);
    assert.match(w.document.querySelector('#overlay-version').textContent, /버전 8/);
    assert.equal(w.document.querySelector('#overlay-save').disabled, false);
    passed('Save sends the current version, exact document schema and existing CSRF credentials');

    responder = () => { throw Error('Invalid input must not request'); };
    for (const invalid of [ { title: '' }, { title: 'x'.repeat(121) },
      { lines: Array(9).fill('line').join('\n') }, { lines: 'x'.repeat(241) } ]) {
      input('#overlay-title', invalid.title ?? 'valid'); input('#overlay-lines', invalid.lines ?? 'valid');
      const before = calls.length; await w.document.querySelector('#overlay-save').onclick();
      assert.equal(calls.length, before, 'Invalid title/lines must be rejected before HTTP');
      assert.match(status(), /길이/);
    }
    passed('Blank or oversized titles, too many lines and oversized lines never submit');

    input('#overlay-title', '수정 중'); input('#overlay-lines', '아직 저장 안 된 내용');
    responder = () => response({ ok: false, error: 'OVERLAY_TEMPLATE_CONFLICT' }, 409);
    await w.document.querySelector('#overlay-save').onclick();
    assert.equal(w.document.querySelector('#overlay-title').value, '수정 중');
    assert.equal(w.document.querySelector('#overlay-lines').value, '아직 저장 안 된 내용');
    assert.match(status(), /입력 내용은 유지/);
    assert.equal(w.document.querySelector('#overlay-save').disabled, false);
    passed('A conflicting save preserves the draft and allows reload or retry');

    const save = deferred(); responder = () => save.promise;
    const beforeSave = postCalls().length;
    const pendingSave = w.document.querySelector('#overlay-save').onclick();
    await w.document.querySelector('#overlay-save').onclick();
    assert.equal(postCalls().length, beforeSave + 1);
    save.resolve(response(model(9))); await pendingSave;
    passed('A second click cannot start a duplicate in-flight save');

    input('#overlay-title', '권한 회수 중 보존할 제목');
    const beforeRevoke = calls.length;
    responder = request => request.method === 'POST' ? response({ ok: true }) : response({ ...model(9), sessions: [] });
    await w.document.querySelector('#overlay-sessions').onclick({ target: editor().querySelector('[data-overlay-revoke]') });
    assert.equal(calls[beforeRevoke].url, endpoint + '/sessions/' + encodeURIComponent(recordId) + '/revoke');
    assert.equal(calls[beforeRevoke].headers['X-CSRF-Token'], 'OVERLAY_UI_CSRF');
    assert.match(status(), /회수했습니다/);
    assert.equal(w.document.querySelector('#overlay-title').value, '권한 회수 중 보존할 제목');
    passed('Revocation encodes the session ID and refreshes the authoritative list');
    responder = () => response({ ...model(12), document: { ...model().document, title: '명시적으로 다시 읽은 제목' } });
    await w.document.querySelector('#overlay-reload').onclick();
    assert.equal(w.document.querySelector('#overlay-title').value, '명시적으로 다시 읽은 제목');
    assert.match(w.document.querySelector('#overlay-version').textContent, /버전 12/);
    passed('The explicit reload button still refreshes the server document and editing version');
    await close(view.pending); assert.equal(intervals.size, 0);

    session(); view = await open();
    const closingPoll = deferred(); responder = () => closingPoll.promise;
    const pendingClosingPoll = poll(), closingSignal = calls.findLast(item => item.url === endpoint).signal;
    await close(view.pending); await pendingClosingPoll;
    assert.equal(closingSignal.aborted, true); assert.equal(intervals.size, 0); assert.equal(editor(), null);
    closingPoll.resolve(response(model(500)));
    passed('Closing the modal aborts its current read, clears polling and drops late responses');

    session(); view = await open();
    const ownerPoll = deferred(); responder = () => ownerPoll.promise;
    const pendingOwnerPoll = poll(), ownerSignal = calls.findLast(item => item.url === endpoint).signal;
    session(null); await poll(); await pendingOwnerPoll;
    assert.equal(ownerSignal.aborted, true); assert.equal(intervals.size, 0);
    ownerPoll.resolve(response(model(600))); await close(view.pending);
    passed('Logout or owner loss stops polling and aborts outstanding reads without rendering them');

    const load = deferred(); responder = () => load.promise;
    const pendingOpen = w.showDesktopOverlay(); session('admin', 'NEW_OWNER');
    load.resolve(response(model())); await pendingOpen;
    assert.equal(editor(), null);
    passed('A late initial reply cannot open a modal after the login session changes');

    session(); view = await open();
    input('#overlay-title', 'local draft');
    const lateSave = deferred(); responder = () => lateSave.promise;
    const pendingLateSave = w.document.querySelector('#overlay-save').onclick();
    session('admin', 'NEW_OWNER'); lateSave.resolve(response({ ...model(100), document: { ...model().document, title: 'wrong owner' } }));
    await pendingLateSave;
    assert.equal(w.document.querySelector('#overlay-title').value, 'local draft');
    assert.doesNotMatch(w.document.querySelector('#overlay-version').textContent, /버전 100/);
    await close(view.pending);
    passed('A late save reply cannot overwrite another login session or its visible draft');

    session(); view = await open();
    const lateRevoke = deferred(); responder = () => lateRevoke.promise;
    const pendingRevoke = w.document.querySelector('#overlay-sessions').onclick({ target: editor().querySelector('[data-overlay-revoke]') });
    const countAfterRevoke = calls.length;
    session('admin', 'NEW_OWNER'); lateRevoke.resolve(response(model(100)));
    await pendingRevoke;
    assert.equal(calls.length, countAfterRevoke, 'Session change must stop the follow-up read');
    await close(view.pending);
    passed('A late revocation reply starts no follow-up read under a new login');

    session(); view = await open();
    assert.match(w.document.querySelector('#overlay-plugin-state').textContent, /운영 게시된 플러그인이 없습니다/);
    assert.match(w.document.querySelector('#overlay-plugin-state').textContent, /승인 서명 없음/);
    assert.equal(w.document.querySelector('#overlay-plugin-publish').disabled, false);
    assert.match(editor().textContent, /표시 데이터\(\.dat\)는 실행 플러그인이 아닙니다/);
    passed('Native plugin candidates, unsigned state and display data are distinguished without inventing an active release');

    responder = () => response({ ...model(), sessions: [
      { id: 'WAITING', licenseId: 'license', status: 'ACTIVE', lastSeenAt: 0, pluginId: 'PLUGIN_ONE', pluginPhase: 'PENDING' },
      { id: 'INSTALLING', licenseId: 'license', status: 'ACTIVE', lastSeenAt: 0, pluginId: 'PLUGIN_ONE', pluginPhase: 'INSTALLING' },
      { id: 'VERIFIED', licenseId: 'license', status: 'ACTIVE', lastSeenAt: Date.now(), pluginId: 'PLUGIN_ONE', pluginPhase: 'READY', pluginVerifiedAt: Date.now() },
      { id: 'UNASSIGNED', licenseId: 'license', status: 'ACTIVE', lastSeenAt: 0 }
    ] });
    await poll();
    const phaseText = w.document.querySelector('#overlay-sessions').textContent;
    for (const label of ['플러그인 설치 대기', '플러그인 · 무결성 확인 중', '서버 무결성 확인됨', '플러그인 미지정']) assert.ok(phaseText.includes(label));
    assert.equal(w.document.querySelectorAll('#overlay-sessions [data-overlay-revoke]').length, 4);
    passed('Issued grants show server-reported install/verification phases and identify grants without a pinned plugin');

    const uploadFile = nativeFile(); chooseFile('#overlay-plugin-file', uploadFile);
    input('#overlay-plugin-version', '2.0.0'); input('#overlay-title', '플러그인 게시 중 문서 초안');
    pluginResponder = () => response(pluginModel({ revision: 4, artifacts: [pluginArtifact(), pluginArtifact({ id: 'PLUGIN_TWO', version: '2.0.0' })] }));
    await poll();
    assert.equal(w.document.querySelector('#overlay-plugin-file').files[0], uploadFile);
    assert.equal(w.document.querySelector('#overlay-plugin-version').value, '2.0.0');
    assert.equal(w.document.querySelector('#overlay-title').value, '플러그인 게시 중 문서 초안');
    assert.equal(w.document.querySelector('#overlay-plugin-candidate').value, 'PLUGIN_ONE');
    passed('Automatic status refresh preserves plugin file, version, candidate and display drafts');

    pluginResponder = () => { throw Error('Invalid plugin must not upload'); };
    for (const file of [null, nativeFile({ name: 'overlay.dat' }), nativeFile({ name: 'overlay.exe' }),
      nativeFile({ size: 0 }), nativeFile({ size: 16777217 })]) {
      chooseFile('#overlay-plugin-file', file); const before = calls.length;
      await w.document.querySelector('#overlay-plugin-upload').onclick(); assert.equal(calls.length, before);
      assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /\.bin 파일/);
    }
    chooseFile('#overlay-plugin-file', uploadFile); input('#overlay-plugin-version', '../bad');
    const beforeBadVersion = calls.length; await w.document.querySelector('#overlay-plugin-upload').onclick();
    assert.equal(calls.length, beforeBadVersion); input('#overlay-plugin-version', '2.0.0');
    passed('Non-bin, empty, oversized and invalid-version uploads stop before HTTP');

    const approval = { component: 'O', version: '2.0.0', sha256: nativeHash,
      approval: { keyId: 'd'.repeat(64), signature: 'fixture-signature-validated-by-server' } };
    chooseFile('#overlay-plugin-approval', { size: 1024, text: async () => JSON.stringify({ ...approval, sha256: 'e'.repeat(64) }) });
    const beforeBadApproval = calls.length; await w.document.querySelector('#overlay-plugin-upload').onclick();
    assert.equal(calls.length, beforeBadApproval);
    assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /버전·해시/);
    chooseFile('#overlay-plugin-approval', { size: 1024, text: async () => JSON.stringify(approval) });
    pluginResponder = request => {
      if (request.method === 'POST') {
        const url = new URL(request.url, 'https://fixture.invalid');
        assert.equal(url.pathname, pluginEndpoint); assert.equal(url.searchParams.get('version'), '2.0.0');
        assert.equal(url.searchParams.get('fileName'), 'overlay.bin');
        assert.equal(request.rawBody, uploadFile); assert.equal(request.headers['Content-Type'], 'application/octet-stream');
        assert.equal(request.headers['X-CSRF-Token'], 'OVERLAY_UI_CSRF');
        assert.equal(request.headers['x-game-release-key-id'], approval.approval.keyId);
        assert.equal(request.headers['x-game-release-signature'], approval.approval.signature);
        return response({ ok: true, artifact: pluginArtifact({ id: 'PLUGIN_TWO', version: '2.0.0' }), revision: 5, activeUnchanged: true });
      }
      return response(pluginModel({ revision: 5, artifacts: [pluginArtifact(), pluginArtifact({ id: 'PLUGIN_TWO', version: '2.0.0' })] }));
    };
    await w.document.querySelector('#overlay-plugin-upload').onclick();
    assert.equal(w.document.querySelector('#overlay-plugin-candidate').value, 'PLUGIN_TWO');
    assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /후보 등록 완료/);
    assert.match(w.document.querySelector('#overlay-plugin-state').textContent, /운영 게시된 플러그인이 없습니다/);
    assert.equal(w.document.querySelector('#overlay-title').value, '플러그인 게시 중 문서 초안');
    passed('Upload matches local hash and O approval, includes session CSRF, and remains a candidate until explicit activation');

    pluginResponder = request => {
      assert.equal(request.url, pluginEndpoint + '/activate'); assert.equal(request.method, 'POST');
      assert.equal(request.headers['X-CSRF-Token'], 'OVERLAY_UI_CSRF');
      assert.deepEqual(request.body, { id: 'PLUGIN_TWO', expectedRevision: 5 });
      return response(pluginModel({ revision: 6, activeId: 'PLUGIN_TWO', ready: true,
        artifacts: [pluginArtifact(), pluginArtifact({ id: 'PLUGIN_TWO', version: '2.0.0', active: true, signaturePresent: true, signatureValid: true })] }));
    };
    await w.document.querySelector('#overlay-plugin-publish').onclick();
    assert.match(w.document.querySelector('#overlay-plugin-state').textContent, /운영 버전 2.0.0 · 서버 사용 가능/);
    assert.match(w.document.querySelector('#overlay-plugin-state').textContent, /승인 서명 확인됨/);
    assert.equal(w.document.querySelector('#overlay-plugin-publish').disabled, true);
    const beforeRepeatPublish = calls.length; await w.document.querySelector('#overlay-plugin-publish').onclick();
    assert.equal(calls.length, beforeRepeatPublish);
    passed('Explicit publication uses authoritative revision and shows only the returned active version');

    chooseFile('#overlay-plugin-approval', null);
    pluginResponder = () => response({ ok: false, error: 'OVERLAY_PLUGIN_ABI', message: '플러그인 ABI가 일치하지 않습니다.' }, 400);
    await w.document.querySelector('#overlay-plugin-upload').onclick();
    assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /플러그인 ABI가 일치하지 않습니다/);
    assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /OVERLAY_PLUGIN_ABI/);
    assert.equal(w.document.querySelector('#overlay-plugin-file').files[0], uploadFile);
    assert.equal(w.document.querySelector('#overlay-plugin-upload').disabled, false);
    passed('Rejected uploads show actual server message/code and keep selected files for correction');

    pluginResponder = () => response({ ok: true, artifact: pluginArtifact({ sha256: 'f'.repeat(64) }) });
    await w.document.querySelector('#overlay-plugin-upload').onclick();
    assert.match(w.document.querySelector('#overlay-plugin-result').textContent, /서버에서 확인한 파일 해시가 다릅니다/);
    passed('A mismatched server digest cannot be reported as successful registration');
    await close(view.pending);

    session(); view = await open(); chooseFile('#overlay-plugin-file', nativeFile());
    const uploading = deferred(); pluginResponder = () => uploading.promise;
    const pendingUpload = w.document.querySelector('#overlay-plugin-upload').onclick();
    await until(() => calls.at(-1).method === 'POST' && calls.at(-1).url.startsWith(pluginEndpoint + '?'));
    const uploadSignal = calls.at(-1).signal, beforeDuplicate = calls.length;
    await w.document.querySelector('#overlay-plugin-upload').onclick(); assert.equal(calls.length, beforeDuplicate);
    await close(view.pending); await pendingUpload;
    assert.equal(uploadSignal.aborted, true); assert.equal(intervals.size, 0); assert.equal(editor(), null);
    uploading.resolve(response({ ok: true, artifact: pluginArtifact() }));
    passed('Duplicate upload clicks are blocked; closing aborts the upload and drops late state updates');

    session(); view = await open(); chooseFile('#overlay-plugin-file', nativeFile());
    const ownerUpload = deferred(); pluginResponder = () => ownerUpload.promise;
    const pendingOwnerUpload = w.document.querySelector('#overlay-plugin-upload').onclick();
    await until(() => calls.at(-1).method === 'POST' && calls.at(-1).url.startsWith(pluginEndpoint + '?') && !calls.at(-1).signal.aborted);
    const ownerUploadSignal = calls.at(-1).signal; session(null); await poll(); await pendingOwnerUpload;
    assert.equal(ownerUploadSignal.aborted, true); assert.equal(intervals.size, 0);
    ownerUpload.resolve(response({ ok: true, artifact: pluginArtifact() })); await close(view.pending);
    passed('Logout cancels active plugin transport and prevents follow-up reads under another owner');

    session(); const unauthorized = deferred(); responder = () => unauthorized.promise;
    const oldRequest = w.api(endpoint); session('admin', 'NEW_OWNER');
    unauthorized.resolve(response({ ok: false, error: 'NOT_AUTHORIZED' }, 401));
    await assert.rejects(oldRequest); assert.equal(w.session.csrf, 'NEW_OWNER');
    passed('An old request with a late 401 cannot log out a newer administrator session');

    assert.equal(intervals.size, 0);
    assert.deepEqual(errors, []);
    console.log(`OVERLAY ADMIN UI PASS: ${checks} browser-logic checks; jsdom with production helpers, mocked HTTP/modal host.`);
  } finally {
    dom.window.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
