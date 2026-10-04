'use strict';
// Focused browser behavior checks. Loads production modal logic and HTTP helpers;
// HTTP replies and the common modal host are fixtures, not a real browser/server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { JSDOM, VirtualConsole } = require('jsdom');
const root = path.resolve(__dirname, '..');
const source = name => fs.readFileSync(path.join(root, 'public', name), 'utf8');
const endpoint = '/api/desktop/bootstrap/overlay';
const errors = [], calls = [];
const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', error => errors.push(error.message));
const dom = new JSDOM('<!doctype html><main id="modal-host"></main>', {
  url: 'https://fixture.invalid/', runScripts: 'outside-only', virtualConsole, pretendToBeVisual: true
});
const w = dom.window;
const intervals = new Map(); let nextInterval = 1;
w.setInterval = (callback, delay) => { const id = nextInterval++; intervals.set(id, { callback, delay }); return id; };
w.clearInterval = id => intervals.delete(id);
function poll() { assert.equal(intervals.size, 1); const item = intervals.values().next().value; assert.equal(item.delay, 4000); return item.callback(); }
let modalResolve, modalOptions, responder, checks = 0;
const malicious = '<img src=x onerror="window.injected=true">';
const recordId = 'id\" onclick=\"window.injected=true';
const model = (version = 7) => ({
  ok: true, version, enabled: true, documentSha256: 'a'.repeat(64),
  document: { schema: 1, format: 'GAME-OVERLAY-DATA-1', title: malicious,
    lines: ['</textarea><script>window.injected=true</script>', '두 번째 줄'], theme: 'dark' },
  sessions: [{ id: recordId, licenseId: malicious, status: 'ACTIVE', lastSeenAt: Date.now() },
    { id: 'second', licenseId: 'license', status: malicious, lastSeenAt: 0 }]
});
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
  const pending = w.showDesktopOverlay();
  await until(() => editor());
  return { pending };
}
w.fetch = async (url, options) => {
  const item = { url, method: options.method, headers: options.headers,
    credentials: options.credentials, signal: options.signal, body: options.body ? JSON.parse(options.body) : undefined };
  calls.push(item);
  const result = Promise.resolve().then(() => responder(item));
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
    assert.equal(calls.length, beforePoll + 1); assert.equal(calls.at(-1).signal.aborted, false);
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
    assert.match(editor().textContent, /라이선스 완료 요청/); assert.match(editor().textContent, /최신 A\/B/); assert.match(editor().textContent, /새 A/);
    assert.equal(w.document.querySelector('#overlay-title').value, '조회 중에도 편집');
    passed('Transient poll errors recover and empty grants explain completion and current A/B publication');

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
    const pendingClosingPoll = poll(), closingSignal = calls.at(-1).signal;
    await close(view.pending); await pendingClosingPoll;
    assert.equal(closingSignal.aborted, true); assert.equal(intervals.size, 0); assert.equal(editor(), null);
    closingPoll.resolve(response(model(500)));
    passed('Closing the modal aborts its current read, clears polling and drops late responses');

    session(); view = await open();
    const ownerPoll = deferred(); responder = () => ownerPoll.promise;
    const pendingOwnerPoll = poll(), ownerSignal = calls.at(-1).signal;
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
