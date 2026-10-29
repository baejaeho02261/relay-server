'use strict';

// Actual relay HTTP routing and SQLite lifecycle, with synthetic credentials and
// a generated 2x2 PNG. No browser, desktop capture, or external service is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const net = require('node:net');
const zlib = require('node:zlib');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const origin = 'https://admin.example.test';
const host = 'admin.example.test';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const requestId = () => crypto.randomUUID();
const adminPassword = crypto.randomBytes(48).toString('base64url');
const viewerPassword = crypto.randomBytes(48).toString('base64url');
let child, ended, spawnError, exited = false, webPort, tcpPort, logs = '', checks = 0;

function childEnvironment() {
  // Do not inherit integration endpoints, witness/data/key/TLS paths or Node
  // preloads from an operator shell. NODE_PATH is only the installed dependency
  // lookup path used by this test runner; all application state is configured below.
  const env = {};
  for (const name of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'PATHEXT', 'COMSPEC', 'LANG', 'LC_ALL', 'TZ', 'NODE_PATH'])
    if (typeof process.env[name] === 'string') env[name] = process.env[name];
  return env;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

function request(url, { method = 'GET', body, auth, csrf = true, headers = {}, timeout = 5000 } = {}) {
  assert.ok(url.startsWith('/') && !url.startsWith('//'), 'Only local test paths are allowed');
  const bytes = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
  const sentHeaders = {
    Host: host, Origin: origin, 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': host,
    'X-Railway-Request-Id': crypto.randomBytes(12).toString('hex'), 'X-Real-IP': '127.0.0.1',
    'User-Agent': 'Cozy-synthetic-diagnostic-http-test', Connection: 'close',
    ...(bytes === undefined ? {} : { 'Content-Type': Buffer.isBuffer(body) ? 'image/png' : 'application/json', 'Content-Length': String(bytes.length) }),
    ...(auth ? { Cookie: auth.cookie, ...(csrf ? { 'X-CSRF-Token': auth.csrf } : {}) } : {}),
    ...headers
  };
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: webPort, path: url, method, headers: sentHeaders, agent: false, timeout }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 2 * 1024 * 1024) res.destroy(Error('TEST_RESPONSE_TOO_LARGE')); else chunks.push(chunk); });
      res.once('error', reject);
      res.once('end', () => {
        const data = Buffer.concat(chunks);
        let json;
        if (String(res.headers['content-type']).includes('application/json')) {
          try { json = JSON.parse(data.toString('utf8')); } catch { reject(Error('TEST_INVALID_JSON_RESPONSE')); return; }
        }
        resolve({ status: res.statusCode, headers: res.headers, bytes: data, json });
      });
    });
    req.once('timeout', () => req.destroy(Error('TEST_REQUEST_TIMEOUT')));
    req.once('error', reject);
    req.end(bytes);
  });
}

function expectStatus(result, expected, label) {
  assert.equal(result.status, expected, label + ': HTTP ' + result.status + ' ' + (result.json?.error || ''));
  return result;
}

function expectError(result, expected, code, label) {
  expectStatus(result, expected, label);
  assert.equal(result.json?.error, code, label + ': wrong error code');
  return result;
}

async function check(name, action) { await action(); checks++; console.log('PASS ' + name); }

async function login(role) {
  const response = expectStatus(await request('/api/login', {
    method: 'POST', body: { role, password: role === 'admin' ? adminPassword : viewerPassword }
  }), 200, role + ' login');
  assert.match(response.headers['set-cookie'][0], /; Secure(?:;|$)/i);
  assert.match(response.headers['set-cookie'][0], /; HttpOnly(?:;|$)/i);
  return { cookie: response.headers['set-cookie'][0].split(';')[0], csrf: response.json.csrf };
}

async function mutate(url, body, auth, headers = {}) {
  let response = await request(url, { method: 'POST', body, auth, headers });
  if (response.status === 428 && response.json?.error === 'ADMIN_ACTION_REQUIRED') {
    const actionId = response.json.action.id;
    expectStatus(await request('/api/session/reauthenticate', {
      method: 'POST', body: { password: adminPassword, actionId }, auth
    }), 200, 'operation-bound reauthentication');
    response = await request(url, { method: 'POST', body, auth, headers: { ...headers, 'X-Admin-Action': actionId } });
  }
  return response;
}

function crc32(bytes) {
  let value = 0xFFFFFFFF;
  for (const octet of bytes) {
    value ^= octet;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xEDB88320 : 0);
  }
  return (value ^ 0xFFFFFFFF) >>> 0;
}
function chunk(name, bytes) {
  const type = Buffer.from(name, 'ascii'), out = Buffer.alloc(bytes.length + 12);
  out.writeUInt32BE(bytes.length); type.copy(out, 4); bytes.copy(out, 8);
  out.writeUInt32BE(crc32(Buffer.concat([type, bytes])), out.length - 4);
  return out;
}
function syntheticPng(red = 255) {
  const header = Buffer.alloc(13); header.writeUInt32BE(2); header.writeUInt32BE(2, 4); header[8] = 8; header[9] = 6;
  const raw = Buffer.from([0, red, 0, 0, 255, 0, 255, 0, 255, 0, 0, 0, 255, 255, 255, 255, 255, 255]);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

function bearer(token, extra = {}) { return { Authorization: 'Bearer ' + token, ...extra }; }
function status(token, headers = {}) {
  return request('/api/diagnostic-capture/status', { method: 'POST', body: {}, headers: bearer(token, headers) });
}
function upload(token, bytes, id = requestId(), headers = {}) {
  return request('/api/diagnostic-capture/upload', {
    method: 'POST', body: bytes, headers: bearer(token, { 'X-Diagnostic-Consent': '1', 'X-Diagnostic-Request': id, ...headers })
  });
}

async function waitForExit(timeout) {
  let timer;
  try { return await Promise.race([ended, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('TEST_SERVER_SHUTDOWN_DEADLINE')), timeout); })]); }
  finally { clearTimeout(timer); }
}

async function assertListenerClosed(port) {
  const isOpen = await new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', error => { socket.destroy(); if (error.code === 'ECONNREFUSED') resolve(false); else reject(error); });
    socket.setTimeout(1000, () => socket.destroy(Error('TEST_LISTENER_CLOSE_TIMEOUT')));
  });
  assert.equal(isOpen, false, 'The owned listener must close after server shutdown');
}

async function run() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cozy-diagnostic-http-'));
  fs.chmodSync(dataDir, 0o700);
  try {
    webPort = await freePort(); tcpPort = await freePort();
    while (tcpPort === webPort) tcpPort = await freePort();
    const env = {
      ...childEnvironment(), DATA_DIR: dataDir, NODE_ENV: 'production', STORAGE_ENGINE: 'sqlite', HA_ENABLED: '0',
      TMPDIR: dataDir, TMP: dataDir, TEMP: dataDir,
      CONNECT_TCP_HOST: '127.0.0.1', CONNECT_TCP_PORT: String(tcpPort), PORT: String(webPort), WEB_ADMIN_PORT: String(webPort), HEALTH_PORT: '0',
      WEB_ADMIN_TRANSPORT: 'railway', WEB_ADMIN_RAILWAY_EDGE_ONLY: '1', WEB_ADMIN_HOST: '0.0.0.0',
      WEB_ADMIN_REQUIRE_HTTPS: '1', WEB_ADMIN_SECURE_COOKIE: '1', WEB_ADMIN_TRUSTED_PROXIES: '',
      RAILWAY_PROJECT_ID: '11111111-1111-4111-8111-111111111111', RAILWAY_ENVIRONMENT_ID: '22222222-2222-4222-8222-222222222222', RAILWAY_SERVICE_ID: '33333333-3333-4333-8333-333333333333',
      WEBAUTHN_RP_ID: host, WEBAUTHN_ORIGIN: origin, ADMIN_SECRET: adminPassword, VIEWER_SECRET: viewerPassword,
      VAPID_PUBLIC_KEY: '', VAPID_PRIVATE_KEY: ''
    };
    child = spawn(process.execPath, [path.join(root, 'peace.relay-server.js')], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', bytes => { logs = (logs + bytes.toString()).slice(-16384); });
    child.stderr.on('data', bytes => { logs = (logs + bytes.toString()).slice(-16384); });
    ended = new Promise(resolve => {
      // Handle failed spawn immediately, before readiness polling can await exit.
      // An error with an existing PID still requires the normal shutdown path.
      child.once('error', error => {
        spawnError = error;
        if (!child.pid) { exited = true; resolve({ code: null, signal: null, error }); }
      });
      child.once('exit', (code, signal) => { exited = true; resolve({ code, signal }); });
    });
    let ready = false;
    const start = Date.now();
    while (Date.now() - start < 20000 && !exited && !spawnError) {
      try { if ((await request('/readyz', { timeout: 500 })).status === 200) { ready = true; break; } } catch {}
      await delay(100);
    }
    assert.ok(ready && !spawnError, 'Real Railway-mode server must become ready: ' + (spawnError?.code || '') + ' ' + logs);

    await check('anonymous diagnostics page has its dedicated capture policy and no-cache headers', async () => {
      const page = expectStatus(await request('/diagnostics.html'), 200, 'diagnostics static page');
      assert.match(page.headers['content-type'], /^text\/html/);
      assert.match(page.bytes.toString(), /peace\.diagnostic-capture\.js/);
      assert.match(page.headers['cache-control'], /no-store/);
      assert.equal(page.headers['referrer-policy'], 'no-referrer');
      assert.equal(page.headers['permissions-policy'], 'display-capture=(self), camera=(), microphone=(), geolocation=()');
      const csp = page.headers['content-security-policy'];
      for (const directive of ["default-src 'none'", "script-src 'self'", "connect-src 'self'", 'img-src blob:', 'media-src blob:', "worker-src 'none'", "frame-ancestors 'none'", "form-action 'none'"]) assert.ok(csp.includes(directive), directive);
      assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:|data:/);
      assert.equal(page.headers['set-cookie'], undefined);
      const main = expectStatus(await request('/'), 200, 'main static page');
      assert.doesNotMatch(main.headers['permissions-policy'], /display-capture/);
    });

    const admin = await login('admin'), viewer = await login('viewer');
    const membersPath = '/api/desktop/members';
    async function createMember(displayName) {
      const list = expectStatus(await request(membersPath, { auth: admin }), 200, 'member revision');
      const made = expectStatus(await mutate(membersPath, { displayName, note: '', requestId: requestId(), expectedRevision: list.json.revision }, admin), 200, 'create member');
      return made.json.member.id;
    }
    const member = await createMember('Synthetic diagnostic HTTP member'), other = await createMember('Other synthetic member');
    const capturesPath = id => membersPath + '/' + id + '/captures';
    async function revision(id = member) { return expectStatus(await request(capturesPath(id), { auth: admin }), 200, 'capture revision').json.revision; }
    async function createCapture() {
      return expectStatus(await mutate(capturesPath(member), { expectedRevision: await revision(), requestId: requestId() }, admin), 200, 'create capture').json;
    }
    const invitation = await createCapture(), imagePath = capturesPath(member) + '/' + invitation.capture.id + '/image';
    const png = syntheticPng(), differentPng = syntheticPng(127), uploadId = requestId();

    await check('real login creates member-bound invitation and bearer status needs neither session nor cookies', async () => {
      assert.match(invitation.token, /^[A-F0-9]{24}\.[a-f0-9]{64}$/);
      assert.equal(invitation.fragmentPath, '/diagnostics.html#token=' + encodeURIComponent(invitation.token));
      const publicState = expectStatus(await status(invitation.token), 200, 'public status');
      assert.equal(publicState.json.status, 'AVAILABLE');
      assert.ok(Number.isSafeInteger(publicState.json.serverTime));
      assert.equal(publicState.json.memberId, undefined); assert.equal(publicState.json.displayName, undefined);
      assert.equal(publicState.headers['set-cookie'], undefined); assert.match(publicState.headers['cache-control'], /no-store/);
      expectStatus(await status(invitation.token, { Origin: 'https://other.example.test' }), 403, 'cross-origin status');
      expectStatus(await request('/api/diagnostic-capture/status', { method: 'POST', body: {} }), 403, 'missing bearer');
      expectStatus(await request(capturesPath(member)), 401, 'anonymous capture list');
      expectStatus(await request(capturesPath(member), { auth: viewer }), 403, 'viewer capture list');
      expectStatus(await request(capturesPath(member), { method: 'POST', auth: admin, csrf: false, body: { expectedRevision: await revision(), requestId: requestId() } }), 403, 'create without CSRF');
    });

    await check('explicit-consent public PNG upload crosses the actual HTTP parser and commits one encrypted image', async () => {
      expectStatus(await upload(invitation.token, png, uploadId, { 'X-Diagnostic-Consent': '0' }), 400, 'missing consent');
      assert.equal(expectStatus(await status(invitation.token), 200, 'grant survives missing consent').json.status, 'AVAILABLE');
      const uploaded = expectStatus(await upload(invitation.token, png, uploadId), 200, 'synthetic upload');
      assert.equal(uploaded.json.status, 'UPLOADED'); assert.equal(uploaded.json.duplicate, false);
      assert.equal(uploaded.headers['set-cookie'], undefined); assert.match(uploaded.headers['cache-control'], /no-store/);
      const files = fs.readdirSync(path.join(dataDir, 'support-captures'));
      assert.deepEqual(files, [invitation.capture.id + '.enc']);
      const encrypted = fs.readFileSync(path.join(dataDir, 'support-captures', files[0]));
      assert.ok(!encrypted.includes(png), 'Only ciphertext is committed to the isolated image directory');
    });

    await check('image retrieval rejects anonymous/viewer/wrong-member access and accepts freshly reauthenticated admin', async () => {
      expectStatus(await request(imagePath), 401, 'anonymous image');
      expectStatus(await request(imagePath, { auth: viewer }), 403, 'viewer image');
      expectStatus(await request(imagePath, { headers: bearer(invitation.token) }), 401, 'public bearer cannot read admin image');
      expectError(await request(capturesPath(other) + '/' + invitation.capture.id + '/image', { auth: admin }), 404, 'CAPTURE_NOT_FOUND', 'wrong member image');
      expectStatus(await request('/api/session/reauthenticate', { method: 'POST', body: { password: adminPassword }, auth: admin }), 200, 'recent admin authentication');
      const image = expectStatus(await request(imagePath, { auth: admin }), 200, 'recent admin image');
      assert.equal(image.headers['content-type'], 'image/png'); assert.deepEqual(image.bytes, png);
      assert.match(image.headers['cache-control'], /no-store/); assert.equal(image.headers['referrer-policy'], 'no-referrer');
      assert.equal(image.headers['x-content-type-options'], 'nosniff');
      expectStatus(await request(imagePath, { auth: admin, headers: { Range: 'bytes=0-4' } }), 400, 'range forbidden');
      expectStatus(await request('/api/diagnostic-capture/image', { method: 'POST', body: {}, headers: bearer(invitation.token) }), 404, 'no public image route');
      expectStatus(await request('/support-captures/' + invitation.capture.id + '.enc'), 404, 'no static ciphertext route');
    });

    await check('one-use capture permits exact transport retry but no second request or replacement image', async () => {
      assert.equal(expectStatus(await upload(invitation.token, png, uploadId), 200, 'exact upload retry').json.duplicate, true);
      expectError(await upload(invitation.token, png), 409, 'CAPTURE_REQUEST_REUSED', 'new upload request');
      expectError(await upload(invitation.token, differentPng, uploadId), 409, 'CAPTURE_REQUEST_REUSED', 'replacement image');
      const state = expectStatus(await request(capturesPath(member), { auth: admin }), 200, 'capture list after retries');
      assert.equal(state.json.totalCount, 1); assert.equal(state.json.items[0].status, 'UPLOADED');
      assert.equal(fs.readdirSync(path.join(dataDir, 'support-captures')).length, 1);
      assert.deepEqual(expectStatus(await request(imagePath, { auth: admin }), 200, 'original image retained').bytes, png);
      expectError(await mutate(capturesPath(other) + '/' + invitation.capture.id + '/delete', { expectedRevision: await revision(), requestId: requestId() }, admin), 404, 'CAPTURE_NOT_FOUND', 'wrong member deletion');
      assert.deepEqual(expectStatus(await request(imagePath, { auth: admin }), 200, 'wrong member cannot mutate original').bytes, png);
    });

    await check('revocation closes the bearer and deletion removes the committed image', async () => {
      const revoked = await createCapture();
      const revoke = expectStatus(await mutate(capturesPath(member) + '/' + revoked.capture.id + '/revoke', { expectedRevision: await revision(), requestId: requestId() }, admin), 200, 'revoke invitation');
      assert.equal(revoke.json.capture.status, 'REVOKED');
      expectError(await status(revoked.token), 403, 'CAPTURE_NOT_AVAILABLE', 'revoked status');
      expectError(await upload(revoked.token, png), 403, 'CAPTURE_NOT_AVAILABLE', 'revoked upload');
      assert.equal(fs.existsSync(path.join(dataDir, 'support-captures', revoked.capture.id + '.enc')), false);
      const deleted = expectStatus(await mutate(capturesPath(member) + '/' + invitation.capture.id + '/delete', { expectedRevision: await revision(), requestId: requestId() }, admin), 200, 'delete image');
      assert.equal(deleted.json.capture.status, 'DELETED');
      expectError(await request(imagePath, { auth: admin }), 403, 'CAPTURE_NOT_AVAILABLE', 'deleted image inaccessible');
      expectError(await status(invitation.token), 403, 'CAPTURE_NOT_AVAILABLE', 'deleted bearer inaccessible');
      expectError(await upload(invitation.token, png, uploadId), 403, 'CAPTURE_NOT_AVAILABLE', 'deleted exact retry rejected');
      assert.deepEqual(fs.readdirSync(path.join(dataDir, 'support-captures')), []);
      const remaining = expectStatus(await request(capturesPath(member), { auth: admin }), 200, 'closed capture list');
      assert.equal(remaining.json.items.filter(item => item.status === 'UPLOADED').length, 0);
    });

    await check('orderly SIGTERM retains the SQLite file and closes both owned HTTP and native listeners', async () => {
      assert.equal(child.kill('SIGTERM'), true);
      const outcome = await waitForExit(11000);
      assert.equal(outcome.code, 0); assert.equal(outcome.signal, null);
      await assertListenerClosed(webPort); await assertListenerClosed(tcpPort);
      assert.ok(fs.existsSync(path.join(dataDir, 'relay.db')));
    });
  } finally {
    if (child && !exited) {
      child.kill('SIGTERM');
      try { await waitForExit(11000); } catch { child.kill('SIGKILL'); await waitForExit(5000); }
    }
    child?.stdout?.destroy(); child?.stderr?.destroy();
    fs.rmSync(dataDir, { recursive: true, force: true });
    assert.equal(fs.existsSync(dataDir), false, 'The isolated test DATA_DIR must be removed');
  }
  console.log('SUPPORT_CAPTURE_HTTP_PASS ' + checks + ' checks; actual loopback HTTP/SQLite lifecycle; synthetic PNG only; browser/Windows NOT_RUN; temporary data removed.');
}

run().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
