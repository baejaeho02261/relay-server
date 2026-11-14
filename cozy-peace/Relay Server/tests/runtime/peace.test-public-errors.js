'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Exercise the actual response/stream modules without starting any store or
// listener. Dependencies are stubbed only at the module boundary.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const crypto = require('node:crypto'), { EventEmitter } = require('node:events');
const root = path.resolve(MODULE_RESOURCE_ROOT, '..');
function Load(file, overrides = {}, extras = {}) {
    const inert = new Proxy(function () { return inert; }, { get: () => inert });
    const module = { exports: {} };
    const localRequire = name => Object.prototype.hasOwnProperty.call(overrides, name) ? overrides[name] :
        ['fs', 'path', 'crypto'].includes(name) ? require(name) : inert;
    vm.runInNewContext(fs.readFileSync(path.join(root, file), 'utf8'), {
        module, exports: module.exports, require: localRequire, Buffer, console,
        setInterval, clearInterval, Date, URL, ...extras
    }, { filename: file });
    return module.exports;
}
function Response() {
    return { status: null, body: '', packets: [], writableLength: 0, destroyed: false,
        writeHead(status) { this.status = status; },
        write(packet) { this.packets.push(packet); return true; },
        end(body = '') { this.body += body; this.writableEnded = true; },
        destroy() { this.destroyed = true; }
    };
}
const api = Load("web/http/peace.api-context.js", {
    "../../services/runtime/peace.desktop-operations-errors": require("../../services/runtime/peace.desktop-operations-errors")
});
test('API errors do not echo paths, private data, malformed codes or arbitrary detail', () => {
    for (const code of ['ENOENT /private/admin-key.pem', 'SECRET token=value', '<script>alert(1)</script>', 'A'.repeat(500), null]) {
        const res = Response(); api.ApiError(res, 400, code, 'private-token-value');
        const body = JSON.parse(res.body);
        assert.equal(body.error, 'REQUEST_FAILED'); assert.equal(body.detail, '');
        assert.equal(body.problem.code, 'REQUEST_FAILED');
        assert.doesNotMatch(res.body, /private|token=value|script|AAAAA/);
    }
});
test('safe response references and dual-approval ticket retain their exact purpose', () => {
    const res = Response(); api.ApiError(res, 500, 'INTERNAL_ERROR', 'REF:AABBCCDDEEFF');
    assert.equal(JSON.parse(res.body).detail, 'REF:AABBCCDDEEFF');
    const approval = Response(); api.ApiError(approval, 428, 'DUAL_APPROVAL_REQUIRED', 'DUAL-' + 'AB'.repeat(10));
    assert.equal(JSON.parse(approval.body).detail, 'DUAL-' + 'AB'.repeat(10));
    const crossed = Response(); api.ApiError(crossed, 400, 'INPUT_INVALID', 'DUAL-' + 'AB'.repeat(10));
    assert.equal(JSON.parse(crossed.body).detail, '');
    const invalid = Response(); api.ApiError(invalid, 'evil', 'INPUT_INVALID'); assert.equal(invalid.status, 500);
});
test('response serialization failures log a fixed code without exception data or stack', () => {
    const logged = [];
    const isolated = Load('web/http/peace.api-context.js', {}, {
        console: { error(...values) { logged.push(values.map(String).join(' ')); } }
    });
    const res = Response();
    isolated.Json(res, 200, { toJSON() { throw Error('PRIVATE_SERIALIZATION_PAYLOAD /private/key.pem token=secret'); } });
    assert.equal(res.status, 500);
    assert.equal(JSON.parse(res.body).error, 'RESPONSE_SERIALIZATION_FAILED');
    assert.deepEqual(logged, ['[WEB_JSON_ERROR] RESPONSE_SERIALIZATION_FAILED']);
    assert.doesNotMatch(logged.join('\n') + res.body, /PRIVATE_SERIALIZATION_PAYLOAD|key\.pem|token=secret|\bat\s+\w/);
});
test('request read failures do not echo the originating socket error', async () => {
    const read = Load("web/http/peace.read-json-body.js", { "../../services/protocol/peace.strict-json": require("../../services/protocol/peace.strict-json") });
    const req = new EventEmitter(); const pending = read.ReadJsonBody(req);
    req.emit('error', Error('private socket credential /private/key.pem'));
    await assert.rejects(pending, /^Error: BODY_READ_FAILED$/);
});
test('malformed backup JSON returns fixed guidance without submitted content', () => {
    const integrity = Load("services/integrity/peace.integrity-check.js", {
        fs: { existsSync: () => true, readFileSync: () => '{"private":"SECRET_PARSE_VALUE" bad}' },
        "../../config/peace.runtime-configuration": { BACKUP_DIR: '/synthetic-backups' },
        "../../core/peace.utilities.js": { Now: () => 1 }
    });
    const result = integrity.VerifyBackup('synthetic.json');
    assert.equal(result.errors[0].code, 'INVALID_JSON');
    assert.equal(result.errors[0].message, 'Backup JSON is invalid or unreadable.');
    assert.doesNotMatch(JSON.stringify(result), /SECRET_PARSE_VALUE/);
});
test('HA malformed payload returns a fixed failure instead of JSON parser input', async () => {
    const config = { HA_ENABLED: true, HA_PEER_URL: 'https://synthetic.invalid', HA_SHARED_SECRET: 's'.repeat(32) };
    const ha = Load("services/network/peace.ha-coordinator.js", { "../../config/peace.runtime-configuration": config });
    const body = '{"secret":"SECRET_HA_VALUE" malformed}', pathname = '/internal/ha/replicate';
    const timestamp = String(Date.now()), digest = crypto.createHash('sha256').update(body).digest('hex');
    const signature = crypto.createHmac('sha256', config.HA_SHARED_SECRET).update(`${timestamp}\nPOST\n${pathname}\n${digest}`).digest('hex');
    const req = new EventEmitter(); req.method = 'POST'; req.headers = { 'x-relay-ha-time': timestamp, 'x-relay-ha-signature': signature };
    const res = Response(), pending = ha.HandleInternal(req, res, pathname);
    req.emit('data', Buffer.from(body)); req.emit('end'); await pending;
    assert.equal(res.status, 409); assert.equal(JSON.parse(res.body).error, 'HA_REPLICATION_FAILED');
    assert.doesNotMatch(res.body, /SECRET_HA_VALUE|SyntaxError/);
});
function Events() {
    const handles = new Set(); let active = true;
    const events = Load("web/events/peace.web-events.js", {
        "../../core/peace.utilities.js": { Now: () => 123 },
        "../authentication/peace.web-auth": { IsSessionActive: () => active }
    }, { setInterval(fn) { const timer = { fn, unref() {} }; handles.add(timer); return timer; }, clearInterval(timer) { handles.delete(timer); } });
    return { events, handles, expire: () => { active = false; } };
}
test('slow SSE client is destroyed without retaining further messages or timer', () => {
    const { events, handles } = Events(), req = new EventEmitter(), res = Response();
    events.OpenEventStream(req, res, { role: 'admin' }); assert.equal(handles.size, 1);
    res.writableLength = 65536; events.BroadcastNotification({ text: 'bounded' });
    assert.equal(res.destroyed, true); assert.equal(handles.size, 0); assert.equal(req.listenerCount('close'), 0);
    const count = res.packets.length; events.BroadcastEvent({ text: 'never queued' }); assert.equal(res.packets.length, count);
    events.Stop();
});
test('SSE write backpressure and Stop close all responses and remove close handlers', () => {
    const { events, handles } = Events(), req = new EventEmitter(), res = Response();
    events.OpenEventStream(req, res, { role: 'admin' }); res.write = () => false;
    events.BroadcastServiceState({}); assert.equal(res.destroyed, true); assert.equal(handles.size, 0);
    const requests = [new EventEmitter(), new EventEmitter()], responses = [Response(), Response()];
    requests.forEach((q, i) => events.OpenEventStream(q, responses[i], { role: 'admin' }));
    events.Stop(); events.Stop();
    assert.equal(handles.size, 0); responses.forEach(r => assert.equal(r.destroyed, true));
    requests.forEach(q => assert.equal(q.listenerCount('close'), 0));
});
test('SSE expiry and normal request close remove the last timer immediately', () => {
    const { events, handles, expire } = Events(), req = new EventEmitter(), res = Response();
    events.OpenEventStream(req, res, { role: 'admin' }); expire();
    [...handles][0].fn(); assert.equal(res.writableEnded, true); assert.equal(handles.size, 0); assert.equal(req.listenerCount('close'), 0);
    const next = Events(), q = new EventEmitter(), r = Response();
    next.events.OpenEventStream(q, r, { role: 'admin' }); q.emit('close'); assert.equal(next.handles.size, 0);
});
test('HA Stop aborts in-flight requests, clears polling and prevents later replication', async () => {
    const handles = new Set(), signals = [];
    const config = { HA_ENABLED: true, HA_PEER_URL: 'https://synthetic.invalid', HA_SHARED_SECRET: 's'.repeat(32), HA_POLL_MS: 1000 };
    const ha = Load("services/network/peace.ha-coordinator.js", {
        "../../config/peace.runtime-configuration": config,
        "../../storage/sqlite/peace.sqlite-database": { LoadSnapshot: () => null }
    }, {
        AbortSignal, AbortController,
        fetch(url, options) { signals.push(options.signal); return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('synthetic aborted request')), { once: true })); },
        setInterval(fn) { const timer = { fn, unref() {} }; handles.add(timer); return timer; },
        clearInterval(timer) { handles.delete(timer); }
    });
    ha.Start(); assert.equal(signals.length, 1); assert.equal(handles.size, 1);
    const oldPoll = [...handles][0].fn;
    ha.Stop(); ha.Stop();
    assert.equal(signals[0].aborted, true); assert.equal(handles.size, 0);
    ha.OnLocalSnapshot({ large: 'discarded' }, { revision: 1 }); ha.Start(); oldPoll();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(signals.length, 1); assert.equal(ha.CanAcceptTraffic(), false);
    const res = Response(); await ha.HandleInternal({}, res, '/internal/ha/status');
    assert.equal(res.status, 503); assert.equal(JSON.parse(res.body).error, 'SERVER_SHUTTING_DOWN');
});
