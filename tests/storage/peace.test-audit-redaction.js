'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), crypto = require('node:crypto'), vm = require('node:vm');
const { createRequire } = require('node:module');
const redact = require('../../storage/audit/peace.audit-redaction');
const key = () => 'LICENSE-' + crypto.randomBytes(10).toString('hex').toUpperCase();
function Fixture(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'peace-audit-redaction-'));
    t.after(() => fs.rmSync(dir, { recursive:true, force:true }));
    const state = { events:[], licenses:new Map(), production:{ auditChain:{ count:0, head:'', anchor:'', lastError:'' } } };
    const output = [], broadcast = [], file = path.resolve(__dirname, '../../storage/audit/peace.audit.js');
    const req = createRequire(file), module = { exports:{} };
    const field = value => String(value || '').replace(/[\r\n|]/g, ' ').trim();
    function local(name) {
        if (/peace\.runtime-configuration(?:\.js)?$/.test(name)) return { DATA_DIR:dir, AUDIT_DIR:dir, MAX_EVENT_MEMORY:1000, MAX_SEARCH_RESULTS:1000 };
        if (/peace\.runtime-state(?:\.js)?$/.test(name)) return state;
        if (/peace\.utilities(?:\.js)?$/.test(name)) return { Now:Date.now, SafeField:field };
        if (/peace\.desktop-audit-retention(?:\.js)?$/.test(name)) return { Read:() => ({ sequence:0, operations:{} }), StripPrefix:(_, bytes) => bytes };
        if (/peace\.web-events(?:\.js)?$/.test(name)) return { BroadcastEvent:e => broadcast.push(structuredClone(e)) };
        if (/peace\.(notification-center|incident-center|security-detection)(?:\.js)?$/.test(name)) return { CaptureEvent:() => {}, Capture:() => {} };
        return req(name);
    }
    vm.runInNewContext(fs.readFileSync(file, 'utf8'), { module, exports:module.exports, require:local, Buffer,
        console:{ log:(...v) => output.push(v.join(' ')), error:(...v) => output.push(v.join(' ')) }, process:{ platform:process.platform } }, { filename:file });
    const audit = module.exports;
    return { dir, state, output, broadcast, audit,
        rows:() => fs.readdirSync(dir).filter(x => /^audit-.*\.jsonl$/.test(x)).flatMap(x => fs.readFileSync(path.join(dir, x), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)) };
}
test('new license audit rows, stdout and broadcasts contain references instead of full credentials', t => {
    const f = Fixture(t), first = key(), second = key(); f.audit.LoadRecentAudit();
    for (const type of ['LICENSE_CREATE','LICENSE_BOUND','LICENSE_AUTH','LICENSE_EXTEND','LICENSE_UNBIND','LICENSE_SUSPEND','LICENSE_RESUME','LICENSE_REISSUE','LICENSE_TRANSFER','QR_LICENSE_AUTH'])
        assert.equal(f.audit.LogEvent(type, first + ' -> ' + second, { durable:true }).ok, true);
    const channels = [JSON.stringify(f.rows()), f.output.join('\n'), JSON.stringify(f.broadcast)];
    for (const text of channels) { assert.ok(!text.includes(first)); assert.ok(!text.includes(second)); assert.match(text, /REDACTED_SHA256/); }
    assert.equal(f.audit.VerifyAuditChain().ok, true); assert.equal(f.rows().length, 10);
});
test('JSON secret fields and canonical keys are redacted recursively without removing public event IDs', t => {
    const f = Fixture(t), license = key(), secret = 'password123!', guessedHash = crypto.createHash('sha256').update(secret).digest('hex'), id = crypto.randomBytes(32).toString('hex'); f.audit.LoadRecentAudit();
    const data = { auditEventId:id, operationId:crypto.randomBytes(32).toString('hex'), nested:{ password:secret, passwordHash:guessedHash, ADMIN_SECRET:secret, privateKey:secret, token:secret, authToken:secret, cookie:secret, api_key:secret, license_key:license }, description:license, reason:'PUBLIC_REASON' };
    assert.equal(f.audit.LogEvent('CREDENTIAL_TEST', JSON.stringify(data), { durable:true }).ok, true);
    const row = f.rows()[0], parsed = JSON.parse(row.detail);
    assert.equal(parsed.auditEventId, id); assert.equal(parsed.reason, 'PUBLIC_REASON');
    assert.ok(!row.detail.includes(license));
    assert.equal(parsed.nested.password, '[CREDENTIAL_REDACTED]'); assert.equal(parsed.nested.passwordHash, '[CREDENTIAL_REDACTED]');
    for (const channel of [JSON.stringify(f.rows()), f.output.join('\n'), JSON.stringify(f.broadcast)]) {
        assert.ok(!channel.includes(secret)); assert.ok(!channel.includes(guessedHash), 'a password hash must not become a guessing oracle');
    }
    assert.equal(redact.Detail(row.type, row.detail), row.detail, 'redaction must be idempotent');
    assert.equal(f.audit.VerifyAuditChain().ok, true);
});
test('durable operation retries use the same normalized fingerprint and never append twice', t => {
    const f = Fixture(t), id = crypto.randomBytes(32).toString('hex'), details = { operationId:crypto.randomBytes(32).toString('hex'), token:'SYNTHETIC_SESSION_TOKEN', reason:'PUBLIC_REASON' };
    const first = f.audit.AppendOperationEvent(id, 'DESKTOP_SERVER_OPERATION', details);
    assert.equal(first.ok, true); const second = f.audit.AppendOperationEvent(id, 'DESKTOP_SERVER_OPERATION', details);
    assert.equal(second.duplicate, true); assert.equal(second.sequence, first.sequence); assert.equal(f.rows().length, 1);
    assert.equal(f.audit.VerifyAuditChain().ok, true);
    assert.equal(f.audit.AppendOperationEvent(id, 'DESKTOP_SERVER_OPERATION', details).duplicate, true);
    assert.ok(!JSON.stringify(f.rows()).includes(details.token));
    const count = f.rows().length;
    assert.throws(() => f.audit.AppendOperationEvent(crypto.randomBytes(32).toString('hex'), 'DESKTOP_SERVER_OPERATION', { payload:'x'.repeat(70000) }), /AUDIT_OPERATION_INVALID/);
    assert.equal(f.rows().length, count, 'a record without a retry identity must not be acknowledged');
});
test('historical raw rows stay byte-identical and hash-valid while newly appended rows are redacted', t => {
    const f = Fixture(t), oldKey = key(), fresh = key(), time = Date.now();
    const row = { time, type:'LICENSE_CREATE', detail:oldKey, sequence:1, previousHash:'' };
    row.hash = crypto.createHash('sha256').update('|' + row.sequence + '|' + row.time + '|' + row.type + '|' + row.detail).digest('hex').toUpperCase();
    const original = JSON.stringify(row) + '\n', file = f.audit.AuditFileForTime(time); fs.writeFileSync(file, original, { mode:0o600 });
    f.audit.LoadRecentAudit(); assert.equal(f.audit.VerifyAuditChain().ok, true);
    assert.equal(f.audit.LogEvent('LICENSE_CREATE', fresh, { durable:true }).ok, true);
    const bytes = fs.readFileSync(file, 'utf8'); assert.ok(bytes.startsWith(original)); assert.ok(bytes.includes(oldKey)); assert.ok(!bytes.includes(fresh));
    assert.equal(f.audit.VerifyAuditChain().ok, true);
});
test('redaction is bounded and does not pollute object prototypes', () => {
    const large = 'SYNTHETIC_SECRET_'.repeat(6000), bounded = redact.Detail('TEST', large);
    assert.ok(bounded.length < 256); assert.ok(!bounded.includes('SYNTHETIC_SECRET_'));
    assert.ok(!bounded.includes(crypto.createHash('sha256').update(large).digest('hex')));
    let complex = { password:'1234' }; for (let i=0; i<20; i++) complex = { nested:complex };
    const rawComplex = JSON.stringify(complex), safeComplex = redact.Detail('TEST', rawComplex);
    assert.equal(safeComplex, '{"version":1,"kind":"AUDIT_DETAIL_REDACTED"}');
    assert.ok(!safeComplex.includes(crypto.createHash('sha256').update(rawComplex).digest('hex')));
    for (const legacy of ['1234', 'QR-12345678', 'SYNTHETIC_LOW_ENTROPY_KEY']) {
        const result = redact.Detail('LICENSE_CREATE', legacy);
        assert.equal(result, '{"version":1,"kind":"LICENSE_EVENT_REDACTED"}');
        assert.ok(!result.includes(crypto.createHash('sha256').update(legacy).digest('hex')));
        assert.equal(redact.Detail('LICENSE_CREATE', result), result);
    }
    const value = '{"__proto__":{"polluted":true},"password":"SYNTHETIC_SECRET"}';
    const result = redact.Detail('TEST', value); assert.equal({}.polluted, undefined); assert.ok(!result.includes('SYNTHETIC_SECRET'));
});
