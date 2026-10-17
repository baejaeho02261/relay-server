'use strict';
// Real ES256 assertions against the production ceremony implementation. Storage
// and clocks are isolated so expiry and failed commits are deterministic.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Isolated } = require('./completion-6-10-fixture');
const realDeadline = require('../services/desktopDeadline');
const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
process.env.WEBAUTHN_RP_ID = 'localhost'; process.env.WEBAUTHN_ORIGIN = 'https://localhost';
const wire = require('./passkey-wire-fixture');
const request = { headers: { host: 'localhost' } };
const b64 = value => Buffer.from(value).toString('base64url');
let count = 0;
function fixture() {
    let wall = 1900000000000, tick = 1000, saveOk = true, saves = 0, afterVerify = () => {};
    const credentialId = b64(crypto.randomBytes(32));
    const record = { id: 'ABCDEF0123456789ABCDEF01', credentialId, role: 'admin',
        publicKeySpki: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        rpId: 'localhost', signCount: 0, lastUsedAt: 0, revokedAt: 0 };
    const credentials = new Map([[record.id, record]]);
    const passkey = Isolated('services/passkeyAuth.js', [], {
        crypto: { ...crypto, verify(...args) { const valid = crypto.verify(...args); afterVerify(); return valid; } },
        '../core/state': { production: { passkeyCredentials: credentials } },
        '../core/utils': { Now: () => wall, SafeField: String },
        '../web/webAuth': { IsHttps: () => true },
        '../storage/database': { SaveDatabase() { saves++; return saveOk; } },
        '../storage/audit': { LogEvent() {} },
        './desktopDeadline': {
            After(ms) { return { expiresAt: wall + ms, deadline: tick + ms }; },
            Expired(value) { return realDeadline.Expired(value, { wall, tick }); }
        }
    });
    function assertion(signCount = 0) {
        const start = passkey.LoginBegin('admin', request);
        assert.equal(start.ok, true);
        const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: start.publicKey.challenge, origin: 'https://localhost' }));
        const auth = Buffer.alloc(37);
        crypto.createHash('sha256').update('localhost').digest().copy(auth);
        auth[32] = 5; auth.writeUInt32BE(signCount, 33);
        return { challengeId: start.challengeId, credentialId, clientDataJSON: b64(client),
            authenticatorData: b64(auth), signature: b64(crypto.sign('sha256',
                Buffer.concat([auth, crypto.createHash('sha256').update(client).digest()]), pair.privateKey)) };
    }
    function registration(signCount = 0) {
        const session = { id: 'registration-admin', role: 'admin' };
        const start = passkey.RegistrationBegin(session, request);
        assert.equal(start.ok, true);
        return { session, body: { challengeId: start.challengeId, ...wire.Registration('localhost', pair.publicKey, crypto.randomBytes(32), signCount), name: 'Synthetic credential',
            clientDataJSON: b64(JSON.stringify({ type: 'webauthn.create', challenge: start.publicKey.challenge, origin: 'https://localhost' })) } };
    }
    return { passkey, record, credentials, assertion, registration,
        move(w, t) { wall += w; tick += t; }, failSave() { saveOk = false; },
        afterVerify(fn) { afterVerify = fn; }, saves: () => saves };
}
function test(name, fn) { fn(); count++; console.log('PASS ' + name); }

test('Always-zero passkeys remain supported across independent assertions', () => {
    const f = fixture();
    for (let i = 0; i < 2; i++) assert.equal(f.passkey.LoginFinish(request, f.assertion()).ok, true);
    assert.equal(f.record.signCount, 0); assert.equal(f.saves(), 2);
});
test('Observed positive counter cannot be reset to zero, decreased or replayed', () => {
    const f = fixture();
    assert.equal(f.passkey.LoginFinish(request, f.assertion(8)).ok, true);
    for (const n of [0, 7, 8]) {
        assert.equal(f.passkey.LoginFinish(request, f.assertion(n)).reason, 'PASSKEY_COUNTER_REPLAY');
        assert.equal(f.record.signCount, 8);
    }
    assert.equal(f.passkey.LoginFinish(request, f.assertion(9)).ok, true);
    assert.equal(f.saves(), 2);
});
test('Challenge expires by either clock and cannot survive wall-clock rollback', () => {
    for (const movement of [[300000, 0], [0, 300000], [-1, 0]]) {
        const f = fixture(), body = f.assertion(); f.move(...movement);
        assert.equal(f.passkey.LoginFinish(request, body).reason, 'PASSKEY_CHALLENGE_INVALID');
        assert.equal(f.saves(), 0);
    }
});
test('A valid proof crossing expiry does not change the credential or issue a login', () => {
    const f = fixture(), body = f.assertion(1);
    f.afterVerify(() => f.move(0, 300000));
    assert.equal(f.passkey.LoginFinish(request, body).reason, 'PASSKEY_CHALLENGE_INVALID');
    assert.equal(f.record.signCount, 0); assert.equal(f.record.lastUsedAt, 0); assert.equal(f.saves(), 0);
});
test('Revocation during proof verification wins over the previously selected credential', () => {
    const f = fixture(), body = f.assertion(1); f.afterVerify(() => { f.record.revokedAt = 1; });
    assert.equal(f.passkey.LoginFinish(request, body).reason, 'PASSKEY_CREDENTIAL_NOT_FOUND');
    assert.equal(f.record.signCount, 0); assert.equal(f.saves(), 0);
});
test('Failed login persistence restores counters and consumes the one-use challenge', () => {
    const f = fixture(), body = f.assertion(1); f.failSave();
    assert.equal(f.passkey.LoginFinish(request, body).reason, 'PASSKEY_STORAGE_UNAVAILABLE');
    assert.equal(f.record.signCount, 0); assert.equal(f.record.lastUsedAt, 0);
    assert.equal(f.passkey.LoginFinish(request, body).reason, 'PASSKEY_CHALLENGE_INVALID');
});
test('Registration retains the first counter and refuses an expired ceremony', () => {
    const f = fixture(), first = f.registration(6);
    const result = f.passkey.RegistrationFinish(first.session, request, first.body);
    assert.equal(result.ok, true); assert.equal(f.credentials.get(result.credential.id).signCount, 6);
    const late = f.registration(); f.move(0, 300000);
    assert.equal(f.passkey.RegistrationFinish(late.session, request, late.body).reason, 'PASSKEY_CHALLENGE_INVALID');
    assert.equal(f.credentials.size, 2);
});
test('Failed registration or revocation persistence is not reported as success', () => {
    const f = fixture(), registration = f.registration(); f.failSave();
    assert.equal(f.passkey.RegistrationFinish(registration.session, request, registration.body).reason, 'PASSKEY_STORAGE_UNAVAILABLE');
    assert.equal(f.credentials.size, 1);
    assert.equal(f.passkey.Revoke(f.record.id, 'TEST').reason, 'PASSKEY_STORAGE_UNAVAILABLE');
    assert.equal(f.record.revokedAt, 0); assert.equal(Object.hasOwn(f.record, 'revokedBy'), false);
});
test('Pending ceremony storage is bounded and expired entries free capacity', () => {
    const f = fixture();
    for (let i = 0; i < 4096; i++) assert.equal(f.passkey.LoginBegin('admin', request).ok, true);
    assert.equal(f.passkey.LoginBegin('admin', request).reason, 'PASSKEY_CAPACITY');
    f.move(0, 300000);
    assert.equal(f.passkey.LoginBegin('admin', request).ok, true);
});
console.log(`PASSKEY LIFETIME PASS: ${count} deterministic cases; no physical authenticator claim`);
