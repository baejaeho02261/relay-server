"use strict";
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const { Isolated } = require('./completion-6-10-fixture');
const w = require('./passkey-wire-fixture'), parse = require('../services/passkeyAuthData');
const ctx = require('../services/passkeyContext');
const req = { headers: { host: 'admin.example.test', origin: 'https://admin.example.test' } };
function reset() { process.env.WEBAUTHN_RP_ID = 'admin.example.test'; process.env.WEBAUTHN_ORIGIN = 'https://admin.example.test'; }
function fixture() {
    reset(); const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const records = new Map(); let saves = 0;
    const api = Isolated('services/passkeyAuth.js', [], {
        '../core/state': { production: { passkeyCredentials: records } },
        '../core/utils': { Now: () => Date.now(), SafeField: String },
        '../web/webAuth': { IsHttps: r => !r.insecure },
        '../storage/database': { SaveDatabase() { saves++; return true; } }, '../storage/audit': { LogEvent() {} }
    });
    const session = { id: 'synthetic-admin', role: 'admin' };
    function registration(options = {}) {
        const begin = api.RegistrationBegin(session, req); assert.equal(begin.ok, true);
        return { challengeId: begin.challengeId, ...w.Registration('admin.example.test', pair.publicKey, crypto.randomBytes(32), 0, options),
            clientDataJSON: w.b64(JSON.stringify({ type: 'webauthn.create', challenge: begin.publicKey.challenge, origin: 'https://admin.example.test' })) };
    }
    function register(options) { const body = registration(options), out = api.RegistrationFinish(session, req, body); assert.equal(out.ok, true, JSON.stringify(out)); return records.get(out.credential.id); }
    function assertion(record, { auth, clientPatch = {}, privateKey } = {}) {
        const begin = api.LoginBegin('admin', req); assert.equal(begin.ok, true, JSON.stringify(begin));
        const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begin.publicKey.challenge, origin: 'https://admin.example.test', ...clientPatch }));
        auth ||= w.Auth('admin.example.test');
        return { challengeId: begin.challengeId, credentialId: record.credentialId, clientDataJSON: w.b64(client),
            authenticatorData: w.b64(auth), signature: w.b64(crypto.sign('sha256', Buffer.concat([auth, crypto.createHash('sha256').update(client).digest()]), privateKey || pair.privateKey)) };
    }
    return { api, pair, records, session, registration, register, assertion, saves: () => saves };
}
let count = 0; function test(name, fn) { reset(); fn(); count++; console.log('PASS ' + name); }
function rejectRegistration(change, reason, options) {
    const f = fixture(), body = f.registration(options); change(body, f);
    const out = f.api.RegistrationFinish(f.session, req, body);
    assert.equal(out.ok, false); if (reason) assert.equal(out.reason, reason); assert.equal(f.records.size, 0); assert.equal(f.saves(), 0);
}
test('Valid raw none/ES256 registration derives the stored key from COSE and signs in', () => {
    const f = fixture(), body = f.registration(); delete body.publicKeySpki; delete body.authenticatorData;
    const result = f.api.RegistrationFinish(f.session, req, body); assert.equal(result.ok, true);
    const record = f.records.get(result.credential.id); assert.equal(record.verificationVersion, 2);
    assert.equal(record.publicKeySpki, w.b64(f.pair.publicKey.export({ type: 'spki', format: 'der' })));
    assert.equal(f.api.LoginFinish(req, f.assertion(record)).ok, true);
});
test('Matching legacy convenience fields are checked, not trusted independently', () => { assert.equal(fixture().register().role, 'admin'); });
test('Missing configured RP or origin never falls back to Host', () => {
    const f = fixture(); delete process.env.WEBAUTHN_RP_ID;
    assert.equal(f.api.RegistrationBegin(f.session, req).reason, 'PASSKEY_CONFIG_REQUIRED');
    reset(); delete process.env.WEBAUTHN_ORIGIN; assert.equal(f.api.LoginBegin('admin', req).reason, 'PASSKEY_CONFIG_REQUIRED');
});
test('Only a fixed HTTPS single-host RP configuration is supported', () => {
    for (const patch of [{ WEBAUTHN_ORIGIN: 'http://admin.example.test' }, { WEBAUTHN_ORIGIN: 'https://admin.example.test/path' },
        { WEBAUTHN_ORIGIN: 'https://evil.test' }, { WEBAUTHN_RP_ID: 'example.test' }, { WEBAUTHN_RP_ID: '*.example.test' },
        { WEBAUTHN_ORIGIN: 'https://user@admin.example.test' }, { WEBAUTHN_ORIGIN: 'https://admin.example.test/#x' }])
        assert.throws(() => ctx.Configuration({ WEBAUTHN_RP_ID: 'admin.example.test', WEBAUTHN_ORIGIN: 'https://admin.example.test', ...patch }));
});
test('Wrong or injected Host and Origin are rejected before challenge allocation', () => {
    const f = fixture();
    for (const host of ['evil.test', 'admin.example.test@evil.test', 'admin.example.test/path', 'admin.example.test:444', 'admin.example.test,evil.test'])
        assert.equal(f.api.RegistrationBegin(f.session, { headers: { host } }).reason, 'PASSKEY_HOST_INVALID');
    assert.equal(f.api.LoginBegin('admin', { headers: { ...req.headers, origin: 'https://evil.test' } }).reason, 'PASSKEY_ORIGIN_INVALID');
    assert.equal(f.api.RegistrationBegin(f.session, { ...req, rawHeaders: ['Host', 'admin.example.test', 'Host', 'admin.example.test'] }).ok, false);
});
test('Plain HTTP is refused by the ceremony itself', () => { const f = fixture(); assert.equal(f.api.RegistrationBegin(f.session, { ...req, insecure: true }).reason, 'ADMIN_HTTPS_REQUIRED'); });
test('Registration requires the raw attestation object', () => rejectRegistration(b => delete b.attestationObject, 'PASSKEY_ATTESTATION_REQUIRED'));
test('The old 37-byte no-AT registration is rejected', () => rejectRegistration(b => {
    const auth = w.Auth('admin.example.test'); b.authenticatorData = w.b64(auth);
    b.attestationObject = w.b64(w.Cbor(new Map([['fmt', 'none'], ['authData', auth], ['attStmt', new Map()]])));
}, 'PASSKEY_ATTESTED_DATA_REQUIRED'));
test('Submitted credential ID must match the attested credential ID', () => rejectRegistration(b => b.credentialId = w.b64(crypto.randomBytes(32)), 'PASSKEY_CREDENTIAL_MISMATCH'));
test('Submitted SPKI must match the attested COSE key', () => rejectRegistration(b => b.publicKeySpki = w.b64(crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' })), 'PASSKEY_PUBLIC_KEY_MISMATCH'));
test('Submitted authenticator data must match the attestation bytes', () => rejectRegistration(b => b.authenticatorData = w.b64(w.Auth('admin.example.test')), 'PASSKEY_AUTH_DATA_MISMATCH'));
test('Unsupported attestation formats and non-empty none statements fail closed', () => {
    rejectRegistration(() => {}, 'PASSKEY_ATTESTATION_FORMAT_UNSUPPORTED', { fmt: 'packed' });
    rejectRegistration(() => {}, 'PASSKEY_ATTESTATION_FORMAT_UNSUPPORTED', { attStmt: new Map([['sig', Buffer.alloc(64)]]) });
});
test('Wrong COSE algorithm or curve is not accepted', () => {
    for (const [label, value] of [[1, 3], [3, -257], [-1, 2]]) {
        const f = fixture(), cose = w.KeyMap(f.pair.publicKey); cose.set(label, value);
        const b = f.registration({ cose }); assert.equal(f.api.RegistrationFinish(f.session, req, b).reason, 'PASSKEY_KEY_TYPE_INVALID');
    }
});
test('Off-curve coordinates are rejected by the native EC implementation', () => {
    const f = fixture(), cose = w.KeyMap(f.pair.publicKey); cose.set(-2, Buffer.alloc(32)); cose.set(-3, Buffer.alloc(32));
    assert.equal(f.api.RegistrationFinish(f.session, req, f.registration({ cose })).reason, 'PASSKEY_KEY_POINT_INVALID');
});
test('Registration requires user presence and verification', () => {
    for (const flags of [64, 65, 68]) rejectRegistration(() => {}, 'PASSKEY_USER_VERIFICATION_REQUIRED', { flags });
});
test('Inconsistent backup flags are rejected; valid synchronized zero-counter keys work', () => {
    rejectRegistration(() => {}, 'PASSKEY_BACKUP_FLAGS_INVALID', { flags: 85 });
    const f = fixture(), record = f.register({ flags: 93 }); assert.equal(record.backupEligible, true);
    assert.equal(f.api.LoginFinish(req, f.assertion(record, { auth: w.Auth('admin.example.test', 0, 29) })).ok, true);
});
test('Duplicate COSE labels, truncation and trailing data are rejected', () => {
    const f = fixture(), key = w.Cbor(w.KeyMap(f.pair.publicKey));
    const duplicate = Buffer.concat([Buffer.from([0xa6]), key.subarray(1), w.Cbor(1), w.Cbor(2)]);
    for (const coseBytes of [duplicate, key.subarray(0, -1), Buffer.concat([key, Buffer.from([0])])]) {
        const body = f.registration({ coseBytes }); assert.equal(f.api.RegistrationFinish(f.session, req, body).ok, false);
    }
    assert.equal(f.saves(), 0);
});
test('Extension bytes are bounded, fully consumed and structurally checked', () => {
    const f = fixture(); assert.equal(f.register({ flags: 197, extensionBytes: w.Cbor(new Map([['credProtect', 2]])) }).role, 'admin');
    rejectRegistration(() => {}, undefined, { flags: 197 });
    rejectRegistration(() => {}, undefined, { flags: 197, extensionBytes: w.Cbor([1, 2]) });
});
test('Attestation CBOR rejects duplicate top keys, trailing bytes and oversized values', () => {
    rejectRegistration(b => b.attestationObject = w.b64(Buffer.concat([Buffer.from(b.attestationObject, 'base64url'), Buffer.from([0])])));
    rejectRegistration(b => b.attestationObject = w.b64(Buffer.alloc(16385)));
    const bytes = Buffer.concat([Buffer.from([0xa2]), w.Cbor('fmt'), w.Cbor('none'), w.Cbor('fmt'), w.Cbor('none')]);
    assert.throws(() => parse.Cbor(bytes), /MAP_KEY/);
});
test('CBOR rejects indefinite lengths, nonminimal integers, invalid UTF8 and excessive nesting', () => {
    for (const b of [Buffer.from([0x9f, 0xff]), Buffer.from([0x18, 0]), Buffer.from([0x61, 0xff]), Buffer.from([0xc0, 0]), Buffer.concat([Buffer.alloc(12, 0x81), Buffer.from([0])])])
        assert.throws(() => parse.Cbor(b));
});
test('Registration challenge is single-use on both success and verification failure', () => {
    const f = fixture(), body = f.registration(); assert.equal(f.api.RegistrationFinish(f.session, req, body).ok, true);
    assert.equal(f.api.RegistrationFinish(f.session, req, body).reason, 'PASSKEY_CHALLENGE_INVALID');
    const bad = f.registration(); bad.credentialId = w.b64(crypto.randomBytes(32));
    assert.equal(f.api.RegistrationFinish(f.session, req, bad).ok, false);
    assert.equal(f.api.RegistrationFinish(f.session, req, bad).reason, 'PASSKEY_CHALLENGE_INVALID');
});
test('Other RP credentials are never offered and missing stored RP is not inferred', () => {
    const f = fixture(), record = f.register(); record.rpId = 'evil.test';
    assert.equal(f.api.LoginBegin('admin', req).reason, 'PASSKEY_NOT_REGISTERED');
    delete record.rpId; assert.equal(f.api.LoginBegin('admin', req).reason, 'PASSKEY_NOT_REGISTERED');
});
test('A changed server RP/origin invalidates pending ceremonies', () => {
    const f = fixture(), record = f.register(), body = f.assertion(record);
    process.env.WEBAUTHN_RP_ID = 'new.example.test'; process.env.WEBAUTHN_ORIGIN = 'https://new.example.test';
    assert.equal(f.api.LoginFinish({ headers: { host: 'new.example.test' } }, body).reason, 'PASSKEY_CONTEXT_CHANGED');
});
test('Stored RP is rechecked at finish, not only at challenge creation', () => {
    const f = fixture(), record = f.register(), body = f.assertion(record); record.rpId = 'evil.test';
    assert.equal(f.api.LoginFinish(req, body).reason, 'PASSKEY_RP_INVALID');
});
test('Even a valid signature cannot authorize the wrong RP hash', () => {
    const f = fixture(), record = f.register(); assert.equal(f.api.LoginFinish(req, f.assertion(record, { auth: w.Auth('evil.test') })).reason, 'PASSKEY_RP_INVALID');
});
test('Signed origin changes or cross-origin assertions are refused', () => {
    const f = fixture(), record = f.register();
    for (const clientPatch of [{ origin: 'https://evil.test' }, { crossOrigin: true }, { topOrigin: 'https://admin.example.test' }])
        assert.equal(f.api.LoginFinish(req, f.assertion(record, { clientPatch })).ok, false);
});
test('Assertion AT flag and trailing bytes are rejected despite a valid signature', () => {
    const f = fixture(), record = f.register();
    assert.equal(f.api.LoginFinish(req, f.assertion(record, { auth: w.Auth('admin.example.test', 0, 69) })).reason, 'PASSKEY_ASSERTION_AT_FORBIDDEN');
    assert.equal(f.api.LoginFinish(req, f.assertion(record, { auth: Buffer.concat([w.Auth('admin.example.test'), Buffer.from([0])]) })).reason, 'PASSKEY_AUTH_DATA_TRAILING');
});
test('Wrong private key fails and cannot reuse the consumed challenge', () => {
    const f = fixture(), record = f.register(), pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const body = f.assertion(record, { privateKey: pair.privateKey });
    assert.equal(f.api.LoginFinish(req, body).reason, 'PASSKEY_SIGNATURE_INVALID');
    assert.equal(f.api.LoginFinish(req, body).reason, 'PASSKEY_CHALLENGE_INVALID'); assert.equal(f.saves(), 1);
});
test('Existing RP-bound credentials are not silently upgraded to verified registration', () => {
    const f = fixture(), record = f.register(); delete record.verificationVersion; delete record.backupEligible; delete record.backupState;
    assert.equal(f.api.LoginFinish(req, f.assertion(record)).ok, true); assert.equal(record.verificationVersion, undefined);
});
test('A later-added credential cannot answer an earlier allow-list challenge', () => {
    const f = fixture(), a = f.register(), body = f.assertion(a), b = f.register(); body.credentialId = b.credentialId;
    assert.equal(f.api.LoginFinish(req, body).reason, 'PASSKEY_CREDENTIAL_NOT_FOUND');
});
console.log(`PASSKEY VALIDATION SECURITY PASS: ${count} cases; real ES256 / synthetic authenticator / isolated storage`);
