"use strict";
const crypto = require('crypto');
const state = require('../core/state');
const { Now, SafeField } = require('../core/utils');
const deadline = require('./desktopDeadline');
const data = require('./passkeyAuthData');
const CHALLENGE_MS = 5 * 60000, MAX_CHALLENGES = 4096;
const challenges = new Map();
const B64 = value => Buffer.from(value).toString('base64url');
const Buf = data.Binary;
function Body(value, fields) {
    return !!value && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).every(k => fields.includes(k));
}
function Context(req) { return require('./passkeyContext').Resolve(req, require('../web/webAuth').IsHttps(req)); }
function SameContext(item, req) {
    const current = Context(req);
    if (current.rpId !== item.rpId || current.origin !== item.origin) throw Error('PASSKEY_CONTEXT_CHANGED');
}
function Failure(error) {
    const reason = /^PASSKEY_[A-Z_]+$|^ADMIN_HTTPS_REQUIRED$/.test(error?.message || '') ? error.message : 'PASSKEY_VERIFICATION_FAILED';
    return { ok: false, reason, ...(/CONFIG/.test(reason) ? { status: 503 } : {}) };
}
function ChallengeActive(item) { return !!item && !deadline.Expired(item) && Now() >= item.createdAt; }
function NewChallenge(kind, role, sessionId, ctx) {
    Cleanup(); if (challenges.size >= MAX_CHALLENGES) return null;
    const id = `PKC-${crypto.randomBytes(10).toString('hex').toUpperCase()}`, challenge = B64(crypto.randomBytes(32)), bounds = deadline.After(CHALLENGE_MS);
    const item = { id, kind, role, sessionId: sessionId || '', challenge, ...ctx, createdAt: bounds.expiresAt - CHALLENGE_MS, ...bounds };
    challenges.set(id, item); return item;
}
function SaveCredentials() { if (require('../storage/database').SaveDatabase() === false) throw Error('PASSKEY_STORAGE_UNAVAILABLE'); }
function CheckClientData(item, value, type) { return require('./passkeyClientData').Check(item, value, type); }
function CredentialsForRole(role) { return [...state.production.passkeyCredentials.values()].filter(x => x.role === role && !x.revokedAt); }
function RegistrationBegin(session, req) {
    if (!session || session.role !== 'admin') return { ok: false, reason: 'ADMIN_REQUIRED' };
    try {
        const ctx = Context(req), item = NewChallenge('CREATE', 'admin', session.id, ctx);
        if (!item) return { ok: false, status: 503, reason: 'PASSKEY_CAPACITY' };
        return { ok: true, challengeId: item.id, publicKey: {
            challenge: item.challenge, rp: { name: 'Relay Operations', id: item.rpId },
            user: { id: B64(Buffer.from(`admin:${session.id}`)), name: 'relay-admin', displayName: 'Relay Administrator' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: CHALLENGE_MS, attestation: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }
        } };
    } catch (error) { return Failure(error); }
}
function RegistrationFinish(session, req, body) {
    if (!Body(body, ['challengeId', 'clientDataJSON', 'attestationObject', 'authenticatorData', 'publicKeySpki', 'credentialId', 'name'])) return { ok: false, reason: 'PASSKEY_INPUT_INVALID' };
    const item = challenges.get(String(body.challengeId || ''));
    if (!ChallengeActive(item) || item.kind !== 'CREATE' || !session || session.role !== 'admin' || item.sessionId !== session.id) return { ok: false, reason: 'PASSKEY_CHALLENGE_INVALID' };
    // One verification attempt per challenge. Storage failure cannot resurrect it.
    challenges.delete(item.id);
    try {
        SameContext(item, req); CheckClientData(item, body.clientDataJSON, 'webauthn.create');
        if (!Object.hasOwn(body, 'attestationObject')) throw Error('PASSKEY_ATTESTATION_REQUIRED');
        const auth = data.Registration(item, body), credentialId = B64(auth.credentialId);
        const id = crypto.createHash('sha256').update(auth.credentialId).digest('hex').slice(0, 24).toUpperCase();
        if (state.production.passkeyCredentials.has(id) || [...state.production.passkeyCredentials.values()].some(x => x.credentialId === credentialId)) throw Error('PASSKEY_ALREADY_REGISTERED');
        const record = { id, role: 'admin', credentialId, publicKeySpki: B64(auth.publicKeySpki), rpId: item.rpId,
            name: SafeField(body.name || `Admin key ${id.slice(-6)}`).slice(0, 64), createdAt: Now(), lastUsedAt: 0,
            signCount: auth.signCount, backupEligible: auth.backupEligible, backupState: auth.backupState,
            verificationVersion: 2, revokedAt: 0 };
        if (!ChallengeActive(item)) throw Error('PASSKEY_CHALLENGE_INVALID');
        SameContext(item, req);
        state.production.passkeyCredentials.set(id, record);
        try { SaveCredentials(); } catch (error) { state.production.passkeyCredentials.delete(id); throw error; }
        require('../storage/audit').LogEvent('PASSKEY_REGISTERED', `${id} / admin`);
        return { ok: true, credential: { ...record, publicKeySpki: undefined } };
    } catch (error) { return Failure(error); }
}
function LoginBegin(role, req, session = null) {
    role = String(role || '').toLowerCase();
    try {
        const ctx = Context(req), creds = CredentialsForRole(role).filter(x => x.rpId === ctx.rpId);
        if (!creds.length) return { ok: false, reason: 'PASSKEY_NOT_REGISTERED' };
        if (session && (session.role!==role || !require('../web/webAuth').IsSessionActive(session))) throw Error('PASSKEY_SESSION_INVALID');
        const item = NewChallenge(session ? 'REAUTH' : 'GET', role, session?.id || '', ctx);
        if (!item) return { ok: false, status: 503, reason: 'PASSKEY_CAPACITY' };
        item.allowedIds = new Set(creds.map(x => x.id));
        return { ok: true, challengeId: item.id, publicKey: { challenge: item.challenge, rpId: item.rpId,
            allowCredentials: creds.map(x => ({ type: 'public-key', id: x.credentialId })), timeout: CHALLENGE_MS, userVerification: 'required' } };
    } catch (error) { return Failure(error); }
}
function LoginFinish(req, body, session = null) {
    if (!Body(body, ['challengeId', 'credentialId', 'clientDataJSON', 'authenticatorData', 'signature'])) return { ok: false, reason: 'PASSKEY_INPUT_INVALID' };
    const item = challenges.get(String(body.challengeId || ''));
    if (!ChallengeActive(item) || item.kind !== (session ? 'REAUTH' : 'GET') || session && (item.sessionId!==session.id || item.role!==session.role || !require('../web/webAuth').IsSessionActive(session))) return { ok: false, reason: 'PASSKEY_CHALLENGE_INVALID' };
    challenges.delete(item.id);
    try {
        SameContext(item, req);
        const credentialId = B64(Buf(body.credentialId, 1023));
        const cred = CredentialsForRole(item.role).find(x => x.credentialId === credentialId && item.allowedIds.has(x.id));
        if (!cred) throw Error('PASSKEY_CREDENTIAL_NOT_FOUND');
        if (cred.rpId !== item.rpId) throw Error('PASSKEY_RP_INVALID');
        const clientData = CheckClientData(item, body.clientDataJSON, 'webauthn.get');
        const auth = data.AuthData(item, Buf(body.authenticatorData, 8192), false);
        if (typeof cred.backupEligible === 'boolean' && cred.backupEligible !== auth.backupEligible) throw Error('PASSKEY_BACKUP_FLAGS_INVALID');
        const signed = Buffer.concat([auth.buffer, crypto.createHash('sha256').update(clientData.bytes).digest()]);
        const key = crypto.createPublicKey({ key: Buf(cred.publicKeySpki, 1024), type: 'spki', format: 'der' });
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw Error('PASSKEY_KEY_TYPE_INVALID');
        if (!crypto.verify('sha256', signed, key, Buf(body.signature, 144, 8))) throw Error('PASSKEY_SIGNATURE_INVALID');
        const oldCount = cred.signCount === undefined ? 0 : cred.signCount;
        if (!Number.isInteger(oldCount) || oldCount < 0 || oldCount > 0xffffffff) throw Error('PASSKEY_COUNTER_INVALID');
        // Keep the existing positive-counter rollback policy; always-zero works.
        if ((oldCount || auth.signCount) && auth.signCount <= oldCount) throw Error('PASSKEY_COUNTER_REPLAY');
        if (!ChallengeActive(item)) throw Error('PASSKEY_CHALLENGE_INVALID');
        SameContext(item, req);
        if (session && !require('../web/webAuth').IsSessionActive(session)) throw Error('PASSKEY_SESSION_INVALID');
        if (state.production.passkeyCredentials.get(cred.id) !== cred || cred.revokedAt || cred.role !== item.role || cred.rpId !== item.rpId) throw Error('PASSKEY_CREDENTIAL_NOT_FOUND');
        const previous = { ...cred };
        cred.signCount = auth.signCount; cred.lastUsedAt = Now(); cred.backupEligible = auth.backupEligible; cred.backupState = auth.backupState;
        try { SaveCredentials(); } catch (error) {
            for (const key of Object.keys(cred)) if (!Object.hasOwn(previous, key)) delete cred[key];
            Object.assign(cred, previous); throw error;
        }
        require('../storage/audit').LogEvent('PASSKEY_AUTH', `${cred.id} / ${item.role}`);
        return { ok: true, role: item.role, credentialId: cred.id };
    } catch (error) { return Failure(error); }
}
function List() { return [...state.production.passkeyCredentials.values()].map(x => ({ id: x.id, role: x.role, name: x.name, createdAt: x.createdAt, lastUsedAt: x.lastUsedAt, signCount: x.signCount, revokedAt: x.revokedAt || 0 })); }
function Revoke(id, actor) {
    const item = state.production.passkeyCredentials.get(String(id || '').toUpperCase());
    if (!item) return { ok: false, reason: 'PASSKEY_NOT_FOUND' };
    const previous = { ...item }; item.revokedAt = Now(); item.revokedBy = SafeField(actor).slice(0, 64);
    try { SaveCredentials(); } catch (error) {
        for (const key of Object.keys(item)) if (!Object.hasOwn(previous, key)) delete item[key];
        Object.assign(item, previous); return Failure(error);
    }
    return { ok: true };
}
function Cleanup() { for (const [k, v] of challenges) if (!ChallengeActive(v)) challenges.delete(k); }
module.exports = { RegistrationBegin, RegistrationFinish, LoginBegin, LoginFinish, List, Revoke, Cleanup };
