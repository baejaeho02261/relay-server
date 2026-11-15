"use strict";
// WebAuthn 6.1/6.5.1: bounded byte parsing, not a general purpose CBOR library.
// Cryptography remains Node/OpenSSL; no handwritten signature arithmetic.
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function Binary(value, max = 16384, min = 1) {
    if (typeof value !== 'string' || !value || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('PASSKEY_BINARY_INVALID');
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length < min || bytes.length > max || bytes.toString('base64url') !== value) throw Error('PASSKEY_BINARY_INVALID');
    return bytes;
}
function Cbor(bytes, offset = 0) {
    if (!Buffer.isBuffer(bytes) || bytes.length > 16384 || !Number.isInteger(offset) || offset < 0 || offset >= bytes.length) throw Error('PASSKEY_CBOR_INVALID');
    let pos = offset, nodes = 0;
    function need(n) { if (!Number.isSafeInteger(n) || n < 0 || n > bytes.length - pos) throw Error('PASSKEY_CBOR_TRUNCATED'); }
    function read(depth) {
        if (++nodes > 512 || depth > 8) throw Error('PASSKEY_CBOR_LIMIT');
        need(1); const head = bytes[pos++], major = head >> 5, ai = head & 31;
        if (major === 7) {
            if (ai === 20) return false;
            if (ai === 21) return true;
            if (ai === 22) return null;
            throw Error('PASSKEY_CBOR_TYPE_UNSUPPORTED');
        }
        if (major === 6 || ai >= 27) throw Error('PASSKEY_CBOR_TYPE_UNSUPPORTED');
        let n = ai;
        if (ai >= 24) {
            const size = 1 << (ai - 24); need(size);
            n = bytes.readUIntBE(pos, size); pos += size;
            if (n < (size === 1 ? 24 : size === 2 ? 256 : 65536)) throw Error('PASSKEY_CBOR_NONCANONICAL');
        }
        if (major === 0) return n;
        if (major === 1) return -1 - n;
        if (major === 2 || major === 3) {
            need(n); const value = bytes.subarray(pos, pos + n); pos += n;
            if (major === 2) return value;
            try { return utf8.decode(value); } catch (_) { throw Error('PASSKEY_CBOR_UTF8'); }
        }
        if (n > 128) throw Error('PASSKEY_CBOR_LIMIT');
        if (major === 4) { const value = []; for (let i = 0; i < n; i++) value.push(read(depth + 1)); return value; }
        if (major === 5) {
            const value = new Map();
            for (let i = 0; i < n; i++) {
                const key = read(depth + 1);
                if (!(typeof key === 'string' || Number.isInteger(key)) || value.has(key)) throw Error('PASSKEY_CBOR_MAP_KEY_INVALID');
                value.set(key, read(depth + 1));
            }
            return value;
        }
        throw Error('PASSKEY_CBOR_TYPE_UNSUPPORTED');
    }
    const value = read(0); return { value, end: pos };
}
function PublicKey(cose) {
    const labels = [1, 3, -1, -2, -3];
    if (!(cose instanceof Map) || cose.size !== labels.length || labels.some(x => !cose.has(x)) ||
        cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) throw Error('PASSKEY_KEY_TYPE_INVALID');
    const x = cose.get(-2), y = cose.get(-3);
    if (!Buffer.isBuffer(x) || x.length !== 32 || !Buffer.isBuffer(y) || y.length !== 32) throw Error('PASSKEY_KEY_TYPE_INVALID');
    const point = Buffer.concat([Buffer.from([4]), x, y]);
    try { crypto.ECDH.convertKey(point, 'prime256v1', undefined, undefined, 'uncompressed'); }
    catch (_) { throw Error('PASSKEY_KEY_POINT_INVALID'); }
    const der = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex'), x, y]);
    crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
    return der;
}
function AuthData(item, bytes, registration) {
    if (!Buffer.isBuffer(bytes) || bytes.length < 37 || bytes.length > 8192) throw Error('PASSKEY_AUTH_DATA_INVALID');
    if (!crypto.timingSafeEqual(bytes.subarray(0, 32), crypto.createHash('sha256').update(item.rpId).digest())) throw Error('PASSKEY_RP_INVALID');
    const flags = bytes[32];
    if (!(flags & 1) || !(flags & 4)) throw Error('PASSKEY_USER_VERIFICATION_REQUIRED');
    if ((flags & 16) && !(flags & 8)) throw Error('PASSKEY_BACKUP_FLAGS_INVALID');
    const at = !!(flags & 64), ed = !!(flags & 128);
    if (at !== registration) throw Error(registration ? 'PASSKEY_ATTESTED_DATA_REQUIRED' : 'PASSKEY_ASSERTION_AT_FORBIDDEN');
    let pos = 37, credentialId, publicKeySpki;
    if (registration) {
        if (bytes.length < 55) throw Error('PASSKEY_AUTH_DATA_INVALID');
        const size = bytes.readUInt16BE(53); pos = 55;
        if (size < 1 || size > 1023 || size > bytes.length - pos) throw Error('PASSKEY_CREDENTIAL_INVALID');
        credentialId = bytes.subarray(pos, pos + size); pos += size;
        const key = Cbor(bytes, pos); pos = key.end; publicKeySpki = PublicKey(key.value);
    }
    if (ed) {
        const extensions = Cbor(bytes, pos); pos = extensions.end;
        if (!(extensions.value instanceof Map) || [...extensions.value.keys()].some(k => typeof k !== 'string')) throw Error('PASSKEY_EXTENSIONS_INVALID');
        // No extension is requested or used as an authorization factor here.
    }
    if (pos !== bytes.length) throw Error('PASSKEY_AUTH_DATA_TRAILING');
    return { buffer: bytes, flags, signCount: bytes.readUInt32BE(33), credentialId, publicKeySpki,
        backupEligible: !!(flags & 8), backupState: !!(flags & 16) };
}
function Registration(item, body) {
    const raw = Binary(body.attestationObject), attestation = Cbor(raw);
    const map = attestation.value;
    if (attestation.end !== raw.length || !(map instanceof Map) || map.size !== 3 ||
        !['fmt', 'authData', 'attStmt'].every(k => map.has(k))) throw Error('PASSKEY_ATTESTATION_INVALID');
    if (map.get('fmt') !== 'none' || !(map.get('attStmt') instanceof Map) || map.get('attStmt').size !== 0) throw Error('PASSKEY_ATTESTATION_FORMAT_UNSUPPORTED');
    const auth = AuthData(item, map.get('authData'), true);
    if (!auth.credentialId.equals(Binary(body.credentialId, 1023))) throw Error('PASSKEY_CREDENTIAL_MISMATCH');
    // getAuthenticatorData()/getPublicKey() remain optional compatibility fields;
    // neither one is trusted as the authoritative credential source.
    if (Object.hasOwn(body, 'authenticatorData') && !auth.buffer.equals(Binary(body.authenticatorData, 8192))) throw Error('PASSKEY_AUTH_DATA_MISMATCH');
    if (Object.hasOwn(body, 'publicKeySpki') && !auth.publicKeySpki.equals(Binary(body.publicKeySpki, 1024))) throw Error('PASSKEY_PUBLIC_KEY_MISMATCH');
    return auth;
}
module.exports = { Binary, Cbor, AuthData, Registration };
