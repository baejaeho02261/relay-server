"use strict";
const crypto = require('node:crypto');
const b64 = x => Buffer.from(x).toString('base64url');
function head(type, n) {
    if (n < 24) return Buffer.from([(type << 5) | n]);
    if (n < 256) return Buffer.from([(type << 5) | 24, n]);
    const b = Buffer.alloc(3); b[0] = (type << 5) | 25; b.writeUInt16BE(n, 1); return b;
}
function Cbor(v) {
    if (Number.isInteger(v)) return v < 0 ? head(1, -1 - v) : head(0, v);
    if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
    if (typeof v === 'string') { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
    if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, v]) => [Cbor(k), Cbor(v)])]);
    if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(Cbor)]);
    if (v === true) return Buffer.from([0xf5]); if (v === false) return Buffer.from([0xf4]);
    throw Error('FIXTURE_CBOR_UNSUPPORTED');
}
function KeyMap(publicKey) {
    const jwk = publicKey.export({ format: 'jwk' });
    return new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]);
}
function Auth(rpId, signCount = 0, flags = 5) {
    const b = Buffer.alloc(37); crypto.createHash('sha256').update(rpId).digest().copy(b);
    b[32] = flags; b.writeUInt32BE(signCount, 33); return b;
}
function Registration(rpId, publicKey, id = crypto.randomBytes(32), signCount = 0, opts = {}) {
    const credLength = Buffer.alloc(2); credLength.writeUInt16BE(id.length);
    const auth = Buffer.concat([Auth(rpId, signCount, opts.flags ?? 69), Buffer.alloc(16), credLength, id,
        opts.coseBytes || Cbor(opts.cose || KeyMap(publicKey)), opts.extensionBytes || Buffer.alloc(0)]);
    const attestation = Cbor(new Map([['fmt', opts.fmt || 'none'], ['authData', auth], ['attStmt', opts.attStmt || new Map()]]));
    return { credentialId: b64(id), publicKeySpki: b64(publicKey.export({ type: 'spki', format: 'der' })),
        authenticatorData: b64(auth), attestationObject: b64(attestation) };
}
module.exports = { b64, Cbor, KeyMap, Auth, Registration };
