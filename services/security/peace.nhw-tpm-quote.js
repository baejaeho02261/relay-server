'use strict';

// TPM 2.0 Part 2 TPMS_ATTEST / TPMS_QUOTE_INFO and Part 3 TPM2_Quote.
// Restricted AK provenance comes only from the earlier EK chain verification
// AND successful ActivateCredential transaction for this exact role/session.
// A valid quote authenticates selected PCR bytes, not their acceptability or
// the completeness of a client WBCL. No boot-health decision is inferred here.
const crypto = require('node:crypto');
const tpm = require('../devices/peace.desktop-tpm-attestation');
const DOMAIN = Buffer.from('COZY-NHW-PCR-QUOTE-V1\0', 'ascii');
const PCR_SELECTION = Buffer.from([0xff, 0, 0]);
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;
const hash = value => crypto.createHash('sha256').update(value).digest();

function Fail(code = 'SECURITY_NHW_QUOTE_INVALID') {
  throw Object.assign(Error(code), { desktopError: true, status: 403 });
}

function QualifyingDigest(frame) {
  if (!Buffer.isBuffer(frame) || frame.length !== 179 ||
      frame.toString('ascii', 0, 4) !== 'NHWA' || frame.readUInt16LE(4) !== 1 ||
      frame[6] !== 2 || frame[7] !== 0 || frame.readUInt32LE(8) !== 167) Fail();
  return crypto.createHash('sha256').update(DOMAIN).update(frame).digest();
}

function Verify(quote, frame, anchor) {
  if (!plain(quote) || Object.keys(quote).sort().join(',') !== 'attest,pcrs,signature,version' ||
      quote.version !== 1 || !plain(anchor)) Fail();
  let attest, signature, pcrs, expected;
  try {
    const ak = tpm.PublicArea(tpm.B64(anchor.akPublic, 32, 2048), 'AK');
    const signer = tpm.B64(anchor.akQualifiedName, 34, 34);
    if (signer.readUInt16BE() !== 11) Fail();
    attest = tpm.B64(quote.attest, 100, 2048);
    signature = tpm.B64(quote.signature, 262, 262);
    pcrs = tpm.B64(quote.pcrs, 256, 256);
    expected = QualifyingDigest(frame);
    const r = new tpm.Reader(attest, 2048);
    if (r.u32() !== 0xff544347 || r.u16() !== 0x8018) Fail('SECURITY_NHW_QUOTE_TYPE');
    if (!tpm.Equal(r.sized(68), signer)) Fail('SECURITY_NHW_QUOTE_SIGNER');
    if (!tpm.Equal(r.sized(64), expected)) Fail('SECURITY_NHW_QUOTE_BINDING');
    r.bytes(8); // clock
    r.u32(); // resetCount
    r.u32(); // restartCount
    const clockSafe = r.u8();
    if (clockSafe > 1) Fail('SECURITY_NHW_QUOTE_CLOCK');
    r.bytes(8); // firmwareVersion
    if (r.u32() !== 1 || r.u16() !== 11 || r.u8() !== 3 ||
        !tpm.Equal(r.bytes(3), PCR_SELECTION)) Fail('SECURITY_NHW_QUOTE_SELECTION');
    const quotedDigest = r.sized(32);
    r.end();
    if (!tpm.Equal(quotedDigest, hash(pcrs))) Fail('SECURITY_NHW_QUOTE_PCR_DIGEST');
    const s = new tpm.Reader(signature, 262);
    if (s.u16() !== 20 || s.u16() !== 11) Fail('SECURITY_NHW_QUOTE_ALGORITHM');
    const rawSignature = s.sized(256);
    s.end();
    if (rawSignature.length !== 256 || !crypto.verify('sha256', attest,
      { key: ak.key, padding: crypto.constants.RSA_PKCS1_PADDING }, rawSignature))
      Fail('SECURITY_NHW_QUOTE_SIGNATURE');
    // safe=0 is a valid, signed TPM uncertainty about clock continuity. It
    // is not a forged quote and must not become a security-session incident.
    return { status: clockSafe ? 'VERIFIED' : 'UNKNOWN',
      ...(clockSafe ? {} : { reason: 'TPM_CLOCK_UNSAFE' }), clockSafe: !!clockSafe,
      pcrs: [0, 1, 2, 3, 4, 5, 6, 7], bank: 'SHA256',
      scope: 'TPM_QUOTE_ONLY', bootHealthVerified: false };
  } catch (error) {
    if (/^SECURITY_NHW_QUOTE_/.test(error.message)) throw error;
    Fail();
  } finally {
    attest?.fill(0); signature?.fill(0); pcrs?.fill(0); expected?.fill(0);
  }
}

function VerifySession(quote, frame, row, stage) {
  // Unavailable TPM or PCR bank is UNKNOWN, never an incident or an invented
  // hardware claim. Existing session/device policy still applies independently.
  if (quote === undefined) return { status: 'UNAVAILABLE', scope: 'NONE', bootHealthVerified: false };
  if (!['A', 'B', 'O'].includes(stage) || !row) Fail();
  const db = require('../bootstrap/peace.desktop-bootstrap-store').Load();
  const identity = require('../devices/peace.desktop-device-identity');
  identity.AssertSession(row, stage);
  const state = identity.State(db);
  const current = stage === 'O' ? db.overlays[row.id] : db.flows[row.id];
  const proof = current?.deviceIdentityProofs?.[stage];
  const enrolled = state.enrollments[proof?.enrollmentId];
  const now = Date.now();
  const revoked = new Set(state.trust?.revokedCertificateSha256 || []);
  if (!proof || !enrolled || enrolled.status !== 'ACTIVE' ||
      enrolled.assurance !== 'TPM_KEY_ATTESTED' || proof.appKeyId !== row.deviceId ||
      proof.policyRevision !== state.revision ||
      proof.epoch !== require('../recovery/peace.desktop-recovery').Epoch(db) ||
      !Number.isSafeInteger(proof.nhwAttestedUntil) || proof.nhwAttestedUntil <= now ||
      !state.trust || state.trust.validUntil <= now ||
      revoked.has(proof.nhwEkLeafSha256) || revoked.has(proof.nhwEkRootSha256) ||
      !state.trust.roots.some(pem => hash(new crypto.X509Certificate(pem).raw).toString('hex') === proof.nhwEkRootSha256))
    Fail('SECURITY_NHW_QUOTE_UNENROLLED');
  return Verify(quote, frame, { akPublic: proof.nhwAkPublic,
    akQualifiedName: proof.nhwAkQualifiedName });
}

module.exports = { QualifyingDigest, Verify, VerifySession };
