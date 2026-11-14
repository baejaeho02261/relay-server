'use strict';

const crypto = require('node:crypto');

const HEADER_BYTES = 12;
const CHALLENGE_BYTES = 60;
const EVIDENCE_BYTES = 179;
const VERDICT_BYTES = 93;
const MAX_BOOT_LOG_BYTES = 16 * 1024 * 1024;
const PATHS = ['trust', 'driver', 'integrity'];
const ZERO_HEX = '0000000000000000';
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;
let lastSequence = 0n;

function Fail() {
  throw Object.assign(Error('SECURITY_NHW_EVIDENCE_INVALID'), { desktopError: true, status: 400 });
}

function Frame(kind, size) {
  const frame = Buffer.alloc(size);
  frame.write('NHWA', 0, 'ascii');
  frame.writeUInt16LE(1, 4);
  frame[6] = kind;
  frame.writeUInt32LE(size - HEADER_BYTES, 8);
  return frame;
}

function Issue(row) {
  const now = Date.now();
  if (!Number.isSafeInteger(row.createdAt) || row.createdAt <= 0 ||
      !Number.isSafeInteger(now) || now < row.createdAt) Fail();
  // Same-session epochs survive a routine server restart. The nested UInt64
  // sequence is time-seeded across restarts and strictly increasing locally.
  // A restart with a rolled-back clock cannot reset the client's replay guard.
  const candidate = BigInt(now) << 20n;
  const sequence = candidate > lastSequence ? candidate : lastSequence + 1n;
  if (sequence > 0xffffffffffffffffn) Fail();
  lastSequence = sequence;
  const frame = Frame(1, CHALLENGE_BYTES);
  frame.writeBigUInt64LE(BigInt(row.createdAt), 12);
  frame.writeBigUInt64LE(sequence, 20);
  let nonce;
  do { nonce = crypto.randomBytes(32); } while (nonce.every(byte => byte === 0));
  nonce.copy(frame, 28);
  return frame;
}

function ParseFrame(text, kind, size) {
  if (typeof text !== 'string' || text.length !== Math.ceil(size / 3) * 4) Fail();
  const frame = Buffer.from(text, 'base64');
  if (frame.length !== size || frame.toString('base64') !== text ||
      frame.toString('ascii', 0, 4) !== 'NHWA' || frame.readUInt16LE(4) !== 1 ||
      frame[6] !== kind || frame[7] !== 0 || frame.readUInt32LE(8) !== size - HEADER_BYTES) Fail();
  return frame;
}

function CheckResponses(responses, mask, frame) {
  if (!plain(responses) || Object.keys(responses).some(name => !PATHS.includes(name))) Fail();
  let count = 0;
  for (const [index, path] of PATHS.entries()) {
    const active = (mask & (1 << index)) !== 0;
    if (active !== Object.hasOwn(responses, path)) Fail();
    if (!active) continue;
    const item = responses[path];
    if (!plain(item) || Object.keys(item).sort().join(',') !== 'digest,sequence,tick') Fail();
    for (const field of ['sequence', 'tick', 'digest']) {
      if (typeof item[field] !== 'string' || !/^[a-f0-9]{16}$/.test(item[field])) Fail();
    }
    const producerDigest = frame.readBigUInt64LE(79 + 8 * index).toString(16).padStart(16, '0');
    if (item.sequence === ZERO_HEX || item.tick === ZERO_HEX ||
        item.digest === ZERO_HEX || item.digest !== producerDigest) Fail();
    count++;
  }
  return count;
}

function Evidence(value, challenge) {
  if (value.nhwEvidence === undefined) {
    if (value.nhwResponses !== undefined || value.nhwInvalidated !== undefined) Fail();
    return null;
  }
  if (!Buffer.isBuffer(challenge) || challenge.length !== CHALLENGE_BYTES) Fail();
  const frame = ParseFrame(value.nhwEvidence, 2, EVIDENCE_BYTES);
  if (!crypto.timingSafeEqual(frame.subarray(12, 60), challenge.subarray(12, 60))) Fail();
  const trust = frame[76];
  const mask = frame[77];
  const bootAvailable = frame[78];
  const tpmVersion = frame.readUInt32LE(103);
  const bootLogSize = frame.readUInt32LE(107);
  const bootLogDigest = frame.subarray(111, 143);
  if (trust > 3 || mask > 7 || bootAvailable > 1 || frame.readUInt32LE(175) !== 0 ||
      frame.subarray(60, 76).every(byte => byte === 0)) Fail();
  if (bootAvailable === 1) {
    if (bootLogSize < 1 || bootLogSize > MAX_BOOT_LOG_BYTES ||
        bootLogDigest.every(byte => byte === 0)) Fail();
  } else if (tpmVersion !== 0 || bootLogSize !== 0 || bootLogDigest.some(byte => byte !== 0)) Fail();

  // The upstream binding transcript places the availability byte after the
  // three response digests. The wire frame places it before those digests.
  const binding = crypto.createHash('sha256').update(frame.subarray(12, 78))
    .update(frame.subarray(79, 103)).update(frame.subarray(78, 79))
    .update(frame.subarray(103, 143)).digest();
  if (!crypto.timingSafeEqual(binding, frame.subarray(143, 175))) Fail();
  const votes = CheckResponses(value.nhwResponses, mask, frame);
  const invalidated = value.nhwInvalidated === true;
  if (value.nhwInvalidated !== undefined && (!invalidated || trust !== 3 || votes < 2)) Fail();

  // A signed client summary binds the bytes to the device/session proof. A
  // WBCL digest has no independent PCR quote or trust-chain verification here.
  return { frame, binding, invalidated };
}

function Verdict(evidence, accepted) {
  const frame = Frame(3, VERDICT_BYTES);
  evidence.frame.copy(frame, 12, 12, 60);
  evidence.binding.copy(frame, 60);
  frame[92] = accepted ? 1 : 0;
  return frame.toString('base64');
}

module.exports = { Issue, Evidence, Verdict };
