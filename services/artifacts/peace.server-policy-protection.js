'use strict';
// Public artifact-to-policy binding. This module never encrypts or loads native
// code. Only public commitments enter the PE slot; bounded IR stays in the
// separate serverPolicy record. A slot is NOT authorization or a signature.
// Callers must authenticate and authorize a fresh server operation before
// EvaluateServerPolicy; this module exposes no HTTP route or registration API.
const crypto = require('node:crypto'), fs = require('node:fs');
const vm = require('./peace.cozy-protection-engine');
const ENGINE = 'COZY_SERVER_POLICY_V2', SLOT_BYTES = 4096, HEADER_BYTES = 160, TAIL_OFFSET = 4080;
const HEAD = Buffer.from('COZY-POLICY-V2\0\0', 'ascii');
const TAIL = Buffer.from('COZY-POLEND-V2\0\0', 'ascii');
const LEGACY_HEAD = Buffer.from('COZY-VM-SLOT-V1\0', 'ascii');
const LEGACY_TAIL = Buffer.from('COZY-VM-END--V1\0', 'ascii');
const MAX_FILE = 64 * 1024 * 1024, MAX_FUNCTIONS = 16, MAX_PROFILE_BYTES = 65536;
const HASH = /^[a-f0-9]{128}$/, ID = /^[a-f0-9]{64}$/;
const FORMAT = Object.freeze({ version: 2, slotBytes: SLOT_BYTES, headerBytes: HEADER_BYTES,
  trailerOffset: TAIL_OFFSET, roleOffset: 24, stateOffset: 25, policyFormatOffset: 28,
  functionCountOffset: 32, maxStepsOffset: 36, policyIdOffset: 40, policyIdBytes: 32,
  policySha512Offset: 72, policySha512Bytes: 64, zeroPaddingOffset: 136,
  policyFormat: 1, maxSteps: vm.MAX_STEPS, headHex: HEAD.toString('hex'), tailHex: TAIL.toString('hex') });
const sha = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
// A receipt pins both this serializer and the bounded compiler/interpreter it
// reuses. Changing either implementation creates a different tool identity.
const TOOL_SHA512 = sha(Buffer.from('COZY-SERVER-POLICY-TOOL-V2\n' + sha(fs.readFileSync(__filename)) + '\n' +
  sha(fs.readFileSync(require.resolve('./peace.cozy-protection-engine'))) + '\n', 'utf8'));
const plain = value => !!value && Object.getPrototypeOf(value) === Object.prototype;
function Fail(code, status = 400) {
  const error = Error('COZY_SERVER_POLICY_' + code);
  error.desktopError = true; error.status = status; throw error;
}
function Exact(value, fields, code) {
  if (!plain(value) || Object.keys(value).length !== fields.length || fields.some(key => !Object.hasOwn(value, key))) Fail(code);
}
function Role(role) {
  const value = { A: 1, B: 2, O: 3 }[role];
  if (!value || typeof role !== 'string' || role.length !== 1) Fail('ROLE_INVALID');
  return value;
}
function PolicyId(role, policySha512) {
  Role(role); if (typeof policySha512 !== 'string' || !HASH.test(policySha512)) Fail('COMMITMENT_INVALID');
  return crypto.createHash('sha256').update('COZY-SERVER-POLICY-ID-V2\n' + role + '\n' + policySha512, 'utf8').digest('hex');
}
function ProgramHash(role, bytes) {
  return crypto.createHash('sha512').update('COZY-SERVER-POLICY-PROGRAM-V2\n' + role + '\n', 'utf8').update(bytes).digest('hex');
}
function ParsePE(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 512 || bytes.length > MAX_FILE || bytes.readUInt16LE(0) !== 0x5a4d) Fail('PE_INVALID');
  const pe = bytes.readUInt32LE(60);
  if (pe < 64 || pe + 24 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550 || bytes.readUInt16LE(pe + 4) !== 0x8664) Fail('PE_INVALID');
  const count = bytes.readUInt16LE(pe + 6), optionalSize = bytes.readUInt16LE(pe + 20), flags = bytes.readUInt16LE(pe + 22);
  const optional = pe + 24, table = optional + optionalSize;
  if (count < 1 || count > 96 || optionalSize < 112 || table + count * 40 > bytes.length ||
      !(flags & 2) || (flags & 0x2000) || bytes.readUInt16LE(optional) !== 0x20b) Fail('PE_INVALID');
  const imageSize = bytes.readUInt32LE(optional + 56), headers = bytes.readUInt32LE(optional + 60);
  const entry = bytes.readUInt32LE(optional + 16), directories = bytes.readUInt32LE(optional + 108), sections = [];
  if (headers < table + count * 40 || headers > bytes.length || !imageSize || !entry || entry >= imageSize ||
      directories > 16 || 112 + directories * 8 > optionalSize) Fail('PE_INVALID');
  let executableEntry = false;
  for (let n = 0; n < count; n++) {
    const p = table + n * 40, rva = bytes.readUInt32LE(p + 12), virtualSize = bytes.readUInt32LE(p + 8);
    const size = bytes.readUInt32LE(p + 16), offset = bytes.readUInt32LE(p + 20), attributes = bytes.readUInt32LE(p + 36);
    const span = Math.max(size, virtualSize);
    if (!rva || !span || rva + span > imageSize || size && (offset < headers || offset + size > bytes.length) ||
        sections.some(s => rva < s.rva + s.span && rva + span > s.rva || size && s.size && offset < s.offset + s.size && offset + size > s.offset)) Fail('PE_INVALID');
    sections.push({ rva, virtualSize, size, offset, span, attributes });
    if ((attributes & 0x20000000) && entry >= rva && entry < rva + size) executableEntry = true;
  }
  if (!executableEntry) Fail('PE_INVALID');
  let certificateOffset = 0, certificateSize = 0;
  if (directories >= 5) {
    certificateOffset = bytes.readUInt32LE(optional + 144); certificateSize = bytes.readUInt32LE(optional + 148);
    if ((certificateOffset === 0) !== (certificateSize === 0) || certificateOffset &&
        (certificateOffset % 8 || certificateSize < 8 || certificateOffset + certificateSize > bytes.length ||
         certificateOffset < Math.max(...sections.map(s => s.offset + s.size)))) Fail('PE_INVALID');
  }
  return { sections, signed: !!certificateOffset };
}
function Candidates(bytes, head, tail, headerBytes) {
  const candidates = new Set();
  for (let p = bytes.indexOf(head); p >= 0; p = bytes.indexOf(head, p + 1)) {
    if (p + SLOT_BYTES <= bytes.length && (bytes.readUInt16LE(p + 18) === headerBytes &&
        bytes.readUInt32LE(p + 20) === SLOT_BYTES || bytes.subarray(p + TAIL_OFFSET, p + SLOT_BYTES).equals(tail))) candidates.add(p);
    if (candidates.size > 1) break;
  }
  for (let p = bytes.indexOf(tail); p >= 0; p = bytes.indexOf(tail, p + 1)) {
    const start = p - TAIL_OFFSET;
    if (start >= 0 && (bytes.subarray(start, start + 16).equals(head) ||
        bytes.readUInt16LE(start + 18) === headerBytes && bytes.readUInt32LE(start + 20) === SLOT_BYTES)) candidates.add(start);
    if (candidates.size > 1) break;
  }
  return candidates;
}
function FindSlot(bytes, pe) {
  if (Candidates(bytes, LEGACY_HEAD, LEGACY_TAIL, 128).size) Fail('LEGACY_FORMAT_REJECTED');
  const candidates = Candidates(bytes, HEAD, TAIL, HEADER_BYTES);
  if (candidates.size > 1) Fail('SLOT_DUPLICATE');
  if (!candidates.size) {
    // A recognizable marker that is truncated or structurally inconsistent
    // cannot silently downgrade to a format-free legacy artifact.
    if (bytes.includes(HEAD) || bytes.includes(TAIL)) Fail('SLOT_INVALID');
    return null;
  }
  const offset = [...candidates][0], slot = bytes.subarray(offset, offset + SLOT_BYTES);
  const section = pe.sections.find(s => offset >= s.offset && offset + SLOT_BYTES <= s.offset + s.size &&
    offset - s.offset + SLOT_BYTES <= (s.virtualSize || s.size));
  if (!section || !(section.attributes & 0x40) || !(section.attributes & 0x40000000) || (section.attributes & 0x220000a0)) Fail('SLOT_MAPPING_INVALID');
  if (slot.length !== SLOT_BYTES || !slot.subarray(0, 16).equals(HEAD) || !slot.subarray(TAIL_OFFSET).equals(TAIL) ||
      slot.readUInt16LE(16) !== 2 || slot.readUInt16LE(18) !== HEADER_BYTES || slot.readUInt32LE(20) !== SLOT_BYTES ||
      slot.readUInt16LE(26) !== 0 || slot.readUInt32LE(28) !== 1 || slot.readUInt32LE(36) !== vm.MAX_STEPS ||
      slot.subarray(136, TAIL_OFFSET).some(x => x !== 0)) Fail('SLOT_INVALID');
  const state = slot[25], role = { 1: 'A', 2: 'B', 3: 'O' }[slot[24]], count = slot.readUInt32LE(32);
  if (state === 0) {
    if (slot[24] !== 0 || count !== 0 || slot.subarray(40, 136).some(x => x !== 0)) Fail('SLOT_INVALID');
  } else {
    if (state !== 1 || !role || count < 1 || count > MAX_FUNCTIONS) Fail('SLOT_INVALID');
    const policySha512 = slot.subarray(72, 136).toString('hex'), policyId = slot.subarray(40, 72).toString('hex');
    if (!slot.subarray(72, 136).some(x => x !== 0) || policyId !== PolicyId(role, policySha512)) Fail('COMMITMENT_INVALID');
  }
  return { offset, slot, state, role: role || null, count };
}
function CreateUnsealedSlot() {
  const slot = Buffer.alloc(SLOT_BYTES); HEAD.copy(slot); TAIL.copy(slot, TAIL_OFFSET);
  slot.writeUInt16LE(2, 16); slot.writeUInt16LE(HEADER_BYTES, 18); slot.writeUInt32LE(SLOT_BYTES, 20);
  slot.writeUInt32LE(1, 28); slot.writeUInt32LE(vm.MAX_STEPS, 36); return slot;
}
function Metadata(found) {
  return { engine: ENGINE, version: 2, state: found.state ? 'BOUND' : 'UNSEALED', role: found.role,
    slotBytes: SLOT_BYTES, functionCount: found.count,
    policyId: found.state ? found.slot.subarray(40, 72).toString('hex') : null,
    policySha512: found.state ? found.slot.subarray(72, 136).toString('hex') : null,
    execution: 'SERVER_ONLY', authenticationRequired: true, slotContainsSecret: false,
    clientBytecode: false, windowsVerified: false, arbitraryDelphiTranslation: false };
}
function ValidateMetadata(value) {
  Exact(value, ['engine', 'version', 'state', 'role', 'slotBytes', 'functionCount', 'policyId', 'policySha512',
    'execution', 'authenticationRequired', 'slotContainsSecret', 'clientBytecode', 'windowsVerified', 'arbitraryDelphiTranslation'], 'METADATA_INVALID');
  if (value.engine !== ENGINE || value.version !== 2 || value.slotBytes !== SLOT_BYTES || value.execution !== 'SERVER_ONLY' ||
      value.authenticationRequired !== true || value.slotContainsSecret !== false || value.clientBytecode !== false ||
      value.windowsVerified !== false || value.arbitraryDelphiTranslation !== false) Fail('METADATA_INVALID');
  if (value.state === 'UNSEALED') {
    if (value.role !== null || value.functionCount !== 0 || value.policyId !== null || value.policySha512 !== null) Fail('METADATA_INVALID');
  } else if (value.state !== 'BOUND' || !['A', 'B', 'O'].includes(value.role) ||
      !Number.isInteger(value.functionCount) || value.functionCount < 1 || value.functionCount > MAX_FUNCTIONS ||
      typeof value.policyId !== 'string' || !ID.test(value.policyId) || typeof value.policySha512 !== 'string' ||
      !HASH.test(value.policySha512) || value.policySha512 === '0'.repeat(128) || value.policyId !== PolicyId(value.role, value.policySha512)) Fail('METADATA_INVALID');
  return value;
}
function Inspect(bytes) {
  const pe = ParsePE(bytes), found = FindSlot(bytes, pe); return found ? Metadata(found) : null;
}
function OpenServerPolicy(value) {
  Exact(value, ['version', 'role', 'policyId', 'policySha512', 'functionCount', 'maxSteps', 'programBase64'], 'RECORD_INVALID');
  if (value.version !== 2 || !['A', 'B', 'O'].includes(value.role) || typeof value.policyId !== 'string' || !ID.test(value.policyId) ||
      typeof value.policySha512 !== 'string' || !HASH.test(value.policySha512) || value.maxSteps !== vm.MAX_STEPS ||
      !Number.isInteger(value.functionCount) || value.functionCount < 1 || value.functionCount > MAX_FUNCTIONS ||
      typeof value.programBase64 !== 'string' || value.programBase64.length < 24 ||
      value.programBase64.length > 4 * Math.ceil(vm.MAX_PROGRAM / 3) || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.programBase64)) Fail('RECORD_INVALID');
  const program = Buffer.from(value.programBase64, 'base64');
  try {
    if (program.toString('base64') !== value.programBase64 || ProgramHash(value.role, program) !== value.policySha512 ||
        PolicyId(value.role, value.policySha512) !== value.policyId) Fail('RECORD_COMMITMENT_MISMATCH');
    vm.ValidateProgram(program, value.role);
    if (program.readUInt16LE(4) !== value.functionCount) Fail('RECORD_INVALID');
    return program;
  } catch (error) { program.fill(0); throw error; }
}
function ValidateServerPolicy(value) {
  const program = OpenServerPolicy(value); program.fill(0); return value;
}
function EvaluateServerPolicy(value, functionId, args) {
  // Pure internal evaluator, not an authorization API. The integration must
  // select the record from its server registry, never from a desktop request.
  const program = OpenServerPolicy(value);
  try { return vm.Evaluate(program, functionId, args, { maxSteps: value.maxSteps, role: value.role }); }
  finally { program.fill(0); }
}
function BindTemplate(bytes, role, profile) {
  Role(role); const pe = ParsePE(bytes);
  if (pe.signed) Fail('SIGNED_INPUT_REQUIRES_NEW_SIGNATURE');
  const found = FindSlot(bytes, pe); if (!found) Fail('SLOT_MISSING'); if (found.state !== 0) Fail('ALREADY_BOUND');
  if (profile !== undefined) {
    let encoded;
    try { encoded = JSON.stringify(profile); } catch (_) { Fail('PROFILE_INVALID'); }
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > MAX_PROFILE_BYTES) Fail('PROFILE_LIMIT');
  }
  const program = vm.Compile(profile, role), out = Buffer.from(bytes);
  try {
    const policySha512 = ProgramHash(role, program), policyId = PolicyId(role, policySha512), functionCount = program.readUInt16LE(4);
    const slot = CreateUnsealedSlot(); slot[24] = Role(role); slot[25] = 1; slot.writeUInt32LE(functionCount, 32);
    Buffer.from(policyId, 'hex').copy(slot, 40); Buffer.from(policySha512, 'hex').copy(slot, 72); slot.copy(out, found.offset);
    for (const section of pe.sections) if ((section.attributes & 0x20000020) &&
        !out.subarray(section.offset, section.offset + section.size).equals(bytes.subarray(section.offset, section.offset + section.size))) Fail('EXECUTABLE_SECTION_CHANGED');
    const serverPolicy = { version: 2, role, policyId, policySha512, functionCount, maxSteps: vm.MAX_STEPS, programBase64: program.toString('base64') };
    ValidateServerPolicy(serverPolicy);
    return { bytes: out, sha512: sha(out), inputSha512: sha(bytes), profileSha512: policySha512,
      toolSha512: TOOL_SHA512, ownProtection: Inspect(out), serverPolicy };
  } catch (error) { out.fill(0); throw error; }
  finally { program.fill(0); }
}
module.exports = { ENGINE, SLOT_BYTES, HEADER_BYTES, TAIL_OFFSET, FORMAT, TOOL_SHA512,
  CreateUnsealedSlot, Inspect, ValidateMetadata, PolicyId, BindTemplate, ValidateServerPolicy, EvaluateServerPolicy };
