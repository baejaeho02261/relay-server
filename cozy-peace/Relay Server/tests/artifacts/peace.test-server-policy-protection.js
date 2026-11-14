'use strict';
// Synthetic PE data only. No Windows execution, signature verification or
// server authorization is claimed by these pure binding-format tests.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const fs = require('node:fs');
const policy = require('../../services/artifacts/peace.server-policy-protection');
const vm = require('../../services/artifacts/peace.cozy-protection-engine');
const SLOT = 1024, TABLE = 128 + 24 + 240, sha = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
function PE(slots = 1) {
  const count = Math.max(1, slots), bytes = Buffer.alloc(1024 + 4096 * count), optional = 152;
  bytes.write('MZ'); bytes.writeUInt32LE(128, 60); bytes.write('PE\0\0', 128, 'ascii');
  bytes.writeUInt16LE(0x8664, 132); bytes.writeUInt16LE(2, 134); bytes.writeUInt16LE(240, 148); bytes.writeUInt16LE(0x22, 150);
  bytes.writeUInt16LE(0x20b, optional); bytes.writeUInt32LE(0x1000, optional + 16); bytes.writeBigUInt64LE(0x140000000n, optional + 24);
  bytes.writeUInt32LE(4096, optional + 32); bytes.writeUInt32LE(512, optional + 36);
  bytes.writeUInt32LE(0x2000 + 4096 * count, optional + 56); bytes.writeUInt32LE(512, optional + 60);
  bytes.writeUInt16LE(2, optional + 68); bytes.writeUInt32LE(16, optional + 108);
  bytes.write('.text', TABLE); bytes.writeUInt32LE(512, TABLE + 8); bytes.writeUInt32LE(0x1000, TABLE + 12);
  bytes.writeUInt32LE(512, TABLE + 16); bytes.writeUInt32LE(512, TABLE + 20); bytes.writeUInt32LE(0x60000020, TABLE + 36);
  bytes.fill(0x90, 512, 1024); bytes.write('SYNTHETIC PE DATA; NEVER EXECUTED', 600, 'ascii');
  const data = TABLE + 40; bytes.write('.cozy', data); bytes.writeUInt32LE(4096 * count, data + 8);
  bytes.writeUInt32LE(0x2000, data + 12); bytes.writeUInt32LE(4096 * count, data + 16);
  bytes.writeUInt32LE(SLOT, data + 20); bytes.writeUInt32LE(0xc0000040, data + 36);
  for (let n = 0; n < slots; n++) policy.CreateUnsealedSlot().copy(bytes, SLOT + 4096 * n);
  return bytes;
}
const constant = value => ({ op: 'const', value }), arg = index => ({ op: 'arg', index });
const Profile = () => ({ version: 1, functions: [{ id: 2, args: 1, body: { op: 'xor', left: arg(0), right: constant(0x76543210) } }] });
function Reject(fn, code) { assert.throws(fn, error => error.message === 'COZY_SERVER_POLICY_' + code); }

test('format is an explicit versioned public data commitment, with a strict unsealed state', () => {
  const slot = policy.CreateUnsealedSlot();
  assert.equal(slot.length, 4096); assert.equal(slot.subarray(0, 16).toString('hex'), '434f5a592d504f4c4943592d56320000');
  assert.equal(slot.subarray(4080).toString('hex'), '434f5a592d504f4c454e442d56320000');
  assert.equal(slot.readUInt16LE(16), 2); assert.equal(slot.readUInt16LE(18), 160);
  assert.equal(slot.readUInt32LE(28), 1); assert.equal(slot.readUInt32LE(36), 1024);
  assert.ok(slot.subarray(40, 4080).every(value => value === 0));
  const metadata = policy.Inspect(PE()); assert.equal(metadata.state, 'UNSEALED'); assert.equal(metadata.role, null);
  assert.equal(metadata.policyId, null); assert.equal(metadata.policySha512, null); assert.equal(metadata.functionCount, 0);
  assert.equal(policy.ValidateMetadata(metadata), metadata);
  assert.equal(policy.Inspect(PE(0)), null); Reject(() => policy.BindTemplate(PE(0), 'A'), 'SLOT_MISSING');
});
test('all three roles bind without modifying executable code, source input or file length', () => {
  for (const role of ['A', 'B', 'O']) {
    const input = PE(), before = Buffer.from(input), result = policy.BindTemplate(input, role, Profile());
    assert.deepEqual(input, before); assert.equal(result.bytes.length, input.length);
    assert.deepEqual(result.bytes.subarray(0, SLOT), input.subarray(0, SLOT));
    assert.deepEqual(result.bytes.subarray(SLOT + 4080), input.subarray(SLOT + 4080));
    assert.notEqual(result.sha512, result.inputSha512); assert.equal(result.sha512, sha(result.bytes)); assert.equal(result.inputSha512, sha(input));
    const toolSource = sha(fs.readFileSync(require.resolve('../../services/artifacts/peace.server-policy-protection')));
    const compilerSource = sha(fs.readFileSync(require.resolve('../../services/artifacts/peace.cozy-protection-engine')));
    assert.equal(result.toolSha512, sha(Buffer.from('COZY-SERVER-POLICY-TOOL-V2\n' + toolSource + '\n' + compilerSource + '\n')));
    assert.equal(result.ownProtection.engine, 'COZY_SERVER_POLICY_V2'); assert.equal(result.ownProtection.role, role);
    assert.equal(result.ownProtection.state, 'BOUND'); assert.equal(result.ownProtection.functionCount, 2);
    assert.equal(result.ownProtection.execution, 'SERVER_ONLY'); assert.equal(result.ownProtection.authenticationRequired, true);
    assert.equal(result.ownProtection.slotContainsSecret, false); assert.equal(result.ownProtection.clientBytecode, false);
    assert.equal(result.ownProtection.windowsVerified, false); assert.equal(result.ownProtection.arbitraryDelphiTranslation, false);
    assert.equal(policy.ValidateMetadata(result.ownProtection), result.ownProtection);
  }
});
test('client slot has public commitments only; IR, keys, nonces and ciphertext are not written', () => {
  const result = policy.BindTemplate(PE(), 'B', Profile()), slot = result.bytes.subarray(SLOT, SLOT + 4096);
  const program = Buffer.from(result.serverPolicy.programBase64, 'base64');
  assert.equal(result.bytes.includes(program), false); assert.equal(result.bytes.includes(Buffer.from(JSON.stringify(Profile()))), false);
  assert.deepEqual(slot.subarray(40, 72), Buffer.from(result.ownProtection.policyId, 'hex'));
  assert.deepEqual(slot.subarray(72, 136), Buffer.from(result.ownProtection.policySha512, 'hex'));
  assert.ok(slot.subarray(136, 4080).every(value => value === 0));
  for (const name of ['key', 'privateKey', 'ciphertext', 'nonce', 'programBase64', 'functions', 'profile']) assert.equal(Object.hasOwn(result.ownProtection, name), false);
  assert.equal(typeof result.serverPolicy.programBase64, 'string');
  assert.equal(policy.EvaluateServerPolicy(result.serverPolicy, 2, [123]), (123 ^ 0x76543210) | 0);
  program.fill(0);
});
test('commitments are deterministic, role-separated and sensitive to the actual compiled policy', () => {
  const a = policy.BindTemplate(PE(), 'A', Profile()), again = policy.BindTemplate(PE(), 'A', Profile());
  const b = policy.BindTemplate(PE(), 'B', Profile()), changed = Profile(); changed.functions[0].body.right.value++;
  assert.deepEqual(a.bytes, again.bytes); assert.deepEqual(a.serverPolicy, again.serverPolicy);
  assert.notEqual(a.ownProtection.policyId, b.ownProtection.policyId);
  assert.notEqual(a.profileSha512, policy.BindTemplate(PE(), 'A', changed).profileSha512);
  const program = Buffer.from(a.serverPolicy.programBase64, 'base64');
  const expectedSha = crypto.createHash('sha512').update('COZY-SERVER-POLICY-PROGRAM-V2\nA\n').update(program).digest('hex');
  const expectedId = crypto.createHash('sha256').update('COZY-SERVER-POLICY-ID-V2\nA\n' + expectedSha).digest('hex');
  assert.equal(a.ownProtection.policySha512, expectedSha); assert.equal(a.ownProtection.policyId, expectedId); program.fill(0);
});
test('native cross-language public commitment vectors remain stable', () => {
  const vectors = [
    ['A', 'f25273322e7f9c33ae87e01816dc2fadf54a5f0aa3dbcc51eed81af45349f03a30b73883f9d8fd48425bf0fa308b4ef583a4e1200d41277fff336d2486fb7107', '89df5d165c7f9112ec382c707336cb655d95522cfca353a47ba9be5cb23f0951'],
    ['B', '0f7e03b9e4c23724ce45e83dc5a3d3a0f2801a70d5877fa177038867c6e2aae3679309f40f86a47d37a535bece4911c084cb08c92a9433a6a79db27c0d383147', '3a447fa121b5447b26b391b02811dd4460e0e8ab3ea8d99cd26bf52272eca621'],
    ['O', 'd1244271a9c8926421394ff0b893037216afd1c5e3bfd52c00e961f9fcc8d1875a271cb3cd1357d1be678a3c336882400dc141becabb460c04356a3c5a7eb8ee', '3dcb16ec5058a547ddd0a84ff0bcff8a0badce6fe9036cef247a0c7e39c4e508']
  ];
  assert.equal(sha(policy.CreateUnsealedSlot()), '2e0fa1e4d95750cab4b3e67512f5c53b7771432d5e67807ec21ed024ec7afc8beb02d14374d3a3521501db04c5f62a1abaf3c7f13e5521d835bb0788ced2f2ff');
  for (const [role, digest, id] of vectors) {
    const output = policy.BindTemplate(PE(), role);
    assert.equal(output.ownProtection.functionCount, 1);
    assert.equal(output.ownProtection.policySha512, digest); assert.equal(output.ownProtection.policyId, id);
    assert.equal(Buffer.from(output.serverPolicy.programBase64, 'base64').length, 43);
  }
});
test('rebinding an existing public commitment is rejected, even for the same role or policy', () => {
  const result = policy.BindTemplate(PE(), 'A');
  Reject(() => policy.BindTemplate(result.bytes, 'A'), 'ALREADY_BOUND');
  Reject(() => policy.BindTemplate(result.bytes, 'O'), 'ALREADY_BOUND');
});
test('legacy and mixed VM slots fail closed instead of retaining a hidden legacy key slot', () => {
  const legacy = PE(); vm.CreateUnsealedSlot().copy(legacy, SLOT);
  Reject(() => policy.BindTemplate(legacy, 'A'), 'LEGACY_FORMAT_REJECTED');
  const sealed = vm.Pack(legacy, 'A').bytes;
  Reject(() => policy.Inspect(sealed), 'LEGACY_FORMAT_REJECTED');
  const mixed = PE(2); vm.CreateUnsealedSlot().copy(mixed, SLOT + 4096);
  Reject(() => policy.BindTemplate(mixed, 'B'), 'LEGACY_FORMAT_REJECTED');
  const malformedMixed = Buffer.from(mixed); malformedMixed[SLOT + 4096] ^= 1;
  Reject(() => policy.Inspect(malformedMixed), 'LEGACY_FORMAT_REJECTED');
});
test('slot location must be unique, file-backed, fully mapped readable non-executable data', () => {
  Reject(() => policy.BindTemplate(PE(2), 'A'), 'SLOT_DUPLICATE');
  for (const flags of [0xe0000060, 0xc0000080, 0x00000040, 0x42000040]) {
    const bytes = PE(); bytes.writeUInt32LE(flags, TABLE + 40 + 36);
    Reject(() => policy.BindTemplate(bytes, 'A'), 'SLOT_MAPPING_INVALID');
  }
  const short = PE(); short.writeUInt32LE(4095, TABLE + 40 + 8); Reject(() => policy.BindTemplate(short, 'A'), 'SLOT_MAPPING_INVALID');
  const unmapped = PE(); unmapped.writeUInt32LE(3584, TABLE + 40 + 16); Reject(() => policy.BindTemplate(unmapped, 'A'), 'SLOT_MAPPING_INVALID');
});
test('unsafe PE headers, overlapping mappings and out-of-range entry points are rejected', () => {
  for (const change of [b => b.writeUInt32LE(0xffffffff, 60), b => b.writeUInt16LE(0x14c, 132),
    b => b.writeUInt32LE(0x400000, 152 + 16), b => b.writeUInt32LE(512, TABLE + 40 + 20),
    b => b.writeUInt32LE(0x1000, TABLE + 40 + 12), b => b.writeUInt32LE(0xffffffff, TABLE + 40 + 16)]) {
    const bytes = PE(); change(bytes); Reject(() => policy.BindTemplate(bytes, 'A'), 'PE_INVALID');
  }
  for (const bytes of [null, Buffer.alloc(100), Buffer.alloc(64 * 1024 * 1024 + 1)]) Reject(() => policy.Inspect(bytes), 'PE_INVALID');
});
test('existing Authenticode material cannot be silently invalidated by binding', () => {
  const base = PE(), signed = Buffer.concat([base, Buffer.alloc(8)]);
  signed.writeUInt32LE(base.length, 152 + 144); signed.writeUInt32LE(8, 152 + 148);
  Reject(() => policy.BindTemplate(signed, 'A'), 'SIGNED_INPUT_REQUIRES_NEW_SIGNATURE');
  const malformed = Buffer.from(signed); malformed.writeUInt32LE(base.length - 8, 152 + 144);
  Reject(() => policy.BindTemplate(malformed, 'A'), 'PE_INVALID');
});
test('every unused slot byte must remain zero, before and after binding', () => {
  for (const source of [PE(), policy.BindTemplate(PE(), 'A').bytes]) {
    for (const at of [136, 159, 160, 2048, 4079]) {
      const changed = Buffer.from(source); changed[SLOT + at] = 1; Reject(() => policy.Inspect(changed), 'SLOT_INVALID');
    }
  }
});
test('header corruption, inconsistent state and malformed public commitments are rejected', () => {
  const bound = policy.BindTemplate(PE(), 'A').bytes;
  for (const at of [0, 16, 18, 20, 25, 26, 28, 36, 4080]) {
    const bytes = Buffer.from(bound); bytes[SLOT + at] ^= 1; Reject(() => policy.Inspect(bytes), 'SLOT_INVALID');
  }
  for (const at of [24, 40, 72]) {
    const bytes = Buffer.from(bound); bytes[SLOT + at] ^= 2;
    assert.throws(() => policy.Inspect(bytes), /COZY_SERVER_POLICY_(?:SLOT_INVALID|COMMITMENT_INVALID)/);
  }
  const zeroHash = Buffer.from(bound); zeroHash.fill(0, SLOT + 72, SLOT + 136); Reject(() => policy.Inspect(zeroHash), 'COMMITMENT_INVALID');
  const falseUnsealed = Buffer.from(bound); falseUnsealed[SLOT + 25] = 0; Reject(() => policy.Inspect(falseUnsealed), 'SLOT_INVALID');
  const wrongCount = Buffer.from(bound); wrongCount.writeUInt32LE(17, SLOT + 32); Reject(() => policy.Inspect(wrongCount), 'SLOT_INVALID');
});
test('metadata rejects added secrets, authentication bypass claims and false verification claims', () => {
  const metadata = policy.BindTemplate(PE(), 'A').ownProtection;
  for (const patch of [{ key: 'forbidden' }, { programBase64: 'forbidden' }, { slotContainsSecret: true },
    { authenticationRequired: false }, { windowsVerified: true }, { arbitraryDelphiTranslation: true },
    { clientBytecode: true }, { functionCount: 17 }, { policySha512: '0'.repeat(128) }, { state: 'SEALED' }, { role: 'B' }]) {
    Reject(() => policy.ValidateMetadata({ ...metadata, ...patch }), 'METADATA_INVALID');
  }
});
test('server-only record validation catches digest, program, role, count and schema substitution', () => {
  const record = policy.BindTemplate(PE(), 'A', Profile()).serverPolicy;
  assert.equal(policy.ValidateServerPolicy(record), record);
  for (const patch of [{ key: 'forbidden' }, { maxSteps: 0 }, { maxSteps: 1025 }, { version: 1 },
    { functionCount: 0 }, { functionCount: 17 }, { programBase64: 'A'.repeat(10000) }]) {
    Reject(() => policy.ValidateServerPolicy({ ...record, ...patch }), 'RECORD_INVALID');
  }
  for (const patch of [{ role: 'B' }, { policyId: '0'.repeat(64) }, { policySha512: '0'.repeat(128) },
    { programBase64: Buffer.alloc(32).toString('base64') }]) {
    Reject(() => policy.ValidateServerPolicy({ ...record, ...patch }), 'RECORD_COMMITMENT_MISMATCH');
  }
  Reject(() => policy.ValidateServerPolicy({ ...record, functionCount: 1 }), 'RECORD_INVALID');
});
test('server evaluation remains bounded and rejects code-shaped profiles or wrong arguments', () => {
  const record = policy.BindTemplate(PE(), 'B', Profile()).serverPolicy;
  assert.equal(policy.EvaluateServerPolicy(record, 1, [2, 1, 1]), 1);
  assert.equal(policy.EvaluateServerPolicy(record, 1, [2, 1, 0]), 0);
  for (const args of [[], [1, 2], [1.1], ['1']]) assert.throws(() => policy.EvaluateServerPolicy(record, 2, args), /COZY_PROTECTION_ARGUMENT_INVALID/);
  assert.throws(() => policy.BindTemplate(PE(), 'A', { version: 1, functions: [{ id: 2, args: 0, body: { op: 'eval', source: 'process.exit()' } }] }), /COZY_PROTECTION_PROFILE_INVALID/);
  assert.throws(() => policy.BindTemplate(PE(), 'A', { version: 1, functions: [{ id: 1, args: 0, body: constant(1) }] }), /COZY_PROTECTION_PROFILE_INVALID/);
  let deep = constant(1); for (let n = 0; n < 34; n++) deep = { op: 'not', value: deep };
  assert.throws(() => policy.BindTemplate(PE(), 'A', { version: 1, functions: [{ id: 2, args: 0, body: deep }] }), /COZY_PROTECTION_PROFILE_LIMIT/);
  Reject(() => policy.BindTemplate(PE(), 'A', { value: 'x'.repeat(65537) }), 'PROFILE_LIMIT');
  Reject(() => policy.BindTemplate(PE(), 'X'), 'ROLE_INVALID');
});
test('the public slot is a binding, not a client signature or independent authorization', () => {
  const a = policy.BindTemplate(PE(), 'A'), other = policy.BindTemplate(PE(), 'A', Profile());
  // An attacker can copy public commitments. Server-side exact artifact hashes,
  // approved registry selection and session authorization must reject that file.
  const modified = Buffer.from(a.bytes); other.bytes.copy(modified, SLOT, SLOT, SLOT + 4096);
  const metadata = policy.Inspect(modified);
  assert.equal(metadata.policyId, other.ownProtection.policyId); assert.notEqual(sha(modified), a.sha512);
  assert.equal(metadata.authenticationRequired, true); assert.equal(Object.hasOwn(metadata, 'authorized'), false);
  assert.equal(Object.hasOwn(policy, 'Handle'), false); assert.equal(Object.hasOwn(policy, 'Execute'), false);
});
