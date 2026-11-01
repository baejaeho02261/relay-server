'use strict';
// Independent public fixtures: execute production JS parser/encoders and compare
// native constants when the private source tree is present. Never runs a session.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const schema = require('../../services/protocol/peace.packet-schema');
const rpc = require('../../services/security/peace.server-policy-operations');
const fixtures = require('../fixtures/protocol/peace.native-policy-contract-vectors.json');
const sha = text => crypto.createHash('sha512').update(text, 'utf8').digest('hex');
const native = process.env.COZY_NATIVE_SOURCE_ROOT || path.resolve(__dirname, '../../../Railway');
const available = fs.existsSync(native);
const read = file => fs.readFileSync(path.join(native, file), 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
function independent(body, c) {
  const argsSha512 = sha(JSON.stringify(body.args));
  const fields = ['COZY-SERVER-OPERATION-V1', body.stage, body.sessionId, body.machineId,
    body.policyId, String(body.functionId), body.requestId, argsSha512];
  const binding = sha(fields.join('\n'));
  const canonical = [...fields, binding, c.challengeId, c.nonce, c.epoch,
    String(c.revision), String(c.operationsRevision), String(c.expiresAt)].join('\n');
  return {argsSha512, binding, canonicalSha512:sha(canonical), canonical};
}

test('18 A/B/O independent transcript vectors preserve exact production V1 bytes', () => {
  assert.equal(fixtures.transcriptVectors.length, 18);
  for (const vector of fixtures.transcriptVectors) {
    const e = independent(vector.body, vector.challenge);
    for (const field of ['argsSha512','binding','canonicalSha512']) assert.equal(vector[field], e[field], vector.name+':'+field);
    assert.equal(rpc.Binding(vector.body), vector.binding, vector.name);
    assert.equal(rpc.Canonical(vector.body, vector.challenge), e.canonical, vector.name);
    assert.equal(sha(rpc.Canonical(vector.body, vector.challenge)), vector.canonicalSha512, vector.name);
  }
});

test('14 bound-field mutations independently change the signed digest', () => {
  const base = independent(fixtures.base, fixtures.challenge);
  assert.equal(fixtures.mutations.length, 14);
  const seen = new Set();
  for (const mutation of fixtures.mutations) {
    const b = {...fixtures.base, ...mutation.bodyPatch}, c = {...fixtures.challenge, ...mutation.challengePatch};
    const e = independent(b, c);
    for (const field of ['argsSha512','binding','canonicalSha512']) assert.equal(mutation[field], e[field], mutation.name+':'+field);
    assert.equal(rpc.Binding(b), mutation.binding, mutation.name);
    assert.equal(sha(rpc.Canonical(b,c)), mutation.canonicalSha512, mutation.name);
    assert.notEqual(mutation.canonicalSha512, base.canonicalSha512, mutation.name);
    assert(!seen.has(mutation.canonicalSha512), mutation.name+' collides with another mutation');
    seen.add(mutation.canonicalSha512);
  }
});

test('actual request parser evaluates 118 policy field/type/version/budget boundaries', () => {
  let accepted = 0, rejected = 0;
  const names = new Set();
  for (const item of fixtures.wireCases) {
    assert(!names.has(item.name)); names.add(item.name);
    const options = Object.hasOwn(item, 'maxBytes') ? {maxBytes:item.maxBytes} : {};
    if (item.accept) {
      const parsed = schema.ParseRequest(item.wire, options);
      assert.equal(parsed.operation, 'policy', item.name);
      assert(['challenge','invoke'].includes(parsed.body.action), item.name);
      accepted++;
    } else {
      assert.throws(() => schema.ParseRequest(item.wire, options), error =>
        ['PROTOCOL_SCHEMA_INVALID','JSON_SIZE','JSON_DUPLICATE_FIELD','JSON_RESERVED_FIELD','JSON_INVALID'].includes(error.message), item.name);
      rejected++;
    }
  }
  assert.equal(accepted, 43); assert.equal(rejected, 75);
});

test('shape-only acceptance is not domain signature/session authorization', () => {
  const cases = fixtures.wireCases.filter(c => c.name.startsWith('shape-only-'));
  assert.equal(cases.length, 3);
  for (const item of cases) {
    const envelope = schema.ParseRequest(item.wire);
    assert.throws(() => rpc.Execute(envelope.body), /COZY_OPERATION_INPUT_INVALID/);
  }
});

function pascalString(fragment) {
  return [...fragment.matchAll(/'((?:''|[^'])*)'/g)].map(m => m[1].replace(/''/g,"'")).join('');
}
test('native parser fixture is byte-identical to every independent wire case', {skip:!available}, () => {
  const source = read('Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaPolicyCases.inc');
  const rows = [...source.matchAll(/\(Name: ([\s\S]*?); WireText: ([\s\S]*?);\s*Accept: (True|False); MaximumBytes: (-?\d+)\)/g)];
  assert.equal(rows.length, fixtures.wireCases.length);
  rows.forEach((row, i) => {
    const item = fixtures.wireCases[i];
    assert.equal(pascalString(row[1]), item.name);
    assert.equal(pascalString(row[2]), item.wire, item.name);
    assert.equal(row[3] === 'True', item.accept, item.name);
    assert.equal(Number(row[4]), item.maxBytes ?? -1, item.name);
  });
  const probe = read('Cozy.Tests/Cozy.Protocol/Cozy.ProtocolSchemaProbe.dpr');
  assert.match(probe, /Parsed := ParseProtocolRequest\(PolicyWireCases\[I\].WireText, MaximumBytes\)/);
  assert.match(probe, /finally\s+Parsed.Free/);
});

test('native transcript constants match every independent role and mutation vector', {skip:!available}, () => {
  const source = read('Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolVectors.inc');
  const rows = [...source.matchAll(/\(Stage: '([ABO])'; FunctionID: (\d+); ArgsVariant: (\d+);\s*ArgsSHA512: '([a-f0-9]{128})';\s*BindingSHA512: '([a-f0-9]{128})';\s*CanonicalSHA512: '([a-f0-9]{128})'\)/g)];
  assert.equal(rows.length, fixtures.transcriptVectors.length);
  rows.forEach((row, i) => {
    const v = fixtures.transcriptVectors[i];
    assert.deepEqual(row.slice(1), [v.body.stage,String(v.body.functionId),String(v.argsVariant),v.argsSha512,v.binding,v.canonicalSha512]);
  });
  const mutations = source.split('OperationMutations:')[1];
  const mr = [...mutations.matchAll(/\(BindingSHA512: '([a-f0-9]{128})';\s*CanonicalSHA512: '([a-f0-9]{128})'\)/g)];
  assert.equal(mr.length, fixtures.mutations.length);
  mr.forEach((row,i) => assert.deepEqual(row.slice(1), [fixtures.mutations[i].binding,fixtures.mutations[i].canonicalSha512]));
});
