'use strict';

// Independent reference calculations bind native known-answer probes to their
// existing ASCII domains. Native execution is a separate compiler/runner check.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { blake3 } = require('@noble/hashes/blake3');

const relayRoot = path.resolve(__dirname, '../..');
const nativeRoot = path.resolve(relayRoot, '../Railway');
const readNative = relative => fs.readFileSync(path.join(nativeRoot, relative), 'utf8');
const utf8 = text => Uint8Array.from(Buffer.from(text, 'utf8'));
const hex = bytes => Buffer.from(bytes).toString('hex');
const upstreamDirectory = path.dirname(require.resolve('@noble/hashes/blake3'));
const upstreamPackage = JSON.parse(fs.readFileSync(path.join(upstreamDirectory, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(relayRoot, 'package-lock.json'), 'utf8'));
assert.equal(upstreamPackage.version, '1.8.0');
assert.equal(lock.packages['node_modules/@noble/hashes'].version, upstreamPackage.version);

const handoffDomain = 'cozy.Client.Handoff.V3.AES256GCM.ContentKey.v1';
const handoffSource = readNative('Cozy.Source/Cozy.Handoff/Cozy.Handoff.Kdf.pas');
const handoffProbe = readNative('Cozy.Tests/Cozy.Handoff/Cozy.HandoffKdfProbe.dpr');
const purposes = JSON.parse(fs.readFileSync(path.join(relayRoot, 'contracts/runtime/crypto-purpose-v1.json'), 'utf8'));
const handoffPurpose = purposes.purposes.find(value => value.purpose === 'native one-shot Handoff content key');
assert.equal(handoffPurpose.context, handoffDomain);
assert.equal(handoffSource.match(/const Domain: AnsiString = '([^']+)';/)[1], handoffDomain);
assert.match(handoffProbe, /SetLength\(Seed,\s*32\);\s*for I := 0 to 31 do Seed\[I\] := I;/);
assert.match(handoffProbe, /Transcript := Bytes\('GAME-HANDOFF-V3'#10'A->B'#10'PUBLIC-TEST'\)/);

const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const transcript = utf8('GAME-HANDOFF-V3\nA->B\nPUBLIC-TEST');
const material = Uint8Array.from([...seed, ...transcript]);
const handoff = hex(blake3(material, { context: utf8(handoffDomain) }));
assert.equal(handoffProbe.match(/if Hex\(Key\) <> '([a-f0-9]{64})'/)[1], handoff);
assert.deepEqual(seed, Uint8Array.from({ length: 32 }, (_, index) => index));

const itemDomain = 'cozy.Client.DeviceSignals.Item.v1';
const setDomain = 'cozy.Client.DeviceSignals.Set.v1';
const deviceSource = readNative('Cozy.Source/Cozy.Identity/Cozy.DeviceSignals.Core.pas');
const deviceProbe = readNative('Cozy.Tests/Cozy.Identity/Cozy.DeviceSignalsProbe.dpr');
assert.deepEqual([...deviceSource.matchAll(/const Domain: AnsiString = '([^']+)';/g)].map(match => match[1]), [itemDomain, setDomain]);
assert.match(deviceProbe, /const Serial: AnsiString = '  SERIAL-ABC  ';/);
assert.match(deviceProbe, /SetLength\(Key,32\); FillChar\(Key\[0\],32,7\)/);
assert.match(deviceProbe, /SetLength\(Mac,6\); Mac\[0\]:=2; Mac\[1\]:=\$11; Mac\[2\]:=\$22; Mac\[3\]:=\$33; Mac\[4\]:=\$44; Mac\[5\]:=\$55;/);

// Upstream owns a .slice() of its key: use Uint8Array so the copy is independent
// of Node Buffer storage. Every digest below must see the same public test key.
const key = new Uint8Array(32).fill(7);
function item(kind, raw) {
  const size = Buffer.alloc(4);
  size.writeUInt32LE(raw.length);
  const framed = Uint8Array.from(Buffer.concat([
    Buffer.from(itemDomain, 'ascii'), Buffer.from([kind]), size, Buffer.from(raw)
  ]));
  return { kind, digest: blake3(framed, { key }) };
}
function signalSet(items) {
  const unique = [...new Map(items.map(value => [value.kind + ':' + hex(value.digest), value])).values()];
  unique.sort((a, b) => a.kind - b.kind || Buffer.compare(Buffer.from(a.digest), Buffer.from(b.digest)));
  const framed = Uint8Array.from(Buffer.concat([
    Buffer.from(setDomain, 'ascii'),
    ...unique.map(value => Buffer.concat([Buffer.from([value.kind]), Buffer.from(value.digest)]))
  ]));
  return hex(blake3(framed, { key }));
}
const disk = item(1, utf8('SERIAL-ABC'));
const nic = item(2, Uint8Array.from([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
const device = signalSet([disk, nic, disk]);
assert.equal(signalSet([nic, disk]), device);
assert.equal(deviceProbe.match(/Require\(Expected='([a-f0-9]{64})'\)/)[1], device);
assert.deepEqual(key, new Uint8Array(32).fill(7));

console.log(JSON.stringify({
  status: 'PASS', scope: 'INDEPENDENT_NATIVE_SOURCE_VECTOR_BINDING',
  reference: '@noble/hashes 1.8.0', vectors: 2,
  handoff, device, actualNativeExecuted: false
}));
