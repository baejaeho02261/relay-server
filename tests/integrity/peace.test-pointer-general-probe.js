'use strict';
// The server validator runs here. The Delphi companion is a Windows-only test;
// checked-in vectors/source linkage do not claim that it compiled or executed.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const contract = require('../../services/integrity/peace.pointer-graph-contract');
const vector = require('../fixtures/integrity/pointer-general-v1.json');
const clone = () => structuredClone({nodes: vector.nodes, edges: vector.edges});
const check = (g, depth) => {
  const actual = contract.Bytes(g.nodes, g.edges);
  assert.equal(actual.depth, depth);
  assert(actual.bytes.length > 0);
  return actual.bytes;
};
const reject = g => assert.throws(() => contract.Bytes(g.nodes, g.edges), /^Error: INTEGRITY_POINTER_GRAPH_INVALID$/);
const node = (id, span = 8) => ({id, kind: 1, span, generation: 1, alive: true});
const edge = (source, target, offset = 0, width = 8) => ({source, target, offset, width});
function chain(levels) {
  return {nodes: Array.from({length: levels + 1}, (_, i) => node(i + 1)),
    edges: Array.from({length: levels}, (_, i) => edge(i + 1, i + 2))};
}
function cachedDepth(chainNodes) {
  const g = {nodes: Array.from({length: 4 + chainNodes}, (_, i) => node(i + 1)),
    edges: [edge(1, 2), edge(1, 5, 8), edge(2, 3), edge(3, 4)]};
  g.nodes[0].span = 16;
  for (let i = 5; i < g.nodes.length; ++i) g.edges.push(edge(i, i + 1));
  g.edges.push(edge(g.nodes.length, 2));
  return g;
}
function independentCRC64(bytes) {
  let crc = 0n;
  const mask = (1n << 64n) - 1n, polynomial = 0x42f0e1eba9ea3693n;
  for (const b of bytes) {
    crc ^= BigInt(b) << 56n;
    for (let bit = 0; bit < 8; ++bit) crc = ((crc << 1n) ^ ((crc & (1n << 63n)) ? polynomial : 0n)) & mask;
  }
  return crc.toString(16).toUpperCase().padStart(16, '0');
}
test('V1 shared diamond with internal 4/8-byte slots matches independent byte/hash/CRC vector', () => {
  const bytes = check(clone(), 2);
  assert.equal(bytes.length, vector.length);
  assert.equal(bytes.toString('hex'), vector.hex);
  assert.equal(crypto.createHash('sha512').update(bytes).digest('hex'), vector.sha512);
  assert.equal(independentCRC64(bytes), vector.crc64);
});
const mutations = [
  ['zero generation', g => g.nodes[0].generation = 0],
  ['edge generation mismatch', g => g.nodes[3].generation = 8],
  ['duplicate node identity', g => g.nodes[2].id = 2],
  ['retired node', g => g.nodes[2].alive = false],
  ['zero kind', g => g.nodes[2].kind = 0],
  ['kind over limit', g => g.nodes[2].kind = 17],
  ['zero span', g => g.nodes[2].span = 0],
  ['span over limit', g => g.nodes[2].span = 1048577],
  ['zero source', g => g.edges[0].source = 0],
  ['source over limit', g => g.edges[0].source = 5],
  ['zero target', g => g.edges[0].target = 0],
  ['target over limit', g => g.edges[0].target = 5],
  ['zero pointer width', g => g.edges[0].width = 0],
  ['unsupported pointer width', g => g.edges[0].width = 16],
  ['one byte past source end', g => g.edges[1].offset = 17],
  ['offset arithmetic overflow', g => g.edges[1].offset = 0xffffffff],
  ['overlapping source slots', g => g.edges[1].offset = 6],
  ['out of canonical edge order', g => { [g.edges[0], g.edges[1]] = [g.edges[1], g.edges[0]]; }],
  ['self-cycle', g => g.edges[1].target = 1],
  ['ancestor cycle', g => g.edges[2].target = 1],
  ['unreachable registered node', g => g.edges[1].target = 2],
];
for (const [name, mutate] of mutations) test(`V1 rejects ${name}`, () => { const g = clone(); mutate(g); reject(g); });
test('V1 accepts maximum uint32 generation and kind', () => {
  const g = clone(); g.nodes.forEach(n => n.generation = 0xffffffff); g.nodes[3].kind = 16; check(g, 2);
});
test('V1 accepts maximum source span and exact-end slot', () => {
  const g = clone(); g.nodes[0].span = 1048576; g.edges[1].offset = 1048568; check(g, 2);
});
test('V1 accepts a registered single node', () => check(chain(0), 0));
test('V1 accepts depth 16', () => check(chain(16), 16));
test('V1 rejects depth 17', () => reject(chain(17)));
test('V1 shared cached tail accepts total depth 16', () => check(cachedDepth(13), 16));
test('V1 shared cached tail cannot bypass total depth 17', () => reject(cachedDepth(14)));
test('V1 accepts simultaneous maximum nodes and edges', () => {
  const g = {nodes: Array.from({length: contract.MAX_NODES}, (_, i) => node(i + 1, 1)),
    edges: Array.from({length: contract.MAX_EDGES}, (_, i) => edge(1, i + 2, i * 4, 4))};
  g.nodes[0].span = g.edges.length * 4; g.edges.at(-1).target = 2; check(g, 1);
});
test('V1 rejects too many edges before traversal', () => {
  const g = chain(1); g.edges = Array.from({length: contract.MAX_EDGES + 1}, () => edge(1, 2)); reject(g);
});
test('V1 rejects too many nodes before traversal', () => {
  const g = chain(1); g.nodes = Array.from({length: contract.MAX_NODES + 1}, (_, i) => node(i + 1)); reject(g);
});
test('V1 rejects empty graphs', () => reject({nodes: [], edges: []}));
const nativeRoot = path.resolve(__dirname, '../../../Railway');
test('native companion uses production serializer and the same independent golden vector', {skip: !fs.existsSync(nativeRoot)}, () => {
  const include = fs.readFileSync(path.join(nativeRoot, 'Cozy.Tests/Cozy.Platform/Cozy.PointerGraphGeneralContracts.inc'), 'utf8');
  const main = fs.readFileSync(path.join(nativeRoot, 'Cozy.Tests/Cozy.Platform/Cozy.PointerGraphProbe.dpr'), 'utf8');
  assert(include.includes(vector.sha512)); assert(include.includes(vector.crc64));
  assert(include.includes('CozyPointerGraphBytes(N, E, D)'));
  assert(main.includes('RunGeneralPointerGraphContracts'));
  assert(main.includes('RunPointerLifecycleContracts'));
  assert(main.includes('ProbeApiPointerGraphRejects(I)'));
});
