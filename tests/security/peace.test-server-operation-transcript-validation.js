'use strict';
// Real production encoders and dispatcher validation, without creating a
// session, publishing an artifact or granting a license.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const rpc = require('../../services/security/peace.server-policy-operations');
const sha = text => crypto.createHash('sha512').update(text, 'utf8').digest('hex');
const body = () => ({ action:'challenge', stage:'B', sessionId:'A'.repeat(24), sessionToken:'s'.repeat(32),
  machineId:'B'.repeat(64), requestId:'11111111-2222-3333-4444-555555555555', policyId:'c'.repeat(64),
  functionId:2, args:[-2147483648, 0, 2147483647] });
const challenge = () => ({ challengeId:'1'.repeat(48), nonce:'2'.repeat(48), epoch:'3'.repeat(48),
  revision:0, operationsRevision:0, expiresAt:1790000000000 });
function expected(b, c) {
  const fields = ['COZY-SERVER-OPERATION-V1', b.stage, b.sessionId, b.machineId, b.policyId,
    String(b.functionId), b.requestId, sha(JSON.stringify(b.args))];
  const binding = sha(fields.join('\n'));
  return { binding, canonical:[...fields,binding,c.challengeId,c.nonce,c.epoch,String(c.revision),
    String(c.operationsRevision),String(c.expiresAt)].join('\n') };
}
function rejects(fn) { assert.throws(fn, /COZY_OPERATION_INPUT_INVALID/); }

test('valid V1 encodings keep exact legacy bytes for all roles and integer boundaries', () => {
  for (const stage of ['A','B','O']) for (const args of [[], [-2147483648,0,2147483647], Array(8).fill(-1)]) {
    for (const functionId of [2,65535]) {
      const b = {...body(), stage, args, functionId}, c = challenge(), e = expected(b,c);
      assert.equal(rpc.Binding(b), e.binding);
      assert.equal(rpc.Canonical(b,c), e.canonical);
    }
  }
});

test('public transcript encoders reject delimiters, trailing newline, wrong case and overlong IDs', () => {
  const invalid = [
    {stage:'B\n'}, {stage:'b'}, {stage:''}, {stage:'AB'},
    {sessionId:'a'.repeat(24)}, {sessionId:'A'.repeat(24)+'\n'}, {sessionId:'A'.repeat(23)},
    {machineId:'b'.repeat(64)}, {machineId:'B'.repeat(64)+'\r'},
    {policyId:'C'.repeat(64)}, {policyId:'c'.repeat(64)+'\n'},
    {requestId:'valid-id\n'}, {requestId:'valid-id\r'}, {requestId:'valid\0id'},
    {requestId:'valid id'}, {requestId:'사용자request'}, {requestId:'a'.repeat(7)}, {requestId:'a'.repeat(81)},
    {functionId:0}, {functionId:1}, {functionId:65536}, {functionId:2.5}, {functionId:'2'}
  ];
  for (const patch of invalid) {
    rejects(() => rpc.Binding({...body(),...patch}));
    rejects(() => rpc.Canonical({...body(),...patch},challenge()));
  }
  for (const requestId of ['a'.repeat(8),'_-'.repeat(40)]) assert.equal(rpc.Binding({...body(),requestId}).length,128);
});

test('dense Int32-only arrays reject holes, extra properties and altered prototypes', () => {
  const sparse = Array(1), extra = [1], inherited = [1]; extra.label = 1;
  Object.setPrototypeOf(inherited, null);
  for (const args of [sparse,extra,inherited,null,{},Array(9).fill(0),[2147483648],[-2147483649],[NaN],[Infinity],[1.5],[true],['1'],[null]]) {
    rejects(() => rpc.Binding({...body(),args}));
  }
});

test('challenge transcript fields enforce exact ASCII and safe integer limits', () => {
  for (const field of ['challengeId','nonce','epoch']) for (const value of ['a'.repeat(47),'a'.repeat(48)+'\n','A'.repeat(48),'a'.repeat(49),null]) {
    rejects(() => rpc.Canonical(body(),{...challenge(),[field]:value}));
  }
  for (const field of ['revision','operationsRevision']) for (const value of [-1,0.5,9007199254740992,'0',null]) {
    rejects(() => rpc.Canonical(body(),{...challenge(),[field]:value}));
  }
  for (const expiresAt of [0,-1,0.5,9007199254740992,'1',null]) rejects(() => rpc.Canonical(body(),{...challenge(),expiresAt}));
  const c = {...challenge(),revision:Number.MAX_SAFE_INTEGER,operationsRevision:Number.MAX_SAFE_INTEGER,expiresAt:Number.MAX_SAFE_INTEGER};
  assert.equal(rpc.Canonical(body(),c),expected(body(),c).canonical);
});

test('dispatcher rejects malformed variable-length identity and signature before any authorization lookup', () => {
  rejects(() => rpc.Execute({...body(),requestId:'valid-id\n'}));
  rejects(() => rpc.Execute({...body(),action:'invoke',challengeId:'1'.repeat(48),signature:'A'.repeat(342)+'==\n'}));
  rejects(() => rpc.Execute({...body(),args:Array(1)}));
  rejects(() => rpc.Execute({...body(),unexpected:true}));
});

test('each valid binding field and challenge component independently changes the signed message', () => {
  const base = body(), c = challenge(), original = sha(rpc.Canonical(base,c));
  const patches = [{stage:'A'},{stage:'O'},{sessionId:'C'.repeat(24)},{machineId:'D'.repeat(64)},
    {policyId:'e'.repeat(64)},{requestId:'changed-request'},{functionId:65535},{args:[]}];
  for (const patch of patches) assert.notEqual(sha(rpc.Canonical({...base,...patch},c)),original);
  for (const patch of [{challengeId:'4'.repeat(48)},{nonce:'5'.repeat(48)},{epoch:'6'.repeat(48)},
    {revision:1},{operationsRevision:1},{expiresAt:c.expiresAt+1}]) assert.notEqual(sha(rpc.Canonical(base,{...c,...patch})),original);
});
