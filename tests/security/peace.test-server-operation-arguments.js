'use strict';
// Internal entry-point regression: the network dispatcher already rejects
// sparse arrays. The server evaluator must enforce that boundary independently.
// No application, session, key, database or Windows process is created here.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const vm = require('../../services/artifacts/peace.cozy-protection-engine');
const policy = require('../../services/artifacts/peace.server-policy-protection');
const profile = {version:1,functions:[{id:2,args:2,body:{op:'add',left:{op:'arg',index:0},right:{op:'arg',index:1}}}]};
function Record(role) {
  const program = vm.Compile(profile,role);
  const policySha512 = crypto.createHash('sha512').update('COZY-SERVER-POLICY-PROGRAM-V2\n'+role+'\n').update(program).digest('hex');
  return {program,record:{version:2,role,policyId:policy.PolicyId(role,policySha512),policySha512,
    functionCount:2,maxSteps:vm.MAX_STEPS,programBase64:program.toString('base64')}};
}
function Malformed() {
  const inherited = Array(2); Object.setPrototypeOf(inherited,{0:17,1:25});
  const extra = [17,25]; extra.untrusted = true;
  const hidden = [17,25]; Object.defineProperty(hidden,'untrusted',{value:true});
  const symbol = [17,25]; symbol[Symbol('untrusted')] = true;
  const accessor = [17,25]; Object.defineProperty(accessor,'0',{get(){throw Error('UNTRUSTED_GETTER_EXECUTED');}});
  class CustomArray extends Array {}
  return [Array(2),[17,,],inherited,extra,hidden,symbol,accessor,new CustomArray(17,25),
    null,{},[17],[17,25,1],[NaN,1],[Infinity,1],[2147483648,1],[-2147483649,1],[true,1],['17',25]];
}
test('all server policy layers reject sparse, inherited and accessor Int32 input without evaluating it',()=>{
  for(const role of ['A','B','O']) {
    const {program,record} = Record(role);
    try {
      for(const args of Malformed()) {
        assert.throws(()=>policy.ValidateInvocation(record,2,args),/COZY_SERVER_POLICY_(INVOCATION_INVALID|FUNCTION_NOT_ALLOWED)/);
        assert.throws(()=>policy.EvaluateServerPolicy(record,2,args),/COZY_PROTECTION_ARGUMENT_INVALID/);
        assert.throws(()=>vm.Evaluate(program,2,args,{role}),/COZY_PROTECTION_ARGUMENT_INVALID/);
      }
    } finally {program.fill(0);}
  }
});
test('ordinary and frozen dense arguments retain exact Int32 arithmetic for A/B/O',()=>{
  for(const role of ['A','B','O']) {
    const {program,record} = Record(role);
    try {
      for(const [args,result] of [[[17,25],42],[Object.freeze([17,25]),42],[[2147483647,1],-2147483648],[[-2147483648,-1],2147483647]]) {
        assert.doesNotThrow(()=>policy.ValidateInvocation(record,2,args));
        assert.equal(policy.EvaluateServerPolicy(record,2,args),result);
        assert.equal(vm.Evaluate(program,2,args,{role}),result);
      }
      for(const other of ['A','B','O'].filter(v=>v!==role)) {
        assert.throws(()=>vm.Evaluate(program,2,[17,25],{role:other}),/COZY_PROTECTION_PROGRAM_INVALID/);
        assert.throws(()=>policy.EvaluateServerPolicy({...record,role:other},2,[17,25]),/COZY_SERVER_POLICY_RECORD_COMMITMENT_MISMATCH/);
      }
    } finally {program.fill(0);}
  }
});
