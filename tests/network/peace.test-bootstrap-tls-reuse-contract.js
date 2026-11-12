'use strict';
// Pure production protocol gates: no live server, keys, DB or production reset.
const test=require('node:test'),assert=require('node:assert/strict');
const {performance}=require('node:perf_hooks');
const gate=require('../../services/network/peace.desktop-connect');
const frame={v:1,keyId:'a'.repeat(64),requestId:'d2cf398a-8322-4e1a-98c6-b8b000000001',wrappedKey:'encoded',nonce:'encoded',ciphertext:'encoded',tag:'encoded'};
const chunk={operation:'bootstrap',body:{action:'chunk',flowId:'KNOWN_FLOW',downloadTicket:'opaque'}};
test('legacy TLS request frame remains strict and unchanged',()=>{
 assert.equal(gate.FrameShape(frame),true);
 assert.equal(gate.FrameShape({...frame,keepAlive:1}),true);
 for(const value of [undefined,0,2,true,'1',null,{}])assert.equal(gate.FrameShape({...frame,keepAlive:value}),false);
 for(const value of [[],null,'x',Object.assign(Object.create(null),frame),{...frame,privateKey:'forbidden'}])assert.equal(gate.FrameShape(value),false);
});
test('TLS reuse requires authenticated chunk success and a fresh per-frame deadline',()=>{
 const hard=performance.now()+60000;
 assert.equal(gate.CanReuseBootstrap({...frame,keepAlive:1},chunk,{ok:true},1,hard),true);
 const cases=[
  [frame,chunk,{ok:true},1,hard],
  [{...frame,keepAlive:1},{operation:'security',body:chunk.body},{ok:true},1,hard],
  [{...frame,keepAlive:1},{operation:'bootstrap',body:{...chunk.body,action:'finish'}},{ok:true},1,hard],
  [{...frame,keepAlive:1},chunk,{ok:false,error:'BOOTSTRAP_FLOW_INVALID'},1,hard],
  [{...frame,keepAlive:1},chunk,{ok:true},256,hard],
  [{...frame,keepAlive:1},chunk,{ok:true},1,performance.now()+1],
  [{...frame,keepAlive:1},{...chunk,body:{...chunk.body,flowId:''}},{ok:true},1,hard]
 ];
 for(const args of cases)assert.equal(gate.CanReuseBootstrap(...args),false);
});
test('reused TLS connection cannot change its flow or operation',()=>{
 assert.equal(gate.SameBootstrapFlow('',{operation:'challenge',body:{}}),true);
 assert.equal(gate.SameBootstrapFlow('KNOWN_FLOW',chunk),true);
 for(const payload of [
  {...chunk,body:{...chunk.body,flowId:'OTHER_FLOW'}},
  {...chunk,body:{...chunk.body,action:'finish'}},
  {...chunk,operation:'security'},null,{}
 ])assert.equal(gate.SameBootstrapFlow('KNOWN_FLOW',payload),false);
});
