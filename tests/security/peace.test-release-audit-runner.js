'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { Worker } = require('node:worker_threads');
const { EventEmitter } = require('node:events');
const { CreateRunner } = require('../../services/security/peace.release-audit-runner');
const source = `const {parentPort,workerData}=require('node:worker_threads');
if(workerData.mode==='hang')while(true){}
if(workerData.mode==='error')throw Error('PRIVATE_TEST_VALUE');
parentPort.postMessage({ok:true,result:{value:workerData.value}});`;
function realRunner(timeoutMs = 1000) {
  const workers = [];
  return { workers, runner: CreateRunner({ timeoutMs, createWorker: workerData => {
    const worker = new Worker(source, { eval: true, workerData, env: {}, execArgv: [] }); workers.push(worker); return worker;
  } }) };
}
test('success waits for actual worker exit and the main event loop remains responsive', async () => {
  const {runner,workers}=realRunner(); let ticked=false;
  const timer=setTimeout(()=>{ticked=true;},0);
  try {assert.deepEqual(await runner.Run({value:42}),{value:42});assert.equal(ticked,true);assert.equal(workers[0].threadId,-1);}
  finally {clearTimeout(timer);await runner.Close();}
});
test('timeout kills a CPU-bound worker and the next request can run', async () => {
  const {runner,workers}=realRunner(1000);
  try {await assert.rejects(runner.Run({mode:'hang'}),{message:'RELEASE_AUDIT_TIMEOUT',status:504});
    assert.equal(workers[0].threadId,-1);assert.deepEqual(await runner.Run({value:8}),{value:8});}
  finally {await runner.Close();}
});
test('abort before submission never starts a worker; disconnect abort terminates running work', async () => {
  const {runner,workers}=realRunner();const first=new AbortController();first.abort();
  try {await assert.rejects(runner.Run({}, {signal:first.signal}),{message:'RELEASE_AUDIT_CANCELLED'});assert.equal(workers.length,0);
    const cancel=new AbortController(),job=runner.Run({mode:'hang'},{signal:cancel.signal});
    setTimeout(()=>cancel.abort(),20);await assert.rejects(job,{message:'RELEASE_AUDIT_CANCELLED'});assert.equal(workers[0].threadId,-1);}
  finally {await runner.Close();}
});
test('one slot stays occupied until termination finishes, with no waiting queue', async () => {
  let worker,finishExit;
  const runner=CreateRunner({createWorker:()=>{worker=new EventEmitter();worker.terminate=()=>new Promise(resolve=>{
    finishExit=()=>{worker.emit('exit',1);resolve(1);};
  });return worker;}});
  const cancel=new AbortController(),first=runner.Run({}, {signal:cancel.signal});
  const failed=assert.rejects(first,{message:'RELEASE_AUDIT_CANCELLED'});
  cancel.abort();
  await assert.rejects(runner.Run({}),{message:'RELEASE_AUDIT_BUSY',status:429});
  worker.emit('message',{ok:true,result:{value:99}}); // a late answer cannot undo cancellation
  finishExit();await failed;await runner.Close();
});
test('worker failures expose a safe code and release the slot', async () => {
  const {runner,workers}=realRunner();
  try {await assert.rejects(runner.Run({mode:'error'}),{message:'RELEASE_AUDIT_FAILED'});assert.equal(workers[0].threadId,-1);
    assert.deepEqual(await runner.Run({value:7}),{value:7});}
  finally {await runner.Close();}
});
test('live administrator authorization is rechecked during long-running work', async () => {
  const {runner,workers}=realRunner();let allowed=true;
  const checkAccess=()=>{if(!allowed){const e=Error('ADMIN_SESSION_EXPIRED');e.desktopError=true;e.status=401;throw e;}};
  const job=runner.Run({mode:'hang'},{checkAccess});setTimeout(()=>{allowed=false;},10);
  try {await assert.rejects(job,{message:'ADMIN_SESSION_EXPIRED',status:401});assert.equal(workers[0].threadId,-1);}
  finally {await runner.Close();}
});
test('shutdown joins the worker and rejects new work', async () => {
  const {runner,workers}=realRunner(),job=runner.Run({mode:'hang'});
  const failed=assert.rejects(job,{message:'RELEASE_AUDIT_CANCELLED'});await runner.Close();await failed;
  assert.equal(workers[0].threadId,-1);await assert.rejects(runner.Run({value:1}),{message:'RELEASE_AUDIT_CLOSED'});
});
test('worker constructor failure cannot leak the busy slot or raw error', async () => {
  const runner=CreateRunner({createWorker:()=>{throw Error('/private/path/SECRET');}});
  await assert.rejects(runner.Run({}),{message:'RELEASE_AUDIT_FAILED'});
  await assert.rejects(runner.Run({}),{message:'RELEASE_AUDIT_FAILED'});await runner.Close();
});

test('termination failure closes the runner without allowing another live worker', async () => {
  let worker, launches=0;
  const runner=CreateRunner({createWorker:()=>{
    launches++;worker=new EventEmitter();worker.terminate=()=>Promise.reject(Error('stop failed'));return worker;
  }});
  const cancel=new AbortController(),job=runner.Run({}, {signal:cancel.signal});cancel.abort();
  await assert.rejects(job,{message:'RELEASE_AUDIT_FAILED'});
  await assert.rejects(runner.Run({}),{message:'RELEASE_AUDIT_CLOSED'});assert.equal(launches,1);
  await assert.rejects(runner.Close(),{message:'stop failed'});
  worker.emit('exit',1);await runner.Close();
});
