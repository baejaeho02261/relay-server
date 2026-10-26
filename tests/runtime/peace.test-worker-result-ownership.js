'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {EventEmitter}=require('node:events'),{createRequire}=require('node:module');

// Execute the actual queue implementation with only its clock and Worker event
// transport controlled. Real CPU worker behavior is tested separately.
function Harness(){
 const filename=path.resolve(__dirname,'../../services/runtime/peace.desktop-work-queue.js');
 const localRequire=createRequire(filename),clock={value:0,ticks:[]},workers=[];
 class Worker extends EventEmitter{
  constructor(){super();workers.push(this);}
  ref(){} unref(){}
  postMessage(message){if(message.close)queueMicrotask(()=>this.emit('exit',0));else this.submitted=message;}
  terminate(){queueMicrotask(()=>this.emit('exit',0));return Promise.resolve(0);}
 }
 const module={exports:{}};
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),{
  require:name=>name==='node:worker_threads'?{Worker}:name==='node:perf_hooks'?{performance:{now:()=>clock.ticks.length?clock.ticks.shift():clock.value}}:localRequire(name),
  module,exports:module.exports,__dirname:path.dirname(filename),Buffer,ArrayBuffer,SharedArrayBuffer,Object,
  structuredClone,setTimeout,clearTimeout,console,
 },{filename});
 return {queue:new module.exports.WorkQueue('ownership-test',1,1),clock,workers};
}
function Result(){return {bytes:Buffer.from('public executable fixture'),key:Buffer.alloc(32,7),serverPolicy:{programBase64:'server-only-fixture'}};}

test('successful worker result ownership survives a deadline crossing after the accept decision',async()=>{
 const {queue,clock,workers}=Harness(),pending=queue.run({kind:'fixture'},10000),value=Result();
 const expectedBytes=Buffer.from(value.bytes),expectedKey=Buffer.from(value.key);
 try{
  // finishRun and the acceptance decision see a live deadline. Any subsequent
  // clock read is expired and must not revoke/wipe an already accepted result.
  clock.value=10001;clock.ticks=[9999,9999];
  workers[0].emit('message',{id:workers[0].submitted.id,value});
  const result=await pending;
  assert.equal(result,value);assert.deepEqual(result.bytes,expectedBytes);assert.deepEqual(result.key,expectedKey);
  assert.equal(result.serverPolicy.programBase64,'server-only-fixture');
  assert.equal(queue.snapshot().completed,1);assert.equal(queue.snapshot().timedOut,0);
 }finally{value.bytes.fill(0);value.key.fill(0);await queue.close();}
});

test('expired worker results are rejected and their caller-owned buffer copies are cleared',async()=>{
 const {queue,clock,workers}=Harness(),pending=queue.run({kind:'fixture'},10000),value=Result();
 try{
  clock.value=10000;
  workers[0].emit('message',{id:workers[0].submitted.id,value});
  await assert.rejects(pending,/WORK_DEADLINE/);
  assert(value.bytes.every(byte=>byte===0));assert(value.key.every(byte=>byte===0));
  assert.equal(value.serverPolicy.programBase64,'');assert.equal(queue.snapshot().timedOut,1);
 }finally{await queue.close();}
});
