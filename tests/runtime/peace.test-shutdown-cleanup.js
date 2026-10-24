'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
function load(relative,dependencies={},globals={}){
 const module={exports:{}},cached={};
 const req=name=>Object.hasOwn(dependencies,name)?dependencies[name]:require(name);
 req.resolve=name=>name;req.cache=cached;
 for(const [name,value]of Object.entries(dependencies))cached[name]={exports:value};
 vm.runInNewContext(fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,'..',relative),'utf8'),{require:req,module,exports:module.exports,console,Buffer,AbortController,setTimeout,clearTimeout,setInterval,clearInterval,...globals},{filename:relative});
 return module.exports;
}
test('shutdown joins hooks and workers before durable saves, then closes witness once',async()=>{
 const order=[];let unblock;const gate=new Promise(r=>unblock=r),timers=new Set(),exits=[];
 const dependencies={
  '../config/peace.runtime-configuration':{},'./peace.runtime-state':{},
  "../storage/snapshots/peace.backup.js":{CreateBackup:()=>order.push('backup')},
  "../storage/snapshots/peace.database.js":{SaveDatabase:()=>order.push('save')},
  "../services/runtime/peace.desktop-work-queue":{auth:{close:async()=>{order.push('queue');await gate;order.push('queue-done');}}},
  "../services/recovery/peace.desktop-recovery-witness":{Close:()=>order.push('witness-close')},
  "../storage/sqlite/peace.sqlite-database":{Close:()=>order.push('sqlite-close')},
  "../services/observability/peace.desktop-performance-metrics":{Close:()=>order.push('metrics-close')}
 };
 const api=load('core/peace.lifecycle.js',dependencies,{process:{exit:code=>exits.push(code)},setTimeout:()=>{const t={unref(){}};timers.add(t);return t;},clearTimeout:t=>timers.delete(t)});
 api.MarkStorageReady();
 api.RegisterShutdownHook(async()=>{order.push('listener');await gate;order.push('listener-done');});
 const first=api.Shutdown(),second=api.Shutdown();assert.equal(first,second);
 await Promise.resolve();assert.equal(order.includes('save'),false);unblock();await first;
 assert.ok(order.indexOf('queue-done')<order.indexOf('save'));
 assert.ok(order.indexOf('listener-done')<order.indexOf('save'));
 assert.ok(order.indexOf('save')<order.indexOf('witness-close'));
 assert.deepEqual(exits,[0]);assert.equal(timers.size,0);assert.equal(order.filter(x=>x==='save').length,1);
});
test('startup failure closes loaded resources without creating database or backup state',async()=>{
 const writes=[],closed=[],exits=[];
 const api=load('core/peace.lifecycle.js',{
  '../config/peace.runtime-configuration':{},'./peace.runtime-state':{},
  "../storage/snapshots/peace.backup.js":{CreateBackup:()=>writes.push('backup')},
  "../storage/snapshots/peace.database.js":{SaveDatabase:()=>writes.push('save')},
  "../services/recovery/peace.desktop-recovery-witness":{Close:()=>closed.push('witness')}
 },{process:{exit:code=>exits.push(code)}});
 await api.Shutdown(1);assert.deepEqual(writes,[]);assert.deepEqual(closed,['witness']);assert.deepEqual(exits,[1]);
});
test('packing shutdown aborts active request, erases source and releases lease without output retention',async()=>{
 const input=Buffer.from('sensitive executable'),released=[],retained=[],intervals=[];let entered=false;
 const ids={A:'A'.repeat(24),B:'B'.repeat(24),O:'C'.repeat(24)};
 const rows=Object.fromEntries(Object.entries(ids).map(([component,key])=>[key,{component,size:input.length,sha512:'hash'}]));
 const protocol={Fail:code=>{throw Error(code);}};
 const api=load("services/artifacts/peace.desktop-packing-jobs.js",{
  './peace.desktop-packing-protocol':protocol,
  './peace.desktop-packing-client':{Status:()=>({configured:true}),Pack:(_c,_b,_id,{signal})=>{entered=true;return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(Error('PACKING_CANCELLED')),{once:true}));}},
  "../authentication/peace.desktop-admin-guard":{CheckSession:()=>({ok:true})},"../../web/authentication/peace.web-auth":{IsSessionActive:()=>true},
  "../bootstrap/peace.desktop-bootstrap":{Initialize:()=>({artifacts:rows}),AssertSecurityAvailable(){},ReadArtifactBytes:()=>input},
  "../runtime/peace.server-resource-budget":{Admit:()=>({release:()=>released.push(1),retain:()=>retained.push(1)})},
  "../../storage/audit/peace.audit.js":{LogEvent(){}}
 },{setInterval:()=>{const t={unref(){}};intervals.push(t);return t;},clearInterval:t=>intervals.splice(intervals.indexOf(t),1)});
 const localBody=api.Begin.constructor('return '+JSON.stringify(ids))();
 api.Begin(localBody,{id:'admin'});await Promise.resolve();assert.equal(entered,true);await api.Stop();await api.Stop();
 assert.ok(input.every(x=>x===0));assert.ok(released.length>=1);assert.equal(retained.length,0);assert.equal(intervals.length,0);
 assert.throws(()=>api.Begin(localBody,{id:'admin'}),/PACKING_STOPPED/);
});
