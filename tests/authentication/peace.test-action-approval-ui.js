'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Executes the shipped UI functions in a VM. This is not a browser/passkey test.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(MODULE_RESOURCE_ROOT,"../public/scripts/application/peace.admin.js"),'utf8');
const section=source.slice(source.indexOf('let adminReauthenticationPending'),source.indexOf('\nfunction showLogin()',source.indexOf('async function api(')));
function Fixture({method='password',cancel=false,rejectProof=false,changeBody=false,changedPolicy=false,wrongTarget=false}={}){
 const calls=[],proofs=[],modals=[],body={target:'O',value:'reviewed'},action={id:'a'.repeat(48),method:'POST',path:wrongTarget?'/api/another':'/api/test-change',summary:{target:'O'},requestSha512:'b'.repeat(128)};
 const ctx={URL,location:{href:'https://localhost/'},session:{csrf:'live'},dirtyViews:new Set(),currentView:'x',showLogin(){},readableApiError:c=>c,
 openModal:async o=>{modals.push(o);if(changeBody)body.value='unreviewed';return cancel?null:{method,password:'fixture-password'};},reauthenticateWithPasskey:async id=>{proofs.push(id);if(rejectProof)throw Error('PROOF_REJECTED');},
 fetch:async(url,req)=>{calls.push({url,body:req.body,headers:req.headers});const initial=url==='/api/test-change'&&calls.filter(x=>x.url===url).length===1;const failure=changedPolicy&&url==='/api/test-change'&&!initial;
 const status=initial?428:failure?409:200;const row=initial?{ok:false,error:'ADMIN_ACTION_REQUIRED',action}:failure?{ok:false,error:'ADMIN_ACTION_POLICY_CHANGED'}:{ok:true};return {status,ok:status===200,text:async()=>JSON.stringify(row)};}};
 vm.createContext(ctx);vm.runInContext(section+'\nglobalThis.run=api;',ctx);return {run:()=>ctx.run('/api/test-change',{method:'POST',body}),calls,proofs,modals};
}
test('password approves exact action ID and retries once',async()=>{const f=Fixture();await f.run();assert.equal(f.calls.length,3);assert.equal(JSON.parse(f.calls[1].body).actionId,'a'.repeat(48));assert.equal(f.calls[2].headers['X-Admin-Action'],'a'.repeat(48));assert(f.modals[0].message.includes('SHA-512'));});
test('mutable form object is not reread after user confirmation',async()=>{const f=Fixture({changeBody:true});await f.run();assert.equal(f.calls[0].body,f.calls[2].body);assert.equal(JSON.parse(f.calls[2].body).value,'reviewed');});
test('passkey path passes the action ID and never sends a password',async()=>{const f=Fixture({method:'passkey'});await f.run();assert.deepEqual(f.proofs,['a'.repeat(48)]);assert.equal(f.calls.length,2);});
test('cancelled operation is never retried',async()=>{const f=Fixture({cancel:true});await assert.rejects(f.run());assert.equal(f.calls.length,1);});
test('failed passkey never silently downgrades',async()=>{const f=Fixture({method:'passkey',rejectProof:true});await assert.rejects(f.run(),/PROOF_REJECTED/);assert.equal(f.calls.length,1);});
test('server policy change is displayed without another automatic approval',async()=>{const f=Fixture({changedPolicy:true});await assert.rejects(f.run(),/ADMIN_ACTION_POLICY_CHANGED/);assert.equal(f.calls.length,3);assert.equal(f.modals.length,1);});
test('mismatching target response is rejected before authentication',async()=>{const f=Fixture({wrongTarget:true});await assert.rejects(f.run());assert.equal(f.calls.length,1);assert.equal(f.modals.length,0);});
test('operation approval code creates no browser persistent storage',()=>{assert(!/localStorage|sessionStorage|indexedDB/.test(section));});
