'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),Module=require('node:module');
const {EventEmitter}=require('node:events');
function harness(){
 let allowed=true,options,resolve,reject;const writes=[];
 const filename=require.resolve('../../web/routes/security/peace.desktop-security-routes'),loaded=new Module(filename,module);
 const audit={AuditActive:o=>{options=o;return new Promise((yes,no)=>{resolve=yes;reject=no;
  o.signal.addEventListener('abort',()=>no(Error('RELEASE_AUDIT_CANCELLED')),{once:true});});}};
 const mocks={
  '../../../services/security/peace.desktop-security-authority':{},
  '../../../services/security/peace.desktop-security-operations':{},
  '../../../services/authentication/peace.desktop-admin-guard':{CheckSession:()=>allowed?{ok:true}:{ok:false,status:401,reason:'ADMIN_SESSION_EXPIRED'}},
  '../../../services/security/peace.release-readiness':audit,
  '../../http/peace.api-context':{Json:(res,status,body)=>writes.push({status,body}),ApiError:(res,status,error)=>writes.push({status,error})}
 };
 loaded.filename=filename;loaded.require=name=>{assert.ok(Object.hasOwn(mocks,name),name);return mocks[name];};
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);
 const req=new EventEmitter(),res=new EventEmitter();res.setHeader=()=>{};
 const run=()=>loaded.exports.Handle({method:'GET',pathname:'/api/desktop/bootstrap/security-authority/release-readiness',req,res,session:{role:'admin',id:'test'}});
 return {run,req,res,writes,get options(){return options;},resolve:value=>resolve(value),revoke:()=>{allowed=false;}};
}
test('normal request close does not cancel the outstanding response',async()=>{
 const h=harness(),work=h.run();h.req.emit('close');assert.equal(h.options.signal.aborted,false);
 h.resolve({scope:'TEST'});assert.equal(await work,true);assert.equal(h.writes[0].status,200);
 assert.equal(h.req.listenerCount('aborted'),0);assert.equal(h.res.listenerCount('close'),0);
});
test('response disconnect cancels work and writes no response to the dead socket',async()=>{
 const h=harness(),work=h.run();h.res.destroyed=true;h.res.emit('close');
 assert.equal(h.options.signal.aborted,true);await work;assert.equal(h.writes.length,0);
 assert.equal(h.req.listenerCount('aborted'),0);assert.equal(h.res.listenerCount('close'),0);
});
test('session revoked during the await cannot receive a completed diagnostic',async()=>{
 const h=harness(),work=h.run();h.revoke();h.resolve({scope:'TEST'});await work;
 assert.deepEqual(h.writes,[{status:401,error:'ADMIN_SESSION_EXPIRED'}]);
 assert.equal(h.req.listenerCount('aborted'),0);assert.equal(h.res.listenerCount('close'),0);
});
