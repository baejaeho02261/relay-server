'use strict';
// Actual HTTP dispatcher, administrator sessions and CSRF. No public service,
// Windows executable or operator credential is used by this test.
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-packed-release-http-'));
Object.assign(process.env,{DATA_DIR:directory,STORAGE_ENGINE:'json',HA_ENABLED:'0',
 ADMIN_SECRET:'fixture-packed-release-admin',VIEWER_SECRET:'fixture-packed-release-viewer',
 WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',
 WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',
 DESKTOP_ADMIN_REAUTH_REQUIRED:'0',DESKTOP_SECURITY_STEP_UP_REQUIRED:'0'});
require('../../core/peace.utilities').EnsureDirs();
const {RequestHandler}=require('../../web/http/peace.web-server');
const prefix='/api/desktop/bootstrap/security-operations';
let server;
function call(route,body,session,csrf=true){
 return new Promise((resolve,reject)=>{
  const bytes=body===undefined?null:Buffer.from(JSON.stringify(body));
  const request=http.request({host:'127.0.0.1',port:server.address().port,path:route,method:bytes?'POST':'GET',
   headers:{Host:'localhost','X-Forwarded-Proto':'https',...(bytes?{'Content-Type':'application/json','Content-Length':bytes.length}:{}),
    ...(session?{Cookie:session.cookie,...(csrf?{'X-CSRF-Token':session.csrf}:{})}:{})}},response=>{
   let text='';response.on('data',chunk=>text+=chunk);response.on('end',()=>{
    try{resolve({status:response.statusCode,data:JSON.parse(text),headers:response.headers});}catch(error){reject(error);}
   });
  });
  request.on('error',reject);request.setTimeout(5000,()=>request.destroy(Error('FIXTURE_HTTP_TIMEOUT')));request.end(bytes);
 });
}
async function login(role){
 const result=await call('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});
 assert.equal(result.status,200);
 return {cookie:result.headers['set-cookie'][0].split(';')[0],csrf:result.data.csrf};
}
(async()=>{
 let exitCode=0;
 try{
  server=http.createServer((request,response)=>Promise.resolve(RequestHandler(request,response)).catch(()=>{
   response.writeHead(500,{'Content-Type':'application/json'});response.end('{"error":"FIXTURE_HANDLER_FAILED"}');
  }));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  assert.equal((await call(prefix+'/packed-release-jobs')).status,401);
  assert.equal((await call(prefix+'/plan-packed-release',{})).status,401);
  const viewer=await login('viewer');
  assert.equal((await call(prefix+'/packed-release-jobs',undefined,viewer)).status,403);
  assert.equal((await call(prefix+'/plan-packed-release',{},viewer)).status,403);
  const admin=await login('admin'),listing=await call(prefix+'/packed-release-jobs',undefined,admin);
  assert.equal(listing.status,200);assert.equal(listing.data.ok,true);assert.deepEqual(listing.data.jobs,[]);
  const request={jobId:'a'.repeat(32),expectedRevision:listing.data.expectedRevision,expectedPolicyRevision:listing.data.expectedPolicyRevision};
  assert.equal((await call(prefix+'/plan-packed-release',request,admin,false)).data.error,'CSRF_FAILED');
  const malformed=await call(prefix+'/plan-packed-release',{...request,manifest:{artifacts:{A:'client-claimed-hash'}}},admin);
  assert.equal(malformed.status,400);assert.equal(malformed.data.error,'PACKED_RELEASE_REQUEST_INVALID');
  const missing=await call(prefix+'/plan-packed-release',request,admin);
  assert.equal(missing.status,404);assert.equal(missing.data.error,'PACKED_RELEASE_JOB_NOT_FOUND');
  assert.deepEqual((await call(prefix+'/packed-release-jobs',undefined,admin)).data.jobs,[]);
  console.log('PASS packed release HTTP: anonymous/viewer denial, admin read, CSRF, exact request schema, durable-job lookup and no claimed-hash admission');
 }catch(error){exitCode=1;console.error(error.stack||error.message);}
 finally{
  if(server){server.closeAllConnections?.();await new Promise(resolve=>server.close(resolve));}
  fs.rmSync(directory,{recursive:true,force:true});process.exit(exitCode);
 }
})();
