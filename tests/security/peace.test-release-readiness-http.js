'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Actual HTTP/login/session/CSRF/step-up/route handlers. Only native authority
// storage is a disposable local test store, never production data.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'release-safety-http-'));
Object.assign(process.env,{DATA_DIR:tmp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'test-only-next123-admin',VIEWER_SECRET:'test-only-next123-viewer',WEB_ADMIN_TRANSPORT:'proxy',WEB_ADMIN_TRUSTED_PROXIES:'127.0.0.1/32,::1/128',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEBAUTHN_RP_ID:'localhost',WEBAUTHN_ORIGIN:'https://localhost',DESKTOP_ADMIN_REAUTH_REQUIRED:'0',DESKTOP_SECURITY_STEP_UP_REQUIRED:'0'});
require("../../core/peace.utilities.js").EnsureDirs();const store=require("../../services/bootstrap/peace.desktop-bootstrap-store"),f={get db(){const d=store.Load();return {active:d.active,artifacts:d.artifacts,launchers:d.launchers,flows:d.flows};}};

const web=require("../../web/authentication/peace.web-auth"),{RequestHandler}=require("../../web/http/peace.web-server"),guard=require("../../services/authentication/peace.desktop-admin-guard");
const prefix='/api/desktop/bootstrap/security-authority/release-readiness',realNow=Date.now;let now=realNow(),server,checks=0;Date.now=()=>now;
async function test(name,fn){await fn();checks++;console.log('PASS '+name);}
function request(route,body,actor,headers={}){return new Promise((resolve,reject)=>{const b=body===undefined?null:Buffer.from(JSON.stringify(body));const req=http.request({host:'127.0.0.1',port:server.address().port,path:route,method:b?'POST':'GET',headers:{Host:'localhost','X-Forwarded-Proto':'https',...(b?{'Content-Type':'application/json','Content-Length':b.length}:{}),...(actor?{Cookie:actor.cookie,'X-CSRF-Token':actor.csrf}:{}),...headers}},res=>{let raw='';res.on('data',v=>raw+=v);res.on('end',()=>{try{resolve({status:res.statusCode,data:JSON.parse(raw),headers:res.headers});}catch(e){reject(e);}});});req.on('error',reject);req.setTimeout(7000,()=>req.destroy(Error('TEST_TIMEOUT')));req.end(b);});}
const approvedRequest=(route,body,actor,headers={})=>require("../fixtures/authentication/peace.action-approval-test-client").Approved(request,route,body,actor,headers);
async function login(role){const r=await request('/api/login',{role,password:role==='admin'?process.env.ADMIN_SECRET:process.env.VIEWER_SECRET});assert.equal(r.status,200,JSON.stringify(r.data));return {cookie:r.headers['set-cookie'][0].split(';')[0],csrf:r.data.csrf};}
(async()=>{try{
 server=http.createServer((req,res)=>Promise.resolve(RequestHandler(req,res)).catch(e=>{res.statusCode=500;res.end(JSON.stringify({error:e.message}));}));
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const admin=await login('admin'),viewer=await login('viewer');
 await test('release byte audit rejects anonymous and viewer sessions',async()=>{
  assert.equal((await request(prefix)).status,401);
  assert.equal((await request(prefix,undefined,viewer)).status,403);
 });
 await test('audit does not accept a mutation or arbitrary target file',async()=>{
  const response=await request(prefix,{path:'/etc/passwd',requireCfg:false},admin);
  assert.equal(response.status,405,JSON.stringify(response.data));
 });
 await test('explicit administrator audit is read only and does not claim native execution',async()=>{
  const before=JSON.stringify(f.db),response=await request(prefix,undefined,admin);
  assert.equal(response.status,200,JSON.stringify(response.data));
  assert.equal(response.data.ok,true);
  assert.equal(response.data.readiness.readOnly,true);
  assert.match(response.headers['cache-control'],/no-store/);
  assert.equal(JSON.stringify(f.db),before);
  assert(!JSON.stringify(response.data).includes(process.env.ADMIN_SECRET));
  assert(!JSON.stringify(response.data).includes(tmp));
 });
 await test('repeated expensive audits are bounded by server monotonic cooldown',async()=>{
  const response=await request(prefix,undefined,admin);
  assert.equal(response.status,429,JSON.stringify(response.data));
  assert.equal(response.data.error,'RELEASE_AUDIT_RATE_LIMITED');
  assert.equal(response.headers['retry-after'],'3');
 });
 console.log('Release readiness HTTP: '+checks+' passed; actual HTTP authentication/route, synthetic release storage only.');
}catch(e){console.error(e.stack);process.exitCode=1;}finally{Date.now=realNow;if(server)await new Promise(r=>server.close(r));fs.rmSync(tmp,{recursive:true,force:true});}})();
