'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const net=require('node:net'),http=require('node:http'),crypto=require('node:crypto'),{spawn}=require('node:child_process');
async function port(){const s=net.createServer();await new Promise((r,j)=>s.listen(0,'127.0.0.1',r).once('error',j));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
function request(p){return new Promise((resolve,reject)=>{const req=http.get({host:'127.0.0.1',port:p,path:'/readyz',timeout:500},res=>{res.resume();res.once('end',()=>resolve(res.statusCode));});req.once('timeout',()=>req.destroy(Error('TIMEOUT')));req.once('error',reject);});}
const delay=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'peace-process-lifecycle-'));fs.chmodSync(dir,0o700);
 let child,exited=false,exitCode=null,logs='';
 try{
  const web=await port(),tcp=await port();
  const env={...process.env,DATA_DIR:dir,NODE_ENV:'production',HA_ENABLED:'0',CONNECT_TCP_HOST:'127.0.0.1',STORAGE_ENGINE:'sqlite',PORT:String(web),WEB_ADMIN_PORT:String(web),CONNECT_TCP_PORT:String(tcp),HEALTH_PORT:'0',WEB_ADMIN_TRANSPORT:'railway',WEB_ADMIN_RAILWAY_EDGE_ONLY:'1',WEB_ADMIN_HOST:'0.0.0.0',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEB_ADMIN_TRUSTED_PROXIES:'',RAILWAY_PROJECT_ID:'11111111-1111-4111-8111-111111111111',RAILWAY_ENVIRONMENT_ID:'22222222-2222-4222-8222-222222222222',RAILWAY_SERVICE_ID:'33333333-3333-4333-8333-333333333333',WEBAUTHN_RP_ID:'admin.example.test',WEBAUTHN_ORIGIN:'https://admin.example.test',ADMIN_SECRET:crypto.randomBytes(48).toString('base64url')};
  delete env.DESKTOP_RECOVERY_WITNESS_REQUIRED;delete env.DESKTOP_RECOVERY_WITNESS_URL;
  const probe="const M=require('node:module'),P=require('node:path'),original=M._resolveFilename;M._resolveFilename=function(request,parent,...rest){try{return original.call(this,request,parent,...rest);}catch(error){if(error.code==='MODULE_NOT_FOUND')console.error('[TEST_MODULE_LOAD_FAILURE]',JSON.stringify({request,parent:parent?.filename?P.relative(process.cwd(),parent.filename):''}));throw error;}};require(process.argv[1]);";
  child=spawn(process.execPath,['-e',probe,path.resolve(MODULE_RESOURCE_ROOT,'../peace.relay-server.js')],{cwd:path.resolve(MODULE_RESOURCE_ROOT,'..'),env,stdio:['ignore','pipe','pipe']});
  const capture=b=>{logs=(logs+b.toString()).slice(-16384);};child.stdout.on('data',capture);child.stderr.on('data',capture);
  const ended=new Promise(resolve=>child.once('exit',(code,signal)=>{exited=true;exitCode=code;resolve({code,signal});}));
  let ready=false;const started=Date.now();
  while(Date.now()-started<20000&&!exited){try{if(await request(web)===200){ready=true;break;}}catch{}await delay(100);}
  assert.ok(ready,'real Railway-mode server must become ready; '+logs);
  child.kill('SIGTERM');
  let timer;const outcome=await Promise.race([ended,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SERVER_SHUTDOWN_DEADLINE')),11000);})]).finally(()=>clearTimeout(timer));
  assert.equal(outcome.code,0,'SIGTERM must complete final writes and exit normally');
  await assert.rejects(request(web));
  assert.ok(fs.existsSync(path.join(dir,'relay.db')),'durable database must exist');
  console.log('PASS actual Railway-mode startup, readiness, SQLite persistence, SIGTERM exit and closed listener');
 }finally{
  if(child&&!exited){child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));}
  fs.rmSync(dir,{recursive:true,force:true});
 }
})().catch(e=>{console.error(e.message);process.exitCode=1;});
