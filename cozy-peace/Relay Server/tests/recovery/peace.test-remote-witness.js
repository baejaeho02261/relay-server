'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
const {WitnessFile}=require("../../services/recovery/peace.recovery-witness-file"),{DOMAINS}=require("../../services/recovery/peace.remote-witness-protocol"),tls=require("../../services/network/peace.server-peer-tls");
const {RemoteWitness}=require("../../services/recovery/peace.remote-witness-client");
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'remote-witness-test-')),cert=require("../fixtures/network/peace.next456-tls-fixture").Certificates(tmp),dir=path.join(tmp,'independent');fs.mkdirSync(dir,{mode:0o700});
const zero={seq:0,hash:'0'.repeat(64)},hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const witness=new WitnessFile(dir);witness.enroll(Object.fromEntries(DOMAINS.map(n=>[n,zero])));
const conf={dir,clientPin:tls.Digest(fs.readFileSync(cert.client.cert)),tls:{ca:fs.readFileSync(cert.ca,'utf8'),cert:fs.readFileSync(cert.server.cert,'utf8'),key:fs.readFileSync(cert.server.key,'utf8'),minVersion:'TLSv1.2',requestCert:true,rejectUnauthorized:true}};
fs.writeFileSync(path.join(tmp,'server.json'),JSON.stringify(conf),{mode:0o600});
let child,config,client;const clients=[];
const make=(extra={})=>{const c=new RemoteWitness({...config,...extra});clients.push(c);return c;};
test.before(async()=>{child=cp.fork(path.join(MODULE_RESOURCE_ROOT,"recovery/peace.witness-tls-child.js"),[path.join(tmp,'server.json')],{stdio:['ignore','pipe','pipe','ipc']});let log='';child.stderr.on('data',b=>log+=b);const r=await Promise.race([new Promise((resolve,reject)=>{child.once('message',resolve);child.once('exit',c=>reject(Error('child '+c+' '+log)));}),new Promise((_r,j)=>{const t=setTimeout(()=>j(Error('TEST_CHILD_TIMEOUT')),5000);t.unref();})]);config={url:`https://127.0.0.1:${r.port}`,installationId:r.installationId,ca:cert.ca,cert:cert.client.cert,key:cert.client.key,pin:tls.Digest(fs.readFileSync(cert.server.cert)),timeoutMs:3000};client=make();});
test.after(async()=>{for(const c of clients)await c.close();if(child){child.send('close');await new Promise(r=>child.once('exit',r));}fs.rmSync(tmp,{recursive:true,force:true});});
test('pinned mTLS status matches the pre-enrolled installation',()=>{const s=client.status();assert.equal(s.installationId,config.installationId);assert.equal(s.transport,'PINNED_MUTUAL_TLS');});
for(const name of DOMAINS)test(name+' durable high-water rejects old backup',()=>{const next={seq:1,hash:hash(name+' consumed/revoked')};client.open(name,zero);client.prepare(name,zero,next);client.settle(name,next);assert.equal(client.head(name).current.hash,next.hash);const restored=make();assert.throws(()=>restored.open(name,zero),/ROLLBACK_DETECTED/);assert.equal(client.head(name).current.hash,next.hash);});
test('exact prepare and settle retry are idempotent',()=>{const name=DOMAINS[0],current=client.head(name).current,next={seq:2,hash:hash('next')};client.prepare(name,current,next);const v=client.status().revision;client.prepare(name,current,next);assert.equal(client.status().revision,v);client.settle(name,next);const committed=client.status().revision;client.settle(name,next);assert.equal(client.status().revision,committed);});
test('normal settle cannot rewind a pending append',()=>{const name=DOMAINS[0],current=client.head(name).current,next={seq:3,hash:hash('pending')};client.prepare(name,current,next);const bad=make();assert.throws(()=>bad.settle(name,current),/CONFLICT/);const startup=make();assert.throws(()=>startup.open(name,current),/UNRESOLVED_WRITE/);client.open(name,next);assert.equal(client.head(name).current.seq,3);});
test('startup resolves a durable but unacknowledged next head',()=>{const name=DOMAINS[0],current=client.head(name).current,next={seq:4,hash:hash('durable pending')};client.prepare(name,current,next);const restarted=make();restarted.open(name,next);assert.equal(restarted.head(name).current.seq,4);});
test('one-store future/changed hash and stale prepare are rejected',()=>{const c=make();assert.throws(()=>c.open(DOMAINS[1],{seq:99,hash:hash('future')}),/ROLLBACK/);const d=make();assert.throws(()=>d.prepare(DOMAINS[1],zero,{seq:1,hash:hash('other')}),/CONFLICT/);});
test('unknown domain is never auto-created',()=>{assert.throws(()=>client.head('NEW_DOMAIN'),/DOMAIN_INVALID/);assert.equal(Object.keys(client.status().heads).length,4);});
test('foreign installation is not silently adopted',()=>{const c=make({installationId:'f'.repeat(64)});assert.throws(()=>c.status(),/INSTALLATION_MISMATCH/);});
test('untrusted client with same CA is rejected by SPKI pin',()=>{const c=make({cert:cert.stranger.cert,key:cert.stranger.key});assert.throws(()=>c.status(),/UNAVAILABLE/);});
test('wrong server SPKI pin is rejected',()=>{const c=make({pin:'f'.repeat(128)});assert.throws(()=>c.status(),/UNAVAILABLE/);});
test('network failure fences future calls, no local fallback',()=>{const c=make({url:'https://127.0.0.1:1',timeoutMs:1200});assert.throws(()=>c.status(),/UNAVAILABLE|TIMEOUT/);assert.throws(()=>c.status(),/RESTART_REQUIRED/);});
test('witness file deletion is a failure, not enrollment',()=>{const original=fs.readFileSync(witness.file);fs.unlinkSync(witness.file);try{const c=make();assert.throws(()=>c.status(),/IO_FAILED/);assert.equal(fs.existsSync(witness.file),false);}finally{fs.writeFileSync(witness.file,original,{mode:0o600});}});
test('enrollment cannot replace an existing witness',()=>{assert.throws(()=>witness.enroll(Object.fromEntries(DOMAINS.map(n=>[n,zero]))),/ALREADY_ENROLLED/);});
test('close joins one worker termination and fences later calls',async()=>{
 const c=make();c.status();const first=c.close();assert.equal(c.close(),first);await first;
 assert.equal(c.worker.threadId,-1);assert.throws(()=>c.status(),/RESTART_REQUIRED/);
});
test('network failure terminates its worker without waiting for application shutdown',async()=>{
 const c=make({url:'https://127.0.0.1:1',timeoutMs:1200});assert.throws(()=>c.status(),/UNAVAILABLE|TIMEOUT/);
 assert.ok(c.closing);await c.closing;assert.equal(c.worker.threadId,-1);
});
test('witness close is idempotent and bounds a partial TLS connection',async t=>{
 const {CreateServer,CloseServer}=require("../../tools/recovery/peace.recovery-witness-server");
 const server=CreateServer(conf,witness);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const peer=require('node:net').connect(server.address().port,'127.0.0.1');t.after(()=>peer.destroy());
 await new Promise((resolve,reject)=>{peer.once('connect',resolve);peer.once('error',reject);});
 const first=CloseServer(server,{timeoutMs:100});assert.equal(CloseServer(server,{timeoutMs:100}),first);
 await first;assert.equal(server.listening,false);
});
test('SIGTERM drains witness sockets and exits without a background server',async t=>{
 const peer=require('node:net').connect(new URL(config.url).port,'127.0.0.1');t.after(()=>peer.destroy());
 await new Promise((resolve,reject)=>{peer.once('connect',resolve);peer.once('error',reject);});
 const running=child;let timer;
 const exit=new Promise(resolve=>running.once('exit',(code,signal)=>resolve({code,signal})));
 running.kill('SIGTERM');
 try{
  const result=await Promise.race([exit,new Promise((_,reject)=>{timer=setTimeout(()=>{running.kill('SIGKILL');reject(Error('WITNESS_SHUTDOWN_TIMEOUT'));},3000);})]);
  assert.deepEqual(result,{code:0,signal:null});child=null;
 }finally{clearTimeout(timer);}
});
