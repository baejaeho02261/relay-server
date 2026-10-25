'use strict';
// Real Linux server processes and synthetic PE fixtures. This does not execute
// native Windows code, generate release approvals, or contact production.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto'),http=require('node:http'),net=require('node:net');
const {spawn,spawnSync}=require('node:child_process');
const ROOT=path.resolve(__dirname,'../..');
const entry=require.resolve('../../peace.relay-server');
const modules={
  utilities:require.resolve('../../core/peace.utilities'),
  database:require.resolve('../../storage/snapshots/peace.database'),
  sqlite:require.resolve('../../storage/sqlite/peace.sqlite-database'),
  store:require.resolve('../../services/bootstrap/peace.desktop-bootstrap-store'),
  bootstrap:require.resolve('../../services/bootstrap/peace.desktop-bootstrap'),
  licenses:require.resolve('../../services/licensing/peace.desktop-licenses'),
  fixture:require.resolve('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),
  state:require.resolve('../../core/peace.runtime-state'),
  workspace:require.resolve('../../services/operations/peace.desktop-workspace-store'),
  machine:require.resolve('../../services/devices/peace.desktop-machine-policy'),
  integrity:require.resolve('../../services/integrity/peace.desktop-integrity-reports'),
  witness:require.resolve('../../services/recovery/peace.recovery-witness-file'),
  reset:require.resolve('../../services/operations/peace.registration-reset'),
  resetBootstrap:require.resolve('../../services/bootstrap/peace.desktop-registration-reset')
};
const SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function within(promise,ms){let timer;try{return await Promise.race([promise,new Promise(resolve=>{timer=setTimeout(()=>resolve({timeout:true}),ms);})]);}finally{clearTimeout(timer);}}
async function freePort(){const s=net.createServer();await new Promise((resolve,reject)=>s.listen(0,'127.0.0.1',resolve).once('error',reject));const p=s.address().port;await new Promise(resolve=>s.close(resolve));return p;}
function request(port){return new Promise((resolve,reject)=>{const req=http.get({host:'127.0.0.1',port,path:'/readyz',timeout:300},res=>{res.resume();res.once('end',()=>resolve(res.statusCode));});req.once('timeout',()=>req.destroy(Error('REQUEST_TIMEOUT')));req.once('error',reject);});}
function runScript(env,body){
  const script='const M='+JSON.stringify(modules)+';'+body;
  const r=spawnSync(process.execPath,['-e',script],{cwd:ROOT,env,encoding:'utf8',timeout:30000,maxBuffer:1024*1024});
  assert.equal(r.error,undefined,r.error?.message);assert.equal(r.status,0,r.stderr+'\n'+r.stdout);
  const marker=r.stdout.lastIndexOf('MAINT_TEST:');assert.ok(marker>=0,r.stdout);return JSON.parse(r.stdout.slice(marker+11));
}
const SNAPSHOT=`
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();
const b=require(M.store).Load(),l=require(M.licenses).DB(),state=require(M.state);
const hash=x=>crypto.createHash('sha512').update(x).digest('hex'),root=process.env.DATA_DIR;
const keyFiles=['connect-transport-key.pem','connect-transport-key.id','connect-tls.sha256','desktop-key-purposes.json','desktop-key-purposes.initialized','desktop-license-journal.key','desktop-machine-policy/authority.key','desktop-integrity-reports/authority.key','fixture-custom-package.key'];
function files(dir){if(!fs.existsSync(dir))return [];return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):[path.join(dir,e.name)]);}
keyFiles.push(...files(path.join(root,'connect-tls')).map(f=>path.relative(root,f)));
const keys=Object.fromEntries(keyFiles.map(n=>[n,hash(fs.readFileSync(path.join(root,n)))]));
const heads={};for(const [name,file]of Object.entries({bootstrap:'desktop-bootstrap/authority.json.head',journal:'desktop-license-journal.jsonl.head',machine:'desktop-machine-policy/journal.jsonl.head',integrity:'desktop-integrity-reports/reports.json.head'}))heads[name]=JSON.parse(fs.readFileSync(path.join(root,file))).body.current;
const value={counts:require(M.reset).Counts(),keys,heads,secrets:{bootstrap:hash(b.secret),license:hash(l.signingSecret)},artifactFiles:Object.keys(b.artifacts).map(id=>require(M.store).ArtifactPath(id)),reset:b.registrationResetJob||null,passkeys:Object.fromEntries(state.production.passkeyCredentials),adminCredentialHash:hash(process.env.ADMIN_SECRET),licenseIds:Object.keys(l.licenses),workspace:require(M.workspace).Load()};
if(process.env.DESKTOP_RECOVERY_WITNESS_DIR){const dir=process.env.DESKTOP_RECOVERY_WITNESS_DIR;value.witness=JSON.parse(fs.readFileSync(path.join(dir,'witness.json'))).body;value.keys.witnessKey=hash(fs.readFileSync(path.join(dir,'witness.key')));}
require(M.sqlite).Close();console.log('MAINT_TEST:'+JSON.stringify(value));`;

(async()=>{
  const parent=fs.mkdtempSync(path.join(os.tmpdir(),'peace-reset-startup-'));fs.chmodSync(parent,0o700);
  const data=path.join(parent,'data'),witness=path.join(parent,'witness');fs.mkdirSync(data,{mode:0o700});fs.mkdirSync(witness,{mode:0o700});
  const customKey=path.join(data,'fixture-custom-package.key');fs.writeFileSync(customKey,crypto.randomBytes(32),{mode:0o600});
  const web=await freePort(),tcp=await freePort();
  const env={...process.env,DATA_DIR:data,NODE_ENV:'production',HA_ENABLED:'0',CONNECT_TCP_HOST:'127.0.0.1',STORAGE_ENGINE:'sqlite',PORT:String(web),WEB_ADMIN_PORT:String(web),CONNECT_TCP_PORT:String(tcp),HEALTH_PORT:'0',WEB_ADMIN_TRANSPORT:'railway',WEB_ADMIN_RAILWAY_EDGE_ONLY:'1',WEB_ADMIN_HOST:'0.0.0.0',WEB_ADMIN_REQUIRE_HTTPS:'1',WEB_ADMIN_SECURE_COOKIE:'1',WEB_ADMIN_TRUSTED_PROXIES:'',RAILWAY_PROJECT_ID:'11111111-1111-4111-8111-111111111111',RAILWAY_ENVIRONMENT_ID:'22222222-2222-4222-8222-222222222222',RAILWAY_SERVICE_ID:'33333333-3333-4333-8333-333333333333',WEBAUTHN_RP_ID:'admin.example.test',WEBAUTHN_ORIGIN:'https://admin.example.test',ADMIN_SECRET:crypto.randomBytes(48).toString('base64url'),DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:String(tcp),GAME_CUSTOM_PACKAGE_KEY_FILE:customKey};
  for(const name of Object.keys(env))if(name.startsWith('DESKTOP_RECOVERY_WITNESS_')||name.startsWith('COZY_REGISTRATION_RESET_')||name.startsWith('CONNECT_TLS_'))delete env[name];
  const children=new Set();
  async function start(extra={},expectReady=true){
    const probe="process.on('uncaughtException',error=>console.error('[TEST_STARTUP_STACK]',error.stack));require(process.argv[1]);";
    let logs='',exited=false;const child=spawn(process.execPath,['-e',probe,entry],{cwd:ROOT,env:{...env,...extra},stdio:['ignore','pipe','pipe']});children.add(child);
    const capture=b=>{logs=(logs+b.toString()).slice(-60000);};child.stdout.on('data',capture);child.stderr.on('data',capture);
    const ended=new Promise(resolve=>child.once('exit',(code,signal)=>{exited=true;children.delete(child);resolve({code,signal});}));
    let ready=false;const begin=Date.now();while(Date.now()-begin<22000&&!exited){try{if(await request(web)===200){ready=true;break;}}catch{}await delay(60);}
    if(expectReady)assert.ok(ready,'server failed to become ready: '+logs);
    else{assert.equal(ready,false,'malformed/pending reset must not open HTTP');const outcome=await within(ended,3000);assert.ok(!outcome.timeout,logs);assert.notEqual(outcome.code,0,logs);await assert.rejects(request(web));}
    return {get logs(){return logs;},async stop(){if(exited)return;child.kill('SIGTERM');const outcome=await within(ended,11000);assert.ok(!outcome.timeout,'server did not shut down: '+logs);assert.equal(outcome.code,0,logs);await assert.rejects(request(web));}};
  }
  try{
    // Validate the explicit gate without loading stores or opening ports.
    const gate=runScript(env,`const a=require('node:assert/strict'),r=require(M.reset);a.equal(r.Request({}),null);for(const value of [{COZY_REGISTRATION_RESET_ID:'x'},{COZY_REGISTRATION_RESET_ID:'a'.repeat(64),COZY_REGISTRATION_RESET_SCOPE:'WRONG'},{COZY_REGISTRATION_RESET_SCOPE:r.SCOPE}])a.throws(()=>r.Request(value),/REQUEST_INVALID/);console.log('MAINT_TEST:'+JSON.stringify({gate:true}));`);assert.equal(gate.gate,true);
    const seeded=runScript(env,`
      const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
      require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();
      const b=require(M.bootstrap),f=require(M.fixture),l=require(M.licenses),s=require(M.state);
      for(const role of ['A','B','O'])b.Publish(role,'80.0.0',f.PE(role));
      const license=l.Create({requestId:crypto.randomUUID(),label:'reset fixture'},'RESET_FIXTURE').license;
      const flow=f.Begin(f.Device());
      s.production.passkeyCredentials.set('fixture-credential',{id:'A'.repeat(24),credentialId:'fixture-public-id',role:'admin',counter:8});
      s.production.incidents=[{id:'fixture-incident'}];
      require(M.workspace).Atomic(v=>{v.metadata[license.id]={note:'reset fixture',tags:['fixture'],revision:1};});
      require(M.machine).Load();require(M.integrity).Policy();
      if(!require(M.database).SaveDatabase())throw Error('FIXTURE_SAVE_FAILED');
      const head=file=>JSON.parse(fs.readFileSync(file)).body.current;
      new (require(M.witness).WitnessFile)(${JSON.stringify(witness)}).enroll({DESKTOP_JOURNAL:head(path.join(process.env.DATA_DIR,'desktop-license-journal.jsonl.head')),DESKTOP_MACHINE_POLICY:head(path.join(process.env.DATA_DIR,'desktop-machine-policy/journal.jsonl.head')),DESKTOP_BOOTSTRAP:head(path.join(process.env.DATA_DIR,'desktop-bootstrap/authority.json.head')),DESKTOP_INTEGRITY:head(require(M.integrity).FILE+'.head')});
      require(M.sqlite).Close();console.log('MAINT_TEST:'+JSON.stringify({license:license.id,launcher:flow.issue.launcherId}));`);
    env.DESKTOP_RECOVERY_WITNESS_DIR=witness;env.DESKTOP_RECOVERY_WITNESS_REQUIRED='1';
    const first=runScript(env,SNAPSHOT);assert.equal(first.counts.artifacts,3);assert.equal(first.counts.licenses,1);assert.ok(first.counts.issuedLaunchers>0&&first.counts.flows>0);
    const regular=await start();await regular.stop();const persisted=runScript(env,SNAPSHOT);assert.deepEqual(persisted.counts,first.counts,'ordinary deployment must preserve registration data');
    const operation=crypto.randomBytes(32).toString('hex'),flags={COZY_REGISTRATION_RESET_ID:operation,COZY_REGISTRATION_RESET_SCOPE:SCOPE};
    const resetting=await start(flags);assert.match(resetting.logs,/REGISTRATION_RESET_COMPLETE/);assert.ok(resetting.logs.indexOf('REGISTRATION_RESET_COMPLETE')<resetting.logs.indexOf('CONNECT_TLS_LISTENER_READY'),'reset must finish before the TCP listener');await resetting.stop();
    const empty=runScript(env,SNAPSHOT);assert.ok(Object.values(empty.counts).every(v=>v===0),JSON.stringify(empty.counts));assert.equal(empty.reset.phase,'COMPLETE');
    assert.deepEqual(empty.keys,first.keys,'transport/TLS/custom package/MAC/witness keys and key-purpose registry must retain exact bytes');assert.deepEqual(empty.secrets,first.secrets,'established signing secrets must be retained');assert.deepEqual(empty.passkeys,first.passkeys,'administrator passkeys must remain enrolled');assert.equal(empty.adminCredentialHash,first.adminCredentialHash);
    for(const file of first.artifactFiles)assert.equal(fs.existsSync(file),false,'registered native EXE must be removed after its authority is cleared');
    for(const domain of ['DESKTOP_BOOTSTRAP','DESKTOP_JOURNAL','DESKTOP_MACHINE_POLICY','DESKTOP_INTEGRITY'])assert.ok(empty.witness.heads[domain].current.seq>persisted.witness.heads[domain].current.seq,'witness must advance for '+domain);
    assert.equal(empty.witness.installationId,first.witness.installationId);assert.equal(Object.keys(empty.workspace.metadata).length,0);assert.equal(Object.keys(empty.workspace.jobs).length,0);
    const restarted=await start();await restarted.stop();assert.ok(Object.values(runScript(env,SNAPSHOT).counts).every(v=>v===0),'reset must survive a normal restart');
    const fresh=runScript(env,`require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();const l=require(M.licenses).Create({requestId:require('node:crypto').randomUUID(),label:'after reset'},'RESET_FIXTURE').license;if(!require(M.database).SaveDatabase())throw Error('FIXTURE_SAVE_FAILED');require(M.sqlite).Close();console.log('MAINT_TEST:'+JSON.stringify({id:l.id}));`);assert.notEqual(fresh.id,seeded.license);
    const duplicate=await start(flags);assert.match(duplicate.logs,/REGISTRATION_RESET_ALREADY_COMPLETED/);await duplicate.stop();assert.equal(runScript(env,SNAPSHOT).counts.licenses,1,'spent reset flag must not wipe a newly registered license');
    const malformed=await start({COZY_REGISTRATION_RESET_ID:operation,COZY_REGISTRATION_RESET_SCOPE:'WRONG'},false);assert.match(malformed.logs,/REGISTRATION_RESET_REQUEST_INVALID/);assert.equal(runScript(env,SNAPSHOT).counts.licenses,1);
    const pendingId=crypto.randomBytes(32).toString('hex'),pendingFlags={COZY_REGISTRATION_RESET_ID:pendingId,COZY_REGISTRATION_RESET_SCOPE:SCOPE};
    runScript({...env,...pendingFlags},`require(M.utilities).EnsureDirs();require(M.database).LoadDatabase();const j=require(M.resetBootstrap).Prepare(process.env.COZY_REGISTRATION_RESET_ID);require(M.sqlite).Close();console.log('MAINT_TEST:'+JSON.stringify({phase:j.phase}));`);
    const unauthenticated=await start({},false);assert.match(unauthenticated.logs,/REGISTRATION_RESET_PENDING_AUTHORIZATION_REQUIRED/);
    const resumed=await start(pendingFlags);assert.match(resumed.logs,/REGISTRATION_RESET_COMPLETE/);await resumed.stop();assert.ok(Object.values(runScript(env,SNAPSHOT).counts).every(v=>v===0));
    console.log('PASS real startup registration reset, preserved keys and independent witness, physical EXE cleanup, persistence, spent nonce and pending-intent recovery');
  }finally{
    for(const child of children){child.kill('SIGKILL');await new Promise(resolve=>child.once('exit',resolve));}
    fs.rmSync(parent,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error.stack||error.message);process.exitCode=1;});
