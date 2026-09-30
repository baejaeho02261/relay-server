'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moa-bootstrap-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();
const bootstrap=require('../services/desktopBootstrap'),licenses=require('../services/desktopLicenses'),state=require('../core/state'),database=require('../storage/database'),fixture=require('./desktop-bootstrap-fixture');
const {PE,Device,Sign,Config,sha256}=fixture,a=Device(),b=Device();let checks=0;
function Check(label,fn){fn();checks++;console.log('PASS '+label);}
function Reject(fn,pattern=/^BOOTSTRAP_/){assert.throws(fn,error=>pattern.test(error.message),String(pattern));}
function LicenseProof(device,action,payload,requestId=crypto.randomUUID()){
 const payloadJSON=JSON.stringify(payload),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:sha256(payloadJSON)},challenge=licenses.Challenge(base);
 return {...base,challengeId:challenge.challengeId,payloadJSON,signature:Sign(device,challenge.canonical)};
}
function Restart(input){
 database.SaveDatabase();const copy=fs.mkdtempSync(path.join(os.tmpdir(),'moa-bootstrap-restart-'));fs.cpSync(temp,copy,{recursive:true});
 const script="require(process.cwd()+'/storage/database').LoadDatabase();const b=require(process.cwd()+'/services/desktopBootstrap'),p=JSON.parse(require('node:fs').readFileSync(0,'utf8'));try{process.stdout.write('RESULT:'+JSON.stringify({ok:true,data:b.Execute(p)}));}catch(e){process.stdout.write('RESULT:'+JSON.stringify({ok:false,error:e.message}));}";
 const result=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:copy},input:JSON.stringify(input),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);const marker=result.stdout.lastIndexOf('RESULT:');assert.ok(marker>=0,result.stdout);return JSON.parse(result.stdout.slice(marker+7));
}

let publishedA,publishedB,issued,launcher,config,beginBody,begin,finish,claimBody,session;
Check('Publisher requires structurally bounded AMD64 executables and correct component subsystem',()=>{
 const mutate=fn=>{const value=PE('A');fn(value);return value;};
 const invalid=[Buffer.from('MZ'),mutate(v=>v.writeUInt32LE(v.length-8,0x3c)),mutate(v=>v.writeUInt16LE(0x14c,0x84)),mutate(v=>v.writeUInt16LE(0x2022,0x96)),mutate(v=>v.writeUInt16LE(0x10b,0x98)),mutate(v=>v.writeUInt32LE(0,0xa8)),mutate(v=>v.writeUInt32LE(0xfffffff0,0x19c)),PE('B')];
 for(const bytes of invalid)Reject(()=>bootstrap.Publish('A','80.0.0',bytes));
 Reject(()=>bootstrap.Publish('B','80.0.0',PE('A')));Reject(()=>bootstrap.Publish('CLIENT','80.0.0',PE('A')));
 Reject(()=>bootstrap.Publish('A','80.0.0',Buffer.alloc(64*1024*1024+1)));
 publishedA=bootstrap.Publish('A','80.0.0',PE('A'));publishedB=bootstrap.Publish('B','80.0.0',PE('B'));
 assert.equal(publishedA.sha256,sha256(PE('A')));assert.equal(publishedB.sha256,sha256(PE('B')));assert.equal(publishedB.size,1024);
});
Check('Issued launcher includes pinned profile and one deterministic download for retry',()=>{
 const body={requestId:crypto.randomUUID(),label:'단일 PC 설치'};issued=bootstrap.IssueLauncher(body,'ADMIN:test');assert.ok(issued.launcherId);assert.ok(issued.expiresAt>Date.now());
 assert.equal(bootstrap.IssueLauncher(body,'ADMIN:test').launcherId,issued.launcherId);Reject(()=>bootstrap.IssueLauncher({...body,label:'다른 설치'},'ADMIN:test'));
 launcher=bootstrap.LauncherBytes(issued.launcherId);assert.deepEqual(bootstrap.LauncherBytes(issued.launcherId),launcher);config=Config(launcher);assert.equal(config.launcherId,issued.launcherId);assert.ok(config.launcherTicket);
 const overview=JSON.stringify(bootstrap.Overview());assert.ok(!overview.includes(config.launcherTicket));assert.ok(!overview.includes('BEGIN PRIVATE KEY'));
});
Check('Claim admission checks launcher hash, ticket and proof key binding',()=>{
 beginBody={action:'begin',requestId:crypto.randomUUID(),launcherId:issued.launcherId,launcherTicket:config.launcherTicket,launcherSha256:sha256(launcher),publicKey:a.publicKey,deviceId:a.deviceId};
 Reject(()=>bootstrap.Execute({...beginBody,launcherSha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...beginBody,launcherTicket:'invalid'}));Reject(()=>bootstrap.Execute({...beginBody,deviceId:b.deviceId}),/^(BOOTSTRAP_|DESKTOP_)/);
 begin=bootstrap.Execute(beginBody);assert.equal(begin.release.sha256,publishedB.sha256);assert.equal(begin.release.size,publishedB.size);assert.ok(begin.flowId&&begin.downloadTicket&&begin.finishCanonical);
 assert.equal(bootstrap.Execute(beginBody).flowId,begin.flowId);Reject(()=>bootstrap.Execute({...beginBody,requestId:crypto.randomUUID(),deviceId:b.deviceId,publicKey:b.publicKey}));
 assert.deepEqual(Object.keys(begin.release).sort(),['id','sha256','size','version']);
});
Check('Chunk retrieval checks credentials and integral in-range offsets',()=>{
 Reject(()=>fixture.Finish(a,begin),/^BOOTSTRAP_DOWNLOAD_INCOMPLETE$/);
 for(const offset of [-1,0.5,1,begin.release.size,Number.MAX_SAFE_INTEGER])Reject(()=>bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}));
 Reject(()=>bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:'invalid',offset:0}));
 assert.deepEqual(fixture.Download(begin),PE('B'));const chunk=bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset:0});assert.deepEqual(Buffer.from(chunk.data,'base64'),PE('B'));
});
Check('Finish requires published digest and device signature before returning handoff',()=>{
 const body={action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha256:begin.release.sha256,signature:Sign(a,begin.finishCanonical)};
 Reject(()=>bootstrap.Execute({...body,sha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...body,signature:Sign(b,begin.finishCanonical)}));
 finish=bootstrap.Execute(body);assert.ok(finish.handoffToken&&finish.claimCanonical);assert.equal(bootstrap.Execute(body).handoffToken,finish.handoffToken);
});
Check('B claim requires exact executable digest and bound handoff signature',()=>{
 claimBody={action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(a,finish.claimCanonical),binarySha256:begin.release.sha256};
 Reject(()=>bootstrap.Execute({...claimBody,handoffToken:'invalid'}));Reject(()=>bootstrap.Execute({...claimBody,binarySha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...claimBody,signature:Sign(b,finish.claimCanonical)}));
 session=bootstrap.Execute(claimBody);assert.ok(session.sessionId&&session.sessionToken&&session.expiresAt>Date.now());assert.equal(bootstrap.Execute(claimBody).sessionToken,session.sessionToken);
 assert.ok(bootstrap.Gate(session.sessionId,session.sessionToken,a.deviceId));Reject(()=>bootstrap.Gate(session.sessionId,session.sessionToken,b.deviceId));Reject(()=>bootstrap.Gate(session.sessionId,'invalid',a.deviceId));
});
Check('Launcher device consumption and lost-claim response recovery survive restart',()=>{
 const replay=Restart(claimBody);assert.equal(replay.ok,true,JSON.stringify(replay));assert.equal(replay.data.sessionToken,session.sessionToken);
 const other=Restart({...beginBody,requestId:crypto.randomUUID(),publicKey:b.publicKey,deviceId:b.deviceId});assert.equal(other.ok,false);assert.match(other.error,/^BOOTSTRAP_/);
});
Check('Storage failure and tampered published artifact never consume an unused launcher',()=>{
 const issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Failure atomicity'},'TEST'),bytes=bootstrap.LauncherBytes(issue.launcherId),settings=Config(bytes),body={action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:settings.launcherTicket,launcherSha256:sha256(bytes),publicKey:a.publicKey,deviceId:a.deviceId};
 const store=require('../services/desktopBootstrapStore'),file=store.ArtifactPath(publishedB.id),original=fs.readFileSync(file),tampered=Buffer.from(original);tampered[512]^=1;
 fs.writeFileSync(file,tampered);try{Reject(()=>bootstrap.Execute(body),/^BOOTSTRAP_ARTIFACT_INVALID$/);}finally{fs.writeFileSync(file,original);}
 assert.equal(bootstrap.Overview().launchers.find(row=>row.id===issue.launcherId).status,'AVAILABLE');
 const rename=fs.renameSync;fs.renameSync=(source,target)=>{if(path.basename(target)==='authority.json')throw Error('TEST_WRITE_FAILURE');return rename(source,target);};
 try{Reject(()=>bootstrap.Execute(body),/^STORAGE_SAVE_FAILED$/);}finally{fs.renameSync=rename;}
 assert.equal(bootstrap.Overview().launchers.find(row=>row.id===issue.launcherId).status,'AVAILABLE');const retry=bootstrap.Execute(body);assert.ok(retry.flowId);assert.equal(bootstrap.Execute(body).flowId,retry.flowId);
});
Check('License journal commit survives bootstrap linkage failure and exact proof repairs it',()=>{
 const running=fixture.Session(a,'two-store-failure'),key=licenses.Create({label:'Durable cross-store recovery'},'TEST'),payload={licenseKey:key.licenseKey,bootstrapSessionId:running.sessionId,bootstrapSessionToken:running.sessionToken},proof=LicenseProof(a,'redeem',payload),store=require('../services/desktopBootstrapStore'),atomic=store.Atomic;
 store.Atomic=()=>{throw Error('TEST_BOOTSTRAP_LINKAGE_WRITE_FAILURE');};try{Reject(()=>licenses.Execute(proof),/^STORAGE_SAVE_FAILED$/);}finally{store.Atomic=atomic;}
 const committed=licenses.DB().licenses[key.license.id];assert.equal(committed.consumed,true);assert.equal(committed.status,'ACTIVE');assert.equal(bootstrap.Overview().sessions.find(row=>row.id===running.sessionId).licenseId,'');
 const recovered=licenses.Execute(proof);assert.equal(recovered.status,'ACTIVE');assert.equal(sha256(recovered.activationToken),committed.tokenHash);assert.equal(licenses.Execute(proof).activationToken,recovered.activationToken);assert.equal(bootstrap.Overview().sessions.find(row=>row.id===running.sessionId).licenseId,key.license.id);
 Reject(()=>licenses.Execute(LicenseProof(a,'redeem',payload)),/^DESKTOP_KEY_USED$/);
});
Check('License consumption requires signed, current, same-device B session',()=>{
 const key=licenses.Create({label:'B session gate'},'TEST'),payload={licenseKey:key.licenseKey,deviceName:'부트스트랩 테스트',appVersion:'80.0.0'};
 Reject(()=>licenses.Execute(LicenseProof(a,'redeem',payload)));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 Reject(()=>licenses.Execute(LicenseProof(a,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:'invalid'})));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 Reject(()=>licenses.Execute(LicenseProof(b,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken})));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 const activated=licenses.Execute(LicenseProof(a,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken}));assert.equal(activated.status,'ACTIVE');assert.equal(activated.deviceId,a.deviceId);
 const proof=LicenseProof(a,'verify',{activationToken:activated.activationToken,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken});assert.equal(licenses.Execute(proof).status,'ACTIVE');
 const different=licenses.Create({label:'Must remain unused'},'TEST');Reject(()=>licenses.Execute(LicenseProof(a,'redeem',{licenseKey:different.licenseKey,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken})),/^BOOTSTRAP_LICENSE_MISMATCH$/);assert.equal(licenses.DB().licenses[different.license.id].consumed,false);
 const oldSnapshot=database.BuildDatabaseObject();bootstrap.Execute({action:'close',sessionId:session.sessionId,sessionToken:session.sessionToken});Reject(()=>bootstrap.Gate(session.sessionId,session.sessionToken,a.deviceId));Reject(()=>licenses.Execute(proof));
 database.ImportDatabaseObject(oldSnapshot);Reject(()=>bootstrap.Gate(session.sessionId,session.sessionToken,a.deviceId),/^BOOTSTRAP_SESSION_CLOSED$/);const retry=Restart(claimBody);assert.equal(retry.ok,false);assert.equal(retry.error,'BOOTSTRAP_SESSION_CLOSED');
});
Check('Service pause denies bootstrap and expired sessions cannot authorize licenses',()=>{
 state.serviceEnabled=false;try{Reject(()=>bootstrap.Execute(beginBody),/^(BOOTSTRAP_|SERVICE_DISABLED)/);}finally{state.serviceEnabled=true;}
 const next=fixture.Session(b),real=Date.now;Date.now=()=>next.expiresAt+1;try{Reject(()=>bootstrap.Gate(next.sessionId,next.sessionToken,b.deviceId));}finally{Date.now=real;}
});
Check('Corrupt bootstrap authority stops startup instead of reviving consumed tickets',()=>{
 const copy=fs.mkdtempSync(path.join(os.tmpdir(),'moa-bootstrap-corrupt-'));fs.cpSync(temp,copy,{recursive:true});fs.writeFileSync(path.join(copy,'desktop-bootstrap','authority.json'),'{"schema":1,"broken":');
 const result=child.spawnSync(process.execPath,['-e',"require(process.cwd()+'/storage/database').LoadDatabase();require(process.cwd()+'/services/desktopBootstrap').Initialize();process.stdout.write('UNSAFE_STARTED');"],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:copy},encoding:'utf8'});
 assert.notEqual(result.status,0);assert.ok(!result.stdout.includes('UNSAFE_STARTED'));assert.match(result.stderr,/BOOTSTRAP_STORAGE_INVALID/);
});
console.log(`Desktop bootstrap checks: ${checks} passed (${process.env.STORAGE_ENGINE})`);
