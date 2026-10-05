'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),child=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
require('../core/utils').EnsureDirs();
const bootstrap=require('../services/desktopBootstrap'),licenses=require('../services/desktopLicenses'),state=require('../core/state'),database=require('../storage/database'),fixture=require('./desktop-bootstrap-fixture');
const {PE,Device,Sign,Config,sha256,Crc64,CodeImage}=fixture,a=Device(),b=Device();let checks=0;
function Check(label,fn){fn();checks++;console.log('PASS '+label);}
function Reject(fn,pattern=/^BOOTSTRAP_/){assert.throws(fn,error=>pattern.test(error.message),String(pattern));}
// The native client intentionally rejects unknown or duplicate response fields.
// Exercise that wire contract as well as the JavaScript fixture's loose reads.
const releaseFields=['id','version','sha256','crc64','size','codeSha256','codeCrc64','codeAlgorithm'].sort();
const nativeBootstrap=path.resolve(__dirname,'../../GameConnect_Win64/Game.Bootstrap.pas');
if(fs.existsSync(nativeBootstrap)){
 const source=fs.readFileSync(nativeBootstrap,'utf8'),parseRelease=source.match(/function ParseRelease\(Obj: TJSONObject\): TBootstrapRelease;([\s\S]*?)function RequiredObject/);
 assert.ok(parseRelease,'Locate the native ParseRelease implementation');
 const schema=parseRelease[1].match(/BootstrapValidateObject\(Obj,\s*'([^']+)',\s*(\d+)\)/);
 assert.ok(schema,'Locate the native exact-field release validator');
 assert.equal(Number(schema[2]),releaseFields.length,'Native release field count changed; review protocol compatibility');
 assert.deepEqual(schema[1].split('|').filter(Boolean).sort(),releaseFields,'Native release allowlist changed; review protocol compatibility');
}
function AssertNativeRelease(release,operation){
 // A serialized response is what Delphi receives; JSON omits undefined fields.
 const wire=JSON.parse(JSON.stringify(release));
 assert.equal(Object.keys(wire).length,releaseFields.length,operation+' release must satisfy the native exact 8-field parser');
 assert.deepEqual(Object.keys(wire).sort(),releaseFields,operation+' release must not add unknown fields');
}
function AssertExtendedBaseline(actual,expected,label){
 for(const [native,stored]of [['fileXxh64','xxh64'],['fileBlake3','blake3'],['codeXxh64','codeXxh64'],['codeBlake3','codeBlake3']]){
  assert.match(expected[stored],stored.toLowerCase().includes('xxh')?/^[a-f0-9]{16}$/:/^[a-f0-9]{64}$/,label+' '+stored);
  assert.equal(actual[native],expected[stored],label+' '+native);
 }
}
function Gate(id,token,deviceId){const row=Object.values(bootstrap.Initialize().flows).find(item=>item.sessionId===id),artifact=bootstrap.Initialize().artifacts[row?.releaseId],device=[a,b].find(item=>item.deviceId===deviceId);return bootstrap.Gate(id,token,deviceId,{machineId:device?.machineId,binarySha256:artifact?.sha256,binaryCrc64:artifact?.crc64,codeSha256:artifact?.codeSha256,codeCrc64:artifact?.codeCrc64});}
function LicenseProof(device,action,payload,requestId=crypto.randomUUID()){
 if(payload.bootstrapSessionId)payload=fixture.LicensePayload(device,payload);else {const release=bootstrap.Overview().artifacts.B;payload={...payload,machineId:device.machineId,binarySha256:release.sha256,binaryCrc64:release.crc64,codeSha256:release.codeSha256,codeCrc64:release.codeCrc64};}
 const payloadJSON=JSON.stringify(payload),base={action,requestId,deviceId:device.deviceId,publicKey:device.publicKey,payloadHash:sha256(payloadJSON)},challenge=licenses.Challenge(base);
 return {...base,challengeId:challenge.challengeId,payloadJSON,signature:Sign(device,challenge.canonical)};
}
function Restart(input){
 database.SaveDatabase();const copy=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-restart-'));fs.cpSync(temp,copy,{recursive:true});
 const script="require(process.cwd()+'/storage/database').LoadDatabase();const b=require(process.cwd()+'/services/desktopBootstrap'),p=JSON.parse(require('node:fs').readFileSync(0,'utf8'));try{process.stdout.write('RESULT:'+JSON.stringify({ok:true,data:b.Execute(p)}));}catch(e){process.stdout.write('RESULT:'+JSON.stringify({ok:false,error:e.message}));}";
 const result=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:copy},input:JSON.stringify(input),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);const marker=result.stdout.lastIndexOf('RESULT:');assert.ok(marker>=0,result.stdout);return JSON.parse(result.stdout.slice(marker+7));
}

Check('CRC64 uses ECMA-182 known vectors and SHA-256 remains independent',()=>{assert.equal(Crc64(Buffer.alloc(0)),'0000000000000000');assert.equal(Crc64(Buffer.from('123456789')),'6C40DF5F0B497347');});

let publishedA,publishedB,issued,launcher,config,beginBody,begin,finish,claimBody,session;
Check('Publisher requires structurally bounded AMD64 executables and correct component subsystem',()=>{
 const mutate=fn=>{const value=PE('A');fn(value);return value;};
 const invalid=[Buffer.from('MZ'),mutate(v=>v.writeUInt32LE(v.length-8,0x3c)),mutate(v=>v.writeUInt16LE(0x14c,0x84)),mutate(v=>v.writeUInt16LE(0x2022,0x96)),mutate(v=>v.writeUInt16LE(0x10b,0x98)),mutate(v=>v.writeUInt32LE(0,0xa8)),mutate(v=>v.writeUInt32LE(0xfffffff0,0x19c)),mutate(v=>v.writeUInt16LE(3,0xdc))];
 for(const bytes of invalid)Reject(()=>bootstrap.Publish('A','80.0.0',bytes));
 Reject(()=>bootstrap.Publish('B','80.0.0',mutate(v=>v.writeUInt16LE(3,0xdc))));Reject(()=>bootstrap.Publish('CLIENT','80.0.0',PE('A')));
 Reject(()=>bootstrap.Publish('A','80.0.0',Buffer.alloc(64*1024*1024+1)));
 publishedA=bootstrap.Publish('A','80.0.0',PE('A'));publishedB=bootstrap.Publish('B','80.0.0',PE('B'));
 assert.match(publishedA.id,/^[A-F0-9]{24}$/);assert.match(publishedB.id,/^[A-F0-9]{24}$/);
 assert.equal(publishedA.crc64,Crc64(PE('A')));assert.equal(publishedB.crc64,Crc64(PE('B')));assert.equal(publishedA.sha256,sha256(PE('A')));assert.equal(publishedB.sha256,sha256(PE('B')));assert.equal(publishedB.size,1024);
});
Check('Issued launcher includes pinned profile and one deterministic download for retry',()=>{
 const body={requestId:crypto.randomUUID(),label:'단일 PC 설치'};issued=bootstrap.IssueLauncher(body,'ADMIN:test');assert.match(issued.launcherId,/^[A-F0-9]{24}$/);assert.ok(issued.expiresAt>Date.now());assert.match(issued.downloadName,/^[a-f0-9]{32}\.exe$/);assert.equal(bootstrap.IssueLauncher(body,'ADMIN:test').downloadName,issued.downloadName);assert.equal(bootstrap.LauncherName(bootstrap.Initialize().launchers[issued.launcherId]),issued.downloadName);assert.notEqual(bootstrap.IssueLauncher({requestId:crypto.randomUUID()},'ADMIN:test').downloadName,issued.downloadName);
 assert.equal(bootstrap.IssueLauncher(body,'ADMIN:test').launcherId,issued.launcherId);Reject(()=>bootstrap.IssueLauncher({...body,label:'다른 설치'},'ADMIN:test'));
 launcher=bootstrap.LauncherBytes(issued.launcherId);assert.deepEqual(bootstrap.LauncherBytes(issued.launcherId),launcher);config=Config(launcher);assert.equal(config.launcherId,issued.launcherId);assert.ok(config.launcherTicket);
 const overview=JSON.stringify(bootstrap.Overview());assert.ok(!overview.includes(config.launcherTicket));assert.ok(!overview.includes('BEGIN PRIVATE KEY'));
});
Check('Claim admission checks launcher hash, ticket and proof key binding',()=>{
 beginBody={action:'begin',requestId:crypto.randomUUID(),launcherId:issued.launcherId,launcherTicket:config.launcherTicket,launcherSha256:sha256(launcher),launcherCrc64:Crc64(launcher),aCodeSha256:CodeImage(launcher).sha256,aCodeCrc64:CodeImage(launcher).crc64,machineId:a.machineId,publicKey:a.publicKey,deviceId:a.deviceId};
 Reject(()=>bootstrap.Execute({...beginBody,launcherCrc64:'0'.repeat(16)}));Reject(()=>bootstrap.Execute({...beginBody,launcherSha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...beginBody,launcherTicket:'invalid'}));Reject(()=>bootstrap.Execute({...beginBody,deviceId:b.deviceId}),/^(BOOTSTRAP_|DESKTOP_)/);
 begin=bootstrap.Execute(beginBody);assert.equal(begin.release.sha256,publishedB.sha256);assert.equal(begin.release.size,publishedB.size);assert.match(begin.flowId,/^[A-F0-9]{24}$/);assert.ok(begin.downloadTicket&&begin.finishCanonical);
 assert.equal(bootstrap.Execute(beginBody).flowId,begin.flowId);Reject(()=>bootstrap.Execute({...beginBody,requestId:crypto.randomUUID(),deviceId:b.deviceId,publicKey:b.publicKey}));
 AssertNativeRelease(begin.release,'begin');
});
Check('Extended hashes stay in server baselines and admin projections without changing the native wire schema',()=>{
 const db=bootstrap.Initialize(),overview=bootstrap.Overview();
 for(const artifact of [publishedA,publishedB])for(const field of ['xxh64','blake3','codeXxh64','codeBlake3']){
  assert.equal(db.artifacts[artifact.id][field],artifact[field]);
  assert.equal(overview.artifacts[artifact.component][field],artifact[field]);
 }
 const personalized=require('../services/desktopIntegrity').Digests(launcher),stored=db.launchers[issued.launcherId];
 assert.equal(stored.xxh64,personalized.xxh64);assert.equal(stored.blake3,personalized.blake3);
 const authenticated=bootstrap.AuthenticateIntegrityReport({stage:'A',sessionId:begin.flowId,sessionToken:begin.downloadTicket,machineId:a.machineId});
 AssertExtendedBaseline(authenticated.integrityArtifact,{...publishedA,xxh64:personalized.xxh64,blake3:personalized.blake3},'A personalized baseline');
});
Check('Chunk retrieval checks credentials and integral in-range offsets',()=>{
 Reject(()=>fixture.Finish(a,begin),/^BOOTSTRAP_DOWNLOAD_INCOMPLETE$/);
 for(const offset of [-1,0.5,1,begin.release.size,Number.MAX_SAFE_INTEGER])Reject(()=>bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset}));
 Reject(()=>bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:'invalid',offset:0}));
 assert.deepEqual(fixture.Download(begin),PE('B'));const chunk=bootstrap.Execute({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset:0});assert.deepEqual(Buffer.from(chunk.data,'base64'),PE('B'));
});
Check('Finish requires published digest and device signature before returning handoff',()=>{
 const body={action:'finish',flowId:begin.flowId,downloadTicket:begin.downloadTicket,sha256:begin.release.sha256,crc64:begin.release.crc64,aCodeSha256:begin.finishCanonical.split('\n')[5],aCodeCrc64:begin.finishCanonical.split('\n')[6],signature:Sign(a,begin.finishCanonical)};
 Reject(()=>bootstrap.Execute({...body,crc64:'0'.repeat(16)}));Reject(()=>bootstrap.Execute({...body,sha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...body,signature:Sign(b,begin.finishCanonical)}));
 finish=bootstrap.Execute(body);assert.ok(finish.handoffToken&&finish.claimCanonical);assert.equal(bootstrap.Execute(body).handoffToken,finish.handoffToken);
});
Check('B claim requires exact executable digest and bound handoff signature',()=>{
 claimBody={action:'claim',flowId:begin.flowId,handoffToken:finish.handoffToken,signature:Sign(a,finish.claimCanonical),binarySha256:begin.release.sha256,crc64:begin.release.crc64,bCodeSha256:begin.release.codeSha256,bCodeCrc64:begin.release.codeCrc64};
 Reject(()=>bootstrap.Execute({...claimBody,crc64:'0'.repeat(16)}));Reject(()=>bootstrap.Execute({...claimBody,handoffToken:'invalid'}));Reject(()=>bootstrap.Execute({...claimBody,binarySha256:'0'.repeat(64)}));Reject(()=>bootstrap.Execute({...claimBody,signature:Sign(b,finish.claimCanonical)}));
 session=bootstrap.Execute(claimBody);assert.match(session.sessionId,/^[A-F0-9]{24}$/);assert.ok(session.sessionToken&&session.expiresAt>Date.now());assert.equal(bootstrap.Execute(claimBody).sessionToken,session.sessionToken);
 assert.ok(Gate(session.sessionId,session.sessionToken,a.deviceId));Reject(()=>Gate(session.sessionId,session.sessionToken,b.deviceId));Reject(()=>Gate(session.sessionId,'invalid',a.deviceId));
 AssertNativeRelease(session.release,'claim');
 const status=bootstrap.Execute({action:'status',sessionId:session.sessionId,sessionToken:session.sessionToken});AssertNativeRelease(status.release,'status');
 const authenticated=bootstrap.AuthenticateIntegrityReport({stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:a.machineId});
 AssertExtendedBaseline(authenticated.integrityArtifact,publishedB,'B published baseline');
});
Check('Launcher device consumption and lost-claim response recovery survive restart',()=>{
 const replay=Restart(claimBody);assert.equal(replay.ok,true,JSON.stringify(replay));assert.equal(replay.data.sessionToken,session.sessionToken);
 const other=Restart({...beginBody,requestId:crypto.randomUUID(),publicKey:b.publicKey,deviceId:b.deviceId});assert.equal(other.ok,false);assert.match(other.error,/^BOOTSTRAP_/);
});
Check('Storage failure and tampered published artifact never consume an unused launcher',()=>{
 const issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID(),label:'Failure atomicity'},'TEST'),bytes=bootstrap.LauncherBytes(issue.launcherId),settings=Config(bytes),body={action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:settings.launcherTicket,launcherSha256:sha256(bytes),launcherCrc64:Crc64(bytes),aCodeSha256:CodeImage(bytes).sha256,aCodeCrc64:CodeImage(bytes).crc64,machineId:a.machineId,publicKey:a.publicKey,deviceId:a.deviceId};
 const store=require('../services/desktopBootstrapStore'),file=store.ArtifactPath(publishedB.id),original=fs.readFileSync(file),tampered=Buffer.from(original);tampered[512]^=1;
 fs.writeFileSync(file,tampered);try{Reject(()=>bootstrap.Execute(body),/^BOOTSTRAP_ARTIFACT_INVALID$/);}finally{fs.writeFileSync(file,original);}
 assert.equal(bootstrap.Overview().launchers.find(row=>row.id===issue.launcherId).status,'AVAILABLE');
 const rename=fs.renameSync;fs.renameSync=(source,target)=>{if(path.basename(target)==='authority.json')throw Error('TEST_WRITE_FAILURE');return rename(source,target);};
 try{Reject(()=>bootstrap.Execute(body),/^STORAGE_SAVE_FAILED$/);}finally{fs.renameSync=rename;}
 assert.equal(bootstrap.Overview().launchers.find(row=>row.id===issue.launcherId).status,'AVAILABLE');const retry=bootstrap.Execute(body);assert.ok(retry.flowId);assert.equal(bootstrap.Execute(body).flowId,retry.flowId);
});
Check('License journal commit survives bootstrap linkage failure and exact proof repairs it',()=>{
 const isolated=Device(),running=fixture.Session(isolated,'two-store-failure'),key=licenses.Create({label:'Durable cross-store recovery'},'TEST'),payload={licenseKey:key.licenseKey,bootstrapSessionId:running.sessionId,bootstrapSessionToken:running.sessionToken},proof=LicenseProof(isolated,'redeem',payload),store=require('../services/desktopBootstrapStore'),atomic=store.Atomic;
 store.Atomic=()=>{throw Error('TEST_BOOTSTRAP_LINKAGE_WRITE_FAILURE');};try{Reject(()=>licenses.Execute(proof),/^STORAGE_SAVE_FAILED$/);}finally{store.Atomic=atomic;}
 const committed=licenses.DB().licenses[key.license.id];assert.equal(committed.consumed,true);assert.equal(committed.status,'USED');assert.equal(bootstrap.Overview().sessions.find(row=>row.id===running.sessionId).licenseId,'');
 const recovered=licenses.Execute(proof);assert.equal(recovered.status,'USED');assert.equal(sha256(recovered.activationToken),committed.tokenHash);assert.equal(licenses.Execute(proof).activationToken,recovered.activationToken);assert.equal(bootstrap.Overview().sessions.find(row=>row.id===running.sessionId).licenseId,key.license.id);
 Reject(()=>licenses.Execute(LicenseProof(isolated,'redeem',payload)),/^DESKTOP_KEY_USED$/);
});
Check('License consumption requires signed, current, same-device B session',()=>{
 const key=licenses.Create({label:'B session gate'},'TEST'),payload={licenseKey:key.licenseKey,deviceName:'부트스트랩 테스트',appVersion:'80.0.0'};
 Reject(()=>licenses.Execute(LicenseProof(a,'redeem',payload)));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 Reject(()=>licenses.Execute(LicenseProof(a,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:'invalid'})));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 Reject(()=>licenses.Execute(LicenseProof(b,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken})));assert.equal(licenses.DB().licenses[key.license.id].consumed,false);
 const activated=licenses.Execute(LicenseProof(a,'redeem',{...payload,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken}));assert.equal(activated.status,'USED');assert.equal(activated.deviceId,a.deviceId);
 const proof=LicenseProof(a,'verify',{activationToken:activated.activationToken,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken});assert.equal(licenses.Execute(proof).status,'USED');
 const different=licenses.Create({label:'Must remain unused'},'TEST');Reject(()=>licenses.Execute(LicenseProof(a,'redeem',{licenseKey:different.licenseKey,bootstrapSessionId:session.sessionId,bootstrapSessionToken:session.sessionToken})),/^BOOTSTRAP_LICENSE_MISMATCH$/);assert.equal(licenses.DB().licenses[different.license.id].consumed,false);
 Reject(()=>fixture.Session(a,'attempt-activation-reuse'),/^DESKTOP_MACHINE_BLOCKED$/);
 const oldSnapshot=database.BuildDatabaseObject();bootstrap.Execute({action:'close',sessionId:session.sessionId,sessionToken:session.sessionToken});Reject(()=>Gate(session.sessionId,session.sessionToken,a.deviceId));Reject(()=>licenses.Execute(proof),/^DESKTOP_CHALLENGE_EXPIRED$/);
 database.ImportDatabaseObject(oldSnapshot);Reject(()=>Gate(session.sessionId,session.sessionToken,a.deviceId),/^BOOTSTRAP_SESSION_CLOSED$/);const retry=Restart(claimBody);assert.equal(retry.ok,false);assert.equal(retry.error,'BOOTSTRAP_SESSION_CLOSED');
});
Check('Service pause denies bootstrap and expired sessions cannot authorize licenses',()=>{
 state.serviceEnabled=false;try{Reject(()=>bootstrap.Execute(beginBody),/^(BOOTSTRAP_|SERVICE_DISABLED)/);}finally{state.serviceEnabled=true;}
 const next=fixture.Session(b),real=Date.now;Date.now=()=>next.expiresAt+1;try{Reject(()=>Gate(next.sessionId,next.sessionToken,b.deviceId));}finally{Date.now=real;}Reject(()=>Gate(next.sessionId,next.sessionToken,b.deviceId),/^BOOTSTRAP_EXPIRED$/);const row=Object.values(bootstrap.Initialize().flows).find(item=>item.sessionId===next.sessionId);assert.equal(row.sessionNonce,undefined);assert.equal(row.downloadNonce,undefined);
});
require('../services/desktopMachinePolicy').Set(a.machineId,false,{reason:'Independent bootstrap test epoch',requestId:crypto.randomUUID()},'TEST');
Check('Abort invalidates unfinished and claimed flow without reviving capabilities',()=>{
 for(const claimed of [false,true]){
  const pending=fixture.Begin(a);let running;
  if(claimed){fixture.Download(pending.begin);running=fixture.Claim(a,pending.begin,fixture.Finish(a,pending.begin));}
  const body={action:'abort',flowId:pending.begin.flowId,downloadTicket:pending.begin.downloadTicket};
  Reject(()=>bootstrap.Execute({...body,downloadTicket:'invalid'}));state.serviceEnabled=false;try{assert.equal(bootstrap.Execute(body).status,'CLOSED');}finally{state.serviceEnabled=true;}assert.equal(bootstrap.Execute(body).status,'CLOSED');
  Reject(()=>bootstrap.Execute(pending.body),/^BOOTSTRAP_SESSION_CLOSED$/);Reject(()=>fixture.Download(pending.begin),/^BOOTSTRAP_SESSION_CLOSED$/);
  if(running)Reject(()=>Gate(running.sessionId,running.sessionToken,a.deviceId),/^BOOTSTRAP_SESSION_CLOSED$/);
  const stored=bootstrap.Initialize().flows[pending.begin.flowId];for(const key of ['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'])assert.equal(stored[key],undefined);
  const retry=Restart(body);assert.equal(retry.ok,true,JSON.stringify(retry));assert.equal(retry.data.status,'CLOSED');
 }
});
Check('Expired unused launchers lose derivation secrets and cannot revive after clock rollback',()=>{
 const issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),real=Date.now;Date.now=()=>issue.expiresAt+1;try{Reject(()=>bootstrap.LauncherBytes(issue.launcherId),/^BOOTSTRAP_EXPIRED$/);}finally{Date.now=real;}
 const stored=bootstrap.Initialize().launchers[issue.launcherId];assert.equal(stored.status,'EXPIRED');assert.equal(stored.ticketNonce,undefined);assert.equal(stored.profile,undefined);Reject(()=>bootstrap.LauncherBytes(issue.launcherId));
});
Check('Corrupt bootstrap authority stops startup instead of reviving consumed tickets',()=>{
 const copy=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-corrupt-'));fs.cpSync(temp,copy,{recursive:true});fs.writeFileSync(path.join(copy,'desktop-bootstrap','authority.json'),'{"schema":1,"broken":');
 const result=child.spawnSync(process.execPath,['-e',"require(process.cwd()+'/storage/database').LoadDatabase();require(process.cwd()+'/services/desktopBootstrap').Initialize();process.stdout.write('UNSAFE_STARTED');"],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:copy},encoding:'utf8'});
 assert.notEqual(result.status,0);assert.ok(!result.stdout.includes('UNSAFE_STARTED'));assert.match(result.stderr,/BOOTSTRAP_STORAGE_INVALID/);
});

Check('Historical native templates and personalized overlays are rejected on reupload',()=>{
 for(const hex of ['47414d452d434f4e4e4543542d31','4d4f41504c4159413830434f4e46494721','4d4f41504c41592d434f4e4e4543542d31','4d4f41504c4159413830434f4e46494721']){
  const text=Buffer.from(hex,'hex').toString('ascii');
  for(const encoding of ['ascii','utf16le'])for(const component of ['A','B']){
   const bytes=PE(component);Buffer.from(text,encoding).copy(bytes,600);Reject(()=>bootstrap.Publish(component,'82.0.0',bytes),/^BOOTSTRAP_PE_INVALID$/);
  }
 }
});
Check('Historical authority migrates once, keeps tombstones and artifacts, and retires every old capability',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-migrate-')),authorityDir=path.join(dir,'desktop-bootstrap'),file=path.join(authorityDir,'authority.json');fs.mkdirSync(authorityDir);
 const stamp=Date.now(),secret=crypto.randomBytes(32).toString('hex'),legacyDomain=Buffer.from('4d4f41504c41592d413830','hex').toString('ascii'),legacyProtocol=Buffer.from('4d4f41504c41592d434f4e4e4543542d31','hex').toString('ascii');
 const ids={A:'DA-'+ '1'.repeat(24),B:'DA-'+ '2'.repeat(24),unused:'LA-'+ '3'.repeat(24),used:'LA-'+ '4'.repeat(24),flow:'BF-'+ '5'.repeat(24),session:'DS-'+ '6'.repeat(24)},nonce='a'.repeat(48);
 const token=(domain,id)=>crypto.createHmac('sha256',Buffer.from(secret,'hex')).update([legacyDomain,domain,id,nonce].join('|')).digest('base64url');
 const artifacts={},launchers={},flows={};
 for(const component of ['A','B']){const bytes=PE(component);artifacts[ids[component]]={id:ids[component],component,version:'82.0.0',sha256:sha256(bytes),size:bytes.length,createdAt:stamp};fs.writeFileSync(path.join(authorityDir,ids[component]+'.exe'),bytes);}
 for(const name of ['unused','used']){const id=ids[name];launchers[id]={id,label:'Historical launcher',artifactId:ids.A,sha256:sha256(id),ticketHash:sha256(token('LAUNCHER',id)),issuedAt:stamp,expiresAt:stamp+86400000,status:name==='unused'?'AVAILABLE':'CONSUMED',flowId:name==='used'?ids.flow:''};if(name==='unused'){launchers[id].ticketNonce=nonce;launchers[id].profile={version:1,protocol:legacyProtocol};}else launchers[id].retiredAt=stamp;}
 flows[ids.flow]={id:ids.flow,sessionId:ids.session,launcherId:ids.used,launcherSha256:launchers[ids.used].sha256,releaseId:ids.B,deviceId:a.deviceId,publicKey:a.publicKey,beginFingerprint:sha256('begin'),status:'CLAIMED',createdAt:stamp,expiresAt:stamp+900000,downloadNonce:nonce,finishNonce:nonce,downloadHash:sha256(token('DOWNLOAD',ids.flow)),chunkOffsets:[0],licenseId:'',lastVerifiedAt:0,handoffNonce:nonce,claimNonce:nonce,handoffHash:sha256(token('HANDOFF',ids.flow)),handoffExpiresAt:stamp+120000,sessionNonce:nonce,sessionHash:sha256(token('SESSION',ids.session)),claimedAt:stamp,sessionExpiresAt:stamp+300000};
 const original={schema:1,revision:7,secret,artifacts,active:{A:ids.A,B:ids.B},launchers,flows,issueReceipts:{historical:{fingerprint:sha256('issued'),launcherId:ids.unused}}};fs.writeFileSync(file,JSON.stringify(original));
 const script="const b=require(process.cwd()+'/services/desktopBootstrap'),p=JSON.parse(require('node:fs').readFileSync(0,'utf8'));b.Initialize();const codes={};for(const [name,fn]of Object.entries({issue:()=>b.IssueLauncher({requestId:'upgrade-attempt'}),download:()=>b.LauncherBytes(p.unused),session:()=>b.Gate(p.session,p.token,p.deviceId)}))try{fn();codes[name]='UNSAFE';}catch(e){codes[name]=e.message;}console.log('RESULT:'+JSON.stringify(codes));";
 for(let run=0;run<2;run++){
  const result=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:dir},input:JSON.stringify({...ids,token:token('SESSION',ids.session),deviceId:a.deviceId}),encoding:'utf8'});assert.equal(result.status,0,result.stderr);const out=JSON.parse(result.stdout.slice(result.stdout.lastIndexOf('RESULT:')+7));assert.deepEqual(out,{issue:'BOOTSTRAP_NOT_READY',download:'BOOTSTRAP_EXPIRED',session:'BOOTSTRAP_REVOKED'});
  const stored=JSON.parse(fs.readFileSync(file,'utf8'));assert.equal(stored.schema,4);assert.equal(stored.revision,8);assert.equal(stored.secret,secret);assert.deepEqual(stored.active,{});assert.deepEqual(stored.artifacts,artifacts);assert.deepEqual(stored.issueReceipts,original.issueReceipts);assert.equal(stored.launchers[ids.used].status,'CONSUMED');assert.equal(stored.launchers[ids.unused].status,'EXPIRED');assert.equal(stored.flows[ids.flow].status,'REVOKED');assert.equal(stored.flows[ids.flow].sessionHash,original.flows[ids.flow].sessionHash);
  for(const row of Object.values(stored.launchers)){assert.equal(row.ticketNonce,undefined);assert.equal(row.profile,undefined);}for(const key of ['downloadNonce','finishNonce','handoffNonce','claimNonce','sessionNonce'])assert.equal(stored.flows[ids.flow][key],undefined);
  for(const component of ['A','B'])assert.deepEqual(fs.readFileSync(path.join(authorityDir,ids[component]+'.exe')),PE(component));
 }
});

Check('Actual FIX83 authority upgrades TLS policy without recreating a ticket, session, or release',()=>{
 const original=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures','desktop-bootstrap-authority-v2.json'),'utf8')),dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-v2-')),authorityDir=path.join(dir,'desktop-bootstrap'),file=path.join(authorityDir,'authority.json');
 fs.mkdirSync(authorityDir);fs.writeFileSync(file,JSON.stringify(original));for(const row of Object.values(original.artifacts))fs.writeFileSync(path.join(authorityDir,row.id+'.exe'),PE(row.component));
 const script="const b=require(process.cwd()+'/services/desktopBootstrap');b.Initialize();console.log('RESULT:'+JSON.stringify(b.Overview()));";
 for(let run=0;run<2;run++){
  const result=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:dir},encoding:'utf8'});assert.equal(result.status,0,result.stderr);
  const stored=JSON.parse(fs.readFileSync(file,'utf8'));assert.equal(stored.schema,4);assert.equal(stored.revision,original.revision+1);assert.equal(stored.secret,original.secret);assert.deepEqual(stored.active,{});assert.deepEqual(stored.artifacts,original.artifacts);assert.deepEqual(stored.issueReceipts,original.issueReceipts);
  for(const [id,row]of Object.entries(original.launchers)){assert.equal(stored.launchers[id].status,row.status==='AVAILABLE'?'EXPIRED':row.status);assert.equal(stored.launchers[id].sha256,row.sha256);assert.equal(stored.launchers[id].ticketHash,row.ticketHash);assert.equal(stored.launchers[id].ticketNonce,undefined);assert.equal(stored.launchers[id].profile,undefined);}
  for(const [id,row]of Object.entries(original.flows)){assert.equal(stored.flows[id].status,['CLOSED','REVOKED','EXPIRED'].includes(row.status)?row.status:'REVOKED');assert.equal(stored.flows[id].sessionHash,row.sessionHash);assert.equal(stored.flows[id].sessionNonce,undefined);assert.equal(stored.flows[id].downloadNonce,undefined);}
 }
});
Check('Actual FIX84 authority upgrades code-integrity policy without recreating a ticket, session, or release',()=>{
 const original=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures','desktop-bootstrap-authority-v3.json'),'utf8')),dir=fs.mkdtempSync(path.join(os.tmpdir(),'game-bootstrap-v3-')),authorityDir=path.join(dir,'desktop-bootstrap'),file=path.join(authorityDir,'authority.json');
 fs.mkdirSync(authorityDir);fs.writeFileSync(file,JSON.stringify(original));for(const row of Object.values(original.artifacts))fs.writeFileSync(path.join(authorityDir,row.id+'.exe'),PE(row.component));
 const script="const b=require(process.cwd()+'/services/desktopBootstrap');b.Initialize();console.log('RESULT:'+JSON.stringify(b.Overview()));";
 for(let run=0;run<2;run++){
  const result=child.spawnSync(process.execPath,['-e',script],{cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:dir},encoding:'utf8'});assert.equal(result.status,0,result.stderr);
  const stored=JSON.parse(fs.readFileSync(file,'utf8'));assert.equal(stored.schema,4);assert.equal(stored.revision,original.revision+1);assert.equal(stored.secret,original.secret);assert.deepEqual(stored.active,{});assert.deepEqual(stored.artifacts,original.artifacts);assert.deepEqual(stored.issueReceipts,original.issueReceipts);
  for(const [id,row]of Object.entries(original.launchers)){assert.equal(stored.launchers[id].status,row.status==='AVAILABLE'?'EXPIRED':row.status);assert.equal(stored.launchers[id].sha256,row.sha256);assert.equal(stored.launchers[id].ticketHash,row.ticketHash);assert.equal(stored.launchers[id].ticketNonce,undefined);assert.equal(stored.launchers[id].profile,undefined);}
  for(const [id,row]of Object.entries(original.flows)){assert.equal(stored.flows[id].status,['CLOSED','REVOKED','EXPIRED'].includes(row.status)?row.status:'REVOKED');assert.equal(stored.flows[id].sessionHash,row.sessionHash);assert.equal(stored.flows[id].sessionNonce,undefined);assert.equal(stored.flows[id].downloadNonce,undefined);}
 }
});
Check('Server verifies its stored B bytes again before finish and claim',()=>{
 const pending=fixture.Begin(a);fixture.Download(pending.begin);const artifact=bootstrap.Initialize().artifacts[pending.begin.release.id],file=require('../services/desktopBootstrapStore').ArtifactPath(artifact.id),original=fs.readFileSync(file),tampered=Buffer.from(original);tampered[550]^=128;
 fs.writeFileSync(file,tampered);try{Reject(()=>fixture.Finish(a,pending.begin),/^BOOTSTRAP_ARTIFACT_INVALID$/);}finally{fs.writeFileSync(file,original);}
 const completed=fixture.Finish(a,pending.begin);fs.writeFileSync(file,tampered);try{Reject(()=>fixture.Claim(a,pending.begin,completed),/^BOOTSTRAP_ARTIFACT_INVALID$/);}finally{fs.writeFileSync(file,original);}
 const running=fixture.Claim(a,pending.begin,completed);const evidence=fixture.Evidence(a,running);
 Reject(()=>bootstrap.Gate(running.sessionId,running.sessionToken,a.deviceId,{...evidence,binaryCrc64:'0'.repeat(16)}),/^BOOTSTRAP_HASH_MISMATCH$/);
 Reject(()=>bootstrap.Gate(running.sessionId,running.sessionToken,a.deviceId,{...evidence,binarySha256:'0'.repeat(64)}),/^BOOTSTRAP_HASH_MISMATCH$/);
 Reject(()=>bootstrap.Gate(running.sessionId,running.sessionToken,a.deviceId,{...evidence,machineId:'0'.repeat(64)}),/^BOOTSTRAP_HASH_MISMATCH$/);
});
Check('Machine blocks deny bootstrap and unblocking cannot revive prior sessions',()=>{
 const device=Device(),pending=fixture.Begin(device);fixture.Download(pending.begin);const completed=fixture.Finish(device,pending.begin),running=fixture.Claim(device,pending.begin,completed),policy=require('../services/desktopMachinePolicy'),evidence=fixture.Evidence(device,running);
 const license=licenses.Create({label:'Automatic one use lock'},'TEST');licenses.Execute(LicenseProof(device,'redeem',{licenseKey:license.licenseKey,bootstrapSessionId:running.sessionId,bootstrapSessionToken:running.sessionToken}));
 assert.equal(policy.Public(device.machineId).blocked,true);assert.equal(policy.Public(device.machineId).source,'SINGLE_USE');
 assert.ok(bootstrap.Gate(running.sessionId,running.sessionToken,device.deviceId,evidence));
 bootstrap.Execute({action:'close',sessionId:running.sessionId,sessionToken:running.sessionToken});
 assert.equal(bootstrap.Execute({action:'status',sessionId:running.sessionId,sessionToken:running.sessionToken}).status,'CLOSED');assert.equal(bootstrap.Overview().sessions.find(item=>item.id===running.sessionId).online,false);
 Reject(()=>bootstrap.Gate(running.sessionId,running.sessionToken,device.deviceId,evidence),/^BOOTSTRAP_SESSION_CLOSED$/);
 Reject(()=>fixture.Begin(device),/^DESKTOP_MACHINE_BLOCKED$/);Reject(()=>fixture.Claim(device,pending.begin,completed),/^BOOTSTRAP_SESSION_CLOSED$/);
 policy.Set(device.machineId,false,{reason:'Test machine unblock',requestId:crypto.randomUUID()},'TEST');
 assert.equal(bootstrap.Execute({action:'status',sessionId:running.sessionId,sessionToken:running.sessionToken}).status,'CLOSED');
 Reject(()=>bootstrap.Gate(running.sessionId,running.sessionToken,device.deviceId,evidence),/^DESKTOP_MACHINE_SESSION_REVOKED$/);
 Reject(()=>fixture.Claim(device,pending.begin,completed),/^DESKTOP_MACHINE_SESSION_REVOKED$/);
 const fresh=fixture.Begin(device);fixture.Download(fresh.begin);assert.ok(fixture.Claim(device,fresh.begin,fixture.Finish(device,fresh.begin)).sessionId);
});

Check('Own executable reports compare to pristine upload and revoke modified-code flows',()=>{
 const device=Device(),pending=fixture.Begin(device);fixture.Download(pending.begin);const completed=fixture.Finish(device,pending.begin);
 const claim={action:'claim',flowId:pending.begin.flowId,handoffToken:completed.handoffToken,signature:Sign(device,completed.claimCanonical),binarySha256:pending.begin.release.sha256,crc64:pending.begin.release.crc64,bCodeSha256:'0'.repeat(64),bCodeCrc64:pending.begin.release.codeCrc64};
 Reject(()=>bootstrap.Execute(claim),/^BOOTSTRAP_CODE_MISMATCH$/);assert.equal(bootstrap.Initialize().flows[pending.begin.flowId].status,'REVOKED');assert.equal(bootstrap.Initialize().flows[pending.begin.flowId].codeIntegrityStatus,'REJECTED');
 Reject(()=>fixture.Claim(device,pending.begin,completed),/^BOOTSTRAP_REVOKED$/);
 const fresh=fixture.Begin(device);fixture.Download(fresh.begin);const session=fixture.Claim(device,fresh.begin,fixture.Finish(device,fresh.begin)),evidence=fixture.Evidence(device,session);
 Reject(()=>bootstrap.Gate(session.sessionId,session.sessionToken,device.deviceId,{...evidence,codeCrc64:'0'.repeat(16)}),/^BOOTSTRAP_CODE_MISMATCH$/);
 assert.equal(bootstrap.Overview().sessions.find(s=>s.id===session.sessionId).reason,'CODE_DIGEST_MISMATCH');
 const a=fixture.Begin(device);fixture.Download(a.begin);const finish={action:'finish',flowId:a.begin.flowId,downloadTicket:a.begin.downloadTicket,sha256:a.begin.release.sha256,crc64:a.begin.release.crc64,aCodeSha256:'0'.repeat(64),aCodeCrc64:a.begin.finishCanonical.split('\n')[6],signature:Sign(device,a.begin.finishCanonical)};
 Reject(()=>bootstrap.Execute(finish),/^BOOTSTRAP_CODE_MISMATCH$/);assert.equal(bootstrap.Initialize().flows[a.begin.flowId].status,'REVOKED');
 const issue=bootstrap.IssueLauncher({requestId:crypto.randomUUID()},'TEST'),bytes=bootstrap.LauncherBytes(issue.launcherId),cfg=Config(bytes);
 Reject(()=>bootstrap.Execute({action:'begin',requestId:crypto.randomUUID(),launcherId:issue.launcherId,launcherTicket:cfg.launcherTicket,launcherSha256:sha256(bytes),launcherCrc64:Crc64(bytes),aCodeSha256:'0'.repeat(64),aCodeCrc64:CodeImage(bytes).crc64,machineId:device.machineId,publicKey:device.publicKey,deviceId:device.deviceId}),/^BOOTSTRAP_CODE_MISMATCH$/);
 assert.equal(bootstrap.Initialize().launchers[issue.launcherId].status,'AVAILABLE');
});

Check('A diagnostics bind the personalized launcher and cannot cross into claimed B',()=>{
 const device=Device(),pending=fixture.Begin(device),auth={stage:'A',sessionId:pending.begin.flowId,sessionToken:pending.begin.downloadTicket,machineId:device.machineId};
 const row=bootstrap.AuthenticateIntegrityReport(auth);assert.equal(row.stage,'A');assert.equal(row.reportContextId,pending.begin.flowId);assert.equal(row.integrityArtifact.sha256,sha256(pending.bytes));assert.equal(row.integrityArtifact.crc64,Crc64(pending.bytes));assert.equal(row.integrityArtifact.codeSha256,CodeImage(pending.bytes).sha256);
 Reject(()=>bootstrap.AuthenticateIntegrityReport({...auth,sessionToken:'wrong'}));Reject(()=>bootstrap.AuthenticateIntegrityReport({...auth,machineId:'F'.repeat(64)}));
 fixture.Download(pending.begin);const finished=fixture.Finish(device,pending.begin);assert.equal(bootstrap.AuthenticateIntegrityReport(auth).stage,'A');
 const real=Date.now;Date.now=()=>finished.expiresAt+1;try{Reject(()=>bootstrap.AuthenticateIntegrityReport(auth),/^BOOTSTRAP_EXPIRED$/);}finally{Date.now=real;}
 fixture.Claim(device,pending.begin,finished);Reject(()=>bootstrap.AuthenticateIntegrityReport(auth),/^BOOTSTRAP_LAUNCHER_USED$/);
});

Check('Successful authoritative code checks refresh one bounded server observation',()=>{
 const device=Device(),pending=fixture.Begin(device);fixture.Download(pending.begin);const running=fixture.Claim(device,pending.begin,fixture.Finish(device,pending.begin)),reports=require('../services/desktopIntegrityReports'),evidence=fixture.Evidence(device,running);
 const find=()=>reports.List({sessionId:running.sessionId}).items.filter(r=>r.stage==='B'&&r.check==='OWN_CODE'&&r.status==='VERIFIED');const before=find();assert.equal(before.length,1);
 const real=Date.now,advanced=real()+11000;Date.now=()=>advanced;try{bootstrap.Gate(running.sessionId,running.sessionToken,device.deviceId,evidence);const after=find();assert.equal(after.length,1);assert.ok(after[0].at>before[0].at);assert.equal(after[0].expectedSha256,evidence.codeSha256);bootstrap.Gate(running.sessionId,running.sessionToken,device.deviceId,evidence);assert.equal(find()[0].id,after[0].id);}finally{Date.now=real;}
});

console.log(`Desktop bootstrap checks: ${checks} passed (${process.env.STORAGE_ENGINE})`);
