'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),{performance}=require('node:perf_hooks');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix69-perf-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='sqlite';require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),database=require('../storage/database'),sqlite=require('../storage/sqliteDatabase'),scope=require('../services/member/readScope'),social=require('../services/member/social'),service=require('../services/member/service');
let seq=0;const run=(c,action,body={})=>service.Execute(c,'FIX69-PERF-'+(++seq),action,body);
try{
 // Every transaction retains a durable authoritative snapshot. Normalized
 // relay tables are rewritten only when their own source data changed.
 const snapshot=database.BuildDatabaseObject();snapshot.servers={};snapshot.clients={};snapshot.licenses={};
 for(let i=0;i<120;i++)snapshot.clients['test-device-'+i]={id:i.toString(16).padStart(16,'0'),serverId:'',createdAt:1};
 let saved=sqlite.SaveSnapshot(snapshot);assert.equal(saved.normalizedChanged,true);
 const db=sqlite.Open();db.exec(`CREATE TEMP TABLE normalized_writes(n INTEGER); CREATE TEMP TRIGGER count_client_insert AFTER INSERT ON clients BEGIN INSERT INTO normalized_writes VALUES(1); END; CREATE TEMP TRIGGER count_client_delete AFTER DELETE ON clients BEGIN INSERT INTO normalized_writes VALUES(1); END;`);
 snapshot.memberHub.revision++;snapshot.memberHub.settings.performanceProbe='first';
 saved=sqlite.SaveSnapshot(snapshot);assert.equal(saved.normalizedChanged,false);assert.equal(db.prepare('SELECT COUNT(*) AS n FROM normalized_writes').get().n,0);
 assert.equal(sqlite.LoadSnapshot().data.memberHub.settings.performanceProbe,'first','member mutation still committed');
 snapshot.clients['test-device-0'].lastAuthAt=123;saved=sqlite.SaveSnapshot(snapshot);assert.equal(saved.normalizedChanged,true);assert.equal(db.prepare('SELECT COUNT(*) AS n FROM normalized_writes').get().n,240);
 snapshot.clients['test-device-0'].lastAuthAt=456;db.exec(`CREATE TEMP TRIGGER reject_snapshot BEFORE UPDATE ON state_snapshot BEGIN SELECT RAISE(ABORT,'injected disk failure'); END;`);
 assert.throws(()=>sqlite.SaveSnapshot(snapshot),/injected disk failure/);assert.equal(sqlite.LoadSnapshot().data.clients['test-device-0'].lastAuthAt,123,'failed snapshot rolled back normalized rows');
 db.exec('DROP TRIGGER reject_snapshot');assert.equal(sqlite.SaveSnapshot(snapshot).normalizedChanged,true,'retry still rewrites normalized rows after rollback');assert.equal(sqlite.LoadSnapshot().data.clients['test-device-0'].lastAuthAt,456);
 sqlite.Close();assert.equal(sqlite.SaveSnapshot(snapshot).normalizedChanged,true,'reopened storage rebuilds its projection');
 // A separate license recovery file remains durable, but identical member
 // writes cannot repeatedly copy and rewrite it.
 const licenseSnapshot=require('../storage/licenseSnapshot'),config=require('../config/config');
 let licenseWrites=0;const write=fs.writeFileSync;
 fs.writeFileSync=function(file,...args){if(file===config.LICENSE_SNAPSHOT_FILE+'.tmp')licenseWrites++;return write.call(this,file,...args);};
 try{
  assert.equal(licenseSnapshot.SaveLicenseSnapshot(),true);assert.equal(licenseWrites,1);
  assert.equal(licenseSnapshot.SaveLicenseSnapshot(),true);assert.equal(licenseWrites,1);
  state.licenses.set('PERF-LICENSE',{entryPass:true,expiresAt:0,createdAt:1});
  assert.equal(licenseSnapshot.SaveLicenseSnapshot(),true);assert.equal(licenseWrites,2);
  fs.unlinkSync(config.LICENSE_SNAPSHOT_FILE);assert.equal(licenseSnapshot.SaveLicenseSnapshot(),true);assert.equal(licenseWrites,3,'missing recovery file restored even for identical content');
  state.licenses.clear();
 }finally{fs.writeFileSync=write;}
 // Request-scoped table indexes preserve privacy and exact response values.
 state.memberHub=s.Empty();const hub=s.DB(),now=Date.now()-10000;
 for(let i=0;i<30;i++){const id='USR-PERF-'+i;hub.profiles['subject-'+i]={id,subject:'subject-'+i,nickname:'회원 '+i,bio:'',avatar:'',avatarRevision:0,balance:0,createdAt:now};}
 const people=Object.values(hub.profiles),viewer=people[0];
 for(let i=0;i<400;i++){const id='POST-PERF-'+i;hub.posts[id]={id,accountId:people[i%people.length].id,title:'이야기 '+i,body:'내용',at:now+i,revision:1};}
 for(let i=0;i<4000;i++){const id='REACTION-'+i;hub.reactions[id]={id,postId:'POST-PERF-'+(i%400),accountId:people[i%30].id,value:1};}
 for(let i=0;i<1200;i++){const id='COMMENT-'+i;hub.comments[id]={id,postId:'POST-PERF-'+(i%400),accountId:people[i%30].id,body:'댓글',at:now+i};}
 for(let i=0;i<30;i++)for(let j=i+1;j<30;j++)hub.follows[people[i].id+':'+people[j].id]={follower:people[i].id,following:people[j].id,at:now};
 hub.blocks[viewer.id+':'+people[3].id]={blocker:viewer.id,blocked:people[3].id};
 const watched=new Set([hub.posts,hub.reactions,hub.comments,hub.follows]),values=Object.values;let scans=0;
 Object.values=function(value){if(watched.has(value))scans++;return values(value);};
 let plain,indexed,beforeScans,afterScans;
 try{plain=social.Feed(viewer,{sort:'latest'});beforeScans=scans;scans=0;indexed=scope.Run(()=>social.Feed(viewer,{sort:'latest'}));afterScans=scans;}finally{Object.values=values;}
 assert.deepEqual(indexed,plain);assert.ok(afterScans<beforeScans,`${afterScans} request scans < ${beforeScans} baseline scans`);assert.equal(scope.Active(),false,'scope released after a read');
 scope.Run(()=>{assert.equal(scope.By('posts','accountId',viewer.id).length,14);s.Atomic(()=>{hub.posts.EXTRA={id:'EXTRA',accountId:viewer.id,title:'새 글',body:'',at:now+999,revision:1};});assert.equal(scope.By('posts','accountId',viewer.id).length,15,'atomic write invalidates existing request indexes');});
 const save=database.SaveDatabase;scope.Run(()=>{scope.By('posts','accountId',viewer.id);database.SaveDatabase=()=>false;try{assert.throws(()=>s.Atomic(()=>{s.DB().posts.FAIL={id:'FAIL',accountId:viewer.id};}),/STORAGE_SAVE_FAILED/);}finally{database.SaveDatabase=save;}assert.equal(scope.By('posts','accountId',viewer.id).length,15,'rollback invalidates references to failed rows');});
 assert.throws(()=>scope.Run(()=>{throw Error('scope throw');}),/scope throw/);assert.equal(scope.Active(),false);
 const measure=fn=>{for(let i=0;i<2;i++)fn();const results=[];for(let i=0;i<5;i++){const start=performance.now();fn();results.push(performance.now()-start);}return results.sort((a,b)=>a-b)[2].toFixed(2);};
 const p=s.ProfileById(viewer.id),beforeMs=measure(()=>social.Feed(p,{sort:'latest'})),afterMs=measure(()=>scope.Run(()=>social.Feed(p,{sort:'latest'})));
 // Reconnection can remember intent, never authorization. A fresh challenge
 // invalidates the old test grant and every access gate is checked again.
 const id='0000000000006969',key='FIX69-PERF-CLIENT',c={type:'client',clientId:id,connected:true,permissionsGranted:true,deviceAuthVerified:true,licenseAuthorized:true,biometricVerified:false,installationDeviceKey:key,deviceAuthChallengeId:'AUTH-OLD',socket:{destroyed:false,write(){return true;}}};
 state.clients.set(id,c);state.clientIdentities.set(key,{id,serverId:'',createdAt:Date.now()});state.deviceAuthStatus.set('CLIENT:'+id,{verified:true,verifiedAt:Date.now()});state.deviceSecrets.set('CLIENT:'+id,crypto.randomBytes(32).toString('hex'));
 assert.throws(()=>run(c,'feed'),/MEMBER_AUTH_REQUIRED/);assert.equal(run(c,'test.enter').challengeId,'AUTH-OLD');run(c,'feed');
 // Rotation refreshes the challenge without replacing or disconnecting the
 // socket. Neither a saved native entry intention nor the old server grant
 // authorizes the fresh session until a new test.enter is accepted.
 const sameConnection=c,sameSocket=c.socket;
 c.deviceAuthChallengeId='AUTH-NEW';assert.equal(state.clients.get(id),sameConnection);assert.equal(c.socket,sameSocket);assert.equal(c.connected,true);
 assert.throws(()=>run(c,'feed'),/MEMBER_AUTH_REQUIRED/,'in-session challenge invalidates previous grant');
 assert.equal(run(c,'test.enter').challengeId,'AUTH-NEW');run(c,'feed');
 c.permissionsGranted=false;assert.throws(()=>run(c,'test.enter'),/MEMBER_AUTH_REQUIRED/);assert.throws(()=>run(c,'feed'),/MEMBER_AUTH_REQUIRED/);c.permissionsGranted=true;
 const member=s.Account(c);s.Atomic(()=>{member.blocked=true;});assert.throws(()=>run(c,'test.enter'),/ACCOUNT_BLOCKED/);s.Atomic(()=>{s.ProfileById(member.id).blocked=false;});
 state.serviceEnabled=false;assert.throws(()=>run(c,'test.enter'),/SERVICE_DISABLED/);state.serviceEnabled=true;
 process.env.MEMBER_BIOMETRIC_TEST_MODE='0';assert.throws(()=>run(c,'test.enter'),/MEMBER_AUTH_REQUIRED/);process.env.MEMBER_BIOMETRIC_TEST_MODE='1';
 const native=path.resolve(__dirname,'../../MoaPlayApp_Android64'),read=name=>fs.readFileSync(path.join(native,'MoaPlayApp.'+name+'.inc'),'utf8');
 const flow=read('Member.Flow'),resume=read('Member.TestAccess'),connection=read('Connection'),connectivity=read('Lifecycle.Connectivity'),access=read('Member.Access');
 const transport=fs.readFileSync(path.join(native,'MoaPlayMemberClient.pas'),'utf8'),send=transport.slice(transport.indexOf('function TMoaPlayMemberClient.SendRequest'),transport.indexOf('procedure TMoaPlayMemberClient.PumpUpload'));
 // Exercise the capacity predicate read from the native source. A replay
 // replaces one existing slot; only a new ID consumes additional capacity.
 const slotGate=send.match(/if \(FRequests\.Count >= (\d+)\) and not FRequests\.ContainsKey\(ID\) then Exit;/);assert.ok(slotGate,'capacity guard permits existing ID replacement');
 const limit=Number(slotGate[1]),slots=new Map(Array.from({length:limit},(_,i)=>['REQUEST-'+i,{waiting:true}]));
 const submit=id=>{if(slots.size>=limit&&!slots.has(id))return false;slots.set(id,{retried:true});return true;};
 assert.equal(submit('REQUEST-0'),true,'same durable ID can retry with all six slots occupied');assert.equal(slots.size,limit,'retry does not allocate another slot');
 assert.equal(submit('NEW-REQUEST'),false,'new requests remain bounded to six slots');slots.delete('REQUEST-1');assert.equal(submit('NEW-REQUEST'),true,'a released slot accepts a new request');assert.equal(slots.size,limit);
 assert.ok(send.indexOf('FRequests.ContainsKey(ID)')<send.indexOf('FRequests.AddOrSetValue(ID,Entry)'),'capacity check precedes slot mutation');
 assert.ok(flow.includes('HubFetch;HubRecordVisit(FHubView)'),'foreground read precedes synchronous visit persistence');
 assert.ok(resume.includes("FMemberTestResumeClientID<>FState.ClientID")||resume.includes("FState.ClientID<>FMemberTestResumeClientID"));assert.ok(resume.includes('MemberTestEnterClick(nil)'));assert.ok(resume.includes('FMemberTestChallenge=FPermissionAuthID'));assert.ok(!access.includes('FMemberTestResumePending'),'intent cannot grant access');
 const security=read('Extensions'),challenge=security.slice(security.indexOf("if Line.StartsWith('AUTH_CHALLENGE|') then"),security.indexOf("if Line.StartsWith('DEVICE_AUTH_OK|') then"));
 function challengeIntentGuard(source){
  const active=source.indexOf('if FMemberTestGranted and MemberAccessReady then ResumeClientID:=FState.ClientID'),reset=source.indexOf('ResetLiveAuthentication;');
  assert.ok(active>=0&&active<reset,'active in-session entry intent captured before authorization reset');
  assert.ok(source.includes('not FState.ServiceDisabled')&&source.includes('not FState.ClientDisabled')&&source.includes('not FState.VersionBlocked'),'blocked sessions cannot create resume intent');
  assert.ok(source.indexOf('FMemberTestResumePending:=ResumeClientID')>reset,'only intent is restored after resetting live authorization');
 }
 challengeIntentGuard(challenge);
 assert.throws(()=>challengeIntentGuard(challenge.replace('if FMemberTestGranted and MemberAccessReady then ResumeClientID:=FState.ClientID','')),/entry intent/,'guard detects the original same-connection regression');
 assert.ok(connection.includes('FMemberTestGranted and MemberAccessReady'));assert.ok(connectivity.includes('NowMs - FLastLinkProbeAt >= 15000'));assert.ok(connectivity.indexOf('if not NetworkConnected')<connectivity.indexOf('15000'),'real network loss remains independently detected');
 console.log(`FIX69 PERFORMANCE PASS: same feed projection; table scans ${beforeScans} -> ${afterScans}; local fixture median ${beforeMs}ms -> ${afterMs}ms. SQLite commit/rollback/reopen, normalized writes, fresh challenge authorization and native reconnect guards passed.`);
}finally{sqlite.Close();fs.rmSync(dir,{recursive:true,force:true});}
