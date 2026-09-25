'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{Readable}=require('node:stream');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix72-oauth-'));
Object.assign(process.env,{DATA_DIR:dir,STORAGE_ENGINE:'json',NODE_ENV:'test',MEMBER_OAUTH_PUBLIC_URL:'https://moa.example',MEMBER_OAUTH_TOKEN_KEY:crypto.randomBytes(32).toString('hex'),GOOGLE_OAUTH_CLIENT_ID:'test-google',GOOGLE_OAUTH_CLIENT_SECRET:'google-private-secret',KAKAO_OAUTH_CLIENT_ID:'test-kakao',KAKAO_OAUTH_CLIENT_SECRET:'kakao-private-secret',KAKAO_UNLINK_ADMIN_KEY:'kakao-private-primary-admin-key',KAKAO_APP_ID:'987654',MEMBER_OAUTH_CHECK_INTERVAL_MS:'30000'});
delete process.env.MOAPLAY_ALLOW_LEGACY_TEST_IDENTITY;delete process.env.MEMBER_BIOMETRIC_TEST_MODE;
require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),oauth=require('../services/member/oauthIdentity'),lifecycle=require('../services/member/oauthLifecycle'),vault=require('../services/member/oauthCredentials'),service=require('../services/member/service'),protocol=require('../services/member/protocol'),admin=require('../services/member/adminAccounts'),database=require('../storage/database'),ha=require('../services/haCoordinator');
const originalFetch=global.fetch,originalNow=Date.now,originalSave=database.SaveDatabase,originalCanAcceptTraffic=ha.CanAcceptTraffic;
let now=originalNow(),sequence=0,saves=0;
database.SaveDatabase=function(...args){saves++;return originalSave.apply(this,args);};
Date.now=()=>now;
const rawTokens=new Set(),byRefresh=new Map(),byAccess=new Map(),calls=[];
const tick=ms=>{now+=ms;};
const settled=()=>new Promise(resolve=>setImmediate(resolve));
const binding=p=>p.providerIdentity.key+'\0'+p.id+'\0'+p.subject;
const row=f=>lifecycle.Record(s.ProfileById(f.accountId));
const status=f=>lifecycle.AdminStatus(s.ProfileById(f.accountId));
function token(value){rawTokens.add(value);return value;}
function json(body,status=200){return new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});}
function client(){
 const n=String(++sequence),id=('A'.repeat(16)+n).slice(-16),key='TEST-FIX72-OAUTH-DEVICE-'+n,socket={destroyed:false,lines:[],write(x){this.lines.push(x);},cork(){},uncork(){}};
 const c={clientId:id,installationDeviceKey:key,connected:true,socket,permissionsGranted:true,permissionSequence:1,permissionMask:7,deviceAuthVerified:true,deviceAuthChallengeId:'FIX72-CHALLENGE-'+n,licenseAuthorized:true,biometricVerified:true};
 state.clientIdentities.set(key,{id});state.clients.set(id,c);state.deviceSecrets.set('CLIENT:'+id,'fix72-device-secret-'+n);return c;
}
function fixture(provider='google',subject){
 const c=client(),p=s.Account(c),f={c,provider,sub:subject||String(100000+sequence),accountId:p.id,mode:'valid',refreshes:0,probes:0,rotate:false,epoch:0};
 p.balance=32100+sequence;p.points=430+sequence;
 s.DB().orders['KEEP-'+p.id]={id:'KEEP-'+p.id,accountId:p.id,amount:10};
 f.owned={id:p.id,subject:p.subject,balance:p.balance,points:p.points,order:structuredClone(s.DB().orders['KEEP-'+p.id])};
 relink(f);return f;
}
function relink(f,expiresIn=3600){
 const p=s.ProfileById(f.accountId),key=crypto.createHash('sha256').update(f.provider+'\0'+f.sub).digest('hex');f.epoch++;
 f.access=token('private-access-'+f.accountId+'-'+f.epoch);f.refresh=token('private-refresh-'+f.accountId+'-'+f.epoch);
 byAccess.set(f.access,f);byRefresh.set(f.refresh,f);
 const credentials={accessToken:f.access,refreshToken:f.refresh,expiresAt:now+expiresIn*1000,refreshExpiresAt:now+86400000};
 s.Atomic(()=>{const old=s.DB().oauthAccounts[key];p.providerIdentity={provider:f.provider,key,label:f.provider+' member',linkedAt:p.providerIdentity?.linkedAt||now};s.DB().oauthAccounts[key]=lifecycle.Fresh(p,credentials,old);});
 return row(f).generation;
}
function replaceReplicatedEnvelope(f){
 const p=s.ProfileById(f.accountId),suffix=++sequence,accessToken=token('private-replica-access-'+suffix),refreshToken=token('private-replica-refresh-'+suffix);
 byAccess.set(accessToken,f);byRefresh.set(refreshToken,f);
 const envelope=vault.Seal({accessToken,refreshToken,expiresAt:now+3600000,refreshExpiresAt:now+86400000},binding(p));
 s.Atomic(()=>{row(f).credentials=envelope;});return {envelope,refreshToken};
}
function retained(f){
 const p=s.ProfileById(f.accountId);assert.equal(p.id,f.owned.id);assert.equal(p.subject,f.owned.subject);assert.equal(p.balance,f.owned.balance);assert.equal(p.points,f.owned.points);
 assert.deepEqual(s.DB().orders['KEEP-'+p.id],f.owned.order);assert.equal(s.DB().oauthAccounts[p.providerIdentity.key].accountId,p.id);assert.equal(s.DB().oauthAccounts[p.providerIdentity.key].installationSubject,p.subject);
 if(f.pc)assert.deepEqual(state.licenses.get(f.c.licenseKey),f.pc.license,'Permanent QR license is retained');
}
function attachPc(f){
 const serverId='B'+f.c.clientId.slice(1),activeId='BLS-FIX72-ACTIVE-'+f.c.clientId,pendingId='BLS-FIX72-PENDING-'+f.c.clientId,requestId='FIX72-PENDING-REQUEST-'+f.c.clientId,secret='fix72-server-secret';
 const socket={destroyed:false,lines:[],write(x){this.lines.push(x);},cork(){},uncork(){}};
 const server={serverId,registered:true,socket,buildGateCapable:true,buildUnlocked:true,buildClients:new Set([f.c.clientId]),buildSessions:new Map([[f.c.clientId,activeId]])};
 state.servers.set(serverId,server);state.serverIdentities.set('FIX72-PC-DEVICE',serverId);state.deviceSecrets.set('SERVER:'+serverId,secret);
 state.clientIdentities.get(f.c.installationDeviceKey).serverId=serverId;
 Object.assign(f.c,{serverId,buildCompleted:true,buildSessionId:activeId,hubUpload:{pending:true},licenseKey:'FIX72-PERMANENT-QR-'+f.c.clientId});
 const license={boundClient:f.c.clientId,expiresAt:0,source:'QR',suspended:false};state.licenses.set(f.c.licenseKey,license);
 state.clientBiometricChallenges.set(f.c.clientId,{nonce:'fix72-pending-biometric'});
 state.buildSessions.set(activeId,{sessionId:activeId,clientId:f.c.clientId,serverId,status:'AUTHORIZED',expiresAt:now+600000});
 state.buildSessions.set(pendingId,{sessionId:pendingId,clientId:f.c.clientId,serverId,status:'PENDING'});
 state.pendingBuildGrants.set(f.c.clientId,{sessionId:pendingId,clientId:f.c.clientId,serverId,requestId,status:'PENDING',expiresAt:now+600000});
 state.pendingRequests.set(f.c.clientId+'|'+requestId,{kind:'BUILD',clientId:f.c.clientId,requestId});
 f.pc={server,serverId,activeId,pendingId,requestId,secret,license:structuredClone(license)};
}
function revokedPc(f,reason='IDENTITY_REAUTH_REQUIRED',identityRevoked=true){
 const pc=f.pc;
 assert.equal(state.clientBiometricChallenges.has(f.c.clientId),false);if(identityRevoked)assert.equal(f.c.hubUpload,null);assert.equal(f.c.buildCompleted,false);assert.equal(f.c.buildSessionId,'');
 assert.equal(state.buildSessions.get(pc.activeId).status,'REVOKED');assert.equal(state.buildSessions.get(pc.pendingId).status,'FAILED');
 assert.equal(state.pendingBuildGrants.has(f.c.clientId),false);assert.equal(state.pendingRequests.has(f.c.clientId+'|'+pc.requestId),false);
 assert.equal(pc.server.buildUnlocked,false);assert.equal(pc.server.buildClients.has(f.c.clientId),false);assert.equal(pc.server.buildSessions.has(f.c.clientId),false);
 const proof=crypto.createHmac('sha256',pc.secret).update('REVOKE|'+pc.serverId+'|'+f.c.clientId+'|'+pc.activeId+'|'+reason).digest('hex').toUpperCase();
 assert.ok(pc.server.socket.lines.some(x=>x.trim()==='BUILD_REVOKE|'+f.c.clientId+'|'+pc.activeId+'|'+reason+'|'+proof));
 if(identityRevoked)assert.ok(pc.server.socket.lines.some(x=>x.trim()==='CLIENT_UNAUTHORIZED|'+f.c.clientId+'|'+reason));
}
function privateOutputs(f){
 const p=s.ProfileById(f.accountId),output=JSON.stringify({public:s.PublicProfile(p),own:s.PublicProfile(p,true),admin:admin.Profile(p),integrations:admin.Configuration(),status:service.Execute(f.c,'FIX72-STATUS-'+(++sequence),'identity.status',{})});
 for(const value of [...rawTokens,process.env.GOOGLE_OAUTH_CLIENT_SECRET,process.env.KAKAO_OAUTH_CLIENT_SECRET,process.env.MEMBER_OAUTH_TOKEN_KEY,process.env.KAKAO_UNLINK_ADMIN_KEY])assert.equal(output.includes(value),false,'Public/admin output exposed a credential');
 assert.equal(output.includes('"credentials":"v1.'),false,'Encrypted credentials must also stay out of public/admin projections');
}
function signedRevocation(f,reason){
 const lines=f.c.socket.lines.filter(x=>x.startsWith('HUB_IDENTITY|'));assert.equal(lines.length,1,'One native invalidation per revocation');
 const parts=lines[0].trim().split('|');assert.equal(parts.length,4);assert.equal(parts[2],reason);assert.equal(protocol.Verify(f.c,parts.slice(1,3),parts[3],'HUB_IDENTITY'),true);
 assert.equal(protocol.Verify(f.c,[parts[1],'IDENTITY_OTHER'],parts[3],'HUB_IDENTITY'),false);assert.equal(f.c.biometricVerified,false);assert.equal(f.c.licenseAuthorized,true,'QR license ownership remains registered');
}
global.fetch=async(url,options={})=>{
 assert.equal(options.redirect,'error');assert.ok(options.signal);calls.push({url,options});
 if(url==='https://oauth2.googleapis.com/token'||url==='https://kauth.kakao.com/oauth/token'){
  assert.equal(options.method,'POST');assert.match(options.headers['Content-Type'],/^application\/x-www-form-urlencoded/);
  const body=new URLSearchParams(options.body),f=byRefresh.get(body.get('refresh_token'));assert.ok(f,'Only stored current provider refresh tokens may be used');
  assert.equal(body.get('grant_type'),'refresh_token');assert.equal(body.get('client_id'),'test-'+f.provider);assert.equal(body.get('client_secret'),process.env[f.provider.toUpperCase()+'_OAUTH_CLIENT_SECRET']);f.refreshes++;
  if(f.defer){const mode=f.mode;f.defer=false;return new Promise(resolve=>{f.release=()=>resolve(refreshResponse(f,mode));});}
  return refreshResponse(f,f.mode);
 }
 if(url==='https://openidconnect.googleapis.com/v1/userinfo'||url==='https://kapi.kakao.com/v1/user/access_token_info'){
  const auth=options.headers.Authorization;assert.match(auth,/^Bearer /);const f=byAccess.get(auth.slice(7));assert.ok(f);f.probes++;
  assert.equal(url,f.provider==='google'?'https://openidconnect.googleapis.com/v1/userinfo':'https://kapi.kakao.com/v1/user/access_token_info');
  if(f.mode==='outage'||f.mode==='probe-outage')return json({error:'temporarily_unavailable'},503);
  if(f.mode==='malformed')return new Response('{', {status:200});
  if(f.mode==='missing-subject')return json({});
  if(f.mode==='kakao-transient')return json({code:-1,msg:'temporary failure'},400);
  if(f.mode==='revoked'||f.mode==='access-expired'&&!f.refreshed)return json({code:-401,msg:'invalid token'},401);
  const sub=f.mode==='wrong-subject'?'999999999999':f.sub;
  return json(f.provider==='google'?{sub}:{id:Number(sub),app_id:Number(process.env.KAKAO_APP_ID),expires_in:3600});
 }
 assert.fail('Unexpected outbound endpoint '+url);
};
function refreshResponse(f,mode){
 if(mode==='outage')return json({error:'temporarily_unavailable'},503);
 if(mode==='client-error')return json({error:'invalid_client',error_code:'KOE010'},401);
 if(mode==='revoked')return json({error:'invalid_grant',...(f.provider==='kakao'?{error_code:'KOE322',error_description:'expired_or_invalid_refresh_token'}:{})},400);
 if(mode==='kakao-request-error')return json({error:'invalid_grant',error_code:'KOE319',error_description:'refresh token is blank'},400);
 const access=token('private-renewed-access-'+f.accountId+'-'+f.epoch+'-'+f.refreshes);byAccess.set(access,f);f.refreshed=true;
 const result={access_token:access,expires_in:3600};
 if(f.rotate){const refresh=token('private-rotated-refresh-'+f.accountId+'-'+f.refreshes);byRefresh.set(refresh,f);result.refresh_token=refresh;result.refresh_token_expires_in=86400;}
 return json(result);
}
function response(){return {headers:{},status:0,body:'',setHeader(k,v){this.headers[k]=v;},writeHead(status,h){this.status=status;Object.assign(this.headers,h);},end(b=''){this.body+=b;}};}
async function callback(f,{authorization='KakaoAK '+process.env.KAKAO_UNLINK_ADMIN_KEY,app=process.env.KAKAO_APP_ID,method='GET',extra=''}={}){
 const body=new URLSearchParams({app_id:app,user_id:f.sub,referrer_type:'UNLINK_FROM_APPS'}).toString()+extra,url=new URL('https://moa.example/member/oauth/kakao/unlink'+(method==='GET'?'?'+body:''));
 const req=method==='POST'?Readable.from([Buffer.from(body)]):{};req.method=method;req.headers={authorization,...(method==='POST'?{'content-type':'application/x-www-form-urlencoded'}:{})};
 const res=response();assert.equal(await oauth.HandleHttp(req,res,url),true);return res;
}
(async()=>{try{
 // Real authenticated encryption binds the provider grant to the existing account.
 const google=fixture();attachPc(google);assert.equal(oauth.Ready(google.c),true);assert.equal(service.Allowed(google.c),true);
 const initial=row(google),opened=vault.Open(initial.credentials,binding(s.ProfileById(google.accountId)));
 assert.equal(opened.refreshToken,google.refresh);assert.ok(!JSON.stringify(s.DB()).includes(google.refresh));
 assert.throws(()=>vault.Open(initial.credentials,binding(s.ProfileById(google.accountId))+'other'));privateOutputs(google);

 // A successful refresh rotates secrets, and an omitted replacement retains the new refresh token.
 google.rotate=true;let beforeSaves=saves,result=await lifecycle.CheckAccount(google.accountId,{force:true});await settled();assert.equal(result.status,'active');assert.equal(saves-beforeSaves,1,'Refresh-token rotation is persisted exactly once');
 let saved=vault.Open(row(google).credentials,binding(s.ProfileById(google.accountId)));assert.notEqual(saved.refreshToken,google.refresh);assert.equal(google.probes,1);
 const rotated=saved.refreshToken;google.rotate=false;tick(5001);beforeSaves=saves;const storedBeforeAccessRefresh=row(google).credentials,storedVerifiedAt=row(google).verifiedAt;await lifecycle.CheckAccount(google.accountId,{force:true});await settled();
 assert.equal(saves-beforeSaves,0,'Healthy Google access-only refresh does not save the whole database');assert.equal(row(google).credentials,storedBeforeAccessRefresh);assert.equal(row(google).verifiedAt,storedVerifiedAt);assert.equal(status(google).verifiedAt,now,'Current verification is visible from runtime observation');
 saved=vault.Open(row(google).credentials,binding(s.ProfileById(google.accountId)));assert.equal(saved.refreshToken,rotated);assert.equal(new URLSearchParams(calls.filter(x=>x.url==='https://oauth2.googleapis.com/token').at(-1).options.body).get('refresh_token'),rotated);privateOutputs(google);

 // External grant rejection revokes volatile member access while retaining all local ownership.
 google.mode='revoked';tick(5001);result=await lifecycle.CheckAccount(google.accountId,{force:true});await settled();
 assert.equal(result.status,'revoked');assert.equal(result.linked,false);assert.equal(row(google).credentials,undefined);assert.equal(oauth.Ready(google.c),false);assert.equal(service.Allowed(google.c),false);
 signedRevocation(google,'IDENTITY_REAUTH_REQUIRED');revokedPc(google);retained(google);privateOutputs(google);
 await lifecycle.CheckAccount(google.accountId,{force:true});signedRevocation(google,'IDENTITY_REAUTH_REQUIRED');

 // Provider outages keep the identity visible, but block member access after the 15-minute bound.
 const outage=fixture();attachPc(outage);outage.mode='outage';beforeSaves=saves;await lifecycle.CheckAccount(outage.accountId,{force:true});await settled();assert.equal(saves-beforeSaves,1,'First outage persists its transition');
 assert.equal(status(outage).status,'degraded');assert.equal(status(outage).linked,true);assert.equal(oauth.Ready(outage.c),true);assert.equal(service.Allowed(outage.c),true);
 tick(5001);beforeSaves=saves;await lifecycle.CheckAccount(outage.accountId,{force:true});await settled();assert.equal(saves-beforeSaves,0,'Repeated outage does not snapshot unchanged error state');assert.equal(state.buildSessions.get(outage.pc.activeId).status,'AUTHORIZED');assert.equal(state.clientBiometricChallenges.has(outage.c.clientId),true);
 const encrypted=row(outage).credentials;tick(15*60*1000+1);const degraded=service.Execute(outage.c,'FIX72-STALE-STATUS','identity.status',{}).identity;
 assert.equal(degraded.linked,true);assert.equal(degraded.ready,false);assert.equal(service.Allowed(outage.c),false);assert.equal(oauth.AccessReason(outage.c),'IDENTITY_PROVIDER_UNAVAILABLE');
 await lifecycle.CheckAccount(outage.accountId);await settled();assert.equal(row(outage).credentials,encrypted);assert.equal(outage.c.socket.lines.some(x=>x.startsWith('HUB_IDENTITY|')),false);assert.equal(outage.c.biometricVerified,true,'Stale provider status must not erase a valid OS biometric check');revokedPc(outage,'IDENTITY_PROVIDER_UNAVAILABLE',false);retained(outage);
 beforeSaves=saves;assert.equal(oauth.Ready(outage.c),false);assert.equal(oauth.Ready(outage.c),false);assert.equal(saves-beforeSaves,0,'Already suspended stale access does not repeatedly save');
 outage.mode='valid';tick(5001);beforeSaves=saves;await lifecycle.CheckAccount(outage.accountId,{force:true});await settled();assert.equal(saves-beforeSaves,1,'Recovery clears the persisted outage once');assert.equal(oauth.Ready(outage.c),true);assert.equal(status(outage).status,'active');assert.equal(outage.c.biometricVerified,true);privateOutputs(outage);

 // Concurrent checks share work; force cannot bypass the five-second floor, ordinary checks honor the interval.
 const bounded=fixture();bounded.defer=true;const first=lifecycle.CheckAccount(bounded.accountId,{force:true}),second=lifecycle.CheckAccount(bounded.accountId,{force:true});
 assert.equal(first,second);assert.equal(bounded.refreshes,1);assert.equal(typeof bounded.release,'function');bounded.release();await Promise.all([first,second]);await settled();
 await lifecycle.CheckAccount(bounded.accountId,{force:true});assert.equal(bounded.refreshes,1);tick(4999);await lifecycle.CheckAccount(bounded.accountId,{force:true});assert.equal(bounded.refreshes,1);
 tick(1);await lifecycle.CheckAccount(bounded.accountId,{force:true});await settled();assert.equal(bounded.refreshes,2);tick(5001);await lifecycle.CheckAccount(bounded.accountId);assert.equal(bounded.refreshes,2);
 tick(25000);await lifecycle.CheckAccount(bounded.accountId);await settled();assert.equal(bounded.refreshes,3);

 // A valid response for another provider subject cannot keep this member authenticated.
 const mismatch=fixture();mismatch.mode='wrong-subject';result=await lifecycle.CheckAccount(mismatch.accountId,{force:true});await settled();assert.equal(result.reason,'IDENTITY_TOKEN_INVALID');assert.equal(result.linked,false);signedRevocation(mismatch,'IDENTITY_TOKEN_INVALID');retained(mismatch);

 // A malformed/configuration response is not evidence of grant revocation.
 const config=fixture();config.mode='client-error';await lifecycle.CheckAccount(config.accountId,{force:true});await settled();assert.equal(status(config).linked,true);assert.ok(row(config).credentials);assert.equal(config.c.socket.lines.length,0);
 config.mode='malformed';tick(5001);await lifecycle.CheckAccount(config.accountId,{force:true});await settled();assert.equal(status(config).status,'degraded');assert.equal(status(config).linked,true);
 config.mode='missing-subject';tick(5001);await lifecycle.CheckAccount(config.accountId,{force:true});await settled();assert.equal(status(config).linked,true,'A missing subject is malformed provider data, not a confirmed identity change');assert.ok(row(config).credentials);assert.equal(config.c.socket.lines.length,0);

 // Refresh rotation must survive a subsequent userinfo outage without extending identity freshness.
 const probeOutage=fixture(),verifiedBeforeProbe=status(probeOutage).verifiedAt;probeOutage.mode='probe-outage';probeOutage.rotate=true;tick(5001);
 await lifecycle.CheckAccount(probeOutage.accountId,{force:true});await settled();
 const refreshAfterProbe=vault.Open(row(probeOutage).credentials,binding(s.ProfileById(probeOutage.accountId))).refreshToken;
 assert.notEqual(refreshAfterProbe,probeOutage.refresh);assert.equal(status(probeOutage).linked,true);assert.equal(status(probeOutage).status,'degraded');assert.equal(status(probeOutage).verifiedAt,verifiedBeforeProbe);assert.equal(row(probeOutage).verifiedAt,verifiedBeforeProbe);assert.equal(probeOutage.c.socket.lines.length,0);
 probeOutage.mode='valid';probeOutage.rotate=false;tick(5001);await lifecycle.CheckAccount(probeOutage.accountId,{force:true});await settled();
 assert.equal(new URLSearchParams(calls.filter(x=>x.url==='https://oauth2.googleapis.com/token').at(-1).options.body).get('refresh_token'),refreshAfterProbe);assert.equal(status(probeOutage).status,'active');assert.equal(status(probeOutage).ready,true);retained(probeOutage);privateOutputs(probeOutage);

 // Kakao access-token expiry refreshes and verifies again; transient errors do not revoke.
 const healthyKakao=fixture('kakao'),kakaoStoredCredentials=row(healthyKakao).credentials;
 beforeSaves=saves;await lifecycle.CheckAccount(healthyKakao.accountId,{force:true});await settled();tick(30001);await lifecycle.CheckAccount(healthyKakao.accountId);await settled();
 assert.equal(saves-beforeSaves,0,'Unchanged healthy Kakao grants produce no full-database writes');assert.equal(healthyKakao.probes,2);assert.equal(healthyKakao.refreshes,0);assert.equal(row(healthyKakao).credentials,kakaoStoredCredentials);assert.equal(status(healthyKakao).verifiedAt,now);
 const kakao=fixture('kakao');kakao.mode='access-expired';kakao.rotate=true;await lifecycle.CheckAccount(kakao.accountId,{force:true});await settled();assert.equal(kakao.probes,2);assert.equal(kakao.refreshes,1);assert.equal(status(kakao).status,'active');
 assert.notEqual(vault.Open(row(kakao).credentials,binding(s.ProfileById(kakao.accountId))).refreshToken,kakao.refresh);privateOutputs(kakao);
 kakao.mode='kakao-transient';tick(5001);await lifecycle.CheckAccount(kakao.accountId,{force:true});await settled();assert.equal(status(kakao).linked,true);assert.equal(status(kakao).status,'degraded');assert.equal(kakao.c.socket.lines.length,0);
 const badKakao=fixture('kakao');relink(badKakao,1);badKakao.mode='kakao-request-error';await lifecycle.CheckAccount(badKakao.accountId,{force:true});await settled();assert.equal(status(badKakao).linked,true);assert.equal(badKakao.c.socket.lines.length,0);

 // Authenticate callback credentials and app ID before any provider request.
 const hooked=fixture('kakao'),before=calls.length;
 assert.equal((await callback(hooked,{authorization:'KakaoAK forged'})).status,401);assert.equal((await callback(hooked,{app:'wrong-app'})).status,400);assert.equal((await callback(hooked,{extra:'&user_id=999'})).status,400);assert.equal(calls.length,before);assert.equal(status(hooked).linked,true);
 hooked.mode='revoked';assert.equal((await callback(hooked,{method:'POST'})).status,200);await lifecycle.CheckAccount(hooked.accountId,{force:true});await settled();
 assert.equal(status(hooked).status,'revoked');signedRevocation(hooked,'IDENTITY_REAUTH_REQUIRED');retained(hooked);
 // An identical authenticated callback after a relink only probes the new grant.
 hooked.mode='valid';const freshGeneration=relink(hooked);hooked.c.biometricVerified=true;tick(5001);
 assert.equal((await callback(hooked,{method:'POST'})).status,200);await lifecycle.CheckAccount(hooked.accountId,{force:true});await settled();
 assert.equal(row(hooked).generation,freshGeneration);assert.equal(status(hooked).linked,true);assert.equal(status(hooked).ready,true);assert.equal(hooked.c.biometricVerified,true);assert.equal(hooked.c.socket.lines.filter(x=>x.startsWith('HUB_IDENTITY|')).length,1,'Replayed callback emits no new invalidation');retained(hooked);privateOutputs(hooked);

 // A slow rejection for the old generation cannot revoke a concurrently relinked account.
 const racing=fixture();racing.mode='revoked';racing.defer=true;const pending=lifecycle.CheckAccount(racing.accountId,{force:true});assert.equal(typeof racing.release,'function');
 racing.mode='valid';const replacement=relink(racing);racing.release();await pending;await settled();assert.equal(row(racing).generation,replacement);assert.equal(status(racing).status,'active');assert.equal(racing.c.socket.lines.length,0);retained(racing);privateOutputs(racing);

 // A replicated credential rotation invalidates runtime observations even within the same link generation.
 const replica=fixture(),replicaGeneration=row(replica).generation;await lifecycle.CheckAccount(replica.accountId,{force:true});await settled();
 const newer=replaceReplicatedEnvelope(replica);await lifecycle.CheckAccount(replica.accountId,{force:true});await settled();
 assert.equal(new URLSearchParams(calls.filter(x=>x.url==='https://oauth2.googleapis.com/token').at(-1).options.body).get('refresh_token'),newer.refreshToken);assert.equal(row(replica).generation,replicaGeneration);assert.equal(status(replica).ready,true);
 replica.mode='revoked';replica.defer=true;tick(5001);const oldReplicaCheck=lifecycle.CheckAccount(replica.accountId,{force:true});assert.equal(typeof replica.release,'function');
 const newest=replaceReplicatedEnvelope(replica),replicatedRow=structuredClone(row(replica));replica.release();await oldReplicaCheck;await settled();
 assert.deepEqual(row(replica),replicatedRow,'Old rejection cannot overwrite a newer durable envelope in the same generation');assert.equal(status(replica).linked,true);assert.equal(replica.c.socket.lines.length,0);
 replica.mode='valid';await lifecycle.CheckAccount(replica.accountId,{force:true});await settled();
 assert.equal(new URLSearchParams(calls.filter(x=>x.url==='https://oauth2.googleapis.com/token').at(-1).options.body).get('refresh_token'),newest.refreshToken);assert.equal(status(replica).ready,true);assert.equal(row(replica).generation,replicaGeneration);

 // Standby checks never contact a provider or persist local changes, including stale PC access.
 const standby=fixture();attachPc(standby);ha.CanAcceptTraffic=()=>false;const standbyDb=JSON.stringify(s.DB()),standbyCalls=calls.length;beforeSaves=saves;
 await lifecycle.CheckAccount(standby.accountId,{force:true});tick(15*60*1000+1);await lifecycle.CheckAccount(standby.accountId,{force:true});await settled();
 assert.equal(calls.length,standbyCalls,'Standby must not send provider requests');assert.equal(saves-beforeSaves,0,'Standby must not persist stale-access changes');assert.equal(JSON.stringify(s.DB()),standbyDb);assert.equal(state.buildSessions.get(standby.pc.activeId).status,'AUTHORIZED','Standby cannot revoke PC access');assert.equal(state.pendingBuildGrants.has(standby.c.clientId),true);assert.equal(state.clientBiometricChallenges.has(standby.c.clientId),true);assert.equal(standby.c.socket.lines.length,0);
 ha.CanAcceptTraffic=originalCanAcceptTraffic;
 // A response arriving after loss of HA leadership cannot rotate, revoke, or mark failure.
 for(const mode of ['valid','revoked','outage']){
  const losing=fixture();attachPc(losing);losing.mode=mode;losing.rotate=true;losing.defer=true;
  const priorDb=JSON.stringify(s.DB()),priorRow=structuredClone(row(losing));beforeSaves=saves;const pendingCheck=lifecycle.CheckAccount(losing.accountId,{force:true});assert.equal(typeof losing.release,'function');
  ha.CanAcceptTraffic=()=>false;losing.release();await pendingCheck;await settled();
  assert.equal(saves-beforeSaves,0,'In-flight '+mode+' result must not save after leadership loss');assert.equal(JSON.stringify(s.DB()),priorDb);assert.deepEqual(row(losing),priorRow);assert.equal(status(losing).status,'active');assert.equal(state.buildSessions.get(losing.pc.activeId).status,'AUTHORIZED');assert.equal(losing.c.biometricVerified,true);assert.equal(losing.c.socket.lines.length,0);assert.equal(losing.pc.server.socket.lines.length,0);
  ha.CanAcceptTraffic=originalCanAcceptTraffic;
 }

 assert.ok(calls.every(x=>new URL(x.url).protocol==='https:'));assert.equal(calls.some(x=>x.url.includes('tokeninfo')),false,'Google tokeninfo is not a production grant check');
 console.log('FIX72 OAuth revocation PASS: encrypted credentials; Google/Kakao validation and refresh rotation; zero-write healthy observations and one-write outage transitions; external revocation and signed native/PC invalidation; retained balances/ownership; bounded outage suspension/recovery; check deduplication; subject mismatch; authenticated Kakao callbacks and relink replay/race safety; HA standby and leadership-loss guards; private public/admin projections. Live provider credentials not supplied.');
 }finally{lifecycle.StopMonitor();global.fetch=originalFetch;Date.now=originalNow;database.SaveDatabase=originalSave;ha.CanAcceptTraffic=originalCanAcceptTraffic;fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
