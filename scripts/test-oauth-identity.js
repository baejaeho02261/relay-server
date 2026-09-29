'use strict';
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix71-oauth-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE='json';process.env.MEMBER_OAUTH_PUBLIC_URL='https://moa.example';
process.env.GOOGLE_OAUTH_CLIENT_ID='test-google';process.env.GOOGLE_OAUTH_CLIENT_SECRET='test-secret';process.env.KAKAO_OAUTH_CLIENT_ID='test-kakao';process.env.KAKAO_OAUTH_CLIENT_SECRET='kakao-secret';
process.env.MEMBER_OAUTH_TOKEN_KEY=crypto.randomBytes(32).toString('hex');
delete process.env.MOAPLAY_ALLOW_LEGACY_TEST_IDENTITY;delete process.env.MEMBER_BIOMETRIC_TEST_MODE;
require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),oauth=require('../services/member/oauthIdentity'),service=require('../services/member/service'),protocol=require('../services/member/protocol'),database=require('../storage/database');
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),jwk={...publicKey.export({format:'jwk'}),kid:'real-rsa-key',alg:'RS256',use:'sig'};
let calls=[],expectedNonce='',tokenClaims={},nextProvider='google',codeVerifier='',holdToken=null;
const originalFetch=global.fetch;
global.fetch=async(url,options={})=>{
 calls.push({url,options});assert.equal(options.redirect,'error');
 if(url.endsWith('/certs')||url.endsWith('/jwks.json'))return new Response(JSON.stringify({keys:[jwk]}),{headers:{'content-type':'application/json'}});
 assert.ok(['https://oauth2.googleapis.com/token','https://kauth.kakao.com/oauth/token'].includes(url));
 const b=new URLSearchParams(options.body);assert.equal(b.get('grant_type'),'authorization_code');assert.equal(b.get('code_verifier'),codeVerifier||b.get('code_verifier'));
 const challenge=crypto.createHash('sha256').update(b.get('code_verifier')).digest('base64url');assert.equal(challenge,currentChallenge);
 const now=Math.floor(Date.now()/1000),payload={iss:nextProvider==='google'?'https://accounts.google.com':'https://kauth.kakao.com',aud:'test-'+nextProvider,sub:'provider-subject-1',nonce:expectedNonce,iat:now,exp:now+300,name:'Google 회원',nickname:'카카오 회원',...tokenClaims};
 if(holdToken)await holdToken;
 return new Response(JSON.stringify({id_token:jwt(payload),access_token:'test-access-token',refresh_token:'test-refresh-token',expires_in:3600}),{headers:{'content-type':'application/json'}});
};
function jwt(p,h={alg:'RS256',kid:jwk.kid}){const a=Buffer.from(JSON.stringify(h)).toString('base64url'),b=Buffer.from(JSON.stringify(p)).toString('base64url');return a+'.'+b+'.'+crypto.sign('RSA-SHA256',Buffer.from(a+'.'+b),privateKey).toString('base64url');}
function client(n){const id='AAAAAAAAAAAAAAA'+n,key='TEST-OAUTH-DEVICE-'+n,socket={destroyed:false,lines:[],write(x){this.lines.push(x);},cork(){},uncork(){}};const c={clientId:id,installationDeviceKey:key,connected:true,socket,permissionsGranted:true,permissionSequence:1,permissionMask:7,deviceAuthVerified:true,deviceAuthChallengeId:'CHALLENGE-'+n,licenseAuthorized:false,biometricVerified:false};state.clientIdentities.set(key,{id});state.clients.set(id,c);state.deviceSecrets.set('CLIENT:'+id,'secret-'+n);return c;}
function response(){return {headers:{},status:0,body:'',setHeader(k,v){this.headers[k]=v;},writeHead(status,h){this.status=status;Object.assign(this.headers,h);},end(b=''){this.body+=b;}};}
function call(c,id,action,body={}){return service.Execute(c,id,action,body);}
let currentChallenge='';
async function begin(c,provider='google',request='FLOW-REQUEST-'+crypto.randomBytes(4).toString('hex')){
 c.oauthLastStart=0;const r=call(c,request,'identity.start',{provider}),url=new URL(r.authorizationUrl),res=response();
 await oauth.HandleHttp({method:'GET',headers:{}},res,url);assert.equal(res.status,302);
 const auth=new URL(res.headers.Location),cookie=res.headers['Set-Cookie'].split(';')[0];expectedNonce=auth.searchParams.get('nonce');currentChallenge=auth.searchParams.get('code_challenge');nextProvider=provider;
 assert.equal(auth.searchParams.get('code_challenge_method'),'S256');assert.equal(auth.searchParams.get('scope').includes('openid'),true);assert.match(res.headers['Set-Cookie'],/Secure; HttpOnly; SameSite=Lax/);
 return {r,auth,cookie,request};
}
async function callback(f,extra={}){const res=response(),u=new URL('https://moa.example/member/oauth/callback/'+nextProvider);u.search=new URLSearchParams({state:f.auth.searchParams.get('state'),code:'single-use-code',...extra}).toString();await oauth.HandleHttp({method:'GET',headers:{cookie:f.cookie}},res,u);return res;}
(async()=>{try{
 const c=client('A'),p=s.Account(c);p.balance=32100;p.points=430;s.DB().orders.KEEP={id:'KEEP',accountId:p.id,amount:10};const originalId=p.id;
 assert.equal(oauth.Ready(c),false);assert.equal(service.Allowed(c),false);assert.equal(require('../services/member/testAccess').Enabled(),false);
 process.env.MEMBER_BIOMETRIC_TEST_MODE='1';process.env.NODE_ENV='production';assert.equal(require('../services/member/testAccess').Enabled(),false);
 const status=call(c,'ID-STATUS-1','identity.status');assert.equal(status.identity.linked,false);assert.ok(status.providers.every(x=>x.configured));assert.doesNotMatch(JSON.stringify(status),/test-secret|kakao-secret/);
 delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;assert.throws(()=>call(c,'ID-START-MISSING','identity.start',{provider:'google'}),/IDENTITY_NOT_CONFIGURED/);process.env.GOOGLE_OAUTH_CLIENT_SECRET='test-secret';
 c.permissionsGranted=false;assert.throws(()=>call(c,'ID-STATUS-DENIED','identity.status'),/IDENTITY_DEVICE_REQUIRED/);c.permissionsGranted=true;
 assert.equal(require('../services/qrApproval').Resume(c).reason,'IDENTITY_REQUIRED');
 assert.equal(require('../services/clientBiometric').Begin(c).reason,'IDENTITY_REQUIRED');
 const statusEncoded=Buffer.from('{}').toString('base64'),statusFields=['SIGNED-STATUS-1','identity.status',statusEncoded];
 service.Handle(c,['HUB',...statusFields,protocol.Sign(c,'HUB',statusFields)].join('|'));
 const statusParts=c.socket.lines.pop().trim().split('|');assert.equal(statusParts[2],'identity.status');assert.equal(protocol.Verify(c,statusParts.slice(1,6),statusParts[6],'HUB_RESPONSE'),true);assert.equal(JSON.parse(Buffer.from(statusParts[5],'base64')).data.identity.linked,false);
 const encoded=Buffer.from('{"provider":"google"}').toString('base64');service.Handle(c,['HUB','FORGED-ID-111','identity.start',encoded,'0'.repeat(64)].join('|'));assert.equal(c.oauthLastStart,undefined);
 const f=await begin(c);const replay=call(c,f.request,'identity.start',{provider:'google'});assert.equal(replay.flowId,f.r.flowId);assert.throws(()=>call(c,f.request,'identity.start',{provider:'kakao'}),/REQUEST_REUSED/);
 assert.equal(f.auth.searchParams.get('access_type'),'offline');assert.match(f.auth.searchParams.get('prompt'),/consent/);
 const wrongState=response();await oauth.HandleHttp({method:'GET',headers:{cookie:f.cookie}},wrongState,new URL('https://moa.example/member/oauth/callback/google?state=unrelated-state&code=code'));assert.equal(wrongState.status,400);assert.equal(calls.length,0);
 const wrong=response();await oauth.HandleHttp({method:'GET',headers:{cookie:'__Host-moa_oauth=wrong'}},wrong,new URL('https://moa.example/member/oauth/callback/google?state='+f.auth.searchParams.get('state')+'&code=code'));assert.equal(wrong.status,400);assert.equal(calls.length,0);
 assert.equal((await callback(f)).status,200);assert.equal(oauth.Ready(c),false,'Browser callback cannot grant native access');
 const oldSave=database.SaveDatabase;database.SaveDatabase=()=>false;assert.throws(()=>call(c,'POLL-SAVE-FAIL','identity.poll',{flowId:f.r.flowId}),/STORAGE_SAVE_FAILED/);database.SaveDatabase=oldSave;assert.equal(oauth.Ready(c),false);
 const result=call(c,'ID-POLL-1','identity.poll',{flowId:f.r.flowId});assert.equal(result.status,'linked');assert.equal(result.identity.linked,true);assert.equal(oauth.Ready(c),true);
 const linked=s.Account(c);assert.equal(linked.id,originalId);assert.equal(linked.balance,32100);assert.equal(linked.points,430);assert.equal(s.DB().orders.KEEP.accountId,originalId);assert.equal(s.PublicProfile(linked).accountLabel,'Google 회원');assert.doesNotMatch(JSON.stringify(s.PublicProfile(linked)),/provider-subject-1/);
 assert.equal((await callback(f)).status,400,'Callback state consumed once');
 assert.equal(call(c,'ID-POLL-2','identity.poll',{flowId:f.r.flowId}).status,'linked');
 c.licenseAuthorized=true;assert.equal(service.Allowed(c),false);c.biometricVerified=true;assert.equal(service.Allowed(c),true);
 const other=client('B'),g=await begin(other);assert.equal((await callback(g)).status,200);assert.equal(call(other,'POLL-OTHER-1','identity.poll',{flowId:g.r.flowId}).reason,'IDENTITY_LINKED_ELSEWHERE');assert.equal(oauth.Ready(other),false);
 const third=client('C'),h=await begin(third);third.deviceAuthChallengeId+='NEW';assert.equal((await callback(h)).status,400);assert.throws(()=>call(third,'POLL-ROTATED-1','identity.poll',{flowId:h.r.flowId}),/IDENTITY_FLOW_EXPIRED/);
 const fourth=client('D'),j=await begin(fourth,'kakao');tokenClaims={sub:'kakao-unique'};assert.equal((await callback(j)).status,200);assert.equal(call(fourth,'POLL-KAKAO-1','identity.poll',{flowId:j.r.flowId}).identity.provider,'kakao');tokenClaims={};
 // Admin/provider revocation invalidates already verified and in-flight browser
 // work, even if the stored grant was already revoked before that flow began.
 const fourthId=s.Account(fourth).id;oauth.RevokeAccount(fourthId);
 const verifiedBeforeReset=await begin(fourth,'kakao');tokenClaims={sub:'kakao-unique'};assert.equal((await callback(verifiedBeforeReset)).status,200);oauth.RevokeAccount(fourthId);
 assert.throws(()=>call(fourth,'POLL-RESET-VERIFIED','identity.poll',{flowId:verifiedBeforeReset.r.flowId}),/IDENTITY_FLOW_EXPIRED/);
 const duringReset=await begin(fourth,'kakao');let releaseToken;holdToken=new Promise(resolve=>{releaseToken=resolve;});const callbackPending=callback(duringReset);await new Promise(resolve=>setImmediate(resolve));oauth.RevokeAccount(fourthId);releaseToken();holdToken=null;
 assert.equal((await callbackPending).status,400);assert.throws(()=>call(fourth,'POLL-RESET-INFLIGHT','identity.poll',{flowId:duringReset.r.flowId}),/IDENTITY_FLOW_EXPIRED/);assert.equal(oauth.Ready(fourth),false);
 const afterReset=await begin(fourth,'kakao');assert.equal((await callback(afterReset)).status,200);assert.equal(call(fourth,'POLL-RESET-NEW','identity.poll',{flowId:afterReset.r.flowId}).status,'linked');assert.equal(s.Account(fourth).id,fourthId);tokenClaims={};
 const now=Math.floor(Date.now()/1000),base={iss:'https://accounts.google.com',aud:'test-google',sub:'test',nonce:'N',iat:now,exp:now+300};
 for(const patch of [{iss:'https://evil.example'},{aud:'other'},{exp:now-1},{iat:now+120},{nonce:'wrong'},{sub:''},{aud:['test-google','other']},{azp:'other'}])await assert.rejects(oauth.VerifyToken(jwt({...base,...patch}),'google','N'),/IDENTITY_TOKEN_INVALID/);
 await assert.rejects(oauth.VerifyToken(jwt(base,{alg:'none',kid:jwk.kid}),'google','N'),/IDENTITY_TOKEN_INVALID/);
 await assert.rejects(oauth.VerifyToken(jwt(base,{alg:'RS256',kid:jwk.kid,jku:'https://evil.example'}),'google','N'),/IDENTITY_TOKEN_INVALID/);
 const good=jwt(base),bad=good.slice(0,-5)+'AAAAA';await assert.rejects(oauth.VerifyToken(bad,'google','N'),/IDENTITY_TOKEN_INVALID/);
 const badClient=client('E'),k=await begin(badClient);tokenClaims={nonce:'WRONG'};assert.equal((await callback(k)).status,400);assert.equal(call(badClient,'POLL-FAILED-1','identity.poll',{flowId:k.r.flowId}).reason,'IDENTITY_TOKEN_INVALID');
 assert.equal(calls.filter(x=>x.url.endsWith('/certs')).length,1,'Provider JWKS is cached');assert.ok(calls.every(x=>new URL(x.url).protocol==='https:'));
 const copy=structuredClone(s.DB());s.Import({memberHub:copy});assert.equal(oauth.Ready(c),true,'Verified mapping survives persisted reload');
 c.permissionsGranted=false;assert.equal(oauth.Ready(c),false);c.permissionsGranted=true;c.superseded=true;assert.equal(oauth.Ready(c),false);
 console.log('FIX71 OAuth identity PASS: real RSA/JWKS verification; code+PKCE/state/browser-cookie/nonce; replay, audience, issuer, expiry, challenge rotation, cross-device takeover, atomic rollback, persistence; strict native gates and production test bypass disabled. Live provider credentials not supplied.');
 }finally{global.fetch=originalFetch;fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
