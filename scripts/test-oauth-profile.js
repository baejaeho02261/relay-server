'use strict';
// Real signed provider claims, full authorization-code/native-claim flow; no live credentials.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moa-fix74-email-'));
Object.assign(process.env,{DATA_DIR:dir,STORAGE_ENGINE:'json',MEMBER_OAUTH_PUBLIC_URL:'https://moa.example',GOOGLE_OAUTH_CLIENT_ID:'test-google',GOOGLE_OAUTH_CLIENT_SECRET:'test-secret',KAKAO_OAUTH_CLIENT_ID:'test-kakao',KAKAO_OAUTH_CLIENT_SECRET:'kakao-secret',MEMBER_OAUTH_TOKEN_KEY:crypto.randomBytes(32).toString('hex')});
delete process.env.MOAPLAY_ALLOW_LEGACY_TEST_IDENTITY;delete process.env.MEMBER_BIOMETRIC_TEST_MODE;delete process.env.KAKAO_OAUTH_EMAIL_SCOPE;
require('../core/utils').EnsureDirs();
const state=require('../core/state'),s=require('../services/member/store'),oauth=require('../services/member/oauthIdentity'),service=require('../services/member/service');
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}),jwk={...publicKey.export({format:'jwk'}),kid:'email-key',alg:'RS256',use:'sig'};
let claims={},provider='google',nonce='',challenge='',kakaoInfo={},kakaoCalls=0,failEmail=false;
const originalFetch=global.fetch;
function jwt(p){const h=Buffer.from(JSON.stringify({alg:'RS256',kid:jwk.kid})).toString('base64url'),b=Buffer.from(JSON.stringify(p)).toString('base64url');return h+'.'+b+'.'+crypto.sign('RSA-SHA256',Buffer.from(h+'.'+b),privateKey).toString('base64url');}
global.fetch=async(url,options={})=>{
 assert.equal(options.redirect,'error');
 if(url.endsWith('/certs')||url.endsWith('/jwks.json'))return Response.json({keys:[jwk]});
 if(url==='https://kapi.kakao.com/v2/user/me'){kakaoCalls++;assert.equal(options.headers.Authorization,'Bearer access-'+claims.sub);if(failEmail)throw Error('timeout');return Response.json(kakaoInfo);}
 assert.ok(['https://oauth2.googleapis.com/token','https://kauth.kakao.com/oauth/token'].includes(url));
 const b=new URLSearchParams(options.body);assert.equal(b.get('grant_type'),'authorization_code');assert.equal(crypto.createHash('sha256').update(b.get('code_verifier')).digest('base64url'),challenge);
 const now=Math.floor(Date.now()/1000);
 return Response.json({id_token:jwt({iss:provider==='google'?'https://accounts.google.com':'https://kauth.kakao.com',aud:'test-'+provider,nonce,iat:now,exp:now+300,name:'Google User',nickname:'Kakao User',...claims}),access_token:'access-'+claims.sub,refresh_token:'refresh-'+claims.sub,expires_in:3600});
};
function client(n){const id=Number(n).toString(16).toUpperCase().padStart(16,'B'),key='EMAIL-DEVICE-'+n,c={clientId:id,installationDeviceKey:key,connected:true,socket:{destroyed:false,write(){},cork(){},uncork(){}},permissionsGranted:true,permissionSequence:1,permissionMask:7,deviceAuthVerified:true,deviceAuthChallengeId:'EMAIL-CHALLENGE-'+n,licenseAuthorized:true,biometricVerified:true};state.clientIdentities.set(key,{id});state.clients.set(id,c);state.deviceSecrets.set('CLIENT:'+id,'secret-'+n);return c;}
function response(){return {headers:{},status:0,setHeader(k,v){this.headers[k]=v;},writeHead(status,h){this.status=status;Object.assign(this.headers,h);},end(){}};}
let i=0;
async function link(kind,nextClaims){const c=client(String(++i));provider=kind;claims=nextClaims;const start=service.Execute(c,'START-EMAIL-'+i,'identity.start',{provider:kind}),res=response();await oauth.HandleHttp({method:'GET',headers:{}},res,new URL(start.authorizationUrl));assert.equal(res.status,302);const auth=new URL(res.headers.Location);nonce=auth.searchParams.get('nonce');challenge=auth.searchParams.get('code_challenge');
 if(kind==='google')assert.ok(auth.searchParams.get('scope').split(' ').includes('email'));
 else assert.equal(auth.searchParams.get('scope').includes('account_email'),process.env.KAKAO_OAUTH_EMAIL_SCOPE==='true');
 const cb=new URL('https://moa.example/member/oauth/callback/'+kind);cb.search=new URLSearchParams({state:auth.searchParams.get('state'),code:'email-code'});const callback=response();await oauth.HandleHttp({method:'GET',headers:{cookie:res.headers['Set-Cookie'].split(';')[0]}},callback,cb);assert.equal(callback.status,200);assert.equal(service.Execute(c,'POLL-EMAIL-'+i,'identity.poll',{flowId:start.flowId}).status,'linked');return s.Account(c);}
function assertEmail(p,expected){assert.equal(oauth.Own(p).accountEmail,expected);assert.equal(s.PublicProfile(p,true).accountEmail,expected);assert.equal(Object.hasOwn(oauth.Public(p),'accountEmail'),false);assert.equal(Object.hasOwn(s.PublicProfile(p),'accountEmail'),false);if(expected)assert.ok(!JSON.stringify(s.PublicProfile(p)).includes(expected));}
(async()=>{try{
 const a=await link('google',{sub:'g1',email:'owner@example.com',email_verified:true});assertEmail(a,'owner@example.com');
 for(const verified of [false,'true',undefined]){const p=await link('google',{sub:'unverified-'+i,email:'unverified@example.com',email_verified:verified});assertEmail(p,'');}
 const malformed=await link('google',{sub:'bad-email',email:'unsafe@example.com\nInjected',email_verified:true});assertEmail(malformed,'');
 const noConsent=await link('kakao',{sub:'901'});assertEmail(noConsent,'');assert.equal(kakaoCalls,0);
 process.env.KAKAO_OAUTH_EMAIL_SCOPE='true';
 kakaoInfo={id:902,kakao_account:{email_needs_agreement:false,is_email_valid:true,is_email_verified:true,email:'kakao@example.com'}};const k=await link('kakao',{sub:'902',email:'untrusted-id-token@example.com'});assertEmail(k,'kakao@example.com');
 for(const patch of [{email_needs_agreement:true},{is_email_valid:false},{is_email_verified:false}]){const sub=String(1000+i);kakaoInfo={id:Number(sub),kakao_account:{email_needs_agreement:false,is_email_valid:true,is_email_verified:true,email:'hidden@example.com',...patch}};assertEmail(await link('kakao',{sub,email:'hidden@example.com'}),'');}
 kakaoInfo={id:9999,kakao_account:{email_needs_agreement:false,is_email_valid:true,is_email_verified:true,email:'wrong@example.com'}};assertEmail(await link('kakao',{sub:'2001',email:'wrong@example.com'}),'');
 failEmail=true;const unavailable=await link('kakao',{sub:'2002',email:'optional@example.com'});assertEmail(unavailable,'');assert.equal(oauth.AdminStatus(unavailable).linked,true,'Optional email timeout cannot reject valid login');
 oauth.RevokeAccount(a.id);assertEmail(a,'');assert.equal(a.providerIdentity.email,'owner@example.com','The stable identity remains, while the revoked projection hides the email');
 console.log('FIX74 OAuth profile PASS: Google verified-email scope; Kakao consent/verification/subject checks; optional-email outage; own-only projection and revoked-session privacy.');
 }finally{oauth.StopMonitor();global.fetch=originalFetch;fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
