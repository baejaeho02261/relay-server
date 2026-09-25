'use strict';
// Browser OAuth authorization-code flow. Provider credentials and tokens never reach the APK.
const crypto=require('node:crypto'),state=require('../../core/state'),s=require('./store');
const TTL=5*60*1000,CLAIM_TTL=60*1000,MAX_PENDING=2000;
const pending=new Map(),opens=new Map(),states=new Map(),jwks=new Map();
const PROVIDERS=Object.freeze({
 google:{name:'Google',authorization:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',jwks:'https://www.googleapis.com/oauth2/v3/certs',issuers:['https://accounts.google.com','accounts.google.com'],scope:'openid profile',prefix:'GOOGLE'},
 kakao:{name:'카카오',authorization:'https://kauth.kakao.com/oauth/authorize',token:'https://kauth.kakao.com/oauth/token',jwks:'https://kauth.kakao.com/.well-known/jwks.json',issuers:['https://kauth.kakao.com'],scope:'openid profile_nickname',prefix:'KAKAO'}
});
const hash=x=>crypto.createHash('sha256').update(String(x)).digest('hex');
const random=()=>crypto.randomBytes(32).toString('base64url');
function equal(a,b){const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length>0&&x.length===y.length&&crypto.timingSafeEqual(x,y);}
function TestLegacy(){return process.env.NODE_ENV==='test'&&process.env.MOAPLAY_ALLOW_LEGACY_TEST_IDENTITY==='1';}
function Configuration(provider){
 const p=PROVIDERS[provider];if(!p)s.Fail('IDENTITY_PROVIDER_INVALID');
 const clientId=String(process.env[p.prefix+'_OAUTH_CLIENT_ID']||'').trim(),secret=String(process.env[p.prefix+'_OAUTH_CLIENT_SECRET']||'').trim();
 const raw=String(process.env.MEMBER_OAUTH_PUBLIC_URL||require('../../config/config').UPDATE_BASE_URL||'').trim();
 let origin='';try{const u=new URL(raw);if(u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/')origin=u.origin;}catch(_){}
 const missing=[];if(!clientId)missing.push(p.prefix+'_OAUTH_CLIENT_ID');if(!secret)missing.push(p.prefix+'_OAUTH_CLIENT_SECRET');if(!origin)missing.push('MEMBER_OAUTH_PUBLIC_URL');
 return {...p,provider,clientId,secret,origin,redirectUri:origin+'/member/oauth/callback/'+provider,configured:missing.length===0,missing};
}
function PreAllowed(c){return !!c&&state.serviceEnabled&&require('../haCoordinator').CanAcceptTraffic()&&c.connected&&!c.disconnected&&!c.superseded&&!c.socket?.destroyed&&!!c.deviceAuthChallengeId&&require('../deviceAuth').Verified('CLIENT',c.clientId)&&require('../clientPermissions').Ready(c)&&require('../clientInstallation').Ready(c);}
function RequirePre(c){if(!PreAllowed(c))s.Fail(state.serviceEnabled?'IDENTITY_DEVICE_REQUIRED':'SERVICE_DISABLED');}
function Existing(c){try{return s.DB().profiles[s.Subject(c)]||null;}catch(_){return null;}}
function BindingKey(provider,subject){return hash(provider+'\0'+subject);}
function Public(p){const i=p?.providerIdentity;return i?{accountLabel:i.label||PROVIDERS[i.provider]?.name+' 계정',accountProvider:i.provider,accountVerified:true,accountLinked:true}:{accountLabel:p?s.Handle(p):'',accountProvider:'',accountVerified:false,accountLinked:false};}
function Ready(c){
 if(TestLegacy())return true;
 if(!PreAllowed(c))return false;
 const p=Existing(c),i=p?.providerIdentity;if(!i||p.blocked||!PROVIDERS[i.provider]||!i.key)return false;
 const link=s.DB().oauthAccounts?.[i.key];return !!link&&link.accountId===p.id&&link.installationSubject===p.subject&&link.provider===i.provider;
}
function Identity(c){const p=Existing(c),v=Public(p);return {linked:Ready(c)&&!!p?.providerIdentity,required:true,provider:v.accountProvider,accountLabel:v.accountLabel};}
function Cleanup(){const now=Date.now();for(const [id,f]of pending)if(f.expiresAt<=now||f.status==='linked'&&f.claimedAt+CLAIM_TTL<=now){pending.delete(id);opens.delete(f.openHash);states.delete(f.stateHash);} }
function Bound(c,f){return !!f&&f.connection===c&&f.challenge===c.deviceAuthChallengeId&&f.permissionSequence===c.permissionSequence&&f.subject===s.Subject(c)&&f.expiresAt>Date.now()&&PreAllowed(c);}
function Status(c){RequirePre(c);return {identity:Identity(c),providers:Object.keys(PROVIDERS).map(id=>{const p=Configuration(id);return {id,name:p.name,configured:p.configured,missing:p.missing};})};}
function Start(c,requestId,body){
 RequirePre(c);Cleanup();const provider=String(body.provider||'').toLowerCase(),cfg=Configuration(provider);
 if(!cfg.configured)s.Fail('IDENTITY_NOT_CONFIGURED');
 if(Ready(c))return {status:'linked',identity:Identity(c)};
 const requestKey=c.deviceAuthChallengeId+':'+requestId;
 for(const f of pending.values())if(f.connection===c&&f.requestKey===requestKey){if(f.provider!==provider)s.Fail('REQUEST_REUSED');if(!Bound(c,f))s.Fail('IDENTITY_FLOW_EXPIRED');return StartResponse(f,cfg);}
 if(pending.size>=MAX_PENDING)s.Fail('PLEASE_WAIT');
 if(c.oauthLastStart&&Date.now()-c.oauthLastStart<2000)s.Fail('PLEASE_WAIT');
 c.oauthLastStart=Date.now();
 for(const f of pending.values())if(f.connection===c&&f.status!=='linked'){pending.delete(f.id);opens.delete(f.openHash);states.delete(f.stateHash);}
 const id=random(),open=random(),oauthState=random(),nonce=random(),verifier=random();
 const f={id,connection:c,subject:s.Subject(c),challenge:c.deviceAuthChallengeId,permissionSequence:c.permissionSequence,requestKey,provider,status:'pending',createdAt:Date.now(),expiresAt:Date.now()+TTL,open,openHash:hash(open),state:oauthState,stateHash:hash(oauthState),nonce,verifier};
 pending.set(id,f);opens.set(f.openHash,id);states.set(f.stateHash,id);return StartResponse(f,cfg);
}
function StartResponse(f,cfg){return {flowId:f.id,authorizationUrl:cfg.origin+'/member/oauth/open/'+f.open,expiresAt:f.expiresAt,status:f.status,identity:{linked:false,required:true,provider:f.provider,accountLabel:''}};}
function Poll(c,body){
 RequirePre(c);Cleanup();const f=pending.get(String(body.flowId||''));if(!f||!Bound(c,f))s.Fail('IDENTITY_FLOW_EXPIRED');
 if(f.status==='verified'){
  if(f.verifiedAt+CLAIM_TTL<=Date.now()){f.status='failed';f.reason='IDENTITY_FLOW_EXPIRED';}
  else {
   // Synchronous atomic commit also serializes simultaneous claims from two installations.
   try{Link(c,f.verified);f.status='linked';f.claimedAt=Date.now();delete f.verified;delete f.verifier;delete f.nonce;}
   catch(e){if(e.message==='STORAGE_SAVE_FAILED')throw e;f.status='failed';f.reason=e.memberError?e.message:'IDENTITY_FAILED';delete f.verified;}
  }
 }
 return {status:f.status==='verified'?'pending':f.status,reason:f.reason||'',identity:Identity(c)};
}
function Link(c,claims){
 RequirePre(c);const account=s.Account(c),subject=account.subject,key=BindingKey(claims.provider,claims.sub);
 return s.Atomic(()=>{
  const db=s.DB(),p=db.profiles[subject];if(p.blocked)s.Fail('ACCOUNT_BLOCKED');
  const old=db.oauthAccounts[key];if(old&&(old.accountId!==p.id||old.installationSubject!==subject))s.Fail('IDENTITY_LINKED_ELSEWHERE');
  if(p.providerIdentity&&p.providerIdentity.key!==key)s.Fail('IDENTITY_ACCOUNT_CHANGED');
  const label=String(claims.label||PROVIDERS[claims.provider].name+' 계정').replace(/[\u0000-\u001f\u007f<>]/g,'').trim().slice(0,60)||PROVIDERS[claims.provider].name+' 계정';
  db.oauthAccounts[key]={provider:claims.provider,accountId:p.id,installationSubject:subject,linkedAt:old?.linkedAt||Date.now(),verifiedAt:Date.now()};
  p.providerIdentity={provider:claims.provider,key,label,linkedAt:p.providerIdentity?.linkedAt||Date.now()};
  p.profileRevision=(p.profileRevision||0)+1;
  return Public(p);
 });
}
async function FetchJSON(url,options={}){
 const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(10000)});
 if(!response.ok)s.Fail('IDENTITY_PROVIDER_UNAVAILABLE');
 const length=Number(response.headers.get('content-length')||0);if(length>131072)s.Fail('IDENTITY_PROVIDER_INVALID_RESPONSE');
 const chunks=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;if(bytes>131072){await response.body.cancel?.().catch(()=>{});s.Fail('IDENTITY_PROVIDER_INVALID_RESPONSE');}chunks.push(Buffer.from(chunk));}
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch(_){s.Fail('IDENTITY_PROVIDER_INVALID_RESPONSE');}
}
async function Keys(provider,kid){
 const now=Date.now(),cached=jwks.get(provider);if(cached?.expiresAt>now&&cached.keys.some(k=>k.kid===kid))return cached.keys;
 // Unknown-key floods cannot force unbounded outbound requests.
 if(cached&&now-cached.fetchedAt<30000)s.Fail('IDENTITY_TOKEN_INVALID');
 const cfg=Configuration(provider),result=await FetchJSON(cfg.jwks);if(!Array.isArray(result.keys)||result.keys.length>20)s.Fail('IDENTITY_TOKEN_INVALID');
 const keys=result.keys.filter(k=>k.kty==='RSA'&&k.alg==='RS256'&&k.use==='sig'&&typeof k.kid==='string'&&k.kid.length<=200);
 jwks.set(provider,{keys,fetchedAt:now,expiresAt:now+3600000});return keys;
}
async function VerifyToken(token,provider,nonce){
 if(typeof token!=='string'||token.length>20000)s.Fail('IDENTITY_TOKEN_INVALID');
 const parts=token.split('.');if(parts.length!==3||parts.some(x=>!x||!/^[A-Za-z0-9_-]+$/.test(x)))s.Fail('IDENTITY_TOKEN_INVALID');
 let h,p;try{h=JSON.parse(Buffer.from(parts[0],'base64url'));p=JSON.parse(Buffer.from(parts[1],'base64url'));}catch(_){s.Fail('IDENTITY_TOKEN_INVALID');}
 if(!h||!p||h.alg!=='RS256'||typeof h.kid!=='string'||h.kid.length>200||h.jku||h.x5u||h.crit)s.Fail('IDENTITY_TOKEN_INVALID');
 const key=(await Keys(provider,h.kid)).find(x=>x.kid===h.kid);if(!key)s.Fail('IDENTITY_TOKEN_INVALID');
 let valid=false;try{valid=crypto.verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),crypto.createPublicKey({key,format:'jwk'}),Buffer.from(parts[2],'base64url'));}catch(_){}
 if(!valid)s.Fail('IDENTITY_TOKEN_INVALID');
 const cfg=Configuration(provider),now=Math.floor(Date.now()/1000),aud=Array.isArray(p.aud)?p.aud:[p.aud];
 if(!cfg.issuers.includes(p.iss)||!aud.includes(cfg.clientId)||(aud.length>1||p.azp)&&p.azp!==cfg.clientId||!Number.isFinite(p.exp)||p.exp<=now||!Number.isFinite(p.iat)||p.iat>now+60||p.iat<now-600||!equal(p.nonce,nonce)||typeof p.sub!=='string'||!p.sub||p.sub.length>255)s.Fail('IDENTITY_TOKEN_INVALID');
 return {provider,sub:p.sub,label:String(provider==='kakao'?p.nickname||'카카오 계정':p.name||'Google 계정')};
}
function HTML(res,status,text){
 const nonce=crypto.randomBytes(18).toString('base64');
 res.writeHead(status,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'"});
 const launch=status===200?'<script nonce="'+nonce+'">setTimeout(function(){location.href="moaplay://auth/complete";},400);</script>':'';
 res.end('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MoaPlay 계정 연결</title><body style="margin:0;background:#000;color:#fff;font-family:system-ui;min-height:100vh;display:grid;place-items:center"><main style="max-width:400px;padding:32px"><h1>MoaPlay</h1><p style="line-height:1.7">'+text+'</p><p style="color:#aaa">MoaPlay 앱으로 돌아가주세요.</p><a href="moaplay://auth/complete" style="display:block;padding:16px;background:#fff;color:#000;text-decoration:none;border-radius:12px;text-align:center">MoaPlay로 돌아가기</a></main>'+launch+'</body></html>');
}
function Cookie(req,name){for(const part of String(req.headers.cookie||'').split(';')){const i=part.indexOf('=');if(part.slice(0,i).trim()===name)return part.slice(i+1).trim();}return '';}
async function HandleHttp(req,res,url){
 const path=url.pathname;if(!path.startsWith('/member/oauth/'))return false;
 if(req.method!=='GET'){HTML(res,405,'지원하지 않는 요청입니다.');return true;}
 Cleanup();const open=/^\/member\/oauth\/open\/([A-Za-z0-9_-]{43})$/.exec(path),callback=/^\/member\/oauth\/callback\/(google|kakao)$/.exec(path);
 if(open){
  const f=pending.get(opens.get(hash(open[1])));if(!f||!Bound(f.connection,f)||f.openedAt){HTML(res,400,'연결 요청이 만료되었습니다. 앱에서 다시 시작해주세요.');return true;}
  const cfg=Configuration(f.provider);if(!cfg.configured){HTML(res,503,'관리자가 계정 연결 설정을 완료해야 합니다.');return true;}
  const browser=random();f.browserHash=hash(browser);f.openedAt=Date.now();opens.delete(f.openHash);
  const auth=new URL(cfg.authorization);auth.search=new URLSearchParams({response_type:'code',client_id:cfg.clientId,redirect_uri:cfg.redirectUri,scope:cfg.scope,state:f.state,nonce:f.nonce,code_challenge:crypto.createHash('sha256').update(f.verifier).digest('base64url'),code_challenge_method:'S256',prompt:'select_account'}).toString();
  res.writeHead(302,{'Location':auth.href,'Set-Cookie':'__Host-moa_oauth='+browser+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300','Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.end();return true;
 }
 if(callback){
  const stateValue=url.searchParams.get('state')||'',f=pending.get(states.get(hash(stateValue)));
  if(!f||f.provider!==callback[1]||!f.openedAt||!Bound(f.connection,f)||!equal(f.browserHash,hash(Cookie(req,'__Host-moa_oauth')))){HTML(res,400,'연결 요청을 확인할 수 없습니다. 앱에서 다시 시작해주세요.');return true;}
  states.delete(f.stateHash);res.setHeader('Set-Cookie','__Host-moa_oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0');
  if(url.searchParams.has('error')){f.status='failed';f.reason='IDENTITY_CANCELLED';HTML(res,400,'계정 연결이 취소되었습니다.');return true;}
  const code=url.searchParams.get('code')||'';if(!code||code.length>4096){f.status='failed';f.reason='IDENTITY_TOKEN_INVALID';HTML(res,400,'계정 연결 응답을 확인할 수 없습니다.');return true;}
  f.status='processing';
  try{const cfg=Configuration(f.provider),result=await FetchJSON(cfg.token,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:cfg.clientId,client_secret:cfg.secret,redirect_uri:cfg.redirectUri,code,code_verifier:f.verifier}).toString()});
   const verified=await VerifyToken(result.id_token,f.provider,f.nonce);if(!Bound(f.connection,f))s.Fail('IDENTITY_FLOW_EXPIRED');
   f.verified=verified;f.verifiedAt=Date.now();f.status='verified';delete f.verifier;delete f.nonce;
   HTML(res,200,'계정 확인이 완료되었습니다. 앱에서 연결을 마무리합니다.');
  }catch(e){f.status='failed';f.reason=e.memberError?e.message:'IDENTITY_PROVIDER_UNAVAILABLE';delete f.verifier;delete f.nonce;HTML(res,400,'계정 연결을 완료하지 못했습니다. 앱에서 다시 시도해주세요.');}
  return true;
 }
 HTML(res,404,'연결 요청을 찾을 수 없습니다.');return true;
}
function Execute(c,requestId,action,body){if(Object.keys(body).some(k=>!['_wire','_delta','provider','flowId'].includes(k)))s.Fail('INPUT_INVALID');if(action==='identity.status')return Status(c);if(action==='identity.start')return Start(c,requestId,body);if(action==='identity.poll')return Poll(c,body);s.Fail('UNKNOWN_ACTION');}
module.exports={Ready,Public,Execute,HandleHttp,Configuration,PreAllowed,VerifyToken};
