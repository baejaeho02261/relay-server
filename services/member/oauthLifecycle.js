'use strict';
const crypto=require('node:crypto'),state=require('../../core/state'),s=require('./store'),vault=require('./oauthCredentials');
const inFlight=new Map(),attempts=new Map(),denied=new Map(),observations=new Map(),queue=[];
let active=0,timer=null;
const MAX_CONCURRENT=4,MAX_QUEUE=2000,MAX_OBSERVATIONS=10000,MAX_STALE=15*60*1000;
const hash=x=>crypto.createHash('sha256').update(String(x)).digest('hex');
function Writable(){return require('../haCoordinator').CanAcceptTraffic();}
function Interval(){return Math.max(30000,Math.min(15*60*1000,Number(process.env.MEMBER_OAUTH_CHECK_INTERVAL_MS)||30000));}
function Record(p){const i=p?.providerIdentity,link=i&&s.DB().oauthAccounts?.[i.key];return link&&link.accountId===p.id&&link.installationSubject===p.subject&&link.provider===i.provider?link:null;}
function Binding(p){return p.providerIdentity.key+'\0'+p.id+'\0'+p.subject;}
function Remember(accountId,snapshot){
 observations.delete(accountId);observations.set(accountId,snapshot);
 if(observations.size>MAX_OBSERVATIONS)for(const [id,value]of observations)if(!inFlight.has(id)&&!value.dirtyCredentials){observations.delete(id);if(observations.size<=MAX_OBSERVATIONS)break;}
}
function Observation(p){const row=Record(p),cached=p&&observations.get(p.id);return row&&row.credentials&&row.status!=='revoked'&&cached?.generation===row.generation&&cached.baselineCredentials===row.credentials?cached:null;}
function View(p){const row=Record(p);return row?{...row,...(Observation(p)||{nextCheckAt:0})}:null;}
function Denial(p){const saved=p&&denied.get(p.id),row=Record(p);if(saved&&row&&(saved.generation!==row.generation||saved.credentials!==row.credentials)){denied.delete(p.id);return null;}return saved;}
function Live(p){const link=Record(p);return !!link&&!!link.credentials&&link.status!=='revoked'&&!Denial(p);}
function SuspendStale(p){
 if(!Writable())return;
 const link=View(p);if(!Live(p)||Date.now()-(link.verifiedAt||0)<=MAX_STALE||Observation(p)?.staleSuspended)return;
 Remember(p.id,{...(Observation(p)||{}),generation:link.generation,baselineCredentials:Record(p).credentials,staleSuspended:true});
 for(const id of require('./identity').ClientIds(p)){state.clientBiometricChallenges.delete(id);require('../buildGate').RevokeForClient(id,'IDENTITY_PROVIDER_UNAVAILABLE');}
}
function Ready(p){if(!Live(p))return false;const cached=Observation(p);if(!cached||Date.now()-(cached.verifiedAt||0)>MAX_STALE){SuspendStale(p);return false;}return true;}
function AdminStatus(p){
 const link=View(p),runtime=Denial(p),linked=Live(p),legacy=!!link&&!link.credentials&&link.status!=='revoked';
 const checkPending=!!p&&inFlight.has(p.id),status=runtime?'revoked':!link?'unlinked':link.status==='revoked'?'revoked':legacy?'reauth_required':checkPending&&!Observation(p)?.verifiedAt?'checking':link.lastError||!Ready(p)?'degraded':'active';
 return {status,checkPending,reason:runtime?.reason||link?.reason||(legacy?'IDENTITY_REAUTH_REQUIRED':status==='degraded'?'IDENTITY_PROVIDER_UNAVAILABLE':''),provider:p?.providerIdentity?.provider||'',accountLabel:p?.providerIdentity?.label||'',linked,ready:Ready(p),linkedAt:link?.linkedAt||0,verifiedAt:link?.verifiedAt||0,lastCheckedAt:link?.lastCheckedAt||0,nextCheckAt:link?.nextCheckAt||0,revokedAt:link?.revokedAt||0,lastError:link?.lastError||'',events:(link?.events||[]).map(x=>({...x}))};
}
function Event(link,type,reason,actor='',detail=''){
 const clean=(x,n)=>String(x||'').replace(/[\u0000-\u001f\u007f<>]/g,'').slice(0,n);
 link.events=[...(link.events||[]),{at:Date.now(),type,reason:clean(reason,80),actor:clean(actor,80),detail:clean(detail,240)}].slice(-40);
}
function Notify(p,reason){
 const ids=new Set(require('./identity').ClientIds(p));
 for(const c of state.clients.values()){
  let own=false;try{own=s.Subject(c)===p.subject;}catch(_){}if(!own)continue;
  ids.add(c.clientId);
  c.biometricVerified=false;c.hubUpload=null;require('./testAccess').Revoke(c);
  // Clear only volatile member access, retaining the registered device and QR license.
  const fields=[String(s.DB().revision),reason],mac=require('./protocol').Sign(c,'HUB_IDENTITY',fields);
  if(mac&&c.connected&&!c.disconnected&&!c.socket?.destroyed)require('../../core/utils').SendLine(c.socket,'HUB_IDENTITY|'+fields.join('|')+'|'+mac);
 }
 for(const id of ids){state.clientBiometricChallenges.delete(id);require('../../relay/notifications').NotifyServerUnauthorized(id,reason);}
}
function RevokeAccount(accountId,reason='IDENTITY_ADMIN_REAUTH',actor='',detail='',expected=''){
 if(!Writable())s.Fail('SERVICE_DISABLED');
 const p=s.ProfileById(accountId);if(!p)s.Fail('MEMBER_NOT_FOUND');const link=Record(p);
 if(expected&&link?.generation!==expected)return AdminStatus(p);
 require('./oauthIdentity').InvalidateFlows(p.subject);if(!link)return AdminStatus(p);
 if(link.status==='revoked'&&!link.credentials){denied.delete(p.id);return AdminStatus(p);}
 denied.set(p.id,{reason,generation:link.generation,credentials:link.credentials});
 try{s.Atomic(()=>{const current=Record(s.ProfileById(accountId));if(expected&&current.generation!==expected)return;
  current.status='revoked';current.reason=reason;current.revokedAt=Date.now();current.lastCheckedAt=Date.now();current.nextCheckAt=0;current.lastError='';delete current.credentials;
  Event(current,'reauth_required',reason,actor,detail);p.profileRevision=(p.profileRevision||0)+1;
 });denied.delete(p.id);}catch(e){Notify(p,reason);throw e;}
 observations.delete(accountId);Notify(p,reason);return AdminStatus(s.ProfileById(accountId));
}
async function Request(url,options={}){
 const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(8000)});
 if(Number(response.headers.get('content-length')||0)>131072)throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');
 const parts=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;if(bytes>131072)throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');parts.push(Buffer.from(chunk));}
 let data;try{data=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch(_){throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');}
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');return {status:response.status,ok:response.ok,data};
}
function InvalidGrant(provider,r){
 return [400,401].includes(r.status)&&(provider==='google'?r.data.error==='invalid_grant':r.data.error==='invalid_grant'&&r.data.error_code==='KOE322');
}
async function Refresh(cfg,credentials){
 const r=await Request(cfg.token,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:cfg.clientId,client_secret:cfg.secret,refresh_token:credentials.refreshToken}).toString()});
 if(InvalidGrant(cfg.provider,r))return {revoked:true};
 if(!r.ok)throw Error('IDENTITY_PROVIDER_UNAVAILABLE');
 return {credentials:vault.Normalize(r.data,credentials)};
}
async function Probe(cfg,credentials,key,onRefresh){
 // Refresh Google on each bounded check: ID tokens and cached profile data cannot
 // prove that the OAuth grant remains usable after external revocation.
 if(cfg.provider==='google'||credentials.expiresAt<=Date.now()+15000){const r=await Refresh(cfg,credentials);if(r.revoked)return r;credentials=r.credentials;onRefresh(credentials);}
 const url=cfg.provider==='google'?'https://openidconnect.googleapis.com/v1/userinfo':'https://kapi.kakao.com/v1/user/access_token_info';
 let r=await Request(url,{headers:{Authorization:'Bearer '+credentials.accessToken}});
 if(cfg.provider==='kakao'&&r.status===401&&r.data.code===-401){
  const next=await Refresh(cfg,credentials);if(next.revoked)return next;credentials=next.credentials;onRefresh(credentials);r=await Request(url,{headers:{Authorization:'Bearer '+credentials.accessToken}});
 }
 if(!r.ok)throw Error('IDENTITY_PROVIDER_UNAVAILABLE');
 const sub=cfg.provider==='google'?r.data.sub:r.data.id;
 const validSub=cfg.provider==='google'?typeof sub==='string'&&sub.length>0&&sub.length<=255:typeof sub==='number'?Number.isSafeInteger(sub)&&sub>0:typeof sub==='string'&&/^\d{1,30}$/.test(sub);
 if(!validSub)throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');
 if(hash(cfg.provider+'\0'+String(sub))!==key)return {revoked:true,reason:'IDENTITY_TOKEN_INVALID'};
 if(cfg.provider==='kakao'&&String(r.data.app_id)!==String(process.env.KAKAO_APP_ID||'')&&process.env.KAKAO_APP_ID)throw Error('IDENTITY_PROVIDER_INVALID_RESPONSE');
 return {credentials};
}
async function Validate(accountId,options){
 const initial=s.ProfileById(accountId),link=View(initial);if(!link)return AdminStatus(initial);
 if(!Writable())return AdminStatus(initial);
 const denial=Denial(initial);if(denial)return RevokeAccount(accountId,denial.reason);
 if(!Live(initial))return AdminStatus(initial);
 const generation=link.generation,key=initial.providerIdentity.key,baselineCredentials=Record(initial).credentials;
 let priorCredentials=null,refreshedCredentials=null;
 try{
  const cfg=require('./oauthIdentity').Configuration(link.provider);if(!cfg.configured)throw Error('IDENTITY_NOT_CONFIGURED');
  let credentials;try{credentials=vault.Open(link.credentials,Binding(initial));}catch(e){throw Error(e.message==='IDENTITY_NOT_CONFIGURED'?e.message:'IDENTITY_CREDENTIALS_UNAVAILABLE');}
  priorCredentials=credentials;
  const result=await Probe(cfg,credentials,key,next=>{refreshedCredentials=next;}),current=s.ProfileById(accountId),nowLink=Record(current);
  if(!Writable())return AdminStatus(current);
  // Provider responses can outlive a fresh browser relink or administrator action.
  if(!nowLink||nowLink.generation!==generation||nowLink.credentials!==baselineCredentials||!Live(current))return AdminStatus(current);
  if(result.revoked)return RevokeAccount(accountId,result.reason||'IDENTITY_REAUTH_REQUIRED','PROVIDER',options.callback?'Kakao unlink webhook confirmed by current credentials':'Provider credentials rejected',generation);
  const encrypted=vault.Seal(result.credentials,Binding(current)),now=Date.now();
  // Access-token rotation is frequent (Google is checked every 30s). Keep those
  // envelopes and freshness in memory; never snapshot the entire member DB per
  // healthy check. Persist refresh-token rotation, Kakao's infrequent access
  // refresh, or recovery from a persisted error. A restart checks immediately.
  const persist=!!Observation(current)?.dirtyCredentials||!!nowLink.lastError||result.credentials.refreshToken!==credentials.refreshToken||result.credentials.refreshExpiresAt!==credentials.refreshExpiresAt||cfg.provider==='kakao'&&result.credentials.accessToken!==credentials.accessToken;
  const snapshot={generation,baselineCredentials,credentials:encrypted,verifiedAt:now,lastCheckedAt:now,nextCheckAt:now+Interval(),lastError:'',reason:'',status:'active',dirtyCredentials:persist,staleSuspended:false};
  Remember(accountId,snapshot);
  if(persist){s.Atomic(()=>{const row=Record(s.ProfileById(accountId));row.credentials=encrypted;row.status='active';row.reason='';row.lastError='';row.verifiedAt=now;row.lastCheckedAt=now;row.nextCheckAt=now+Interval();});snapshot.dirtyCredentials=false;snapshot.baselineCredentials=encrypted;}
  return AdminStatus(s.ProfileById(accountId));
 }catch(e){
  const current=s.ProfileById(accountId),row=Record(current);if(!row||row.generation!==generation||row.credentials!==baselineCredentials||!Live(current))return AdminStatus(current);
  if(!Writable())return AdminStatus(current);
  // Configuration, transport, 429/5xx and malformed responses never erase ownership
  // or credentials. Ready fails closed after the bounded 15-minute grace period.
  const reason=['IDENTITY_NOT_CONFIGURED','IDENTITY_CREDENTIALS_UNAVAILABLE'].includes(e.message)?e.message:'IDENTITY_PROVIDER_UNAVAILABLE';
  const snapshot={...(Observation(current)||{}),generation,baselineCredentials,lastError:reason,lastCheckedAt:Date.now(),nextCheckAt:Date.now()+Interval()};
  // A refresh can rotate its token before the subsequent profile probe times out.
  // Retain that new token without extending identity freshness, so retry never
  // falls back to an obsolete refresh token and incorrectly demands reauth.
  if(refreshedCredentials)try{snapshot.credentials=vault.Seal(refreshedCredentials,Binding(current));snapshot.dirtyCredentials=!!snapshot.dirtyCredentials||refreshedCredentials.refreshToken!==priorCredentials.refreshToken||refreshedCredentials.refreshExpiresAt!==priorCredentials.refreshExpiresAt||row.provider==='kakao'&&refreshedCredentials.accessToken!==priorCredentials.accessToken;}catch(_){}
  Remember(accountId,snapshot);
  if(row.lastError!==reason||snapshot.dirtyCredentials)try{s.Atomic(()=>{const r=Record(s.ProfileById(accountId));if(r.lastError!==reason)Event(r,'check_deferred',reason);if(snapshot.dirtyCredentials)r.credentials=snapshot.credentials;r.lastError=reason;r.lastCheckedAt=Date.now();r.nextCheckAt=Date.now()+Interval();});snapshot.dirtyCredentials=false;snapshot.baselineCredentials=Record(s.ProfileById(accountId)).credentials;}catch(_){}
  SuspendStale(s.ProfileById(accountId));
  return AdminStatus(s.ProfileById(accountId));
 }
}
function Pump(){while(active<MAX_CONCURRENT&&queue.length){const {id,options,resolve}=queue.shift();active++;Validate(id,options).then(resolve,()=>resolve(AdminStatus(s.ProfileById(id)))).finally(()=>{active--;inFlight.delete(id);Pump();});}}
function CheckAccount(accountId,options={}){
 const p=s.ProfileById(accountId);if(!p)return Promise.reject(Object.assign(Error('MEMBER_NOT_FOUND'),{memberError:true}));
 if(!Writable())return Promise.resolve(AdminStatus(p));
 if(inFlight.has(accountId))return inFlight.get(accountId);
 const link=View(p),now=Date.now(),last=Observation(p)?attempts.get(accountId)||0:0;
 if(!link||!Live(p)&&!denied.has(accountId)||now-last<(options.force?5000:Interval())||!options.force&&link.nextCheckAt>now||queue.length>=MAX_QUEUE)return Promise.resolve(AdminStatus(p));
 attempts.set(accountId,now);const promise=new Promise(resolve=>queue.push({id:accountId,options,resolve}));inFlight.set(accountId,promise);Pump();return promise;
}
function CheckClient(c,options={}){let p;try{p=s.DB().profiles[s.Subject(c)];}catch(_){}return p?CheckAccount(p.id,options):Promise.resolve(AdminStatus(null));}
function Tick(){
 if(!state.serviceEnabled||!require('../haCoordinator').CanAcceptTraffic())return;
 const cutoff=Date.now()-3600000;for(const [id,last]of attempts)if(last<cutoff&&!inFlight.has(id))attempts.delete(id);for(const [id,snapshot]of observations)if((snapshot.lastCheckedAt||0)<cutoff&&!inFlight.has(id)&&!snapshot.dirtyCredentials)observations.delete(id);
 for(const c of state.clients.values())if(require('./oauthIdentity').PreAllowed(c))CheckClient(c).catch(()=>{});
}
function StartMonitor(){if(!timer){timer=setInterval(Tick,5000);timer.unref?.();}}
function StopMonitor(){if(timer)clearInterval(timer);timer=null;}
function Fresh(p,tokens,old={}){
 const now=Date.now(),link={provider:p.providerIdentity.provider,accountId:p.id,installationSubject:p.subject,linkedAt:old.linkedAt||now,verifiedAt:now,lastCheckedAt:now,nextCheckAt:now+Interval(),generation:crypto.randomBytes(18).toString('base64url'),status:'active',reason:'',events:old.events||[],credentials:vault.Seal(tokens,Binding(p))};
 Event(link,'linked','', 'MEMBER');Remember(p.id,{generation:link.generation,baselineCredentials:link.credentials,credentials:link.credentials,verifiedAt:now,lastCheckedAt:now,nextCheckAt:now+Interval(),lastError:'',reason:'',status:'active'});attempts.delete(p.id);return link;
}
function AcceptLink(accountId){denied.delete(accountId);}
module.exports={Record,Live,Ready,AdminStatus,RevokeAccount,CheckAccount,CheckClient,StartMonitor,StopMonitor,Fresh,AcceptLink,Request};
