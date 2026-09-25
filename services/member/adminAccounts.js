'use strict';
const s=require('./store');
const names={google:'Google',kakao:'카카오'};
function Profile(p){return {...s.PublicProfile(p,true),blocked:!!p.blocked,identity:require('./oauthIdentity').AdminStatus(p)};}
function Configuration(){
 const oauth=require('./oauthIdentity');
 const providers=Object.entries(names).map(([id,name])=>{
  const cfg=oauth.Configuration(id),prefix=id.toUpperCase();
  const fields=[prefix+'_OAUTH_CLIENT_ID',prefix+'_OAUTH_CLIENT_SECRET','MEMBER_OAUTH_TOKEN_KEY'];
  return {id,name,configured:cfg.configured,origin:cfg.origin,callbackUri:cfg.origin?cfg.redirectUri:'',missing:[...cfg.missing],credentials:Object.fromEntries(fields.map(key=>[key,!!String(process.env[key]||'').trim()])),...(id==='kakao'?{unlinkCallback:cfg.origin?cfg.origin+'/member/oauth/kakao/unlink':'',unlinkNotificationsConfigured:!!process.env.KAKAO_UNLINK_ADMIN_KEY&&!!process.env.KAKAO_APP_ID,unlinkFields:['KAKAO_UNLINK_ADMIN_KEY','KAKAO_APP_ID']}:{})};
 });
 return {providers,checkedAt:Date.now(),publicUrlField:'MEMBER_OAUTH_PUBLIC_URL'};
}
function Read(body={}){
 if(body.view==='integrations')return {oauth:Configuration(),payments:require('./payments').AdminStatus()};
 if(body.accountId){const p=s.ProfileById(body.accountId);if(!p)s.Fail('MEMBER_NOT_FOUND');return {profile:Profile(p)};}
 const query=String(body.q||'').trim().toLocaleLowerCase('ko-KR');
 let rows=Object.values(s.DB().profiles).map(Profile);
 if(body.provider){if(!Object.hasOwn(names,body.provider))s.Fail('IDENTITY_PROVIDER_INVALID');rows=rows.filter(p=>p.identity.provider===body.provider);}
 if(body.status)rows=rows.filter(p=>p.identity.status===body.status);
 if(query)rows=rows.filter(p=>[p.id,p.handle,p.nickname,p.identity.accountLabel].some(value=>String(value||'').toLocaleLowerCase('ko-KR').includes(query.replace(/^@/,''))));
 rows.sort((a,b)=>(b.identity.lastCheckedAt||b.identity.linkedAt||b.createdAt)-(a.identity.lastCheckedAt||a.identity.linkedAt||a.createdAt));
 return s.Page(rows,body,50);
}
function Write(action,body,actor){
 if(Object.keys(body).some(key=>!['action','accountId','confirmedAccountId','confirmed','reason'].includes(key)))s.Fail('INPUT_INVALID');
 const p=s.ProfileById(body.accountId);if(!p)s.Fail('MEMBER_NOT_FOUND');
 if(action==='oauth.recheck')return require('./oauthIdentity').CheckAccount(p.id,{force:true});
 if(action==='oauth.reauth'){
  if(body.confirmed!==true||body.confirmedAccountId!==p.id)s.Fail('ADMIN_CONFIRM_REQUIRED');
  if(typeof body.reason!=='string')s.Fail('ADMIN_REASON_REQUIRED');const reason=s.Text(body.reason,240,true);if(reason.length<3)s.Fail('ADMIN_REASON_REQUIRED');
  return require('./oauthIdentity').RevokeAccount(p.id,'IDENTITY_ADMIN_REAUTH',actor,reason);
 }
 s.Fail('UNKNOWN_ACTION');
}
module.exports={Read,Write,Profile,Configuration};
