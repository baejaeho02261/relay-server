'use strict';
// Tests create persisted provider verification explicitly; never imported by production.
module.exports=function linkedIdentity(c,provider='google'){
 const s=require('../../services/member/store'),crypto=require('node:crypto');
 const p=s.Account(c),key=crypto.createHash('sha256').update(provider+'\0fixture:'+p.id).digest('hex');
 if(!process.env.MEMBER_OAUTH_TOKEN_KEY)process.env.MEMBER_OAUTH_TOKEN_KEY=crypto.randomBytes(32).toString('hex');
 p.providerIdentity={provider,key,label:'검증된 테스트 계정',linkedAt:Date.now()};
 s.DB().oauthAccounts[key]=require('../../services/member/oauthLifecycle').Fresh(p,{accessToken:'fixture-access-'+p.id,refreshToken:'fixture-refresh-'+p.id,expiresAt:Date.now()+3600000,refreshExpiresAt:0});return p;
};
