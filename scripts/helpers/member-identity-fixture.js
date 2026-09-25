'use strict';
// Tests create persisted provider verification explicitly; never imported by production.
module.exports=function linkedIdentity(c,provider='google'){
 const s=require('../../services/member/store'),crypto=require('node:crypto');
 const p=s.Account(c),key=crypto.createHash('sha256').update(provider+'\0fixture:'+p.id).digest('hex');
 s.DB().oauthAccounts[key]={provider,accountId:p.id,installationSubject:p.subject,linkedAt:Date.now(),verifiedAt:Date.now()};
 p.providerIdentity={provider,key,label:'검증된 테스트 계정',linkedAt:Date.now()};return p;
};
