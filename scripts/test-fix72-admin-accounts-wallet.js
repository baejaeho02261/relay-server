'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{Readable}=require('node:stream');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-fix72-admin-'));process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.NODE_ENV='test';
process.env.MEMBER_OAUTH_PUBLIC_URL='https://moa.example';process.env.MEMBER_OAUTH_TOKEN_KEY=Buffer.alloc(32,7).toString('base64');process.env.GOOGLE_OAUTH_CLIENT_ID='private-client-id';process.env.GOOGLE_OAUTH_CLIENT_SECRET='private-google-secret';process.env.KAKAO_OAUTH_CLIENT_ID='private-kakao-id';process.env.KAKAO_OAUTH_CLIENT_SECRET='private-kakao-secret';
const state=require('../core/state'),s=require('../services/member/store'),service=require('../services/member/service'),db=require('../storage/database'),oauth=require('../services/member/oauthIdentity'),web=require('../web/webApi');require('../core/utils').EnsureDirs();
let seq=0;const fail=(fn,reason)=>assert.throws(fn,e=>e.memberError&&e.message===reason);
async function request(method,url,body,role='admin'){
 const req=Readable.from(body?[Buffer.from(JSON.stringify(body))]:[]);Object.assign(req,{method,url,headers:{},socket:{remoteAddress:'127.0.0.1'}});let status,text;await web.HandleApiRequest(req,{writeHead(n){status=n;},end(v){text=v;}},{role,id:'TEST_ADMIN'});return {status,body:JSON.parse(text)};
}
(async()=>{try{
 const p=s.Account({installationDeviceKey:'ADMIN-WALLET-ONE'}),other=s.Account({installationDeviceKey:'ADMIN-WALLET-TWO'});p.handle='grant_target';p.nickname='잔액 대상';
 const grant=(overrides={})=>({action:'wallet.grant',accountId:p.id,confirmedAccountId:p.id,confirmed:true,amount:123456789,reason:'운영 보상 지급',requestId:'GRANT_TEST_'+String(++seq).padStart(4,'0'),...overrides});
 const body=grant(),denied=await request('POST','/api/member/action',body,'operator');assert.equal(denied.status,403);assert.equal(p.balance,0);
 const r=await request('POST','/api/member/action',body);assert.equal(r.status,200);assert.equal(r.body.result.amount,123456789);assert.equal(p.balance,123456789);assert.equal(Object.keys(s.DB().ledger).length,1);assert.equal(r.body.result.actor,'admin:TEST_ADMIN');assert.equal(r.body.result.reason,body.reason);
 assert.deepEqual((await request('POST','/api/member/action',body)).body.result,r.body.result);assert.equal(Object.keys(s.DB().ledger).length,1);
 s.Import({memberHub:structuredClone(s.DB())});assert.deepEqual(service.AdminWrite('wallet.grant',body,'admin:SECOND_SESSION'),r.body.result);assert.equal(s.ProfileById(p.id).balance,123456789);
 fail(()=>service.AdminWrite('wallet.grant',{...body,amount:body.amount+1},'TEST'),'REQUEST_REUSED');
 fail(()=>service.AdminWrite('wallet.grant',{...body,accountId:other.id,confirmedAccountId:other.id},'TEST'),'REQUEST_REUSED');
 for(const amount of [0,-1,1.5,'1000',NaN,Infinity,Number.MAX_SAFE_INTEGER+1])fail(()=>service.AdminWrite('wallet.grant',grant({amount}),'TEST'),'AMOUNT_INVALID');
 fail(()=>service.AdminWrite('wallet.grant',grant({confirmed:false}),'TEST'),'ADMIN_CONFIRM_REQUIRED');
 fail(()=>service.AdminWrite('wallet.grant',grant({confirmedAccountId:other.id}),'TEST'),'ADMIN_CONFIRM_REQUIRED');
 fail(()=>service.AdminWrite('wallet.grant',grant({reason:' '}),'TEST'),'INPUT_INVALID');
 fail(()=>service.AdminWrite('wallet.grant',grant({reason:'a'}),'TEST'),'ADMIN_REASON_REQUIRED');
 fail(()=>service.AdminWrite('wallet.grant',grant({ids:[p.id,other.id]}),'TEST'),'INPUT_INVALID');
 fail(()=>service.AdminWrite('wallet.grant',grant({requestId:12345678}),'TEST'),'REQUEST_ID_INVALID');
 const before=JSON.stringify(s.DB()),save=db.SaveDatabase;db.SaveDatabase=()=>false;const retry=grant({amount:250});fail(()=>service.AdminWrite('wallet.grant',retry,'TEST'),'STORAGE_SAVE_FAILED');db.SaveDatabase=save;assert.equal(JSON.stringify(s.DB()),before);service.AdminWrite('wallet.grant',retry,'TEST');assert.equal(s.ProfileById(p.id).balance,123457039);assert.equal(Object.keys(s.DB().ledger).length,2);
 s.ProfileById(p.id).balance=Number.MAX_SAFE_INTEGER;fail(()=>service.AdminWrite('wallet.grant',grant({amount:1}),'TEST'),'BALANCE_INVALID');s.ProfileById(p.id).balance=123457039;
 s.ProfileById(p.id).blocked=true;fail(()=>service.AdminWrite('wallet.grant',grant(),'TEST'),'ACCOUNT_BLOCKED');s.ProfileById(p.id).blocked=false;
 const setup=await request('GET','/api/member?view=integrations');assert.equal(setup.status,200);assert.equal(setup.body.oauth.providers[0].callbackUri,'https://moa.example/member/oauth/callback/google');const serialized=JSON.stringify(setup.body);for(const secret of ['private-client-id','private-google-secret','private-kakao-id','private-kakao-secret',process.env.MEMBER_OAUTH_TOKEN_KEY])assert.ok(!serialized.includes(secret));assert.equal((await request('GET','/api/member?view=integrations',null,'operator')).status,403);
 const current=s.ProfileById(p.id),key='private-identity-key';current.providerIdentity={provider:'google',key,label:'계정 표시 이름',linkedAt:1};s.DB().oauthAccounts[key]={provider:'google',accountId:p.id,installationSubject:current.subject,linkedAt:1,verifiedAt:2,credentials:'private-encrypted-token',status:'active',generation:'TEST'};
 const list=service.AdminRead({view:'oauthAccounts',provider:'google'});assert.equal(list.total,1);assert.equal(list.items[0].identity.provider,'google');assert.equal(service.AdminRead({view:'oauthAccounts',provider:'kakao'}).total,0);assert.equal(service.AdminRead({view:'oauthAccounts',q:'@grant_target'}).total,1);assert.ok(!JSON.stringify(list).includes(key));assert.ok(!JSON.stringify(list).includes('private-encrypted-token'));
 const check=oauth.CheckAccount;oauth.CheckAccount=async id=>{await Promise.resolve();return {status:'active',accountId:id};};const recheck=await request('POST','/api/member/action',{action:'oauth.recheck',accountId:p.id});assert.equal(recheck.body.result.status,'active');oauth.CheckAccount=check;
 fail(()=>service.AdminWrite('oauth.reauth',{action:'oauth.reauth',accountId:p.id,reason:'운영 확인'},'TEST'),'ADMIN_CONFIRM_REQUIRED');
 const reset=service.AdminWrite('oauth.reauth',{action:'oauth.reauth',accountId:p.id,confirmedAccountId:p.id,confirmed:true,reason:'회원 요청으로 재확인'},'TEST_ADMIN');assert.equal(reset.status,'revoked');assert.equal(s.ProfileById(p.id).balance,123457039);assert.equal(s.DB().oauthAccounts[key].accountId,p.id);assert.equal(s.DB().oauthAccounts[key].credentials,undefined);assert.equal(reset.events.at(-1).actor,'TEST_ADMIN');assert.equal(reset.events.at(-1).detail,'회원 요청으로 재확인');
 const publicPayments=require('../services/member/commerce').Mine(s.ProfileById(p.id),{}).payments.items;assert.equal(publicPayments.length,2);for(const payment of publicPayments)for(const key of ['actor','reason','requestId','memberHandle','reference'])assert.equal(payment[key],undefined);assert.ok(!JSON.stringify(publicPayments).includes(body.requestId));
 assert.equal(service.AdminRead({view:'walletGrants'}).total,2);assert.equal(service.AdminRead({view:'profiles'}).items.find(row=>row.id===p.id).identity.status,'revoked');
 console.log('FIX72 ADMIN PASS: role gates, masked provider config, filtered identity state, async recheck, confirmed local reset, arbitrary positive integer grants, audit, reload replay, conflict detection, overflow and atomic rollback');
}finally{fs.rmSync(temp,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
