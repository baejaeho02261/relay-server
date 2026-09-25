'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{Readable}=require('node:stream');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-pay72-'));
process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';process.env.NODE_ENV='test';
require('../core/utils').EnsureDirs();
const provider=require('../services/member/payment-provider');
const configured={NODE_ENV:'test',PAYMENT_ENABLED:'true',PAYMENT_PUBLIC_ORIGIN:'https://merchant.example',KAKAOPAY_CID:'TC0ONETIME',KAKAOPAY_SECRET_KEY:'DEVprivateFixture',TOSSPAYMENTS_CLIENT_KEY:'test_ck_fixture',TOSSPAYMENTS_SECRET_KEY:'test_sk_privateFixture'};
const config=patch=>provider.Config({...configured,...patch});
function issue(id,patch,code){const status=provider.Status(id,config(patch));assert.equal(status.enabled,false);assert.ok(status.issues.some(x=>x.code===code),code);return status;}
const s=require('../services/member/store'),pay=require('../services/member/payments');
let requests=0;const remote=new Map(),realFetch=globalThis.fetch;
globalThis.fetch=async(url,options)=>{
 requests++;assert.equal(options.redirect,'error');const body=JSON.parse(options.body||'{}');
 if(url.endsWith('/ready')){
  const id=body.partner_order_id;remote.set(id,{state:body.approval_url.split('/').at(-2)});
  return new Response(JSON.stringify({tid:'T'+id,next_redirect_pc_url:'https://online-pay.kakao.com/pay/'+id+'/pc',next_redirect_mobile_url:'https://online-pay.kakao.com/pay/'+id+'/mobile'}));
 }
 throw Error('Unexpected external request in checkout-only test');
};
const http=require('../services/member/payment-http');
async function route(url,headers={}){
 const req=Readable.from([]);req.method='GET';req.headers=headers;
 const res={status:0,headers:{},text:'',writeHead(status,headers={}){this.status=status;this.headers=headers;},end(value=''){this.text+=value;}};
 assert.equal(await http.Handle(req,res,new URL(url,'https://merchant.example')),true);return res;
}
let sequence=0;
function start(id='KAKAOPAY'){const p=s.ProfileById('USR-PAY72');return s.Operation(p,'PAYMENT72-'+(++sequence),'payment.start',{provider:id,amount:1000},()=>pay.Start(p,{provider:id,amount:1000}));}
(async()=>{try{
 const none=provider.AdminStatus(provider.Config({}));assert.equal(none.enabled,false);assert.equal(none.originValid,false);assert.equal(none.providers.length,2);
 assert.deepEqual(none.providers[0].missing,['PAYMENT_PUBLIC_ORIGIN','KAKAOPAY_CID','KAKAOPAY_SECRET_KEY']);
 assert.equal(none.validationScope,'LOCAL_CONFIGURATION');assert.equal(none.providers[0].credentials.KAKAOPAY_SECRET_KEY,false);
 issue('KAKAOPAY',{PAYMENT_ENABLED:'false'},'PAYMENT_DISABLED');
 issue('KAKAOPAY',{PAYMENT_PUBLIC_ORIGIN:''},'PAYMENT_ORIGIN_MISSING');
 for(const origin of ['http://merchant.example','https://merchant.example/path','https://user:secret@merchant.example','https://merchant.example?secret=x','https://merchant.example/#token'])issue('KAKAOPAY',{PAYMENT_PUBLIC_ORIGIN:origin},'PAYMENT_ORIGIN_INVALID');
 issue('KAKAOPAY',{KAKAOPAY_SECRET_KEY:' '},'PAYMENT_CREDENTIALS_MISSING');
 issue('KAKAOPAY',{KAKAOPAY_SECRET_KEY:'DEV invalid'},'PAYMENT_CREDENTIALS_INVALID');
 assert.equal(provider.Ready('KAKAOPAY',config({TOSSPAYMENTS_SECRET_KEY:''})),true,'providers configure independently');
 for(const invalid of ['UNKNOWN','__proto__','constructor','toString'])assert.equal(provider.Ready(invalid,config()),false);
 issue('TOSSPAY',{TOSSPAYMENTS_CLIENT_KEY:'test_gck_widget'},'PAYMENT_CREDENTIALS_INVALID');
 issue('TOSSPAY',{TOSSPAYMENTS_SECRET_KEY:'live_sk_other'},'PAYMENT_KEY_MODE_MISMATCH');
 for(const id of ['KAKAOPAY','TOSSPAY']){
  issue(id,{NODE_ENV:'production'},'PAYMENT_TEST_MODE_BLOCKED');
  issue(id,{NODE_ENV:''},'PAYMENT_TEST_MODE_BLOCKED');
  issue(id,{NODE_ENV:'development'},'PAYMENT_TEST_MODE_BLOCKED');
  issue(id,{NODE_ENV:'production',PAYMENT_ALLOW_TEST_MODE:'true'},'PAYMENT_TEST_MODE_BLOCKED');
  assert.equal(provider.Ready(id,config({NODE_ENV:'development',PAYMENT_ALLOW_TEST_MODE:'true'})),true);
 }
 const live=config({NODE_ENV:'production',KAKAOPAY_CID:'LIVE_CID',KAKAOPAY_SECRET_KEY:'livePrivateFixture',TOSSPAYMENTS_CLIENT_KEY:'live_ck_fixture',TOSSPAYMENTS_SECRET_KEY:'live_sk_privateFixture'});
 assert.equal(provider.Ready('KAKAOPAY',live),true);assert.equal(provider.Ready('TOSSPAY',live),true);
 const admin=provider.AdminStatus(live),publicStatus=provider.Capabilities(live);
 for(const value of [live.kakaoCid,live.kakaoSecret,live.tossClient,live.tossSecret]){assert.ok(!JSON.stringify(admin).includes(value));assert.ok(!JSON.stringify(publicStatus).includes(value));}
 assert.ok(!JSON.stringify(publicStatus).includes('SECRET_KEY'));assert.equal(publicStatus[1].mode,'live');
 assert.equal(provider.Status('TOSSPAY',config()).mode,'test');
 const redirect=provider.Client().Redirect;
 for(const host of ['online-pay.kakao.com','mockup-pg-web.kakao.com','online-pay.kakaopay.com'])assert.equal(redirect('https://'+host+'/checkout'),'https://'+host+'/checkout');
 for(const bad of ['https://online-pay.kakao.com.evil.example/pay','https://evil.kakao.com/pay','https://user@online-pay.kakao.com/pay','http://online-pay.kakao.com/pay','https://online-pay.kakao.com:8443/pay','javascript:alert(1)'])assert.throws(()=>redirect(bad),/PAYMENT_PROVIDER_INVALID/);
 const rejected=provider.Client(async()=>new Response(JSON.stringify({code:'UNAUTHORIZED_KEY'}),{status:401}),()=>config());
 await assert.rejects(()=>rejected.Query({provider:'TOSSPAY',id:'MPO-ORDER'}),/PAYMENT_PROVIDER_CONFIG/);
 const productionClient=provider.Client(async()=>{throw Error('must not call provider');},()=>live);
 assert.throws(()=>productionClient.Verify({provider:'TOSSPAY',paymentMode:'test'},{}),/PAYMENT_UNAVAILABLE/,'test orders cannot be credited after switching to production');
 Object.assign(process.env,configured);
 s.Atomic(()=>s.DB().profiles['pay72']={id:'USR-PAY72',subject:'pay72',nickname:'payment setup',bio:'',balance:0,createdAt:Date.now()});
 const desktop=start(),desktopResponse=await route(new URL(desktop.checkoutUrl).pathname,{'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'});
 assert.equal(desktopResponse.status,303);assert.ok(desktopResponse.headers.Location.endsWith('/pc'));
 const mobile=start(),mobileResponse=await route(new URL(mobile.checkoutUrl).pathname,{'user-agent':'Mozilla/5.0 (Linux; Android 14) Mobile'});
 assert.equal(mobileResponse.status,303);assert.ok(mobileResponse.headers.Location.endsWith('/mobile'));
 const state=remote.get(desktop.checkout.id).state;
 s.Atomic(()=>pay.Find(desktop.checkout.id).status='APPROVING');
 const pending=await route('/pay/return/'+desktop.checkout.id+'/'+state+'/cancel');assert.ok(pending.text.includes('승인 요청이 진행 중입니다.'));assert.ok(!pending.text.includes('충전 잔액은 변경되지 않았습니다.'));
 s.Atomic(()=>pay.Find(desktop.checkout.id).status='PAID');
 const paid=await route('/pay/return/'+desktop.checkout.id+'/'+state+'/fail');assert.ok(paid.text.includes('이미 충전이 완료됐어요'));assert.ok(!paid.text.includes('결제가 취소됐어요'));
 const toss=start('TOSSPAY'),checkout=await route(new URL(toss.checkoutUrl).pathname);
 assert.equal(checkout.status,200);assert.ok(checkout.text.includes('테스트 결제입니다.'));assert.ok(checkout.text.includes('windowTarget:"self"'));assert.ok(checkout.text.includes('easyPay:"TOSSPAY"'));assert.ok(!checkout.text.includes(configured.TOSSPAYMENTS_SECRET_KEY));
 const disabled=start();process.env.PAYMENT_ENABLED='false';
 const requestCount=requests,failed=await route(new URL(disabled.checkoutUrl).pathname);assert.equal(failed.status,503);assert.equal(requests,requestCount);assert.equal(pay.Find(disabled.checkout.id).status,'CREATED');
 process.env.PAYMENT_ENABLED='true';process.env.NODE_ENV='production';
 const before=JSON.stringify(s.DB());assert.throws(()=>start('TOSSPAY'),/PAYMENT_UNAVAILABLE/);assert.equal(JSON.stringify(s.DB()),before);assert.equal(requests,requestCount);
 process.env.KAKAOPAY_CID='LIVE_CID';process.env.KAKAOPAY_SECRET_KEY='livePrivateFixture';
 const changedMode=await route(new URL(disabled.checkoutUrl).pathname);assert.equal(changedMode.status,503);assert.equal(requests,requestCount);assert.equal(pay.Find(disabled.checkout.id).status,'CREATED','changing a test checkout to live credentials must not initiate a real payment');
 console.log('FIX72 payment setup: redacted config matrix, production sandbox gate, documented Kakao hosts, desktop/mobile redirects and checkout status passed ('+process.env.STORAGE_ENGINE+')');
}finally{globalThis.fetch=realFetch;fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
