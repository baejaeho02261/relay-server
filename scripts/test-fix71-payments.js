'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'moaplay-pay71-'));process.env.DATA_DIR=dir;process.env.STORAGE_ENGINE=process.argv.includes('--sqlite')?'sqlite':'json';
process.env.PAYMENT_ENABLED='true';process.env.PAYMENT_PUBLIC_ORIGIN='https://merchant.example';process.env.KAKAOPAY_CID='TC0ONETIME';process.env.KAKAOPAY_SECRET_KEY='test-private';process.env.TOSSPAYMENTS_CLIENT_KEY='test_ck_contract';process.env.TOSSPAYMENTS_SECRET_KEY='test_sk_contract';
require('../core/utils').EnsureDirs();
const s=require('../services/member/store'),db=require('../storage/database'),pay=require('../services/member/payments'),provider=require('../services/member/payment-provider'),retire=require('../services/member/withdraw-retirement');
let sequence=0;
function member(name){const p={id:s.Id('USR'),subject:name,nickname:name,bio:'',balance:0,createdAt:Date.now(),avatar:'',avatarRevision:0};s.Atomic(()=>s.DB().profiles[name]=p);return p.id;}
const owner=id=>s.ProfileById(id),requests=[],remote=new Map();let tamper=null,timeoutAfterApprove=false,saveFailureAfterApprove=false;
function makeResult(row){if(row.provider==='KAKAOPAY')return {status:'SUCCESS_PAYMENT',cid:'TC0ONETIME',partner_order_id:row.id,partner_user_id:row.accountId,tid:row.providerId,amount:{total:row.amount},approved_at:new Date().toISOString()};return {status:'DONE',orderId:row.id,totalAmount:row.amount,currency:'KRW',paymentKey:row.providerId,approvedAt:new Date().toISOString()};}
const normalSave=db.SaveDatabase;
const fakeFetch=async(url,opts)=>{
 requests.push({url,opts});assert.ok(url.startsWith('https://open-api.kakaopay.com/')||url.startsWith('https://api.tosspayments.com/'));assert.equal(opts.redirect,'error');assert.ok(opts.signal);
 const body=opts.body?JSON.parse(opts.body):{};let result;
 if(url.endsWith('/ready')){const id=body.partner_order_id;remote.set(id,{body,state:body.approval_url.split('/').at(-2),approved:false});result={tid:'T'+id.slice(4),next_redirect_mobile_url:'https://online-pay.kakaopay.com/checkout/'+id};}
 else if(url.endsWith('/approve')||url.endsWith('/confirm')){
  const id=body.partner_order_id||body.orderId,row=pay.Find(id);const entry=remote.get(id)||{};entry.approved=true;remote.set(id,entry);result=makeResult(row);
  if(saveFailureAfterApprove){db.SaveDatabase=()=>false;saveFailureAfterApprove=false;}
  if(timeoutAfterApprove){timeoutAfterApprove=false;throw Error('socket timeout');}
 }else{
  const id=body.tid?Object.values(pay.orders()).find(x=>x.providerId===body.tid)?.id:decodeURIComponent(url.split('/').at(-1));const row=pay.Find(id),entry=remote.get(id);
  if(!entry?.approved)return new Response(JSON.stringify({code:'NOT_FOUND_PAYMENT'}),{status:404});
  result=makeResult(row);if(tamper)result=tamper(result,row);
 }
 return new Response(JSON.stringify(result),{status:200,headers:{'content-type':'application/json'}});
};
const client=provider.Client(fakeFetch),engine=pay.Engine(client);
function start(id,providerName='TOSSPAY',amount=1000,request='PAYMENT-TEST-'+(++sequence)){return s.Operation(owner(id),request,'payment.start',{provider:providerName,amount},()=>pay.Start(owner(id),{provider:providerName,amount}));}
async function launch(order,which=engine){const u=new URL(order.checkoutUrl),parts=u.pathname.split('/');const response=await which.Launch(parts[3],parts[4]);const state=response.provider==='KAKAOPAY'?remote.get(order.checkout.id).state:new URL(response.successUrl).pathname.split('/').at(-2);return {response,state};}
const params=(order,key='key-'+order.checkout.id)=>({orderId:order.checkout.id,amount:String(order.checkout.amount),paymentKey:key,pg_token:'pg-'+order.checkout.id});
(async()=>{try{
 const a=member('A'),b=member('B');
 const before=JSON.stringify(s.DB());assert.throws(()=>s.Atomic(()=>pay.Start(owner(a),{provider:'TOSSPAY',amount:1000,accountId:b})),/INPUT_INVALID/);assert.equal(JSON.stringify(s.DB()),before);
 for(const amount of [0,999,1.5,1000001,'1000'])assert.throws(()=>start(a,'TOSSPAY',amount),/AMOUNT_INVALID/);
 process.env.PAYMENT_ENABLED='false';assert.throws(()=>start(a),/PAYMENT_UNAVAILABLE/);process.env.PAYMENT_ENABLED='true';
 const order=start(a,'TOSSPAY',2000,'PAYMENT-ONCE-01');assert.deepEqual(start(a,'TOSSPAY',2000,'PAYMENT-ONCE-01'),order);
 const check=await launch(order);await assert.rejects(()=>engine.Launch(order.checkout.id,new URL(order.checkoutUrl).pathname.split('/').at(-1)),/PAYMENT_EXPIRED/);
 await assert.rejects(()=>engine.Complete(order.checkout.id,'x'.repeat(43),params(order)),/PAYMENT_STATE_INVALID/);
 await assert.rejects(()=>engine.Complete(order.checkout.id,check.state,{...params(order),amount:'1'}),/PAYMENT_RECEIPT_INVALID/);
 const balanceBefore=owner(a).balance;
 await Promise.all(Array.from({length:16},()=>engine.Complete(order.checkout.id,check.state,params(order))));
 assert.equal(owner(a).balance,balanceBefore+2000);assert.equal(owner(b).balance,0);assert.equal(Object.values(s.DB().ledger).filter(x=>x.reference===order.checkout.id).length,1);
 assert.equal(owner(a).eventSpins,2,'verified provider charge keeps existing wheel-turn rewards');assert.ok(Object.values(s.DB().pointLedger).some(x=>x.accountId===a&&x.kind==='BADGE_REWARD'),'provider charge retains charge achievement rewards');
 assert.equal(requests.filter(x=>x.url.endsWith('/confirm')).length,1,'parallel callbacks approve and credit once');
 assert.equal(requests.find(x=>x.url.endsWith('/confirm')).opts.headers['Idempotency-Key'],order.checkout.id);
 const kakao=start(a,'KAKAOPAY',3000),kc=await launch(kakao);timeoutAfterApprove=true;
 await engine.Complete(kakao.checkout.id,kc.state,params(kakao));assert.equal(owner(a).balance,5000,'lost approval reply is recovered by provider order lookup');
 const third=start(b,'TOSSPAY',4000),tc=await launch(third);tamper=(result)=>({...result,totalAmount:1});
 await assert.rejects(()=>engine.Complete(third.checkout.id,tc.state,params(third)),/PAYMENT_RECEIPT_INVALID/);assert.equal(owner(b).balance,0);
 tamper=(result)=>({...result,orderId:order.checkout.id});await assert.rejects(()=>engine.Reconcile(third.checkout.id),/PAYMENT_RECEIPT_INVALID/);assert.equal(owner(b).balance,0);
 tamper=null;await engine.Reconcile(third.checkout.id);assert.equal(owner(b).balance,4000);
 const kk=start(b,'KAKAOPAY',5000),kkc=await launch(kk);tamper=(result)=>({...result,partner_user_id:a});
 await assert.rejects(()=>engine.Complete(kk.checkout.id,kkc.state,params(kk)),/PAYMENT_RECEIPT_INVALID/);assert.equal(owner(b).balance,4000);tamper=null;await engine.Reconcile(kk.checkout.id);
 const persist=start(a,'TOSSPAY',1000),pc=await launch(persist);saveFailureAfterApprove=true;
 await assert.rejects(()=>engine.Complete(persist.checkout.id,pc.state,params(persist)),/STORAGE_SAVE_FAILED/);db.SaveDatabase=normalSave;
 assert.equal(owner(a).balance,5000);assert.equal(pay.Find(persist.checkout.id).status,'APPROVING');
 const fresh=pay.Engine(client);await fresh.Complete(persist.checkout.id,pc.state,params(persist));assert.equal(owner(a).balance,6000,'restart reconciliation settles once after failed local save');
 for(const url of ['http://kakaopay.com','https://kakaopay.com.attacker.test/a','https://user@kakaopay.com','https://127.0.0.1','https://kakaopay.com:444'])assert.throws(()=>client.Redirect(url),/PAYMENT_PROVIDER_INVALID/);
 // The HTTP adapter rejects forged hints and callbacks without exposing a key.
 const realFetch=globalThis.fetch;globalThis.fetch=fakeFetch;
 const http=require('../services/member/payment-http'),{Readable}=require('node:stream');
 async function route(url,method='GET',body=''){
  const req=Readable.from(body?[Buffer.from(body)]:[]);req.method=method;const res={headers:{},status:0,text:'',writeHead(status,headers={}){this.status=status;Object.assign(this.headers,headers);},end(text=''){this.text+=text;}};
  assert.equal(await http.Handle(req,res,new URL(url,'https://merchant.example')),true);return res;
 }
 let result=await route('/pay/webhook/toss','POST',JSON.stringify({data:{orderId:'MPO-unknown',status:'DONE',totalAmount:9999999}}));assert.equal(result.status,204);
 const count=requests.length;result=await route('/pay/return/'+order.checkout.id+'/'+'z'.repeat(43)+'/complete?orderId='+order.checkout.id+'&amount=2000&paymentKey=forged');assert.equal(result.status,400);assert.equal(requests.length,count);
 const hook=start(b),hookStarted=await launch(hook);s.Atomic(()=>{pay.Find(hook.checkout.id).providerId='key-'+hook.checkout.id;});remote.set(hook.checkout.id,{approved:true});
 result=await route('/pay/webhook/toss','POST',JSON.stringify({data:{orderId:hook.checkout.id,status:'DONE',totalAmount:9999999}}));assert.equal(result.status,204);assert.equal(pay.Find(hook.checkout.id).status,'PAID');
 const balanceAfterHook=owner(b).balance;await route('/pay/webhook/toss','POST',JSON.stringify({data:{orderId:hook.checkout.id}}));assert.equal(owner(b).balance,balanceAfterHook);
 globalThis.fetch=realFetch;
 const capped=member('rewards-capped');s.Atomic(()=>owner(capped).eventSpins=10000000);const cappedOrder=start(capped),cappedLaunch=await launch(cappedOrder);
 await engine.Complete(cappedOrder.checkout.id,cappedLaunch.state,params(cappedOrder));assert.equal(owner(capped).balance,1000,'optional capped reward cannot block verified wallet settlement');assert.equal(pay.Find(cappedOrder.checkout.id).status,'PAID');assert.equal(pay.Find(cappedOrder.checkout.id).rewardsPending,true);
 const ha=require('../services/haCoordinator'),canAccept=ha.CanAcceptTraffic;ha.CanAcceptTraffic=()=>false;
 const rowsBeforeStandby=JSON.stringify(pay.orders());await assert.rejects(()=>engine.Reconcile(persist.checkout.id+'BAD'),/PAYMENT_NOT_FOUND/);
 result=await route('/pay/start/'+order.checkout.id+'/'+'a'.repeat(43));assert.equal(result.status,503);assert.equal(JSON.stringify(pay.orders()),rowsBeforeStandby,'standby callbacks cannot write an undurable payment snapshot');ha.CanAcceptTraffic=canAccept;
 const exp=start(a);s.Atomic(()=>pay.Find(exp.checkout.id).expiresAt=Date.now()-1);await assert.rejects(()=>launch(exp),/PAYMENT_EXPIRED/);
 const cancel=start(a),cc=await launch(cancel);engine.Cancel(cancel.checkout.id,cc.state);await assert.rejects(()=>engine.Complete(cancel.checkout.id,cc.state,params(cancel)),/PAYMENT_NOT_READY/);
 const exported=db.BuildDatabaseObject();assert.equal(db.ImportDatabaseObject(exported),true);await fresh.Complete(persist.checkout.id,pc.state,params(persist));assert.equal(owner(a).balance,6000);
 // Feature retirement: reserve proof, paid requests, duplicate release, and a
 // failed durable save cannot create or strand a second credit.
 const w=member('withdraw-owner');s.Atomic(()=>{s.Ledger(owner(w),10000,'TOPUP','FIX71');for(const status of ['PENDING','PAID']){const id=s.Id('WDR'),ledger=s.Ledger(owner(w),-1000,'WITHDRAW_RESERVE',id);s.DB().withdrawRequests[id]={id,accountId:w,amount:1000,status,paymentId:ledger.id};}});
 const pending=Object.values(s.DB().withdrawRequests).find(x=>x.status==='PENDING');assert.equal(owner(w).balance,8000);
 const old=JSON.stringify(s.DB());db.SaveDatabase=()=>false;assert.throws(()=>retire.Ensure(owner(w)),/STORAGE_SAVE_FAILED/);db.SaveDatabase=normalSave;assert.equal(JSON.stringify(s.DB()),old);
 retire.Ensure(owner(w));assert.equal(owner(w).balance,9000);retire.Ensure(owner(w));assert.equal(owner(w).balance,9000);assert.equal(s.DB().withdrawRequests[pending.id].status,'RETIRED');
 assert.equal(Object.values(s.DB().withdrawRequests).find(x=>x.status==='PAID').status,'PAID');
 s.Atomic(()=>{const id=s.Id('WDR');s.DB().withdrawRequests[id]={id,accountId:w,amount:1000,status:'PENDING',paymentId:'forged'};});retire.Ensure(owner(w));assert.equal(owner(w).balance,9000,'a forged pending amount without reservation cannot mint money');
 assert.equal(Object.values(s.DB().ledger).filter(x=>x.kind==='WITHDRAW_RETIREMENT_RELEASE').length,1);
 console.log('FIX71 payments: provider identity/amount/state, replay/concurrency, unknown receipt, timeout/restart, durable rollback, HTTPS and retirement checks passed ('+process.env.STORAGE_ENGINE+')');
}finally{db.SaveDatabase=normalSave;fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
