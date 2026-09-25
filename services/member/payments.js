'use strict';
const crypto=require('node:crypto'),s=require('./store'),provider=require('./payment-provider');
const TTL=15*60000,hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const orders=()=>s.DB().settings.paymentOrders||{};
function Atomic(fn){if(!require('../haCoordinator').CanAcceptTraffic())s.Fail('PAYMENT_PROVIDER_WAIT');return s.Atomic(fn);}
function Public(row){return {id:row.id,provider:row.provider,amount:row.amount,currency:'KRW',status:['CREATED','READY','PREPARING'].includes(row.status)&&row.expiresAt<=Date.now()?'EXPIRED':row.status,at:row.at,expiresAt:row.expiresAt,approvedAt:row.approvedAt||0,paymentId:row.paymentId||''};}
let recoveryEngine;const retryAt=new Map();
function Recover(p){
 const now=Date.now();for(const row of Object.values(orders())){
  if(row.accountId!==p.id||!(row.status==='APPROVING'||row.status==='PAID'&&row.rewardsPending)||now-(retryAt.get(row.id)||0)<15000)continue;
  retryAt.set(row.id,now);
  if(row.status==='PAID'){queueMicrotask(()=>Reward(row.id));continue;}
  recoveryEngine=recoveryEngine||Engine();recoveryEngine.Reconcile(row.id).catch(()=>{});
 }
 if(retryAt.size>5000)for(const[id,at]of retryAt)if(now-at>3600000)retryAt.delete(id);
}
function Read(p){Recover(p);return {wallet:require('./wallet').Read(p),providers:['KAKAOPAY','TOSSPAY'].map(id=>({id,enabled:provider.Ready(id),name:id==='KAKAOPAY'?'카카오페이':'토스페이'})),items:Object.values(orders()).filter(x=>x.accountId===p.id).sort((a,b)=>b.at-a.at).slice(0,10).map(Public)};}
// Invoked by the signed member dispatcher inside its replay-protected transaction.
function Start(p,body){
 const name=body.provider,amount=s.Money(body.amount,1000,1000000);if(!provider.Ready(name))s.Fail('PAYMENT_UNAVAILABLE');
 if(Object.keys(body).some(k=>!['provider','amount','_wire','_delta'].includes(k)))s.Fail('INPUT_INVALID');
 if(!Number.isSafeInteger(p.balance+amount+s.ReservedBalance(p)))s.Fail('BALANCE_INVALID');
 const now=Date.now();if(Object.values(orders()).filter(x=>x.accountId===p.id&&x.at>now-TTL&&['CREATED','READY','PREPARING','APPROVING'].includes(x.status)).length>=4)s.Fail('PLEASE_WAIT');
 const launch=crypto.randomBytes(32).toString('base64url'),id=s.Id('MPO');
 const row={id,accountId:p.id,provider:name,amount,currency:'KRW',at:now,expiresAt:now+TTL,launchHash:hash(launch),status:'CREATED'};
 if(!s.DB().settings.paymentOrders)s.DB().settings.paymentOrders={};s.DB().settings.paymentOrders[id]=row;
 return {checkout:Public(row),checkoutUrl:provider.Config().origin+'/pay/start/'+id+'/'+launch};
}
function Find(id){if(!/^MPO-[A-F0-9]{24}$/.test(id||''))s.Fail('PAYMENT_NOT_FOUND');const row=orders()[id];if(!row)s.Fail('PAYMENT_NOT_FOUND');return row;}
function Token(row,value,field){if(typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value)||!row[field]||!crypto.timingSafeEqual(Buffer.from(hash(value),'hex'),Buffer.from(row[field],'hex')))s.Fail('PAYMENT_STATE_INVALID');}
function Active(row){const p=s.ProfileById(row.accountId);if(!p||p.blocked)s.Fail('ACCOUNT_BLOCKED');return p;}
function Notify(){try{require('./service').NotifyChanged();}catch(_){}}
function Commit(id,receipt){
 if(!require('../haCoordinator').CanAcceptTraffic())s.Fail('PAYMENT_PROVIDER_WAIT');
 let row=Find(id);if(row.status==='PAID')return Public(row);
 if(Object.values(orders()).some(x=>x.id!==row.id&&x.provider===row.provider&&x.providerId===receipt.providerId&&x.status==='PAID'))s.Fail('PAYMENT_RECEIPT_INVALID');
 return Atomic(()=>{
  row=Find(id);const p=s.ProfileById(row.accountId);if(!p)s.Fail('ACCOUNT_REQUIRED');
  // A paid order always stays owned by the account which started it, even if it
  // was blocked meanwhile. Settling verified money does not grant app access.
  const existing=Object.values(s.DB().ledger).find(x=>x.reference===id&&x.kind==='PAYMENT_TOPUP');
  if(existing&&(existing.accountId!==p.id||existing.amount!==row.amount))s.Fail('PAYMENT_RECEIPT_INVALID');
  const ledger=existing||s.Ledger(p,row.amount,'PAYMENT_TOPUP',id);ledger.provider=row.provider;
  Object.assign(row,{status:'PAID',providerId:receipt.providerId,approvedAt:receipt.approvedAt,paymentId:ledger.id,creditedAt:Date.now(),rewardsPending:true});
  return Public(row);
 });
}
function Reward(id){
 const row=Find(id);if(row.status!=='PAID'||!row.rewardsPending)return;
 // Optional points/spins must never roll back verified real-money settlement.
 // If their limits or storage prevent an award, retain a durable retry flag.
 try{Atomic(()=>{const current=Find(id),p=s.ProfileById(current.accountId);require('./rewards').GrantCharge(p,current);require('./badges').ChargeApproved(p,current);delete current.rewardsPending;});}catch(_){}
}
function Engine(client=provider.Client()){
 const busy=new Map();
 async function Lock(id,fn){if(busy.has(id))return busy.get(id);const work=Promise.resolve().then(fn);busy.set(id,work);try{return await work;}finally{busy.delete(id);}}
 async function Launch(id,token){
  const initial=Find(id);Token(initial,token,'launchHash');if(initial.status!=='CREATED'||initial.expiresAt<=Date.now())s.Fail('PAYMENT_EXPIRED');
  return Lock(id,async()=>{
   let row=Find(id);Token(row,token,'launchHash');if(row.status!=='CREATED'||row.expiresAt<=Date.now())s.Fail('PAYMENT_EXPIRED');Active(row);
   const callback=crypto.randomBytes(32).toString('base64url');
   Atomic(()=>{row=Find(id);row.status='PREPARING';row.callbackHash=hash(callback);row.launchedAt=Date.now();});
   const base=provider.Config().origin+'/pay/return/'+id+'/'+callback;
   if(row.provider==='TOSSPAY'){Atomic(()=>{Find(id).status='READY';});return {provider:row.provider,id:row.id,amount:row.amount,customerKey:row.accountId,clientKey:provider.Config().tossClient,successUrl:base+'/complete',failUrl:base+'/fail'};}
   try{
    const result=await client.Prepare(structuredClone(row),base),redirect=client.Redirect(result.next_redirect_mobile_url||result.next_redirect_pc_url);
    if(typeof result.tid!=='string'||!result.tid||result.tid.length>100)s.Fail('PAYMENT_PROVIDER_INVALID');
    Atomic(()=>{row=Find(id);row.status='READY';row.providerId=result.tid;});return {provider:'KAKAOPAY',redirect};
   }catch(e){Atomic(()=>{Find(id).status='FAILED';});throw e;}
  });
 }
 async function Reconcile(id){return Lock(id,async()=>{
  const row=Find(id);if(row.status==='PAID')return Public(row);if(!['READY','APPROVING'].includes(row.status))s.Fail('PAYMENT_NOT_READY');
  const response=await client.Query(structuredClone(row)),receipt=client.Verify(row,response),result=Commit(id,receipt);Reward(id);Notify();return result;
 });}
 async function Complete(id,state,params){
  const initial=Find(id);Token(initial,state,'callbackHash');
  if(initial.provider==='TOSSPAY'&&(params.orderId!==id||String(initial.amount)!==String(params.amount)||typeof params.paymentKey!=='string'||!params.paymentKey||params.paymentKey.length>200))s.Fail('PAYMENT_RECEIPT_INVALID');
  if(initial.provider==='KAKAOPAY'&&(typeof params.pg_token!=='string'||!params.pg_token||params.pg_token.length>200))s.Fail('PAYMENT_STATE_INVALID');
  return Lock(id,async()=>{
   let row=Find(id);Token(row,state,'callbackHash');if(row.status==='PAID')return Public(row);
   if(!['READY','APPROVING'].includes(row.status))s.Fail('PAYMENT_NOT_READY');
   const retry=row.status==='APPROVING';if(!retry&&row.expiresAt<=Date.now())s.Fail('PAYMENT_EXPIRED');
   const token=row.provider==='KAKAOPAY'?params.pg_token:params.paymentKey;
   if(row.provider==='TOSSPAY'&&row.providerId&&row.providerId!==token)s.Fail('PAYMENT_RECEIPT_INVALID');
   // Persist the consumed callback before approval. After a process restart a
   // retry queries the provider first; a success redirect itself is never money.
   Atomic(()=>{row=Find(id);row.status='APPROVING';row.callbackUsedAt=row.callbackUsedAt||Date.now();if(row.provider==='TOSSPAY')row.providerId=token;});
   let verified;
   if(retry){try{verified=client.Verify(row,await client.Query(structuredClone(row)));}catch(e){if(!['PAYMENT_PROVIDER_WAIT','PAYMENT_NOT_APPROVED'].includes(e.message))throw e;}}
   if(!verified){
    try{await client.Approve(structuredClone(row),token);}catch(e){
     // Approval may have succeeded before a connection dropped. Querying the
     // provider reconciles it without issuing a second local credit.
     try{verified=client.Verify(row,await client.Query(structuredClone(row)));}catch(_){throw e;}
    }
    if(!verified)verified=client.Verify(row,await client.Query(structuredClone(row)));
   }
   const result=Commit(id,verified);Reward(id);Notify();return result;
  });
 }
 function Cancel(id,state){const row=Find(id);Token(row,state,'callbackHash');if(row.status==='PAID')return Public(row);if(row.status==='READY')Atomic(()=>{Find(id).status='CANCELED';});return Public(Find(id));}
 return {Launch,Complete,Reconcile,Cancel};
}
module.exports={Read,Start,Public,Find,Engine,orders};
