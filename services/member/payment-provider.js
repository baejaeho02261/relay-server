'use strict';
// The only outbound payment destinations are these fixed provider HTTPS hosts.
const s=require('./store');
function Config(){
 const env=process.env;let origin='';
 try{const u=new URL(env.PAYMENT_PUBLIC_ORIGIN||'');if(u.protocol==='https:'&&!u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash)origin=u.origin;}catch(_){}
 return {origin,enabled:env.PAYMENT_ENABLED==='true',kakaoCid:env.KAKAOPAY_CID||'',kakaoSecret:env.KAKAOPAY_SECRET_KEY||'',tossClient:env.TOSSPAYMENTS_CLIENT_KEY||'',tossSecret:env.TOSSPAYMENTS_SECRET_KEY||''};
}
function Ready(provider,c=Config()){return !!(c.enabled&&c.origin&&(provider==='KAKAOPAY'?c.kakaoCid&&c.kakaoSecret:provider==='TOSSPAY'?c.tossClient&&c.tossSecret:false));}
function Client(fetchImpl=globalThis.fetch,getConfig=Config){
 async function Request(provider,path,body,idempotency){
  const c=getConfig();if(!Ready(provider,c))s.Fail('PAYMENT_UNAVAILABLE');
  const kakao=provider==='KAKAOPAY',host=kakao?'https://open-api.kakaopay.com':'https://api.tosspayments.com';
  if(!path.startsWith(kakao?'/online/v1/payment/':'/v1/payments/')||path.includes('..'))s.Fail('PAYMENT_PROVIDER_INVALID');
  const headers={'Content-Type':'application/json',Authorization:kakao?'SECRET_KEY '+c.kakaoSecret:'Basic '+Buffer.from(c.tossSecret+':').toString('base64')};
  if(idempotency)headers['Idempotency-Key']=idempotency;
  let response;try{response=await fetchImpl(host+path,{method:body?'POST':'GET',redirect:'error',headers,body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(15000)});}catch(_){s.Fail('PAYMENT_PROVIDER_WAIT');}
  // A streamed response bound prevents a provider/proxy error from exhausting memory.
  let text='';if(response.body?.getReader){const reader=response.body.getReader();let length=0;const parts=[];
   try{while(true){const chunk=await reader.read();if(chunk.done)break;length+=chunk.value.length;if(length>262144){await reader.cancel();s.Fail('PAYMENT_PROVIDER_INVALID');}parts.push(Buffer.from(chunk.value));}text=Buffer.concat(parts).toString('utf8');}finally{reader.releaseLock();}
  }else{text=await response.text();if(Buffer.byteLength(text)>262144)s.Fail('PAYMENT_PROVIDER_INVALID');}
  let result;try{result=JSON.parse(text);}catch(_){s.Fail('PAYMENT_PROVIDER_INVALID');}
  if(!response.ok){const e=Error('PAYMENT_PROVIDER_WAIT');e.memberError=true;e.providerCode=String(result.code||result.error_code||'').slice(0,80);throw e;}
  if(!result||typeof result!=='object'||Array.isArray(result))s.Fail('PAYMENT_PROVIDER_INVALID');return result;
 }
 function User(row){return row.accountId;}
 async function Prepare(row,callback){
  const c=getConfig();return Request('KAKAOPAY','/online/v1/payment/ready',{cid:c.kakaoCid,partner_order_id:row.id,partner_user_id:User(row),item_name:'MoaPlay 잔액 충전',quantity:1,total_amount:row.amount,tax_free_amount:0,approval_url:callback+'/complete',cancel_url:callback+'/cancel',fail_url:callback+'/fail'});
 }
 async function Query(row){return row.provider==='KAKAOPAY'?Request(row.provider,'/online/v1/payment/order',{cid:getConfig().kakaoCid,tid:row.providerId}):Request(row.provider,'/v1/payments/orders/'+encodeURIComponent(row.id));}
 async function Approve(row,token){
  if(row.provider==='KAKAOPAY')return Request(row.provider,'/online/v1/payment/approve',{cid:getConfig().kakaoCid,tid:row.providerId,partner_order_id:row.id,partner_user_id:User(row),pg_token:token});
  return Request(row.provider,'/v1/payments/confirm',{paymentKey:token,orderId:row.id,amount:row.amount},row.id);
 }
 function Verify(row,result){
  if(row.provider==='KAKAOPAY'){
   if(result.cid!==getConfig().kakaoCid||result.partner_order_id!==row.id||result.partner_user_id!==User(row)||result.tid!==row.providerId||result.amount?.total!==row.amount)s.Fail('PAYMENT_RECEIPT_INVALID');
   if(result.status!=='SUCCESS_PAYMENT')s.Fail('PAYMENT_NOT_APPROVED');
   return {providerId:result.tid,approvedAt:Date.parse(result.approved_at)||Date.now()};
  }
  if(result.orderId!==row.id||result.currency!=='KRW'||result.totalAmount!==row.amount||typeof result.paymentKey!=='string'||!result.paymentKey||result.paymentKey.length>200||(row.providerId&&row.providerId!==result.paymentKey))s.Fail('PAYMENT_RECEIPT_INVALID');
  if(result.status!=='DONE')s.Fail('PAYMENT_NOT_APPROVED');
  return {providerId:result.paymentKey,approvedAt:Date.parse(result.approvedAt)||Date.now()};
 }
 function Redirect(value){let u;try{u=new URL(value);}catch(_){s.Fail('PAYMENT_PROVIDER_INVALID');}
  if(u.protocol!=='https:'||u.username||u.password||u.port||!(u.hostname==='kakaopay.com'||u.hostname.endsWith('.kakaopay.com')))s.Fail('PAYMENT_PROVIDER_INVALID');return u.href;
 }
 return {Prepare,Query,Approve,Verify,Redirect};
}
module.exports={Config,Ready,Client};
