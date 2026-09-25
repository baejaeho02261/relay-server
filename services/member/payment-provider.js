'use strict';
// The only outbound payment destinations are these fixed provider HTTPS hosts.
const s=require('./store');
const names={KAKAOPAY:'카카오페이',TOSSPAY:'토스페이'};
const credentialFields={KAKAOPAY:{KAKAOPAY_CID:'kakaoCid',KAKAOPAY_SECRET_KEY:'kakaoSecret'},TOSSPAY:{TOSSPAYMENTS_CLIENT_KEY:'tossClient',TOSSPAYMENTS_SECRET_KEY:'tossSecret'}};
function Config(env=process.env){
 let origin='';const originValue=String(env.PAYMENT_PUBLIC_ORIGIN||'').trim();
 try{const u=new URL(originValue);if(u.protocol==='https:'&&!u.username&&!u.password&&u.pathname==='/'&&!u.search&&!u.hash)origin=u.origin;}catch(_){}
 return {origin,originConfigured:!!originValue,enabled:env.PAYMENT_ENABLED==='true',production:env.NODE_ENV==='production',allowTestMode:env.NODE_ENV==='test'||env.NODE_ENV!=='production'&&env.PAYMENT_ALLOW_TEST_MODE==='true',kakaoCid:String(env.KAKAOPAY_CID||'').trim(),kakaoSecret:String(env.KAKAOPAY_SECRET_KEY||'').trim(),tossClient:String(env.TOSSPAYMENTS_CLIENT_KEY||'').trim(),tossSecret:String(env.TOSSPAYMENTS_SECRET_KEY||'').trim()};
}
function Status(id,c=Config()){
 const fields=Object.hasOwn(credentialFields,id)?credentialFields[id]:null,issues=[],missing=[],credentials={};
 if(!fields)return {id,name:'',enabled:false,code:'PAYMENT_PROVIDER_INVALID',message:'지원하지 않는 결제수단입니다.',mode:'unknown',missing,issues,credentials};
 const add=(code,message,fields)=>issues.push({code,message,fields});
 if(!c.enabled)add('PAYMENT_DISABLED','서버에서 PAYMENT_ENABLED=true를 설정해야 합니다.',['PAYMENT_ENABLED']);
 if(!c.origin){const absent=!c.originConfigured;add(absent?'PAYMENT_ORIGIN_MISSING':'PAYMENT_ORIGIN_INVALID',absent?'PAYMENT_PUBLIC_ORIGIN을 공개 HTTPS 서버 주소로 설정해야 합니다.':'PAYMENT_PUBLIC_ORIGIN은 경로·쿼리·자격증명 없는 HTTPS 주소여야 합니다.',['PAYMENT_PUBLIC_ORIGIN']);if(absent)missing.push('PAYMENT_PUBLIC_ORIGIN');}
 for(const[field,key]of Object.entries(fields)){credentials[field]=!!c[key];if(!c[key])missing.push(field);else if(/\s/.test(c[key]))add('PAYMENT_CREDENTIALS_INVALID',field+' 값에 공백이 포함되어 있습니다.',[field]);}
 const absent=Object.keys(fields).filter(field=>!credentials[field]);if(absent.length)add('PAYMENT_CREDENTIALS_MISSING','가맹점 결제 자격증명이 설정되지 않았습니다.',absent);
 let mode='unknown';
 if(id==='KAKAOPAY'&&c.kakaoCid&&c.kakaoSecret)mode=/^TC/.test(c.kakaoCid)||/^DEV/i.test(c.kakaoSecret)?'test':'live';
 if(id==='TOSSPAY'){
  const client=/^(test|live)_ck_[A-Za-z0-9_]+$/.exec(c.tossClient),secret=/^(test|live)_sk_[A-Za-z0-9_]+$/.exec(c.tossSecret);
  if(c.tossClient&&!client)add('PAYMENT_CREDENTIALS_INVALID','토스페이먼츠 API 개별 연동 클라이언트 키(test_ck_ 또는 live_ck_)가 필요합니다. 결제위젯 키와 로그인 키는 사용할 수 없습니다.',['TOSSPAYMENTS_CLIENT_KEY']);
  if(c.tossSecret&&!secret)add('PAYMENT_CREDENTIALS_INVALID','토스페이먼츠 API 개별 연동 시크릿 키(test_sk_ 또는 live_sk_)가 필요합니다.',['TOSSPAYMENTS_SECRET_KEY']);
  if(client&&secret){if(client[1]!==secret[1])add('PAYMENT_KEY_MODE_MISMATCH','토스페이먼츠 클라이언트 키와 시크릿 키의 테스트/운영 모드가 다릅니다.',Object.keys(fields));else mode=client[1];}
 }
 if(!c.allowTestMode&&mode==='test')add('PAYMENT_TEST_MODE_BLOCKED','테스트 결제는 NODE_ENV=test 또는 비운영 서버의 PAYMENT_ALLOW_TEST_MODE=true에서만 허용됩니다. 운영 서버에는 승인된 운영 가맹점 키가 필요합니다.',[...Object.keys(fields),'NODE_ENV','PAYMENT_ALLOW_TEST_MODE']);
 const code=issues[0]?.code||'READY',enabled=!issues.length;
 let message=enabled?(mode==='test'?'테스트 결제입니다. 실제 금액은 결제되지 않습니다.':'결제 후 충전 잔액에 반영됩니다.'):
  code==='PAYMENT_DISABLED'?'현재 결제 충전이 중지되어 있습니다. 고객센터에 문의해주세요.':
  code==='PAYMENT_TEST_MODE_BLOCKED'?'운영 결제 연결이 필요합니다. 테스트 결제로는 충전할 수 없습니다.':
  code.startsWith('PAYMENT_ORIGIN')?'결제 결과를 받을 서버 주소 설정이 필요합니다. 고객센터에 문의해주세요.':names[id]+' 가맹점 연결 설정이 필요합니다. 고객센터에 문의해주세요.';
 return {id,name:names[id],enabled,code,message,mode,missing,issues,credentials};
}
function Ready(id,c=Config()){return Status(id,c).enabled;}
function Capabilities(c=Config()){return Object.keys(names).map(id=>{const{id:providerId,name,enabled,code,message,mode}=Status(id,c);return {id:providerId,name,enabled,code,message,mode};});}
function AdminStatus(c=Config()){return {enabled:c.enabled,origin:c.origin,originValid:!!c.origin,validationScope:'LOCAL_CONFIGURATION',note:'설정 여부와 키 형식만 확인합니다. 가맹점 계약·도메인 등록·키 유효성은 결제사에서 확인해야 합니다.',providers:Object.keys(names).map(id=>Status(id,c)),checkedAt:Date.now()};}
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
  if(!response.ok){const code=String(result?.code||result?.error_code||'').slice(0,80),configuration=[401,403].includes(response.status)||['INVALID_API_KEY','INVALID_CLIENT_KEY','UNAUTHORIZED_KEY','INCORRECT_BASIC_AUTH_FORMAT'].includes(code);const e=Error(configuration?'PAYMENT_PROVIDER_CONFIG':'PAYMENT_PROVIDER_WAIT');e.memberError=true;e.providerCode=code;throw e;}
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
  if(!getConfig().allowTestMode&&row.paymentMode==='test')s.Fail('PAYMENT_UNAVAILABLE');
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
  // The provider documents online-pay.kakao.com even though its API is on
  // open-api.kakaopay.com. Do not accept arbitrary kakao.com subdomains.
  const checkoutHost=u.hostname==='online-pay.kakao.com'||u.hostname==='mockup-pg-web.kakao.com'||u.hostname==='kakaopay.com'||u.hostname.endsWith('.kakaopay.com');
  if(u.protocol!=='https:'||u.username||u.password||u.port||!checkoutHost)s.Fail('PAYMENT_PROVIDER_INVALID');return u.href;
 }
 return {Prepare,Query,Approve,Verify,Redirect};
}
module.exports={Config,Ready,Status,Capabilities,AdminStatus,Client};
