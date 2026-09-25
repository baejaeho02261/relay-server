'use strict';
const crypto=require('node:crypto'),payments=require('./payments'),engine=payments.Engine();
const escape=v=>String(v).replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
function Html(res,status,title,message,extra='',nonce=''){
 res.writeHead(status,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
 'Content-Security-Policy':"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"' https://js.tosspayments.com; connect-src https://*.tosspayments.com https://*.toss.im; frame-src https://*.tosspayments.com https://*.toss.im; img-src data: https:; form-action https://*.tosspayments.com https://*.toss.im"});
 res.end('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+escape(title)+'</title><style>html{color-scheme:dark}body{margin:0;background:#000;color:#fff;font:16px system-ui;min-height:100dvh;display:grid;place-items:center}main{width:min(440px,calc(100% - 48px));padding:32px 0}small{color:#aaa;letter-spacing:.16em}h1{font-size:28px;letter-spacing:-.04em;margin:18px 0}p{color:#bbb;line-height:1.7;white-space:pre-line}button{width:100%;min-height:54px;border:0;border-radius:14px;background:#3182f6;color:#fff;font:700 16px system-ui;margin-top:22px;cursor:pointer}button:active{opacity:.76;transform:scale(.99)}button:disabled{opacity:.5}strong{font-size:30px}</style><main><small>MOAPLAY · PAYMENT</small><h1>'+escape(title)+'</h1><p>'+escape(message)+'</p>'+extra+'</main></html>');
}
function Checkout(res,data){
 const nonce=crypto.randomBytes(18).toString('base64'),safe=JSON.stringify(data).replace(/</g,'\\u003c');
 Html(res,200,'토스페이로 충전',data.mode==='test'?'테스트 결제입니다. 실제 금액은 결제되지 않으며 테스트 서버의 잔액에만 반영됩니다.':'결제를 완료하면 MoaPlay 충전 잔액에 자동으로 반영됩니다.','<strong>'+data.amount.toLocaleString('ko-KR')+'원</strong><button id="pay">토스페이로 결제</button><p id="message" role="status"></p><script nonce="'+nonce+'" src="https://js.tosspayments.com/v2/standard"></script><script nonce="'+nonce+'">const d='+safe+';const b=document.getElementById("pay");b.addEventListener("click",async()=>{b.disabled=true;try{await TossPayments(d.clientKey).payment({customerKey:d.customerKey}).requestPayment({method:"CARD",amount:{currency:"KRW",value:d.amount},orderId:d.id,orderName:"MoaPlay 잔액 충전",successUrl:d.successUrl,failUrl:d.failUrl,windowTarget:"self",card:{flowMode:"DIRECT",easyPay:"TOSSPAY"}});}catch(e){const code=String(e&&e.code||"");document.getElementById("message").textContent=code==="USER_CANCEL"?"결제가 취소됐어요. 원하면 다시 결제할 수 있어요.":/KEY|UNAUTHORIZED|NOT_SUPPORTED/.test(code)?"가맹점 결제 연결을 확인해야 합니다. MoaPlay 고객센터에 문의해주세요.":typeof TossPayments!=="function"?"결제창을 불러오지 못했어요. 인터넷 연결을 확인하고 이 페이지를 새로고침해주세요.":"결제를 완료하지 못했어요. 다시 시도해주세요.";b.disabled=false;}});</script>',nonce);
}
async function JsonBody(req){let size=0;const parts=[];for await(const chunk of req){size+=chunk.length;if(size>16384)throw Error('INPUT_INVALID');parts.push(chunk);}return JSON.parse(Buffer.concat(parts).toString('utf8'));}
const webhookRate=new Map();
async function Webhook(req,res,name){
 if(req.method!=='POST'){res.writeHead(405);res.end();return;}
 // Hooks are untrusted delivery hints. Always fetch the matching order using
 // server credentials; never credit an amount/status supplied in a webhook.
 const body=await JsonBody(req),data=body.data||body;
 let id=String(data.orderId||data.partner_order_id||'');
 if(name==='kakao'&&!id&&typeof data.tid==='string')id=Object.values(payments.orders()).find(x=>x.provider==='KAKAOPAY'&&x.providerId===data.tid)?.id||'';
 const row=payments.orders()[id],provider=name==='kakao'?'KAKAOPAY':'TOSSPAY';
 if(!row||row.provider!==provider||!['READY','APPROVING'].includes(row.status)){res.writeHead(204);res.end();return;}
 const now=Date.now();if(now-(webhookRate.get(id)||0)<5000){res.writeHead(429,{'Retry-After':'5'});res.end();return;}
 webhookRate.set(id,now);if(webhookRate.size>5000)for(const[key,at]of webhookRate)if(now-at>60000)webhookRate.delete(key);
 try{await engine.Reconcile(id);res.writeHead(204);res.end();}catch(_){res.writeHead(503,{'Retry-After':'30'});res.end();}
}
async function Handle(req,res,url){
 if(!url.pathname.startsWith('/pay/'))return false;
 if(!require('../haCoordinator').CanAcceptTraffic()){Html(res,503,'잠시 후 다시 시도해주세요','결제 서버 연결을 확인하고 있습니다.');return true;}
 try{
  const parts=url.pathname.split('/').filter(Boolean);
  if(parts[1]==='webhook'&&['kakao','toss'].includes(parts[2])){await Webhook(req,res,parts[2]);return true;}
  if(req.method!=='GET'){res.writeHead(405);res.end();return true;}
  if(parts[1]==='start'&&parts.length===4){const agent=String(req.headers?.['user-agent']||''),mobile=/Android|iPhone|iPad|iPod|Mobile/i.test(agent)||req.headers?.['sec-ch-ua-mobile']==='?1';const data=await engine.Launch(parts[2],parts[3],{mobile});if(data.redirect){res.writeHead(303,{Location:data.redirect,'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.end();}else Checkout(res,data);return true;}
  if(parts[1]==='return'&&parts.length===5){
   if(parts[4]==='complete'){const result=await engine.Complete(parts[2],parts[3],Object.fromEntries(url.searchParams));Html(res,200,'충전이 완료됐어요',result.amount.toLocaleString('ko-KR')+'원이 충전되었습니다.\nMoaPlay로 돌아가 잔액을 확인해주세요.');}
   else if(['cancel','fail'].includes(parts[4])){const result=engine.Cancel(parts[2],parts[3]);if(result.status==='PAID')Html(res,200,'이미 충전이 완료됐어요',result.amount.toLocaleString('ko-KR')+'원이 충전되었습니다. MoaPlay에서 잔액을 확인해주세요.');else if(result.status==='APPROVING')Html(res,200,'결제 결과를 확인하고 있어요','승인 요청이 진행 중입니다. 결제를 다시 시작하지 말고 MoaPlay에서 잠시 후 잔액을 확인해주세요.');else Html(res,200,'결제가 취소됐어요','충전 잔액은 변경되지 않았습니다. MoaPlay에서 다시 시도해주세요.');}
   else{res.writeHead(404);res.end();}return true;
  }
  res.writeHead(404);res.end();return true;
 }catch(e){const waiting=['PAYMENT_PROVIDER_WAIT','STORAGE_SAVE_FAILED'].includes(e.message),unavailable=['PAYMENT_UNAVAILABLE','PAYMENT_PROVIDER_CONFIG'].includes(e.message);Html(res,waiting||unavailable?503:400,waiting?'결제 결과를 확인하고 있어요':'결제를 진행할 수 없어요',waiting?'승인 결과 확인이 지연되고 있습니다. 결제를 다시 시작하지 말고 잠시 후 이 페이지를 새로고침해주세요.':unavailable?'결제 서비스의 가맹점 연결 설정을 확인해야 합니다. MoaPlay 고객센터에 문의해주세요.':'결제 정보 또는 유효 시간을 확인해주세요. MoaPlay에서 새 충전을 시작할 수 있습니다.');return true;}
}
module.exports={Handle};
