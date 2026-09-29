'use strict';
const desktop=require('../services/desktopLicenses');
const buckets=new Map(),MAX_BODY=12288;
function Json(res,status,value){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});res.end(JSON.stringify(value));}
function TrustedProxy(){return process.env.DESKTOP_TRUST_PROXY==='1'||!!process.env.RAILWAY_PROJECT_ID;}
function Https(req){return !!req.socket?.encrypted||TrustedProxy()&&req.headers['x-forwarded-proto']==='https';}
function Loopback(req){return ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.socket?.remoteAddress);}
function Rate(key,limit){const at=Date.now();if(buckets.size>5000)for(const [key,row]of buckets)if(row.until<=at)buckets.delete(key);if(buckets.size>10000)desktop.Fail('DESKTOP_RATE_LIMIT',429);let b=buckets.get(key);if(!b||b.until<=at){b={count:0,until:at+60000};buckets.set(key,b);}if(++b.count>limit)desktop.Fail('DESKTOP_RATE_LIMIT',429);}
function Read(req){
 return new Promise((resolve,reject)=>{
  let size=0,done=false;const chunks=[],timer=setTimeout(()=>end(Error('BODY_TIMEOUT')),10000);timer.unref?.();
  function end(error){if(done)return;done=true;clearTimeout(timer);if(error){req.resume();reject(error);}else try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch(error){reject(error);}}
  req.on('data',chunk=>{if(done)return;size+=chunk.length;if(size>MAX_BODY)return end(Error('BODY_LIMIT'));chunks.push(chunk);});req.once('end',()=>end());req.once('error',end);req.once('aborted',()=>end(Error('BODY_ABORTED')));
 });
}
async function Handle(req,res,url){
 const pathname=(url||new URL(req.url,'http://localhost')).pathname;if(!['/api/desktop/challenge','/api/desktop/execute'].includes(pathname))return false;
 try{
  if(req.method!=='POST'){Json(res,405,{ok:false,error:'METHOD_NOT_ALLOWED',message:'POST 요청을 사용해 주세요.'});return true;}
  if(!Https(req)&&!(process.env.DESKTOP_ALLOW_HTTP_LOOPBACK==='1'&&Loopback(req)))desktop.Fail('HTTPS_REQUIRED',403);
  // These signed native endpoints never consume browser cookies or CORS sessions.
  if(req.headers.origin||String(req.headers['sec-fetch-site']||'')==='cross-site')desktop.Fail('DESKTOP_BROWSER_FORBIDDEN',403);
  if(!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type']||'')||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')desktop.Fail('INPUT_INVALID');
  if(Number(req.headers['content-length']||0)>MAX_BODY)desktop.Fail('INPUT_INVALID',413);
  const forwarded=TrustedProxy()?String(req.headers['x-forwarded-for']||'').split(',')[0].trim():'';
  Rate('IP:'+String(forwarded||req.socket?.remoteAddress||'').slice(0,100),pathname.endsWith('challenge')?60:180);
  let body;try{body=await Read(req);}catch(_){desktop.Fail('INPUT_INVALID');}
  if(body&&typeof body.deviceId==='string')Rate('DEVICE:'+body.deviceId.slice(0,100),pathname.endsWith('challenge')?20:60);
  const data=pathname.endsWith('challenge')?desktop.Challenge(body):desktop.Execute(body);Json(res,200,{ok:true,data});
 }catch(error){const code=error.desktopError?error.message:'INPUT_INVALID';Json(res,error.desktopError?error.status:400,{ok:false,error:code,reason:code,message:desktop.messages[code]||'요청을 처리하지 못했습니다.'});}
 return true;
}
module.exports={Handle};
