'use strict';
const PREFIX='/api/diagnostic-capture/',MAX_STATUS_ACTIVE=16;
const windows=new Map();let statusActive=0,total={at:0,count:0};
function ErrorCode(code,status){return Object.assign(Error(code),{desktopError:true,status});}
function Headers(res){res.setHeader('Cache-Control','private, no-store');res.setHeader('Pragma','no-cache');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');}
function Reply(res,status,value){Headers(res);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));}
function Rate(token){
 const now=require('node:perf_hooks').performance.now();
 if(now<total.at||now-total.at>=60000)total={at:now,count:0};
 if(++total.count>2000)throw ErrorCode('CAPTURE_BUSY',429);
 for(const [id,row]of windows)if(now<row.at||now-row.at>=60000)windows.delete(id);
 const key=require('node:crypto').createHash('sha256').update(token).digest('hex'),row=windows.get(key)||{at:now,count:0};
 if(++row.count>30)throw ErrorCode('CAPTURE_BUSY',429);
 if(!windows.has(key)&&windows.size>=2048)windows.delete(windows.keys().next().value);windows.set(key,row);
}
function Read(req,maxBytes,timeoutMs){return new Promise((resolve,reject)=>{
 let size=0,done=false;const chunks=[];
 const timer=setTimeout(()=>finish(ErrorCode('CAPTURE_REQUEST_TIMEOUT',408)),timeoutMs);timer.unref?.();
 const clean=()=>{clearTimeout(timer);req.removeListener('data',data);req.removeListener('end',end);req.removeListener('error',error);req.removeListener('aborted',abort);};
 const finish=(e)=>{if(done)return;done=true;clean();if(e){for(const b of chunks)b.fill(0);req.pause();reject(e);}else{const out=Buffer.concat(chunks);for(const b of chunks)b.fill(0);resolve(out);}};
 const data=chunk=>{if(!Buffer.isBuffer(chunk))chunk=Buffer.from(chunk);size+=chunk.length;if(size>maxBytes){chunk.fill(0);finish(ErrorCode('CAPTURE_PAYLOAD_TOO_LARGE',413));return;}chunks.push(chunk);};
 const end=()=>finish(),error=()=>finish(ErrorCode('CAPTURE_REQUEST_ABORTED',400)),abort=error;
 req.on('data',data);req.once('end',end);req.once('error',error);req.once('aborted',abort);
});}
async function Handle(req,res,url){
 const pathname=url.pathname;if(!pathname.startsWith(PREFIX))return false;
 const service=require('../../services/diagnostics/peace.support-captures');let ticket,bytes,statusSlot=false;
 try{
  if(req.method!=='POST'||![PREFIX+'status',PREFIX+'upload'].includes(pathname))throw ErrorCode('CAPTURE_NOT_AVAILABLE',404);
  require('../../services/operations/peace.registration-reset').AssertAvailable();
  if(!require('../authentication/peace.web-auth').IsHttps(req))throw ErrorCode('CAPTURE_HTTPS_REQUIRED',403);
  if([...url.searchParams].length||req.headers.range)throw ErrorCode('CAPTURE_INPUT_INVALID',400);
  let origin;try{origin=new URL(String(req.headers.origin||''));}catch(_){throw ErrorCode('CAPTURE_ORIGIN_INVALID',403);}
  if(origin.protocol!=='https:'||origin.host!==req.headers.host||origin.origin!==req.headers.origin||req.headers['sec-fetch-site']==='cross-site')throw ErrorCode('CAPTURE_ORIGIN_INVALID',403);
  const authorization=req.headers.authorization;if(typeof authorization!=='string'||!/^Bearer [A-F0-9]{24}\.[a-f0-9]{64}$/.test(authorization))throw ErrorCode('CAPTURE_NOT_AVAILABLE',403);
  const token=authorization.slice(7);Rate(token);
  if(pathname===PREFIX+'status'){
   service.Status(token);if(statusActive>=MAX_STATUS_ACTIVE)throw ErrorCode('CAPTURE_BUSY',429);statusActive++;statusSlot=true;
   if(req.headers['content-type']!=='application/json')throw ErrorCode('CAPTURE_INPUT_INVALID',400);
   bytes=await Read(req,256,5000);let body;try{body=require('../../services/protocol/peace.strict-json').Parse(bytes,{maxBytes:256,maxNodes:4});}catch(_){throw ErrorCode('CAPTURE_INPUT_INVALID',400);}
   if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).length)throw ErrorCode('CAPTURE_INPUT_INVALID',400);
   Reply(res,200,{ok:true,...service.Status(token)});
  }else{
   if(req.headers['content-type']!=='image/png'||req.headers['x-diagnostic-consent']!=='1')throw ErrorCode('CAPTURE_CONSENT_REQUIRED',400);
   if(req.headers['content-length']!==undefined&&(!/^[1-9][0-9]{0,7}$/.test(req.headers['content-length'])||Number(req.headers['content-length'])>service.LIMITS.maxPngBytes))throw ErrorCode('CAPTURE_PAYLOAD_TOO_LARGE',413);
   ticket=service.BeginUpload(token,req.headers['x-diagnostic-request']);
   bytes=await Read(req,service.LIMITS.maxPngBytes,15000);
   const result=await service.Upload(ticket,bytes);Reply(res,200,{ok:true,...result});
  }
 }catch(e){
  const safe=e.desktopError&&/^(CAPTURE|REGISTRATION_RESET)_[A-Z_]+$/.test(e.message)?e.message:'CAPTURE_OPERATION_FAILED';
  if(!res.headersSent&&!res.destroyed){res.setHeader('Connection','close');Reply(res,e.desktopError?e.status:503,{ok:false,error:safe});}
  // A rejected upload must not drain an unbounded request body in background.
  if(!req.complete)res.once('finish',()=>req.destroy());
 }finally{bytes?.fill(0);if(ticket)service.EndUpload(ticket);if(statusSlot)statusActive--;}
 return true;
}
module.exports={Handle};
