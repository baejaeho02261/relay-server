'use strict';
const overlay=require('../../services/desktopOverlay');
const plugin=require('../../services/desktopOverlayPlugin');
let uploadPending=false;
const {RequireAdmin,Json,ApiError}=require('../apiContext');
async function Handle({method,pathname,body,req,res,session}){
 const prefix='/api/desktop/bootstrap/overlay';
 if(pathname!==prefix&&!pathname.startsWith(prefix+'/'))return false;
 if(!RequireAdmin(res,session))return true;
 const check=require('../../services/desktopAdminGuard').CheckSession(session,pathname);
 if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
 if(!['GET','HEAD'].includes(method)){
  if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
 }
 const actor=String(session.role)+':'+String(session.id);
 try{
  if(pathname===prefix+'/plugins'&&method==='GET'){Json(res,200,{ok:true,...plugin.Overview()});return true;}
  if(pathname===prefix+'/plugins/activate'&&method==='POST'){Json(res,200,{ok:true,...plugin.Activate(body,actor)});return true;}
  if(pathname===prefix&&method==='GET'){Json(res,200,{ok:true,...overlay.Overview()});return true;}
  if(pathname===prefix&&method==='POST'){Json(res,200,{ok:true,...overlay.Update(body,actor)});return true;}
  if(pathname===prefix+'/module.dat'&&['GET','HEAD'].includes(method)){
   const bytes=overlay.ModuleBytes();res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':bytes.length,'Content-Disposition':'attachment; filename="overlay.dat"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});res.end(method==='HEAD'?undefined:bytes);return true;
  }
  const revoke=/^\/api\/desktop\/bootstrap\/overlay\/sessions\/([A-F0-9]{24})\/revoke$/.exec(pathname);
  if(revoke&&method==='POST'){Json(res,200,{ok:true,session:overlay.Revoke(revoke[1],body,actor)});return true;}
  ApiError(res,404,'NOT_FOUND');
 }catch(error){const code=error.desktopError?error.message:'OVERLAY_STORAGE_INVALID';Json(res,error.desktopError?error.status:503,{ok:false,error:code,reason:code,problem:require('../../services/desktopOperationsErrors').Explain(code),message:plugin.messages[code]||overlay.messages[code]||'오버레이 요청을 처리하지 못했습니다.'});}
 return true;
}
async function HandleUpload({method,pathname,url,req,res,session}){
 if(pathname!=='/api/desktop/bootstrap/overlay/plugins'||method==='GET')return false;
 if(!RequireAdmin(res,session))return true;
 if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
 if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
 if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
 const guard=require('../../services/desktopAdminGuard').CheckSession(session,pathname);if(!guard.ok){ApiError(res,guard.status||403,guard.reason);return true;}
 if(uploadPending){ApiError(res,429,'BOOTSTRAP_UPLOAD_BUSY');return true;}
 try{
  if(!/^application\/octet-stream(?:\s*;|$)/i.test(req.headers['content-type']||'')||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')throw Error('OVERLAY_PLUGIN_INPUT_INVALID');
  const length=Number(req.headers['content-length']||0),version=url.searchParams.get('version'),name=url.searchParams.get('fileName')||'';
  if(!Number.isSafeInteger(length)||length<0||length>plugin.MAX_BYTES||!/^.{1,180}\.bin$/i.test(name)||/[\x00-\x1f\x7f/\\]/.test(name))throw Error(length>plugin.MAX_BYTES?'OVERLAY_PLUGIN_TOO_LARGE':'OVERLAY_PLUGIN_INPUT_INVALID');
  uploadPending=true;
  const bytes=await new Promise((resolve,reject)=>{
   let done=false,size=0;const chunks=[],timer=setTimeout(()=>finish(Error('BOOTSTRAP_UPLOAD_TIMEOUT')),120000);timer.unref();
   function finish(error){if(done)return;done=true;clearTimeout(timer);if(error){chunks.length=0;req.resume();reject(error);}else resolve(Buffer.concat(chunks,size));}
   req.on('data',chunk=>{if(done)return;size+=chunk.length;if(size>plugin.MAX_BYTES)return finish(Error('OVERLAY_PLUGIN_TOO_LARGE'));chunks.push(chunk);});req.once('end',()=>finish());req.once('error',finish);req.once('aborted',()=>finish(Error('BOOTSTRAP_UPLOAD_ABORTED')));
  });
  // Upload completion never revives a logged-out or replaced browser session.
  if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  const approval=req.headers['x-game-release-key-id']||req.headers['x-game-release-signature']?{keyId:req.headers['x-game-release-key-id'],signature:req.headers['x-game-release-signature']}:undefined;
  const artifact=plugin.Stage(version,bytes,approval,String(session.role)+':'+String(session.id));Json(res,200,{ok:true,artifact,revision:plugin.Overview().revision,activeUnchanged:true});
 }catch(error){const code=error.desktopError?error.message:plugin.messages[error.message]?error.message:'OVERLAY_PLUGIN_INPUT_INVALID';Json(res,error.desktopError?error.status:code==='OVERLAY_PLUGIN_TOO_LARGE'?413:400,{ok:false,error:code,reason:code,problem:require('../../services/desktopOperationsErrors').Explain(code),message:plugin.messages[code]||'오버레이 플러그인을 게시하지 못했습니다.'});}
 finally{uploadPending=false;}
 return true;
}
module.exports={Handle,HandleUpload};
