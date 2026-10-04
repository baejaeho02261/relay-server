'use strict';
const overlay=require('../../services/desktopOverlay');
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
  if(pathname===prefix&&method==='GET'){Json(res,200,{ok:true,...overlay.Overview()});return true;}
  if(pathname===prefix&&method==='POST'){Json(res,200,{ok:true,...overlay.Update(body,actor)});return true;}
  if(pathname===prefix+'/module.dat'&&['GET','HEAD'].includes(method)){
   const bytes=overlay.ModuleBytes();res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':bytes.length,'Content-Disposition':'attachment; filename="overlay.dat"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});res.end(method==='HEAD'?undefined:bytes);return true;
  }
  const revoke=/^\/api\/desktop\/bootstrap\/overlay\/sessions\/([A-F0-9]{24})\/revoke$/.exec(pathname);
  if(revoke&&method==='POST'){Json(res,200,{ok:true,session:overlay.Revoke(revoke[1],body,actor)});return true;}
  ApiError(res,404,'NOT_FOUND');
 }catch(error){const code=error.desktopError?error.message:'OVERLAY_STORAGE_INVALID';Json(res,error.desktopError?error.status:503,{ok:false,error:code,reason:code,message:overlay.messages[code]||'오버레이 요청을 처리하지 못했습니다.'});}
 return true;
}
module.exports={Handle};
