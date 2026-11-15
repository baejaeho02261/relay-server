'use strict';
const PREFIX='/api/desktop/bootstrap/security-center';
async function Handle({method,pathname,body,req,res,session,desktopAuthorization}){
 if(pathname!==PREFIX&&!pathname.startsWith(PREFIX+'/'))return false;const {Json,ApiError}=require("../../http/peace.api-context"),auth=require("../../authentication/peace.web-auth"),guard=require("../../../services/authentication/peace.desktop-admin-guard"),center=require("../../../services/security/peace.server-security-center");
 if(!session||session.role!=='admin'||!auth.IsSessionActive(session)){ApiError(res,403,'ADMIN_REQUIRED');return true;}
 try{
  if(method==='GET'){if(pathname===PREFIX)Json(res,200,{ok:true,...center.Status()});else{const m=/^\/(parser-tests|artifact-scan)\/([a-f0-9]{32})$/.exec(pathname.slice(PREFIX.length));if(!m){ApiError(res,404,'NOT_FOUND');return true;}Json(res,200,{ok:true,job:center.Get(m[1],m[2])});}return true;}
  if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  if(!auth.ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
  if(!guard.ConsumeSingleAuthorization(desktopAuthorization?.ticket,session,method,pathname,body)){ApiError(res,428,'ADMIN_ACTION_REQUIRED');return true;}
  let result;if(pathname===PREFIX+'/parser-tests')result=center.BeginFuzz(body,session.id);else if(pathname===PREFIX+'/artifact-scan')result=center.BeginScan(body,session.id);else if(pathname===PREFIX+'/respond')result=require("../../../services/security/peace.security-detection").Respond(body,session.id);else{ApiError(res,404,'NOT_FOUND');return true;}
  Json(res,pathname.endsWith('/respond')?200:202,{ok:true,result});
 }catch(e){ApiError(res,e.desktopError?e.status:400,/^[A-Z][A-Z0-9_]{1,79}$/.test(e.message)?e.message:'SECURITY_CENTER_FAILED');}return true;
}
module.exports={Handle,PREFIX};
