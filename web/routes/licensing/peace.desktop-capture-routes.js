'use strict';
function Query(url,allowed=[]){const out={};for(const [key,value]of url?.searchParams||[]){if(!allowed.includes(key)||Object.hasOwn(out,key))throw Object.assign(Error('CAPTURE_INPUT_INVALID'),{desktopError:true,status:400});out[key]=value;}return out;}
async function Handle({method,pathname,url,req,res,session,body={}}){
 const match=/^\/api\/desktop\/members\/([A-F0-9]{24})\/captures(?:\/([A-F0-9]{24})\/(image|delete|revoke))?$/.exec(pathname);
 if(!match)return false;
 const {RequireAdmin,Json,ApiError}=require('../../http/peace.api-context');if(!RequireAdmin(res,session))return true;
 const auth=require('../../authentication/peace.web-auth'),guard=require('../../../services/authentication/peace.desktop-admin-guard');
 const checked=()=>{const status=guard.CheckSession(session,method==='GET'?'':pathname,method);if(!status.ok)throw Object.assign(Error(status.reason),{desktopError:true,status:status.status});};
 let image;
 try{
  checked();require('../../../services/operations/peace.registration-reset').AssertAvailable();
  if(!['GET','POST'].includes(method)){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  if(method==='POST'){
   if(!auth.ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
   if(!auth.HasRecentAuthentication(session)){ApiError(res,428,'ADMIN_REAUTH_REQUIRED');return true;}
   if(!require('../../../services/network/peace.ha-coordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
  }
  const service=require('../../../services/diagnostics/peace.support-captures'),audit=require('../../../services/storage/peace.desktop-operation-audit'),actor='ADMIN:'+session.id;let result;
  if(method==='GET'&&!match[2]){result=service.List(match[1],Query(url,['page','pageSize']));audit.RecordAccess('ADMIN_CAPTURE_LIST',actor,{subject:require('node:crypto').createHash('sha256').update(match[1]).digest('hex')});}
  else if(method==='GET'&&match[3]==='image'){
   Query(url);if(req.headers.range){ApiError(res,400,'CAPTURE_INPUT_INVALID');return true;}
   if(!auth.HasRecentAuthentication(session)){ApiError(res,428,'ADMIN_REAUTH_REQUIRED');return true;}
   image=service.Image(match[1],match[2]);checked();if(!auth.HasRecentAuthentication(session)){image.bytes.fill(0);ApiError(res,428,'ADMIN_REAUTH_REQUIRED');return true;}
   audit.RecordAccess('ADMIN_CAPTURE_IMAGE',actor,{subject:require('node:crypto').createHash('sha256').update(match[2]).digest('hex')});
   res.writeHead(200,{'Content-Type':'image/png','Content-Length':image.bytes.length,'Content-Disposition':'inline; filename="support-capture.png"','Cache-Control':'private, no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});
   await new Promise(resolve=>{let done=false;const finish=()=>{if(done)return;done=true;image.bytes.fill(0);resolve();};res.once('close',finish);res.end(image.bytes,finish);});return true;
  }else if(method==='POST'&&!match[2]){Query(url);result=service.Create(match[1],body,actor);}
  else if(method==='POST'&&['delete','revoke'].includes(match[3])){Query(url);result=service.Close(match[1],match[2],body,actor,match[3].toUpperCase());}
  else{ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  Json(res,200,{ok:true,...result});
 }catch(e){image?.bytes?.fill(0);if(!res.headersSent)ApiError(res,e.desktopError?e.status:503,e.desktopError?e.message:'CAPTURE_OPERATION_FAILED');}
 return true;
}
module.exports={Handle};
