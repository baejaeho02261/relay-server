'use strict';
const PREFIX='/api/desktop/bootstrap/server-state';
async function Handle(ctx){
 const {method,pathname,req,res,session,body={},url}=ctx;if(pathname!==PREFIX&&!pathname.startsWith(PREFIX+'/'))return false;
 const {Json,ApiError,RequireAdmin}=require('../apiContext');if(!RequireAdmin(res,session))return true;
 try{
  const auth=require('../webAuth'),guard=require('../../services/desktopAdminGuard');
  const checked=guard.CheckSession(session,method==='GET'?'':pathname);if(!checked.ok){ApiError(res,checked.status,checked.reason);return true;}
  if(method!=='GET'){
   if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
   if(!auth.ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
   if(!auth.HasRecentAuthentication(session)){ApiError(res,428,'ADMIN_REAUTH_REQUIRED');return true;}
   if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
  }
  const actor='ADMIN:'+session.id;let result;
  if(method==='GET'&&pathname===PREFIX)result={...require('../../services/desktopRecovery').Status(),journal:require('../../services/desktopJournal').Status(),storage:require('../../services/desktopStorageMaintenance').Status()};
  else if(method==='GET'&&pathname===PREFIX+'/devices')result=require('../../services/desktopDeviceRegistry').List();
  else if(method==='GET'&&pathname===PREFIX+'/device-identity')result=require('../../services/desktopDeviceIdentity').List();
  else if(method==='POST'&&pathname===PREFIX+'/device-identity-policy')result=require('../../services/desktopDeviceIdentity').AdminPolicy(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/device-key-revoke')result=require('../../services/desktopDeviceIdentity').Revoke(body,actor);
  else if(method==='GET'&&pathname===PREFIX+'/orphans')result=require('../../services/desktopOrphanFiles').Scan({after:url?.searchParams.get('after')||''});
  else if(method==='GET'&&pathname===PREFIX+'/quarantine')result=require('../../services/desktopOrphanFiles').List();
  else if(method==='POST'&&pathname===PREFIX+'/recover-sessions')result=require('../../services/desktopRecovery').Apply(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/device-replacement')result=require('../../services/desktopDeviceRegistry').Replace(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/orphan-quarantine')result=require('../../services/desktopOrphanFiles').Quarantine(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/orphan-delete')result=require('../../services/desktopOrphanFiles').Delete(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/storage-maintenance')result=require('../../services/desktopStorageMaintenance').Apply(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/journal-checkpoint')result=require('../../services/desktopLicenses').CreateCheckpoint(body,actor);
  else{ApiError(res,404,'NOT_FOUND');return true;}
  if(method==='GET')require('../../services/desktopOperationAudit').RecordAccess('ADMIN_STORAGE_READ',actor);
  Json(res,200,{ok:true,...result});
 }catch(e){const code=e.desktopError?e.message:'SERVER_STATE_OPERATION_FAILED';ApiError(res,e.desktopError?e.status:503,code);}
 return true;
}
module.exports={Handle};
