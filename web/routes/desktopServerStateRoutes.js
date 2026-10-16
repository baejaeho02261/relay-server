'use strict';
const PREFIX='/api/desktop/bootstrap/server-state';
function Query(url,allowed){
 const params=url?.searchParams||new URLSearchParams(),out=Object.create(null);
 for(const [key,value]of params){
  if(!allowed.includes(key)||Object.hasOwn(out,key))throw Object.assign(new Error('SERVER_STATE_QUERY_INVALID'),{desktopError:true,status:400});
  out[key]=value;
 }
 return out;
}
function InvalidQuery(){throw Object.assign(new Error('SERVER_STATE_QUERY_INVALID'),{desktopError:true,status:400});}
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
  if(method==='GET'&&pathname===PREFIX)result={...require('../../services/desktopRecovery').Status(),journal:require('../../services/desktopJournal').Status(),storage:require('../../services/desktopStorageMaintenance').Status(),capabilities:require('../../services/desktopCapabilities').Status()};
  else if(method==='GET'&&pathname===PREFIX+'/capabilities')result=require('../../services/desktopCapabilities').Status();
  else if(method==='GET'&&pathname===PREFIX+'/verification-context'){
   const query=Query(url,['manifestId']);if(!/^[a-f0-9]{128}$/.test(query.manifestId||''))InvalidQuery();
   result=require('../../services/desktopManualVerification').Context(query.manifestId);
  }
  else if(method==='GET'&&pathname===PREFIX+'/lifecycle'){
   const query=Query(url,['flowId','licenseId','limit']);
   if(query.flowId!==undefined&&!/^(?:BF-)?[A-F0-9]{24}$/.test(query.flowId))InvalidQuery();
   if(query.licenseId!==undefined&&!/^(?:DL-)?[A-F0-9]{24}$/.test(query.licenseId))InvalidQuery();
   if(query.limit!==undefined&&!/^(?:[1-9]|[1-4][0-9]|50)$/.test(query.limit))InvalidQuery();
   result=require('../../services/desktopLifecycleTrace').Overview({...(query.flowId?{flowId:query.flowId}:{}),...(query.licenseId?{licenseId:query.licenseId}:{}),limit:query.limit?Number(query.limit):20});
  }
  else if(method==='GET'&&pathname===PREFIX+'/performance'){
   const query=Query(url,['resolution','limit']),resolution=query.resolution===undefined?'hour':query.resolution;
   if(!['hour','day'].includes(resolution))InvalidQuery();
   if(query.limit!==undefined&&(!/^[1-9][0-9]{0,2}$/.test(query.limit)||Number(query.limit)>(resolution==='hour'?720:365)))InvalidQuery();
   result=require('../../services/desktopPerformanceMetrics').Snapshot({resolution,limit:query.limit===undefined?(resolution==='hour'?24:30):Number(query.limit)});
  }
  else if(method==='POST'&&pathname===PREFIX+'/manual-verification')result=require('../../services/desktopManualVerification').Import(body,actor);
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
