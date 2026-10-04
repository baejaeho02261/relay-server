'use strict';
// This namespace is administrator-only. The native A/B never call it.
const {Json,ApiError,RequireAdmin}=require('../apiContext');
const workspace=require('../../services/desktopWorkspace');
const prefix='/api/desktop/workspace';
async function Handle({method,pathname,url,body,req,res,session}){
 if(pathname!==prefix&&!pathname.startsWith(prefix+'/'))return false;
 if(!RequireAdmin(res,session))return true;
 const check=require('../../services/desktopAdminGuard').CheckSession(session,pathname);if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
 if(!['GET','HEAD'].includes(method)){
  if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
 }
 const actor='ADMIN:'+session.id;
 try{
  const detail=/^\/api\/desktop\/workspace\/licenses\/((?:DL-)?[A-F0-9]{24})(?:\/(metadata))?$/.exec(pathname);
  const job=/^\/api\/desktop\/workspace\/jobs\/([a-f0-9]{32})\/(retry|cancel|export)$/.exec(pathname);
  let data;
  if(method==='GET'&&pathname===prefix+'/licenses')data=workspace.Query(Object.fromEntries(url.searchParams));
  else if(method==='GET'&&pathname===prefix+'/summary')data=workspace.Summary();
  else if(method==='GET'&&pathname===prefix+'/jobs')data=workspace.Jobs();
  else if(method==='GET'&&pathname===prefix+'/storage'){const s=require('../../services/desktopStorageSpace');if(!s.Snapshot().asOf)s.Scan().catch(()=>{});data=s.Snapshot();}
  else if(method==='POST'&&pathname===prefix+'/deployment-note')data=workspace.SaveReleaseNote(body,actor);
  else if(method==='POST'&&pathname===prefix+'/storage/scan'){require('../../services/desktopStorageSpace').Scan().catch(()=>{});data={scheduled:true};}
  else if(method==='POST'&&pathname===prefix+'/jobs/preview')data=await workspace.Preview(body,session);
  else if(method==='POST'&&pathname===prefix+'/jobs')data=workspace.Submit(body,session);
  else if(detail&&method==='GET'&&!detail[2])data=workspace.Detail(detail[1]);
  else if(detail&&method==='POST'&&detail[2]==='metadata')data=workspace.SaveMetadata(detail[1],body,actor);
  else if(job&&method==='POST'&&job[2]==='retry')data=workspace.Retry(job[1],actor);
  else if(job&&method==='POST'&&job[2]==='cancel')data=workspace.Cancel(job[1],actor);
  else if(job&&method==='GET'&&job[2]==='export'){
   const text=JSON.stringify(workspace.Export(job[1]),null,2);res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Length':Buffer.byteLength(text),'Content-Disposition':'attachment; filename="licenses-'+job[1]+'.json"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(text);return true;
  }else{ApiError(res,404,'NOT_FOUND');return true;}
  Json(res,200,{ok:true,...data});
 }catch(e){const code=e.desktopError?e.message:'WORKSPACE_REQUEST_FAILED';ApiError(res,e.desktopError?e.status:500,code);}
 return true;
}
module.exports={Handle};
