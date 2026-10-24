'use strict';
const {RequireAdmin,Json,ApiError}=require("../../http/peace.api-context"),jobs=require("../../../services/artifacts/peace.desktop-packing-jobs"),custom=require("../../../services/artifacts/peace.custom-package-jobs");
const prefix='/api/desktop/bootstrap/packing';
async function Handle({method,pathname,body,req,res,session}){
 if(pathname!==prefix&&!pathname.startsWith(prefix+'/'))return false;
 if(!RequireAdmin(res,session))return true;
 const check=require("../../../services/authentication/peace.desktop-admin-guard").CheckSession(session,pathname,method);if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
 try{
  const customMatch=/^\/api\/desktop\/bootstrap\/packing\/custom\/jobs\/([a-f0-9]{32})(?:\/(download))?$/.exec(pathname);
  if(method==='POST'&&pathname===prefix+'/custom/jobs'){
   if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
   if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
   Json(res,202,{ok:true,job:custom.Begin(body,session)});return true;
  }
  if(method==='GET'&&customMatch){
   if(!customMatch[2]){Json(res,200,{ok:true,job:custom.View(custom.Get(customMatch[1],session))});return true;}
   const out=custom.Output(customMatch[1],session),copy=Buffer.from(out.bytes);
   res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':copy.length,'Content-Disposition':'attachment; filename="game-'+out.kind+'-'+out.id+'.gcpack"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','X-Artifact-Sha512':out.sha512});
   res.end(copy,()=>copy.fill(0));return true;
  }
  const match=/^\/api\/desktop\/bootstrap\/packing\/jobs\/([a-f0-9]{32})(?:\/(A|B|O|report))?$/.exec(pathname);
  if(method==='POST'&&pathname===prefix+'/jobs'){
   if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
   if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
   Json(res,202,{ok:true,job:jobs.Begin(body,session)});return true;
  }
  if(method==='GET'&&pathname===prefix+'/status'){Json(res,200,{ok:true,packing:jobs.Status(),custom:custom.Status()});return true;}
  if(method==='GET'&&match){
   const job=jobs.Get(match[1],session);
   if(!match[2]){Json(res,200,{ok:true,job:jobs.View(job)});return true;}
   if(match[2]==='report'){res.setHeader('Content-Disposition','attachment; filename="packing-'+job.id+'.json"');Json(res,200,{ok:true,job:jobs.View(job)});return true;}
   const out=jobs.Output(job.id,match[2],session),copy=Buffer.from(out.bytes);
   res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':copy.length,'Content-Disposition':'attachment; filename="'+match[2]+'-packed-unapproved.exe"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','X-Artifact-Sha512':out.sha512});
   res.end(copy,()=>copy.fill(0));return true;
  }
  ApiError(res,404,'NOT_FOUND');
 }catch(e){ApiError(res,e.desktopError?e.status:500,e.desktopError?e.message:'PACKING_REQUEST_FAILED');}
 return true;
}
module.exports={Handle};
