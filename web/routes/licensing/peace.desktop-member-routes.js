'use strict';
const PREFIX='/api/desktop/members';
const READ_WINDOW_MS=60000,READ_WINDOW_LIMIT=2048,readWindows=new Map();
function AuditRead(actor,pathname,url){
 const crypto=require('node:crypto'),now=require('node:perf_hooks').performance.now();
 const query=[...url?.searchParams||[]].sort((a,b)=>a[0].localeCompare(b[0]));
 const subject=crypto.createHash('sha256').update(JSON.stringify([pathname,query])).digest('hex');
 const key=crypto.createHash('sha256').update(actor+'\n'+subject).digest('hex');
 for(const [id,row]of readWindows)if(now>=row.until||now<row.from)readWindows.delete(id);
 const row=readWindows.get(key);
 if(row)return {mode:'BOUNDED_REPEAT_WINDOW',windowMs:READ_WINDOW_MS,repeated:true};
 // The first access is durable and fail-closed. This cache only aggregates
 // repeated audit emissions; authorization and data are recomputed every time.
 require('../../../services/storage/peace.desktop-operation-audit').RecordAccess('ADMIN_MEMBER_READ',actor,{subject});
 while(readWindows.size>=READ_WINDOW_LIMIT)readWindows.delete(readWindows.keys().next().value);
 readWindows.set(key,{from:now,until:now+READ_WINDOW_MS});
 return {mode:'BOUNDED_REPEAT_WINDOW',windowMs:READ_WINDOW_MS,repeated:false};
}
function Query(url,allowed){const query={};for(const [key,value]of url?.searchParams||[]){if(!allowed.includes(key)||Object.hasOwn(query,key))throw Object.assign(Error('MEMBER_QUERY_INVALID'),{desktopError:true,status:400});query[key]=value;}return query;}
async function Handle({method,pathname,url,req,res,session,body={}}){
 if(pathname!==PREFIX&&!pathname.startsWith(PREFIX+'/'))return false;
 const {RequireAdmin,Json,ApiError}=require('../../http/peace.api-context');
 if(!RequireAdmin(res,session))return true;
 try{
  const guard=require('../../../services/authentication/peace.desktop-admin-guard'),auth=require('../../authentication/peace.web-auth');
  const checked=guard.CheckSession(session,method==='GET'?'':pathname,method);
  if(!checked.ok){ApiError(res,checked.status,checked.reason);return true;}
  if(method!=='GET'){
   if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
   if(!auth.ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
   if(!auth.HasRecentAuthentication(session)){ApiError(res,428,'ADMIN_REAUTH_REQUIRED');return true;}
   if(!require('../../../services/network/peace.ha-coordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
   if([...url?.searchParams||[]].length){ApiError(res,400,'MEMBER_QUERY_INVALID');return true;}
  }
  const members=require('../../../services/members/peace.desktop-members'),actor='ADMIN:'+session.id;let result;
  const detail=/^\/api\/desktop\/members\/(unassigned|[A-F0-9]{24})$/.exec(pathname),archive=/^\/api\/desktop\/members\/([A-F0-9]{24})\/archive$/.exec(pathname);
  if(method==='GET'&&pathname===PREFIX)result=members.List(Query(url,['q','status','page','pageSize']));
  else if(method==='GET'&&detail)result=members.Detail(detail[1],Query(url,['category','page','pageSize']));
  else if(method==='POST'&&pathname===PREFIX)result=members.Create(body,actor);
  else if(method==='POST'&&pathname===PREFIX+'/assignment')result=members.Assign(body,actor);
  else if(method==='POST'&&detail&&detail[1]!=='unassigned')result=members.Update(detail[1],body,actor);
  else if(method==='POST'&&archive)result=members.Archive(archive[1],body,actor);
  else{ApiError(res,404,'NOT_FOUND');return true;}
  if(method==='GET')result={...result,readAudit:AuditRead(actor,pathname,url)};
  Json(res,200,{ok:true,...result});
 }catch(e){ApiError(res,e.desktopError?e.status:503,e.desktopError?e.message:'MEMBER_OPERATION_FAILED');}
 return true;
}
module.exports={Handle};
