'use strict';
const desktop=require('../../services/desktopLicenses'),machinePolicy=require('../../services/desktopMachinePolicy');
const {RequireAdmin,Json,ApiError}=require('../apiContext');
async function Handle({method,pathname,url,body,res,session}){
 if(pathname!=='/api/desktop/machines'&&!/^\/api\/desktop\/machines\/[A-F0-9]{64}\/(block|unblock)$/.test(pathname)&&pathname!=='/api/desktop/connect-profile'&&pathname!=='/api/desktop/licenses'&&pathname!=='/api/desktop/devices'&&!/^\/api\/desktop\/licenses\/[^/]+(?:\/(revoke|reissue))?$/.test(pathname))return false;
 if(!RequireAdmin(res,session))return true;
 try{
  if(pathname==='/api/desktop/machines'){if(method!=='GET'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}Json(res,200,{ok:true,...machinePolicy.List()});return true;}
  const machineMatch=/^\/api\/desktop\/machines\/([A-F0-9]{64})\/(block|unblock)$/.exec(pathname);
  if(machineMatch){if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}const actor=String(session.role||'ADMIN')+':'+String(session.id||''),result=machinePolicy.Set(machineMatch[1],machineMatch[2]==='block',body,actor);require('../../storage/audit').LogEvent('DESKTOP_MACHINE_'+machineMatch[2].toUpperCase(),JSON.stringify({machineId:machineMatch[1],actor}));Json(res,200,{ok:true,...result});return true;}
  if(pathname==='/api/desktop/connect-profile'){if(method!=='GET'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}Json(res,200,{ok:true,profile:require('../../services/connectTransportKey').Profile(),connection:require('../../services/connectEndpoint').Diagnostics()});return true;}
  if(method==='GET'&&['/api/desktop/licenses','/api/desktop/devices'].includes(pathname)){const result=desktop.List(Object.fromEntries(url.searchParams));if(pathname.endsWith('/devices'))result.items=result.items.filter(row=>row.consumed);Json(res,200,{ok:true,...result,bootstrapRequired:true});return true;}
  const detail=/^\/api\/desktop\/licenses\/((?:DL-)?[A-F0-9]{24})$/.exec(pathname);
  if(method==='GET'&&detail){Json(res,200,{ok:true,...desktop.Detail(detail[1]),revision:desktop.DB().revision,serverTime:Date.now()});return true;}
  const actor=String(session.role||'ADMIN')+':'+String(session.id||'');let result,action;
  if(method==='POST'&&pathname==='/api/desktop/licenses'){result=desktop.Create(body,actor);action='CREATE';}
  else{const match=/^\/api\/desktop\/licenses\/((?:DL-)?[A-F0-9]{24})\/(revoke|reissue)$/.exec(pathname);if(method!=='POST'||!match){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}action=match[2].toUpperCase();result=match[2]==='revoke'?desktop.Revoke(match[1],body,actor):desktop.Reissue(match[1],body,actor);}
  // Never include the one-time plaintext key or activation token in audit logs.
  require('../../storage/audit').LogEvent('DESKTOP_LICENSE_'+action,JSON.stringify({id:result.license.id,replacedId:result.replacedId||'',actor}));
  Json(res,200,{ok:true,...result,revision:desktop.DB().revision,serverTime:Date.now()});
 }catch(error){
  const code=error.desktopError||String(error.message).startsWith('CONNECT_TLS_')?error.message:'INPUT_INVALID';
  const connection=(code==='CONNECT_PUBLIC_ENDPOINT_REQUIRED'||code.startsWith('CONNECT_TLS_'))?require('../../services/connectEndpoint').Diagnostics():null;
  Json(res,error.desktopError?error.status:code.startsWith('CONNECT_TLS_')?503:400,{ok:false,error:code,reason:code,
   message:require('../../services/connectTls').Messages[code]||(connection?connection.problems.join(' '):desktop.messages[code])||'입력 내용을 확인해 주세요.',
   ...(connection?{connection}:{})});
 }
 return true;
}
module.exports={Handle};
