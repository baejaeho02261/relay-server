'use strict';
const desktop=require('../../services/desktopLicenses');
const {RequireAdmin,Json,ApiError}=require('../apiContext');
async function Handle({method,pathname,url,body,res,session}){
 if(pathname!=='/api/desktop/connect-profile'&&pathname!=='/api/desktop/licenses'&&pathname!=='/api/desktop/devices'&&!/^\/api\/desktop\/licenses\/[^/]+\/(revoke|reissue)$/.test(pathname))return false;
 if(!RequireAdmin(res,session))return true;
 try{
  if(pathname==='/api/desktop/connect-profile'){if(method!=='GET'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}Json(res,200,{ok:true,profile:require('../../services/connectTransportKey').Profile(),connection:require('../../services/connectEndpoint').Diagnostics()});return true;}
  if(method==='GET'&&['/api/desktop/licenses','/api/desktop/devices'].includes(pathname)){const result=desktop.List(Object.fromEntries(url.searchParams));if(pathname.endsWith('/devices'))result.items=result.items.filter(row=>row.consumed);Json(res,200,{ok:true,...result});return true;}
  const actor=String(session.role||'ADMIN')+':'+String(session.id||'');let result,action;
  if(method==='POST'&&pathname==='/api/desktop/licenses'){result=desktop.Create(body,actor);action='CREATE';}
  else{const match=/^\/api\/desktop\/licenses\/(DL-[A-F0-9]{24})\/(revoke|reissue)$/.exec(pathname);if(method!=='POST'||!match){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}action=match[2].toUpperCase();result=match[2]==='revoke'?desktop.Revoke(match[1],body,actor):desktop.Reissue(match[1],body,actor);}
  // Never include the one-time plaintext key or activation token in audit logs.
  require('../../storage/audit').LogEvent('DESKTOP_LICENSE_'+action,JSON.stringify({id:result.license.id,replacedId:result.replacedId||'',actor}));
  Json(res,200,{ok:true,...result,revision:desktop.DB().revision,serverTime:Date.now()});
 }catch(error){
  const code=error.desktopError?error.message:'INPUT_INVALID';
  const connection=code==='CONNECT_PUBLIC_ENDPOINT_REQUIRED'?require('../../services/connectEndpoint').Diagnostics():null;
  Json(res,error.desktopError?error.status:400,{ok:false,error:code,reason:code,
   message:connection?connection.problems.join(' '):desktop.messages[code]||'입력 내용을 확인해 주세요.',
   ...(connection?{connection}:{})});
 }
 return true;
}
module.exports={Handle};
