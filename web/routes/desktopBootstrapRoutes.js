'use strict';
const bootstrap=require('../../services/desktopBootstrap');
const {RequireAdmin,Json,ApiError}=require('../apiContext');
let uploadPending=false;
function ErrorResponse(res,error){const code=error.desktopError?error.message:'BOOTSTRAP_INPUT_INVALID';Json(res,error.desktopError?error.status:400,{ok:false,error:code,reason:code,problem:require('../../services/desktopOperationsErrors').Explain(code),message:bootstrap.messages[code]||require('../../services/desktopLicenses').messages[code]||'실행 파일 요청을 처리하지 못했습니다.'});}
function ReadBytes(req){
 return new Promise((resolve,reject)=>{
  let done=false,size=0;const chunks=[],timer=setTimeout(()=>finish(Error('BOOTSTRAP_UPLOAD_TIMEOUT')),120000);timer.unref();
  function finish(error){if(done)return;done=true;clearTimeout(timer);if(error){chunks.length=0;req.resume();reject(error);}else resolve(Buffer.concat(chunks,size));}
  req.on('data',chunk=>{if(done)return;size+=chunk.length;if(size>bootstrap.MAX_ARTIFACT_BYTES){const error=Error('BOOTSTRAP_ARTIFACT_TOO_LARGE');error.desktopError=true;error.status=413;return finish(error);}chunks.push(chunk);});
  req.once('end',()=>finish());req.once('error',finish);req.once('aborted',()=>finish(Error('BOOTSTRAP_UPLOAD_ABORTED')));
 });
}
// Raw PE uploads must be dispatched before the shared JSON-body parser. The
// web server has already authenticated the session; repeat CSRF/admin checks
// here so this special path cannot accidentally bypass either gate.
async function HandleUpload({method,pathname,url,req,res,session}){
 if(!['/api/desktop/bootstrap/artifacts','/api/desktop/bootstrap/module-baselines'].includes(pathname))return false;
 if(pathname==='/api/desktop/bootstrap/module-baselines'&&method==='GET')return false;
 if(!RequireAdmin(res,session))return true;
 if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
 if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
 if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
 const adminCheck=require('../../services/desktopAdminGuard').CheckSession(session);if(!adminCheck.ok){ApiError(res,adminCheck.status||428,adminCheck.reason);return true;}
 if(uploadPending){ApiError(res,429,'BOOTSTRAP_UPLOAD_BUSY');return true;}
 try{
  if(!/^application\/octet-stream(?:\s*;|$)/i.test(req.headers['content-type']||'')||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');
  const length=Number(req.headers['content-length']||0);if(!Number.isSafeInteger(length)||length<0)bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');if(length>bootstrap.MAX_ARTIFACT_BYTES)bootstrap.Fail('BOOTSTRAP_ARTIFACT_TOO_LARGE',413);
  if(pathname==='/api/desktop/bootstrap/module-baselines'){
   if(length>32*1024*1024)bootstrap.Fail('BOOTSTRAP_ARTIFACT_TOO_LARGE',413);uploadPending=true;
   const bytes=await ReadBytes(req),fileName=url.searchParams.get('fileName'),label=url.searchParams.get('label')||'';
   const summary={fileName,label,hashVersion:3,sha512:require('../../services/desktopSecurityOperations').sha512(bytes),size:bytes.length};
   const allowed=require('../../services/desktopAdminGuard').Authorize(session,method,pathname,summary,String(req.headers['x-approval-ticket']||''));
   if(!allowed.ok){ApiError(res,allowed.status||428,allowed.reason,allowed.ticketId||'');return true;}
   require('../../services/desktopSecurityOperations').AuditIntent('MODULE_BASELINE_REGISTER',session.id);
   const baseline=require('../../services/desktopIntegrityReports').RegisterBaseline(fileName,label,bytes,String(session.role||'ADMIN')+':'+String(session.id||''));Json(res,200,{ok:true,baseline});return true;
  }
  const component=url.searchParams.get('component'),version=url.searchParams.get('version'),name=url.searchParams.get('fileName')||'';
  if(!['A','B','O'].includes(component)||!/^\d+(?:\.\d+){0,3}$/.test(version||'')||!/^.{1,200}\.exe$/i.test(name)||/[\x00-\x1f\x7f/\\]/.test(name))bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');
  uploadPending=true;const bytes=await ReadBytes(req),approval=req.headers['x-game-release-key-id']||req.headers['x-game-release-signature']?{keyId:req.headers['x-game-release-key-id'],signature:req.headers['x-game-release-signature']}:undefined;
  const ops=require('../../services/desktopSecurityOperations'),authority=require('../../services/desktopSecurityAuthority');
  const summary={component,version,fileName:name,hashVersion:3,sha512:ops.sha512(bytes),size:bytes.length,keyId:approval?.keyId||'',signatureSha512:approval?ops.sha512(JSON.stringify(approval)):'',expectedPolicyRevision:authority.Policy().revision,expectedOperationsRevision:ops.Revision(),disposition:'CANDIDATE'};
  const allowed=require('../../services/desktopAdminGuard').Authorize(session,method,pathname,summary,String(req.headers['x-approval-ticket']||''));
  if(!allowed.ok){ApiError(res,allowed.status||428,allowed.reason,allowed.ticketId||'');return true;}
  const artifact=ops.Stage(component,version,bytes,approval,session.id);Json(res,200,{ok:true,artifact,disposition:'CANDIDATE',activeUnchanged:true});
 }catch(error){ErrorResponse(res,error);}finally{uploadPending=false;}
 return true;
}
async function Handle({method,pathname,url,body,req,res,session,desktopAuthorization}){
 if(!pathname.startsWith('/api/desktop/bootstrap'))return false;
 if(!RequireAdmin(res,session))return true;
 const actor=String(session.role||'ADMIN')+':'+String(session.id||'');
 try{
  if(await require('./desktopSecurityRoutes').Handle({method,pathname,url,body,req,res,session,desktopAuthorization}))return true;
  if(pathname==='/api/desktop/bootstrap/security-authority'&&method==='GET'){Json(res,200,{ok:true,...require('../../services/desktopSecurityAuthority').List()});return true;}
  if(pathname==='/api/desktop/bootstrap/security-authority'&&method==='POST'){if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}Json(res,200,{ok:true,policy:require('../../services/desktopSecurityAuthority').SetPolicy(body,actor)});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-policy'&&method==='GET'){Json(res,200,{ok:true,policy:require('../../services/desktopIntegrityReports').Policy()});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-policy'&&method==='POST'){if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}Json(res,200,{ok:true,policy:require('../../services/desktopIntegrityReports').SetPolicy(body,actor)});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-reports'&&method==='GET'){Json(res,200,{ok:true,...require('../../services/desktopIntegrityReports').List(Object.fromEntries(url.searchParams))});return true;}
  if(pathname==='/api/desktop/bootstrap/module-baselines'&&method==='GET'){Json(res,200,{ok:true,...require('../../services/desktopIntegrityReports').Baselines()});return true;}
  if(pathname==='/api/desktop/bootstrap'&&method==='GET'){Json(res,200,{ok:true,bootstrap:bootstrap.Overview()});return true;}
  if(pathname==='/api/desktop/bootstrap/launchers'&&method==='POST'){Json(res,200,{ok:true,...bootstrap.IssueLauncher(body,actor)});return true;}
  const download=/^\/api\/desktop\/bootstrap\/launchers\/((?:LA-)?[A-F0-9]{24})\/download$/.exec(pathname);
  if(download&&['GET','HEAD'].includes(method)){
   const bytes=bootstrap.LauncherBytes(download[1]);res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':bytes.length,'Content-Disposition':'attachment; filename="'+bootstrap.LauncherName(bootstrap.Initialize().launchers[download[1]])+'"','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});res.end(method==='HEAD'?undefined:bytes);return true;
  }
  const revoke=/^\/api\/desktop\/bootstrap\/sessions\/((?:DS-)?[A-F0-9]{24})\/revoke$/.exec(pathname);
  if(revoke&&method==='POST'){Json(res,200,{ok:true,session:bootstrap.Revoke(revoke[1],body,actor)});return true;}
  ApiError(res,404,'NOT_FOUND');
 }catch(error){ErrorResponse(res,error);}
 return true;
}
module.exports={Handle,HandleUpload};
