'use strict';
const bootstrap=require("../../../services/bootstrap/peace.desktop-bootstrap");
const {RequireAdmin,Json,ApiError}=require("../../http/peace.api-context");
const {UploadError}=require("../../../services/artifacts/peace.desktop-pe-cache");
let uploadPending=false;
function ErrorResponse(res,error){const code=error.desktopError?error.message:'BOOTSTRAP_INPUT_INVALID';Json(res,error.desktopError?error.status:400,{ok:false,error:code,reason:code,...(code==='ARTIFACT_EXPOSURE_BLOCKED'&&error.exposure?{exposure:error.exposure}:{}),problem:require("../../../services/runtime/peace.desktop-operations-errors").Explain(code),message:bootstrap.messages[code]||require("../../../services/licensing/peace.desktop-licenses").messages[code]||'실행 파일 요청을 처리하지 못했습니다.'});}
function ReadBytes(req,maximum){
 if(!Number.isSafeInteger(maximum)||maximum<1||maximum>bootstrap.MAX_ARTIFACT_BYTES)return Promise.reject(Error('BOOTSTRAP_INPUT_INVALID'));
 return new Promise((resolve,reject)=>{
  let done=false,size=0;const chunks=[],timer=setTimeout(()=>finish(UploadError('BOOTSTRAP_UPLOAD_TIMEOUT')),120000);timer.unref();
  function finish(error){if(done)return;done=true;clearTimeout(timer);if(error){chunks.length=0;req.resume();reject(error);}else resolve(Buffer.concat(chunks,size));}
  req.on('data',chunk=>{if(done)return;size+=chunk.length;if(size>maximum){const error=Error('BOOTSTRAP_ARTIFACT_TOO_LARGE');error.desktopError=true;error.status=413;return finish(error);}chunks.push(chunk);});
  req.once('end',()=>finish());req.once('error',finish);req.once('aborted',()=>finish(UploadError('BOOTSTRAP_UPLOAD_ABORTED')));
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
 if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
 if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
 const adminCheck=require("../../../services/authentication/peace.desktop-admin-guard").CheckSession(session);if(!adminCheck.ok){ApiError(res,adminCheck.status||428,adminCheck.reason);return true;}
 let resourceLease;
 if(uploadPending){ApiError(res,429,'BOOTSTRAP_UPLOAD_BUSY');return true;}
 try{
  if(!/^application\/octet-stream(?:\s*;|$)/i.test(req.headers['content-type']||'')||req.headers['content-encoding']&&req.headers['content-encoding']!=='identity')bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');
  const rawLength=req.headers['content-length'];if(rawLength!==undefined&&(typeof rawLength!=='string'||!/^\d+$/.test(rawLength)))bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');const length=Number(rawLength||0);if(!Number.isSafeInteger(length)||length<0)bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');if(length>bootstrap.MAX_ARTIFACT_BYTES)bootstrap.Fail('BOOTSTRAP_ARTIFACT_TOO_LARGE',413);
  const maximum=pathname==='/api/desktop/bootstrap/module-baselines'?32*1024*1024:bootstrap.MAX_ARTIFACT_BYTES;
  resourceLease=require("../../../services/runtime/peace.server-resource-budget").Admit('upload',{key:session.id,bytes:4*(length||maximum),diskBytes:length||maximum});
  if(pathname==='/api/desktop/bootstrap/module-baselines'){
   if(length>32*1024*1024)bootstrap.Fail('BOOTSTRAP_ARTIFACT_TOO_LARGE',413);uploadPending=true;
   const bytes=await ReadBytes(req,32*1024*1024),fileName=url.searchParams.get('fileName'),label=url.searchParams.get('label')||'';
   await require("../../../services/artifacts/peace.desktop-pe-cache").Prepare(bytes);
   const summary={fileName,label,hashVersion:3,sha512:require("../../../services/security/peace.desktop-security-operations").sha512(bytes),size:bytes.length};
   const allowed=require("../../../services/authentication/peace.desktop-admin-guard").Authorize(session,method,pathname,summary,String(req.headers['x-approval-ticket']||''),'',String(req.headers['x-admin-action']||''));
   if(!allowed.ok){require("../../../services/authentication/peace.desktop-action-approval").Deny(res,allowed);return true;}
   require("../../../services/security/peace.desktop-security-operations").AuditIntent('MODULE_BASELINE_REGISTER',session.id);
   const baseline=require("../../../services/integrity/peace.desktop-integrity-reports").RegisterBaseline(fileName,label,bytes,String(session.role||'ADMIN')+':'+String(session.id||''));Json(res,200,{ok:true,baseline});return true;
  }
  const component=url.searchParams.get('component'),version=url.searchParams.get('version'),name=url.searchParams.get('fileName')||'',releaseManifestId=url.searchParams.get('releaseManifestId')||'';
  if(releaseManifestId&&!/^[a-f0-9]{128}$/.test(releaseManifestId))bootstrap.Fail('SECURITY_RELEASE_MANIFEST_INVALID');
  if(!['A','B','O'].includes(component)||!/^\d+(?:\.\d+){0,3}$/.test(version||'')||!/^.{1,200}\.exe$/i.test(name)||/[\x00-\x1f\x7f/\\]/.test(name))bootstrap.Fail('BOOTSTRAP_INPUT_INVALID');
  uploadPending=true;const bytes=await ReadBytes(req,bootstrap.MAX_ARTIFACT_BYTES),approval=req.headers['x-game-release-key-id']||req.headers['x-game-release-signature']?{keyId:req.headers['x-game-release-key-id'],signature:req.headers['x-game-release-signature']}:undefined;
  await require("../../../services/artifacts/peace.desktop-pe-cache").Prepare(bytes);
  const ops=require("../../../services/security/peace.desktop-security-operations"),authority=require("../../../services/security/peace.desktop-security-authority");
  const summary={component,version,fileName:name,...(releaseManifestId?{releaseManifestId}:{}),hashVersion:3,sha512:ops.sha512(bytes),size:bytes.length,keyId:approval?.keyId||'',signatureSha512:approval?ops.sha512(JSON.stringify(approval)):'',expectedPolicyRevision:authority.Policy().revision,expectedOperationsRevision:ops.Revision(),disposition:'CANDIDATE'};
  const allowed=require("../../../services/authentication/peace.desktop-admin-guard").Authorize(session,method,pathname,summary,String(req.headers['x-approval-ticket']||''),'',String(req.headers['x-admin-action']||''));
  if(!allowed.ok){require("../../../services/authentication/peace.desktop-action-approval").Deny(res,allowed);return true;}
  const artifact=ops.Stage(component,version,bytes,approval,session.id,releaseManifestId);Json(res,200,{ok:true,artifact,disposition:'CANDIDATE',activeUnchanged:true});
 }catch(error){ErrorResponse(res,error);}finally{uploadPending=false;resourceLease?.release();}
 return true;
}
async function Handle({method,pathname,url,body,req,res,session,desktopAuthorization}){
 if(!pathname.startsWith('/api/desktop/bootstrap'))return false;
 if(!RequireAdmin(res,session))return true;
 const actor=String(session.role||'ADMIN')+':'+String(session.id||'');
 try{
  if(['GET','HEAD'].includes(method))require("../../../services/storage/peace.desktop-operation-audit").RecordAccess('ADMIN_BOOTSTRAP_READ','ADMIN:'+session.id);
  if(await require("../security/peace.desktop-security-center-routes").Handle({method,pathname,body,req,res,session,desktopAuthorization}))return true;
  if(await require("../artifacts/peace.desktop-packing-routes").Handle({method,pathname,url,body,req,res,session}))return true;
  if(await require("../security/peace.desktop-security-routes").Handle({method,pathname,url,body,req,res,session,desktopAuthorization}))return true;
  if(pathname==='/api/desktop/bootstrap/security-authority'&&method==='GET'){Json(res,200,{ok:true,...require("../../../services/security/peace.desktop-security-authority").List()});return true;}
  if(pathname==='/api/desktop/bootstrap/security-authority'&&method==='POST'){if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}Json(res,200,{ok:true,policy:require("../../../services/security/peace.desktop-security-authority").SetPolicy(body,actor)});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-policy'&&method==='GET'){Json(res,200,{ok:true,policy:require("../../../services/integrity/peace.desktop-integrity-reports").Policy()});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-policy'&&method==='POST'){if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}Json(res,200,{ok:true,policy:require("../../../services/integrity/peace.desktop-integrity-reports").SetPolicy(body,actor)});return true;}
  if(pathname==='/api/desktop/bootstrap/integrity-reports'&&method==='GET'){Json(res,200,{ok:true,...require("../../../services/integrity/peace.desktop-integrity-reports").List(Object.fromEntries(url.searchParams))});return true;}
  if(pathname==='/api/desktop/bootstrap/module-baselines'&&method==='GET'){Json(res,200,{ok:true,...require("../../../services/integrity/peace.desktop-integrity-reports").Baselines()});return true;}
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
module.exports={Handle,HandleUpload,ReadBytes};
