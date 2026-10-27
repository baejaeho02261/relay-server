'use strict';
const authority=require("../../../services/security/peace.desktop-security-authority");
const operations=require("../../../services/security/peace.desktop-security-operations");
const guard=require("../../../services/authentication/peace.desktop-admin-guard");
const {Json,ApiError}=require("../../http/peace.api-context");
async function Handle({method,pathname,body,req,res,session,desktopAuthorization}) {
  const prefix='/api/desktop/bootstrap/security-operations';
  if(pathname==='/api/desktop/bootstrap/security-authority/preview'&&method==='POST'){
    const check=guard.CheckSession(session,pathname,method);
    if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
    if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
    Json(res,200,{ok:true,preview:authority.PreviewPolicy(body)});return true;
  }
  if(pathname!==prefix&&!pathname.startsWith(prefix+'/'))return false;
  if(!session||session.role!=='admin'){ApiError(res,403,'ADMIN_REQUIRED');return true;}
  if(method==='GET'&&pathname===prefix+'/registration-reset'){
    const check=guard.CheckSession(session,pathname,method);if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
    Json(res,200,{ok:true,...require('../../../services/operations/peace.registration-reset').Status(new URL(req.url,'http://localhost').searchParams.get('requestId')||undefined)});return true;
  }
  if(method==='GET'&&pathname===prefix+'/mitigation-compatibility'){Json(res,200,{ok:true,...require("../../../services/security/peace.desktop-mitigation-compatibility").Status()});return true;}
  if(method==='GET'&&pathname===prefix+'/mitigation-profiles'){Json(res,200,{ok:true,...require("../../../services/security/peace.desktop-mitigation-profiles").Status()});return true;}
  if(method==='GET'&&pathname===prefix+'/tls-pin-transition'){Json(res,200,{ok:true,...require("../../../services/network/peace.desktop-tls-pin-transition").Status()});return true;}
  if(method==='GET'&&pathname===prefix+'/release-safety'){Json(res,200,{ok:true,...require("../../../services/artifacts/peace.desktop-release-safety").Status()});return true;}
  if(method==='GET'&&pathname===prefix+'/publication-status'){Json(res,200,{ok:true,publication:operations.ProductionStatus()});return true;}
  if(method==='GET'&&pathname===prefix+'/keyless-approvals'){
    const check=guard.CheckSession(session,pathname,method);if(!check.ok){ApiError(res,check.status||403,check.reason);return true;}
    Json(res,200,{ok:true,...require('../../../services/bootstrap/peace.keyless-bootstrap').ListPending()});return true;
  }
  if(method==='GET'&&pathname===prefix+'/packed-release-jobs'){Json(res,200,{ok:true,...require('../../../services/artifacts/peace.packed-release-manifest').List()});return true;}
  const receiptExport=/^\/packed-release-jobs\/([^/]+)\/receipts$/.exec(pathname.slice(prefix.length));
  if(receiptExport&&method!=='GET'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  if(method==='GET'&&receiptExport){Json(res,200,{ok:true,jobId:receiptExport[1],receipts:require('../../../services/artifacts/peace.packed-release-manifest').ExportReceipts(receiptExport[1]),windowsVerified:false});return true;}
  if(method==='GET'&&pathname===prefix+'/activation'){Json(res,200,{ok:true,status:require("../../../services/security/peace.desktop-security-activation").Status()});return true;}
  if(method==='GET'&&pathname===prefix){Json(res,200,{ok:true,...operations.List()});return true;}
  if(method==='GET'&&pathname===prefix+'/approvals'){
    const tickets=require("../../../services/authentication/peace.privileged-approval").List().filter(x=>guard.IsMutation(x.pathname));
    Json(res,200,{ok:true,tickets});return true;
  }
  if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  if(!require("../../authentication/peace.web-auth").ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  if(!require("../../../services/network/peace.ha-coordinator").CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
  // Repeat the non-consuming session gate after dispatch; this is not a second
  // consumption of an enable-all/dual-approval capability.
  const live=guard.CheckSession(session,pathname,method);
  if(!live.ok){ApiError(res,live.status||403,live.reason);return true;}
  const action=pathname.slice(prefix.length+1),actor=guard.Identity(session)||'ADMIN:'+session.id;
  const keylessApproval=/^keyless-approvals\/([a-f0-9]{48})\/approve$/.exec(action);
  if(keylessApproval){Json(res,200,{ok:true,...require('../../../services/bootstrap/peace.keyless-bootstrap').Approve(keylessApproval[1],body,actor)});return true;}
  if(action==='registration-reset'){
    const reset=require('../../../services/operations/peace.registration-reset'),result=reset.Schedule(body,session,desktopAuthorization?.ticket);
    if(result.restartRequired)reset.AfterResponse(res);
    Json(res,result.restartRequired?202:200,{ok:true,...result});return true;
  }
  if(action==='step-up/begin'){const out=guard.Begin(session,req);if(out.ok)Json(res,200,out);else ApiError(res,403,out.reason);return true;}
  if(action==='step-up/finish'){const out=guard.Finish(session,req,body);if(out.ok)Json(res,200,out);else ApiError(res,403,out.reason);return true;}
  if(action==='approve'){
    if(!body||Object.keys(body).length!==1||typeof body.ticketId!=='string'){ApiError(res,400,'INPUT_INVALID');return true;}
    const result=require("../../../services/authentication/peace.privileged-approval").Approve(body.ticketId,session);if(result.ok)Json(res,200,result);else ApiError(res,428,result.reason);return true;
  }
  if(action==='preview-enable-all'){
    if(!body||Object.keys(body).length!==1||!['READY','ALL','SERVER'].includes(body.profile)){ApiError(res,400,'SECURITY_ACTIVATION_INPUT_INVALID');return true;}
    Json(res,200,{ok:true,preview:require("../../../services/security/peace.desktop-security-activation").Preview(body.profile,session)});return true;
  }
  if(action==='enable-all'){
    Json(res,200,{ok:true,result:require("../../../services/security/peace.desktop-security-activation").Apply(body,session,desktopAuthorization?.ticket)});return true;
  }
  if(action==='preview-rollout'){Json(res,200,{ok:true,preview:authority.PreviewRollout(body)});return true;}
  if(action==='preview-pair'){Json(res,200,{ok:true,preview:operations.PreviewProductionPair(body)});return true;}
  if(action==='plan-packed-release'){Json(res,200,{ok:true,...require('../../../services/artifacts/peace.packed-release-manifest').Plan(body,actor)});return true;}
  const actions={'baseline-pin':require("../../../services/artifacts/peace.desktop-release-safety").PinBaseline,'retire-cohort':require("../../../services/artifacts/peace.desktop-release-safety").RevokeCohort,'mitigation-compatibility':require("../../../services/security/peace.desktop-mitigation-compatibility").Import,'mitigation-profiles':require("../../../services/security/peace.desktop-mitigation-profiles").Register,'tls-pin-transition':require("../../../services/network/peace.desktop-tls-pin-transition").Schedule,'plan-release':operations.PlanReleaseManifest,'recovery/prepare':operations.PrepareProductionRecovery,'recovery/apply':operations.ApplyProductionRecovery,'release-governance':operations.SetProductionGovernance,'release-manifests':operations.RecordReleaseManifest,controls:operations.SetControls,contracts:operations.SetContract,signers:operations.SetSignerState,rollout:operations.SetRollout,'test-evidence':operations.RecordEvidence,activate:operations.ActivateProductionPair};
  if(!actions[action]){ApiError(res,404,'NOT_FOUND');return true;}
  // Existing admin authentication / CSRF / single-operator authorization were checked
  // by webApi before dispatch. No duplicate consumption of one-use tickets here.
  Json(res,200,{ok:true,result:actions[action](body,actor)});return true;
}
module.exports={Handle};
