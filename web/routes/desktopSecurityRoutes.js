'use strict';
const authority=require('../../services/desktopSecurityAuthority');
const operations=require('../../services/desktopSecurityOperations');
const guard=require('../../services/desktopAdminGuard');
const {Json,ApiError}=require('../apiContext');
async function Handle({method,pathname,body,req,res,session,desktopAuthorization}) {
  const prefix='/api/desktop/bootstrap/security-operations';
  if(pathname==='/api/desktop/bootstrap/security-authority/preview'&&method==='POST'){
    if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
    Json(res,200,{ok:true,preview:authority.PreviewPolicy(body)});return true;
  }
  if(pathname!==prefix&&!pathname.startsWith(prefix+'/'))return false;
  if(!session||session.role!=='admin'){ApiError(res,403,'ADMIN_REQUIRED');return true;}
  if(method==='GET'&&pathname===prefix+'/activation'){Json(res,200,{ok:true,status:require('../../services/desktopSecurityActivation').Status()});return true;}
  if(method==='GET'&&pathname===prefix){Json(res,200,{ok:true,...operations.List()});return true;}
  if(method==='GET'&&pathname===prefix+'/approvals'){
    const tickets=require('../../services/privilegedApproval').List().filter(x=>guard.IsMutation(x.pathname));
    Json(res,200,{ok:true,tickets});return true;
  }
  if(method!=='POST'){ApiError(res,405,'METHOD_NOT_ALLOWED');return true;}
  if(!require('../webAuth').ValidateCsrf(req,session)){ApiError(res,403,'CSRF_FAILED');return true;}
  if(!require('../../services/haCoordinator').CanAcceptTraffic()){ApiError(res,409,'RELAY_STANDBY_READ_ONLY');return true;}
  const action=pathname.slice(prefix.length+1),actor=guard.Identity(session)||'ADMIN:'+session.id;
  if(action==='step-up/begin'){const out=guard.Begin(session,req);if(out.ok)Json(res,200,out);else ApiError(res,403,out.reason);return true;}
  if(action==='step-up/finish'){const out=guard.Finish(session,req,body);if(out.ok)Json(res,200,out);else ApiError(res,403,out.reason);return true;}
  if(action==='approve'){
    if(!body||Object.keys(body).length!==1||typeof body.ticketId!=='string'){ApiError(res,400,'INPUT_INVALID');return true;}
    const result=require('../../services/privilegedApproval').Approve(body.ticketId,session);if(result.ok)Json(res,200,result);else ApiError(res,428,result.reason);return true;
  }
  if(action==='preview-enable-all'){
    if(!body||Object.keys(body).length!==1||!['READY','ALL','SERVER'].includes(body.profile)){ApiError(res,400,'SECURITY_ACTIVATION_INPUT_INVALID');return true;}
    Json(res,200,{ok:true,preview:require('../../services/desktopSecurityActivation').Preview(body.profile,session)});return true;
  }
  if(action==='enable-all'){
    Json(res,200,{ok:true,result:require('../../services/desktopSecurityActivation').Apply(body,session,desktopAuthorization?.ticket)});return true;
  }
  if(action==='preview-rollout'){Json(res,200,{ok:true,preview:authority.PreviewRollout(body)});return true;}
  if(action==='preview-pair'){Json(res,200,{ok:true,preview:operations.PreviewPair(body)});return true;}
  const actions={'plan-release':operations.PlanReleaseManifest,'recovery/prepare':operations.PrepareRecovery,'recovery/apply':operations.ApplyRecovery,'release-governance':operations.SetReleaseGovernance,'release-manifests':operations.RecordReleaseManifest,'ci-signers':operations.SetCiSigner,'ci-evidence':operations.RecordCiEvidence,controls:operations.SetControls,contracts:operations.SetContract,signers:operations.SetSignerState,rollout:operations.SetRollout,'test-evidence':operations.RecordEvidence,activate:operations.ActivatePair};
  if(!actions[action]){ApiError(res,404,'NOT_FOUND');return true;}
  // Existing admin authentication / CSRF / single-operator authorization were checked
  // by webApi before dispatch. No duplicate consumption of one-use tickets here.
  Json(res,200,{ok:true,result:actions[action](body,actor)});return true;
}
module.exports={Handle};
