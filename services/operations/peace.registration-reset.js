'use strict';

// A deliberate, one-shot maintenance operation. The web can durably queue it;
// all destructive phases run with the writer lock before listeners are opened.
const SCOPE = 'ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
const PATH='/api/desktop/bootstrap/security-operations/registration-reset';
const CONFIRMATION='전체 초기화';
let draining=false,restartTimer,restartStarted=false;
function Fail(code) { throw Error('REGISTRATION_RESET_' + code); }
function PublicFail(code,status=409){const error=Error('REGISTRATION_RESET_'+code);error.desktopError=true;error.status=status;throw error;}
function IsDraining(){return draining;}
function AssertAvailable(){if(draining)PublicFail('IN_PROGRESS',503);}
function Request(environment = process.env) {
  const id = environment.COZY_REGISTRATION_RESET_ID || '';
  const scope = environment.COZY_REGISTRATION_RESET_SCOPE || '';
  if (!id && !scope) return null;
  if (!/^[a-f0-9]{64}$/.test(id) || scope !== SCOPE) Fail('REQUEST_INVALID');
  return {id, scope};
}
function Counts() {
  const db = require('../bootstrap/peace.desktop-bootstrap-store').Load();
  const licenses = require('../licensing/peace.desktop-licenses').DB();
  return {
    artifacts: Object.keys(db.artifacts).length,
    activeArtifacts: Object.keys(db.active).length,
    licenses: Object.keys(licenses.licenses).length,
    issuedLaunchers: Object.keys(db.launchers).length,
    flows: Object.keys(db.flows).length,
    overlays: Object.keys(db.overlays || {}).length,
    issueReceipts: Object.keys(db.issueReceipts).length,
    packingEvidence: Object.keys(db.packingEvidence || {}).length,
    releaseManifests: Object.keys(db.securityOperations?.releaseGovernance?.manifests || {}).length
  };
}
function ResetProductionOperations() {
  const production = require('../runtime/peace.production-state');
  const saved = production.ExportPersisted();
  // Preserve administrator passkeys, the authenticated audit head and transport
  // policy; clear application deployment transactions and operational reports.
  production.ImportPersisted({productionControl: {
    passkeyCredentials: saved.passkeyCredentials,
    auditChain: saved.auditChain,
    transportPolicy: saved.transportPolicy,
    deploymentManifest:{revision:(saved.deploymentManifest?.revision||0)+1,updatedAt:Date.now(),updatedBy:'REGISTRATION_RESET',dualApprovalRequired:saved.deploymentManifest?.dualApprovalRequired===true}
  }});
}
function Run() {
  const environmentRequest = Request();
  const permission=require('./peace.registration-reset-authorization');
  const webRequest=permission.WebRequest();
  if(environmentRequest&&webRequest&&environmentRequest.id!==webRequest.id)Fail('AUTHORIZATION_CONFLICT');
  const request=environmentRequest||webRequest;
  const store = require('../bootstrap/peace.desktop-bootstrap-store');
  const reset = require('../bootstrap/peace.desktop-registration-reset');
  const pending = reset.Status();
  if (!request) {
    if (pending && pending.phase !== 'COMPLETE') Fail('PENDING_AUTHORIZATION_REQUIRED');
    return {requested: false};
  }
  if(webRequest)return permission.DuringStartup(webRequest.id,()=>RunAuthorized(request,webRequest));
  return RunAuthorized(request);
}
function RunAuthorized(request,webRequest){
  const store = require('../bootstrap/peace.desktop-bootstrap-store');
  const reset = require('../bootstrap/peace.desktop-registration-reset');
  const db=store.Load(),old=reset.Status(request.id);
  if(webRequest&&old?.phase!=='COMPLETE'){
    const epoch=db.serverRecovery?.epoch||0,job=db.registrationResetJob;
    if(job&&job.phase!=='COMPLETE'&&job.id!==request.id)Fail('IN_PROGRESS');
    if(epoch!==webRequest.expectedEpoch&&!(job?.id===request.id&&job.phase==='APPLIED'&&epoch===webRequest.expectedEpoch+1))Fail('EPOCH_CONFLICT');
  }
  const prepared = reset.Prepare(request.id);
  if (prepared.phase === 'COMPLETE') {
    if(webRequest)ConsumeWebRequest(request.id);
    console.log('REGISTRATION_RESET_ALREADY_COMPLETED', request.id.slice(0, 16));
    return {requested: true, alreadyCompleted: true, id: request.id};
  }
  const licenses = require('../licensing/peace.desktop-licenses');
  const before = {bootstrap: store.Load().secret, license: licenses.DB().signingSecret};
  const next = require('../licensing/peace.desktop-journal').Reset(licenses.DB(), request.id);
  licenses.Import(next);
  const auxiliary = require('./peace.registration-reset-stores');
  auxiliary.Run(request.id);
  reset.Apply(request.id);
  ResetProductionOperations();
  if (store.Load().secret !== before.bootstrap || licenses.DB().signingSecret !== before.license) Fail('KEY_CHANGED');
  const after = Counts();
  if (Object.values(after).some(count => count !== 0)) Fail('INCOMPLETE');
  const related = auxiliary.Counts();
  const relatedFields = {
    machine: ['bindings', 'receipts'],
    integrity: ['records', 'baselines', 'observations'],
    workspace: ['metadata', 'jobs', 'receipts', 'releaseNotes']
  };
  const relatedAfter = {};
  for (const [name, fields] of Object.entries(relatedFields)) {
    relatedAfter[name] = Object.fromEntries(fields.map(field => [field, related[name][field]]));
    if (fields.some(field => related[name][field] !== 0)) Fail('RELATED_STORE_INCOMPLETE');
  }
  const audit = require('../../storage/audit/peace.audit').LogEvent('DESKTOP_REGISTRATION_RESET_APPLIED', JSON.stringify({
    operationId: request.id, scope: SCOPE, after, relatedAfter
  }), {durable: true});
  if (audit?.ok !== true) Fail('AUDIT_SAVE_FAILED');
  if (!require('../../storage/snapshots/peace.database').SaveDatabase()) Fail('SNAPSHOT_SAVE_FAILED');
  reset.Cleanup(request.id);
  const complete = reset.Finish(request.id);
  if(webRequest)ConsumeWebRequest(request.id);
  console.log('REGISTRATION_RESET_COMPLETE', JSON.stringify({
    operationId: request.id, scope: SCOPE, after,
    relatedAfter, artifactFilesCleared: complete.deletedFiles || 0,
    auditHistoryPreserved: true, keysPreserved: true
  }));
  return {requested: true, alreadyCompleted: false, id: request.id, after};
}
function ConsumeWebRequest(id){
  const permission=require('./peace.registration-reset-authorization');
  if(permission.WebRequest()?.id!==id)Fail('WEB_AUTHORIZATION_INVALID');
  require('../storage/peace.desktop-operation-audit').Run('REGISTRATION_RESET_AUTH_CONSUMED','STARTUP_MAINTENANCE',{subject:id},db=>{
    if(permission.Validate(db.registrationResetAuthorization).id!==id||!db.registrationResetReceipts?.[id])Fail('WEB_AUTHORIZATION_INVALID');
    delete db.registrationResetAuthorization;
  });
}
function OperationView(job,authorization){
  if(!job&&!authorization)return null;
  return {id:job?.id||authorization.id,status:job?.phase==='COMPLETE'?'COMPLETE':job?'RUNNING':'QUEUED',requestedAt:authorization?.requestedAt||job.preparedAt,completedAt:job?.completedAt||0};
}
function Status(id){
  if(id!==undefined&&(typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id)))PublicFail('ID_INVALID',400);
  const db=require('../bootstrap/peace.desktop-bootstrap-store').Load();
  const authorization=require('./peace.registration-reset-authorization').WebRequest();
  const job=require('../bootstrap/peace.desktop-registration-reset').Status(id||authorization?.id);
  return {scope:SCOPE,confirmation:CONFIRMATION,epoch:db.serverRecovery?.epoch||0,counts:Counts(),relatedCounts:require('./peace.registration-reset-stores').Counts(),
    operation:OperationView(job,id&&authorization?.id!==id?null:authorization),
    preserved:['서버 키','관리자 로그인 수단','보안 정책과 감사 기록']};
}
function Restart(){
  if(restartStarted)return;restartStarted=true;clearTimeout(restartTimer);
  // Railway ON_FAILURE must relaunch the process. A clean exit would leave the
  // service stopped. Exit 1 also suppresses a misleading pre-reset backup.
  Promise.resolve(require('../../core/peace.lifecycle').Shutdown(1)).catch(()=>process.exit(1));
}
function AfterResponse(res){
  if(!draining||restartStarted)return;
  const finish=()=>setImmediate(Restart);
  res.once('finish',finish);res.once('close',finish);
}
function Schedule(body,session,ticket){
  const guard=require('../authentication/peace.desktop-admin-guard');
  if(!guard.ConsumeSingleAuthorization(ticket,session,'POST',PATH,body))PublicFail('NOT_AUTHORIZED',403);
  if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).sort().join(',')!=='confirmation,expectedEpoch,requestId,scope'||typeof body.requestId!=='string'||!/^[a-f0-9]{64}$/.test(body.requestId)||body.scope!==SCOPE||body.confirmation!==CONFIRMATION||!Number.isSafeInteger(body.expectedEpoch)||body.expectedEpoch<0)PublicFail('REQUEST_INVALID',400);
  const env=Request();if(env&&env.id!==body.requestId)PublicFail('AUTHORIZATION_CONFLICT');
  const store=require('../bootstrap/peace.desktop-bootstrap-store'),db=store.Load(),reset=require('../bootstrap/peace.desktop-registration-reset');
  const old=reset.Status(body.requestId);
  if(old?.phase==='COMPLETE')return {operation:OperationView(old),restartRequired:false};
  const current=require('./peace.registration-reset-authorization').WebRequest();
  if(current&&current.id!==body.requestId||db.registrationResetJob&&db.registrationResetJob.phase!=='COMPLETE'&&db.registrationResetJob.id!==body.requestId)PublicFail('IN_PROGRESS');
  if((db.serverRecovery?.epoch||0)!==body.expectedEpoch)PublicFail('EPOCH_CONFLICT');
  if(Object.keys(db.registrationResetReceipts||{}).length>=reset.MAX_RESETS)PublicFail('RECEIPT_CAPACITY');
  if(!require('../network/peace.ha-coordinator').CanAcceptTraffic())PublicFail('SERVICE_UNAVAILABLE',503);
  if(!current){
    const actor='ADMIN:'+session.id,crypto=require('node:crypto');
    const authorization={version:1,id:body.requestId,scope:SCOPE,requestedAt:Date.now(),actorHash:crypto.createHash('sha256').update(actor).digest('hex'),requestSha512:require('../authentication/peace.admin-action-store').Binding('POST',PATH,body),expectedEpoch:body.expectedEpoch};
    require('./peace.registration-reset-authorization').Validate(authorization);
    require('../storage/peace.desktop-operation-audit').Run('REGISTRATION_RESET_REQUESTED',actor,{subject:body.requestId,epoch:body.expectedEpoch},next=>{
      if(next.registrationResetAuthorization||(next.serverRecovery?.epoch||0)!==body.expectedEpoch)PublicFail('CONFLICT');
      next.registrationResetAuthorization=authorization;
    });
  }
  // Fence admission immediately after the durable intent. Delayed uploads and
  // desktop proof continuations also recheck this fence before committing.
  draining=true;
  require('../network/peace.ha-coordinator').Stop();
  restartTimer=setTimeout(Restart,500);restartTimer.unref();
  return {operation:OperationView(old,require('./peace.registration-reset-authorization').WebRequest()),restartRequired:true};
}
module.exports = {SCOPE, PATH, CONFIRMATION, Request, Counts, Run, Status, Schedule, AfterResponse, IsDraining, AssertAvailable};
