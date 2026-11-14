'use strict';
// Read-only observation of production lifecycle receipts inside a disposable
// Windows fixture. No report/signature/session or timestamps are manufactured.
function Install({service,store,trace,workspace}={}){
 service||=require("../../services/bootstrap/peace.desktop-bootstrap");store||=require("../../services/bootstrap/peace.desktop-bootstrap-store");trace||=require("../../services/observability/peace.desktop-lifecycle-trace");workspace||=require("../../services/operations/peace.desktop-workspace");
 const execute=service.Execute,reports=[],seen=new Set();
 service.Execute=function(body){
  const db=store.Load(),permit=body?.action==='lifecycleReport'&&db.lifecycleTrace?.permits?.[body.permitId];
  const row=permit&&(permit.reporterRole==='O'?Object.values(db.overlays||{}).find(x=>x.sessionId===permit.reporterSessionId):db.flows[permit.flowId]);
  const terminal=!!row&&['CLOSED','REVOKED','EXPIRED'].includes(row.status),expired=!!row&&row.status==='EXPIRED';
  const before=new Set(permit?(db.lifecycleTrace?.flows?.[permit.flowId]?.events||[]).map(x=>x.id):[]);
  const result=execute.apply(this,arguments);
  if(permit&&result?.status==='RECORDED'&&result.permitId===body.permitId&&!seen.has(body.permitId)){
   const events=store.Load().lifecycleTrace?.flows?.[permit.flowId]?.events||[],added=events.filter(x=>!before.has(x.id));
   if(added.length!==result.eventCount||added.some(x=>x.source!=='CLIENT_REPORTED'||x.role!==permit.targetRole||x.reporterRole!==permit.reporterRole||x.reporterSessionId!==permit.reporterSessionId||x.targetSessionId!==permit.targetSessionId))throw Error('LIFECYCLE_FIXTURE_RECEIPT_BINDING_INVALID');
   seen.add(body.permitId);if(reports.length>=32)throw Error('LIFECYCLE_FIXTURE_REPORT_BOUND');
   reports.push({flowId:permit.flowId,reporterRole:permit.reporterRole,targetRole:permit.targetRole,reporterSessionId:permit.reporterSessionId,targetSessionId:permit.targetSessionId,recordedAt:result.recordedAt,eventIds:added.map(x=>x.id),afterAuthorityEnded:terminal,afterLeaseExpired:expired});
  }
  return result;
 };
 function Status(){
  const rows=Object.values(store.Load().flows);if(rows.length!==1)return {flowCount:rows.length,flow:null,overviewMatches:false,workspaceMatches:false,reports:structuredClone(reports)};
  const flow=trace.Flow(rows[0].id),overview=trace.Overview({flowId:flow.flowId,limit:1});
  const detail=rows[0].licenseId?workspace.Detail(rows[0].licenseId):null;
  return {flowCount:1,flow,overviewMatches:overview.items.length===1&&JSON.stringify(overview.items[0])===JSON.stringify(flow),workspaceMatches:!!detail&&JSON.stringify(detail.lifecycle.items.find(x=>x.flowId===flow.flowId))===JSON.stringify(flow),reports:structuredClone(reports)};
 }
 return {Status,Dispose(){service.Execute=execute;seen.clear();reports.length=0;}};
}
module.exports={Install};
