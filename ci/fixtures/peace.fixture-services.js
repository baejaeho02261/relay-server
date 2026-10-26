'use strict';
// Shared CI fixture setup tested with synthetic PE input in portable regression.
// Real Windows integration supplies final built EXEs, never synthetic reports.
const fs=require('node:fs'),path=require('node:path');
function PrivateRoot(run){
 const named=path.resolve(run),root=fs.realpathSync(run),data=path.join(root,'server-data');
 if(root!==named||!fs.existsSync(path.join(root,'ci-owned-marker'))||path.resolve(process.env.DATA_DIR||'')!==data||require('../../config/peace.runtime-configuration').DATA_DIR!==data)throw Error('CI_PRIVATE_DATA_DIR_REQUIRED');
 return root;
}
function Provision(run,out,version){
 const root=PrivateRoot(run);
 const db=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load();
 if(Object.keys(db.artifacts).length||Object.keys(db.flows).length||Object.keys(db.serverPolicies||{}).length||db.securityAuthorityPolicy)throw Error('CI_FIXTURE_MUST_BE_EMPTY');
 const bootstrap=require("../../services/bootstrap/peace.desktop-bootstrap"),authority=require("../../services/security/peace.desktop-security-authority"),ops=require("../../services/security/peace.desktop-security-operations"),prov=require("../../services/artifacts/peace.desktop-release-provenance");
 const policy=authority.ValidatePolicy(JSON.parse(fs.readFileSync(path.join(out,'policy.json'),'utf8')));
 // Provision only this newly created empty fixture; preserve reviewed production
 // revision so the exact policy digest can later be registered on that server.
 require("../../services/bootstrap/peace.desktop-bootstrap-store").Atomic(db=>{if(db.securityAuthorityPolicy)throw Error('CI_POLICY_ALREADY_EXISTS');db.securityAuthorityPolicy=structuredClone(policy);ops.RememberReleaseKeys(db,policy.trustedReleaseKeys);});
 if(prov.PolicyDigest(authority.Policy())!==prov.PolicyDigest(policy))throw Error('CI_POLICY_MISMATCH');
 // A final-file execution run imports the operator's exact recorded cohort
 // into this NEW private fixture only. This neither manufactures packing
 // records nor attests their production origin. The result is not CI proof.
 if(fs.existsSync(path.join(out,'final-execution-inputs.json'))){
  const inputs=require('../pipeline/peace.final-windows-inputs'),input=inputs.Verify(out);
  if(input.releaseVersion!==version)throw Error('CI_FINAL_VERSION_MISMATCH');
  const evidence=require('../../services/artifacts/peace.desktop-packing-evidence');
  const records=JSON.parse(fs.readFileSync(path.join(out,'packing-receipts.json'),'utf8'));
  inputs.CheckReceipts(records,input.artifacts);
  const map=Object.fromEntries(records.map(record=>[evidence.ReceiptId(record),record]));
  let serverPolicies,artifacts;
  if(input.protectionEngine==='COZY_SERVER_POLICY_V2'){
   serverPolicies=inputs.CheckServerPolicies(JSON.parse(fs.readFileSync(path.join(out,'server-policies.json'),'utf8')),input.artifacts);
   artifacts=Object.fromEntries(['A','B','O'].map(role=>[role,{bytes:fs.readFileSync(path.join(out,role+'.exe'))}]));
  }
  try{
  require('../../services/bootstrap/peace.desktop-bootstrap-store').Atomic(next=>{
   if(Object.keys(next.artifacts).length||Object.keys(next.flows).length||Object.keys(next.packingEvidence||{}).length||Object.keys(next.serverPolicies||{}).length)throw Error('CI_FIXTURE_MUST_BE_EMPTY');
   next.packingEvidence=map;evidence.ValidateStore(next);
   if(serverPolicies)require('../../services/security/peace.server-policy-registry').RecordPoliciesForExistingReceipts(next,records,serverPolicies,artifacts);
  });
  }finally{if(artifacts)for(const value of Object.values(artifacts))value.bytes.fill(0);}
 }
 const manifest=JSON.parse(fs.readFileSync(path.join(out,'manifest.json'),'utf8'));ops.PlanReleaseManifest({expectedRevision:ops.Revision(),...manifest},'ISOLATED_WINDOWS_CI');
 ops.SetReleaseGovernance({expectedRevision:ops.Revision(),requireManifest:true},'ISOLATED_WINDOWS_CI');
 const selected={};for(const role of ['A','B','O'])selected[role]=ops.Stage(role,version,fs.readFileSync(path.join(out,role+'.exe')),JSON.parse(fs.readFileSync(path.join(out,role+'.approval.json'),'utf8')),'ISOLATED_WINDOWS_CI',manifest.manifestId);
 ops.RecordReleaseManifest({expectedRevision:ops.Revision(),...manifest},'ISOLATED_WINDOWS_CI');ops.ActivatePair({expectedRevision:ops.Revision(),expectedPolicyRevision:authority.Policy().revision,aId:selected.A.id,bId:selected.B.id,oId:selected.O.id},'ISOLATED_WINDOWS_CI');

 return selected;
}
function KeylessApproval(run,out,issue){
 // Test-only enrollment for one new launcher inside the owned, empty fixture.
 // There is no production environment flag or generic automatic approval path.
 PrivateRoot(run);
 function Loopback(){if(process.env.DESKTOP_PUBLIC_HOST!=='127.0.0.1'||process.env.WEB_ADMIN_PORT!=='0'||process.env.HA_ENABLED!=='0')throw Error('CI_KEYLESS_LOOPBACK_FIXTURE_REQUIRED');}
 Loopback();
 const inputs=require('../pipeline/peace.final-windows-inputs');
 if(!fs.existsSync(path.join(out,'final-execution-inputs.json')))return null;
 const context=inputs.Verify(out);if(context.protectionEngine!=='COZY_SERVER_POLICY_V2')return null;
 const store=require('../../services/bootstrap/peace.desktop-bootstrap-store'),db=store.Load(),row=db.launchers[issue?.launcherId];
 if(!row||row.configFormat!=='COZY_A_CONFIG_V3'||row.status!=='AVAILABLE'||Object.keys(db.launchers).length!==1||Object.keys(db.flows).length)throw Error('CI_KEYLESS_FRESH_LAUNCHER_REQUIRED');
 const keyless=require('../../services/bootstrap/peace.keyless-bootstrap');
 if(keyless.ListPending().requests.length)throw Error('CI_KEYLESS_PENDING_MUST_BE_EMPTY');
 const expected={launcherId:row.id,sha512:row.sha512};let approved=false;
 return ()=>{
  PrivateRoot(run);Loopback();if(approved)return true;
  const requests=keyless.ListPending().requests;if(!requests.length)return false;
  if(requests.length!==1)throw Error('CI_KEYLESS_REQUEST_AMBIGUOUS');
  const p=requests[0];
  if(p.launcherId!==expected.launcherId||p.launcherSha512!==expected.sha512||p.status!=='PENDING_APPROVAL'||p.proof!=='PERSISTENT_KEY_POSSESSION'||p.hardwareAttested!==false)throw Error('CI_KEYLESS_REQUEST_MISMATCH');
  const result=keyless.Approve(p.id,{identityConfirmed:true,persistentKeyId:p.persistentKeyId,launcherId:expected.launcherId},'ISOLATED_WINDOWS_CI');
  if(result.id!==p.id||result.status!=='APPROVED')throw Error('CI_KEYLESS_APPROVAL_FAILED');
  approved=true;return true;
 };
}
function ClaimObservationBarrier(run,updateStatus){
 // The production single-writer/proof commit remains synchronous and intact.
 // This isolated fixture briefly holds its successful claim response so the
 // controller can retain B's real JobObject-owned process handle before B can
 // automatically redeem and transfer to O. It is not performance evidence.
 PrivateRoot(run);
 if(process.env.DESKTOP_PUBLIC_HOST!=='127.0.0.1'||process.env.WEB_ADMIN_PORT!=='0'||process.env.HA_ENABLED!=='0'||typeof updateStatus!=='function')throw Error('CI_CLAIM_OBSERVER_FIXTURE_REQUIRED');
 const ack=path.join(run,'b-process-observed.signal');if(fs.existsSync(ack))throw Error('CI_CLAIM_OBSERVER_NEW_SIGNAL_REQUIRED');
 const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap'),original=bootstrap.Execute,wait=new Int32Array(new SharedArrayBuffer(4));let observed=false;
 const wrapped=body=>{
  const result=original(body);
  if(body?.action!=='claim'||observed)return result;
  const end=require('node:perf_hooks').performance.now()+3000;
  while(true){
   PrivateRoot(run);updateStatus();
   if(fs.existsSync(ack)){
    const stat=fs.lstatSync(ack);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.size!==27||fs.readFileSync(ack,'utf8')!=='COZY_B_PROCESS_OBSERVED_V1\n')throw Error('CI_CLAIM_OBSERVER_SIGNAL_INVALID');
    observed=true;return result;
   }
   if(require('node:perf_hooks').performance.now()>=end)throw Error('CI_CLAIM_OBSERVER_TIMEOUT');
   Atomics.wait(wait,0,0,20);
  }
 };
 bootstrap.Execute=wrapped;
 return {Used:()=>observed,Restore:()=>{if(bootstrap.Execute===wrapped)bootstrap.Execute=original;}};
}
function Status(){const store=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load(),flows=Object.values(store.flows),overlays=Object.values(store.overlays||{});return{version:1,ready:true,flowCount:flows.length,overlayCount:overlays.length,flowStatus:flows[0]?.status||'',overlayStatus:overlays[0]?.status||'',overlayAuthorized:!!overlays[0]?.authorizedAt,transferCommitted:flows[0]?.closedByOverlay===true&&overlays[0]?.transferVersion===1,licenseUsed:require("../../services/licensing/peace.desktop-licenses").List().counts.USED===1,retiredParent:!!flows[0]?.retiredAt,retiredOverlay:!!overlays[0]?.retiredAt};}
module.exports={Provision,Status,KeylessApproval,ClaimObservationBarrier};
