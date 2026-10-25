'use strict';
// Shared CI fixture setup tested with synthetic PE input in portable regression.
// Real Windows integration supplies final built EXEs, never synthetic reports.
const fs=require('node:fs'),path=require('node:path');
function Provision(run,out,version){
 const root=fs.realpathSync(run),data=path.join(root,'server-data');
 if(!fs.existsSync(path.join(root,'ci-owned-marker'))||path.resolve(process.env.DATA_DIR||'')!==data||require("../../config/peace.runtime-configuration").DATA_DIR!==data)throw Error('CI_PRIVATE_DATA_DIR_REQUIRED');
 const db=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load();
 if(Object.keys(db.artifacts).length||Object.keys(db.flows).length||db.securityAuthorityPolicy)throw Error('CI_FIXTURE_MUST_BE_EMPTY');
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
  require('../../services/bootstrap/peace.desktop-bootstrap-store').Atomic(next=>{
   if(Object.keys(next.artifacts).length||Object.keys(next.flows).length||Object.keys(next.packingEvidence||{}).length)throw Error('CI_FIXTURE_MUST_BE_EMPTY');
   next.packingEvidence=map;evidence.ValidateStore(next);
  });
 }
 const manifest=JSON.parse(fs.readFileSync(path.join(out,'manifest.json'),'utf8'));ops.PlanReleaseManifest({expectedRevision:ops.Revision(),...manifest},'ISOLATED_WINDOWS_CI');
 ops.SetReleaseGovernance({expectedRevision:ops.Revision(),requireManifest:true},'ISOLATED_WINDOWS_CI');
 const selected={};for(const role of ['A','B','O'])selected[role]=ops.Stage(role,version,fs.readFileSync(path.join(out,role+'.exe')),JSON.parse(fs.readFileSync(path.join(out,role+'.approval.json'),'utf8')),'ISOLATED_WINDOWS_CI',manifest.manifestId);
 ops.RecordReleaseManifest({expectedRevision:ops.Revision(),...manifest},'ISOLATED_WINDOWS_CI');ops.ActivatePair({expectedRevision:ops.Revision(),expectedPolicyRevision:authority.Policy().revision,aId:selected.A.id,bId:selected.B.id,oId:selected.O.id},'ISOLATED_WINDOWS_CI');

 return selected;
}
function Status(){const store=require("../../services/bootstrap/peace.desktop-bootstrap-store").Load(),flows=Object.values(store.flows),overlays=Object.values(store.overlays||{});return{version:1,ready:true,flowCount:flows.length,overlayCount:overlays.length,flowStatus:flows[0]?.status||'',overlayStatus:overlays[0]?.status||'',overlayAuthorized:!!overlays[0]?.authorizedAt,transferCommitted:flows[0]?.closedByOverlay===true&&overlays[0]?.transferVersion===1,licenseUsed:require("../../services/licensing/peace.desktop-licenses").List().counts.USED===1,retiredParent:!!flows[0]?.retiredAt,retiredOverlay:!!overlays[0]?.retiredAt};}
module.exports={Provision,Status};
