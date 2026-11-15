'use strict';
// Read compatibility only: fixture rows represent historical authenticated-store
// receipt structure. This creates no launcher, approval, or execution authority.
const test=require('node:test'),assert=require('node:assert/strict');
const receipts=require('../../services/bootstrap/peace.keyless-approval-receipt');
function fixture(){
 const row={id:'A'.repeat(24),launcherId:'B'.repeat(24),launcherSha512:'c'.repeat(128),createdAt:1500,expiresAt:100000,deviceId:'D'.repeat(64),keylessPersistentKeyId:'E'.repeat(64),machineId:'F'.repeat(64),machinePolicyGeneration:2,serverEpoch:3};
 const launcher={id:row.launcherId,sha512:row.launcherSha512,configFormat:'COZY_A_CONFIG_V3',keylessApprovalVersion:1,issuedAt:1000,expiresAt:100000};
 const receipt={version:1,challengeSha256:'a'.repeat(64),requestSha256:'b'.repeat(64),canonicalSha256:'c'.repeat(64),approvalActorSha256:'d'.repeat(64),approvedAt:1500,approvalExpiresAt:61500,consumedAt:1501,launcherId:row.launcherId,launcherSha512:row.launcherSha512,flowId:row.id,appKeyId:row.deviceId,persistentKeyId:row.keylessPersistentKeyId,machineId:row.machineId,machinePolicyGeneration:2,epoch:3,identityRevision:4};
 return {row,launcher,receipt};
}
test('legacy receipts remain readable with only a validator export',()=>{
 const {receipt,row,launcher}=fixture();assert.deepEqual(Object.keys(receipts),['Validate']);
 const before=JSON.stringify({receipt,row,launcher});assert.equal(receipts.Validate(receipt,row,launcher),receipt);
 assert.equal(JSON.stringify({receipt,row,launcher}),before,'validation is read only');
});
test('legacy history cannot be substituted or silently stripped of binding fields',()=>{
 const {receipt,row,launcher}=fixture();
 for(const [key,value] of Object.entries({flowId:'C'.repeat(24),launcherId:'D'.repeat(24),launcherSha512:'d'.repeat(128),appKeyId:'A'.repeat(64),persistentKeyId:'B'.repeat(64),machineId:'C'.repeat(64),machinePolicyGeneration:3,epoch:4,consumedAt:61500,approvalExpiresAt:61501,unexpected:true})){
  assert.throws(()=>receipts.Validate({...receipt,[key]:value},row,launcher),{message:'KEYLESS_APPROVAL_RECEIPT_INVALID'},key);
 }
 for(const key of Object.keys(receipt)){const changed={...receipt};delete changed[key];assert.throws(()=>receipts.Validate(changed,row,launcher),{message:'KEYLESS_APPROVAL_RECEIPT_INVALID'},key);}
});
