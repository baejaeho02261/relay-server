'use strict';
// Legacy receipt validation only. Requests issued after the approval rollback
// create no receipt and do not consult old receipts for runtime authorization.
// Existing authenticated store history remains readable and tamper checked.
const APPROVAL_MS=60000,HEX=/^[a-f0-9]{64}$/,UPPER=/^[A-F0-9]{64}$/,ID=/^[A-F0-9]{24}$/;
const FIELDS=['version','challengeSha256','requestSha256','canonicalSha256','approvalActorSha256',
 'approvedAt','approvalExpiresAt','consumedAt','launcherId','launcherSha512','flowId','appKeyId',
 'persistentKeyId','machineId','machinePolicyGeneration','epoch','identityRevision'];
const plain=value=>!!value&&Object.getPrototypeOf(value)===Object.prototype;
const integer=value=>Number.isSafeInteger(value)&&value>=0;
function Invalid(){throw Error('KEYLESS_APPROVAL_RECEIPT_INVALID');}
function Validate(receipt,row,launcher){
 if(!plain(receipt)||Object.keys(receipt).sort().join(',')!==FIELDS.slice().sort().join(',')||receipt.version!==1||
  !['challengeSha256','requestSha256','canonicalSha256','approvalActorSha256'].every(k=>HEX.test(receipt[k]||''))||
  !['appKeyId','persistentKeyId','machineId'].every(k=>UPPER.test(receipt[k]||''))||
  !ID.test(receipt.launcherId||'')||!ID.test(receipt.flowId||'')||!/^[a-f0-9]{128}$/.test(receipt.launcherSha512||'')||
  !['approvedAt','approvalExpiresAt','consumedAt','machinePolicyGeneration','epoch','identityRevision'].every(k=>integer(receipt[k]))||
  receipt.approvedAt<1||receipt.approvalExpiresAt<=receipt.approvedAt||receipt.approvalExpiresAt-receipt.approvedAt>APPROVAL_MS||
  receipt.consumedAt<receipt.approvedAt||receipt.consumedAt>=receipt.approvalExpiresAt||
  receipt.consumedAt<row.createdAt||receipt.consumedAt>=row.expiresAt||
  receipt.flowId!==row.id||receipt.launcherId!==row.launcherId||receipt.launcherSha512!==row.launcherSha512||
  receipt.appKeyId!==(row.parentDeviceId||row.deviceId)||receipt.persistentKeyId!==row.keylessPersistentKeyId||
  receipt.machineId!==row.machineId||receipt.machinePolicyGeneration!==row.machinePolicyGeneration||receipt.epoch!==row.serverEpoch||
  !launcher||launcher.configFormat!=='COZY_A_CONFIG_V3'||launcher.keylessApprovalVersion!==1||
  receipt.launcherId!==launcher.id||receipt.launcherSha512!==launcher.sha512||receipt.approvedAt<launcher.issuedAt||receipt.approvalExpiresAt>launcher.expiresAt)Invalid();
 return receipt;
}
module.exports={Validate};
