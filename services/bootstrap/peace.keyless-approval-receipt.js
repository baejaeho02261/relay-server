'use strict';
// This is a consumed-approval receipt, not a bearer capability. It is committed
// in the same authenticated store transaction as the one-use launcher and flow.
// No signature bytes, nonce, token or private identity is retained here.
const crypto=require('node:crypto');
const APPROVAL_MS=60000,HEX=/^[a-f0-9]{64}$/,UPPER=/^[A-F0-9]{64}$/,ID=/^[A-F0-9]{24}$/;
const FIELDS=['version','challengeSha256','requestSha256','canonicalSha256','approvalActorSha256',
 'approvedAt','approvalExpiresAt','consumedAt','launcherId','launcherSha512','flowId','appKeyId',
 'persistentKeyId','machineId','machinePolicyGeneration','epoch','identityRevision'];
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const plain=value=>!!value&&Object.getPrototypeOf(value)===Object.prototype;
const integer=value=>Number.isSafeInteger(value)&&value>=0;
function Invalid(){throw Error('KEYLESS_APPROVAL_RECEIPT_INVALID');}
function Create(p,row,canonical){
 return {version:1,challengeSha256:sha(p.id),requestSha256:p.fingerprint,canonicalSha256:sha(canonical),
  approvalActorSha256:p.approvedByHash,approvedAt:p.approvedAt,approvalExpiresAt:p.approval.expiresAt,
  consumedAt:Date.now(),launcherId:row.launcherId,launcherSha512:row.launcherSha512,flowId:row.id,
  appKeyId:p.begin.deviceId,persistentKeyId:p.persistentKeyId,machineId:p.begin.machineId,
  machinePolicyGeneration:p.machinePolicyGeneration,epoch:p.epoch,identityRevision:p.revision};
}
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
function Matches(receipt,p,row,launcher,canonical){
 Validate(receipt,row,launcher);
 return receipt.challengeSha256===sha(p.id)&&receipt.requestSha256===p.fingerprint&&
  receipt.canonicalSha256===sha(canonical)&&receipt.approvalActorSha256===p.approvedByHash&&
  receipt.approvedAt===p.approvedAt&&receipt.approvalExpiresAt===p.approval?.expiresAt&&
  receipt.persistentKeyId===p.persistentKeyId&&receipt.machinePolicyGeneration===p.machinePolicyGeneration&&
  receipt.epoch===p.epoch&&receipt.identityRevision===p.revision;
}
module.exports={APPROVAL_MS,Create,Validate,Matches};
