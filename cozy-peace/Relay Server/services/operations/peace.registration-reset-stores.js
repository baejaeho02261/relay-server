'use strict';
// One-time startup maintenance. HTTP can queue, but never execute, a reset.
// Every store advances its existing authenticated history and retains receipts.
const SCOPE='ABO_LICENSES_ISSUANCE_OPERATIONS_V1';
const ID=/^[a-f0-9]{64}$/;
function Fail(code){throw Error(code);}
function Plain(value){return !!value&&Object.getPrototypeOf(value)===Object.prototype;}
function AssertAuthorized(operationId){
 if(typeof operationId!=='string'||!ID.test(operationId))Fail('REGISTRATION_RESET_NOT_AUTHORIZED');
 require('./peace.registration-reset-authorization').Assert(operationId);
 const db=require('../bootstrap/peace.desktop-bootstrap-store').Load(),job=db.registrationResetJob;
 if(!job||job.version!==1||job.id!==operationId||!['PREPARED','APPLIED'].includes(job.phase)||Object.hasOwn(db.registrationResetReceipts||{},operationId))Fail('REGISTRATION_RESET_NOT_AUTHORIZED');
 return job;
}
function WorkspaceReceipts(value,revision){
 const rows=value===undefined?{}:value;
 if(!Plain(rows)||Object.keys(rows).length>1024)Fail('REGISTRATION_RESET_WORKSPACE_RECEIPT_INVALID');
 for(const [id,r]of Object.entries(rows))if(!ID.test(id)||!Plain(r)||Object.keys(r).sort().join(',')!=='at,jobs,metadata,receipts,releaseNotes,revision'||!Number.isSafeInteger(r.at)||r.at<1||!Number.isSafeInteger(r.revision)||r.revision<1||r.revision>revision||['metadata','jobs','receipts','releaseNotes'].some(k=>!Number.isSafeInteger(r[k])||r[k]<0))Fail('REGISTRATION_RESET_WORKSPACE_RECEIPT_INVALID');
 return rows;
}
function ResetWorkspace(operationId){
 AssertAuthorized(operationId);const store=require('./peace.desktop-workspace-store'),before=store.Load(),receipts=WorkspaceReceipts(before.registrationResetReceipts,before.revision),prior=receipts[operationId];
 if(prior)return {...prior,duplicate:true};
 if(Object.keys(receipts).length>=1024)Fail('REGISTRATION_RESET_RECEIPT_CAPACITY');
 const result={at:Date.now(),revision:before.revision+1,metadata:Object.keys(before.metadata).length,jobs:Object.keys(before.jobs).length,receipts:Object.keys(before.receipts).length,releaseNotes:Object.keys(before.releaseNotes||{}).length};
 store.Atomic(next=>{
  AssertAuthorized(operationId);
  if(next.revision!==before.revision||Object.hasOwn(WorkspaceReceipts(next.registrationResetReceipts,next.revision),operationId))Fail('REGISTRATION_RESET_WORKSPACE_CONFLICT');
  next.metadata={};next.jobs={};next.receipts={};next.releaseNotes={};next.registrationResetReceipts={...receipts,[operationId]:result};
 },{kind:'REGISTRATION_RESET_WORKSPACE',actor:'STARTUP_MAINTENANCE'});
 return {...result,duplicate:false};
}
function Counts(){
 const machine=require('../devices/peace.desktop-machine-policy').RegistrationStatus(),integrity=require('../integrity/peace.desktop-integrity-reports').RegistrationStatus(),workspace=require('./peace.desktop-workspace-store').Load();
 WorkspaceReceipts(workspace.registrationResetReceipts,workspace.revision);
 return {machine,integrity,workspace:{metadata:Object.keys(workspace.metadata).length,jobs:Object.keys(workspace.jobs).length,receipts:Object.keys(workspace.receipts).length,releaseNotes:Object.keys(workspace.releaseNotes||{}).length,revision:workspace.revision,resetReceipts:Object.keys(workspace.registrationResetReceipts||{}).length}};
}
function Run(operationId){
 AssertAuthorized(operationId);
 return {machine:require('../devices/peace.desktop-machine-policy').ResetRegistrations(operationId),integrity:require('../integrity/peace.desktop-integrity-reports').ResetRegistrations(operationId),workspace:ResetWorkspace(operationId)};
}
module.exports={SCOPE,AssertAuthorized,Run,Counts,Status:Counts,ResetWorkspace};
