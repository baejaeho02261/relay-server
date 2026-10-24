"use strict";
// Revocation tombstones live in the authenticated, witness-fenced native
// authority, not the restorable administrator database. No un-revoke API.
function Validate(rows){if(!rows||Object.getPrototypeOf(rows)!==Object.prototype||Object.keys(rows).length>4096)throw Error('ADMIN_REVOCATION_STORAGE_INVALID');for(const [id,v]of Object.entries(rows))if(!/^[A-F0-9]{24}$/.test(id)||!v||!Number.isSafeInteger(v.at)||v.at<1)throw Error('ADMIN_REVOCATION_STORAGE_INVALID');}
function Rows(){const rows=require("../bootstrap/peace.desktop-bootstrap-store").Load().adminCredentialRevocations||{};Validate(rows);return rows;}
function At(id){return Rows()[id]?.at||0;}
function Mark(id,actor='ADMIN',at=Date.now()){
 if(!/^[A-F0-9]{24}$/.test(id)||!Number.isSafeInteger(at)||at<1)throw Error('ADMIN_REVOCATION_INPUT_INVALID');
 const old=At(id);if(old)return old;
 return require("../storage/peace.desktop-operation-audit").Run('ADMIN_CREDENTIAL_REVOKE',actor,{credentialId:id},db=>{
  const rows=db.adminCredentialRevocations||{};Validate(rows);
  if(rows[id])return rows[id].at;if(Object.keys(rows).length>=4096)throw Error('ADMIN_REVOCATION_CAPACITY');
  rows[id]={at};db.adminCredentialRevocations=rows;return at;
 });
}
function Reconcile(){for(const c of require("../../core/peace.runtime-state").production.passkeyCredentials.values())if(c.revokedAt)Mark(c.id,'STARTUP_REVOCATION_RECONCILE',c.revokedAt);}
module.exports={Validate,Rows,At,Mark,Reconcile};
