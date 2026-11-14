'use strict';
// Pre-bootstrap enrollment candidates carry public metadata only. They grant
// neither execution nor recovery until certify/activate, explicit administrator
// acknowledgement and the exact issued-A consume transaction all succeed.
const crypto=require('node:crypto'),identity=require('../devices/peace.desktop-device-identity');
const registry=require('../devices/peace.desktop-device-registry');
const Stable=require('../protocol/peace.desktop-request-protocol').Stable;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function Fail(code,status=403){throw Object.assign(Error(code),{desktopError:true,bootstrapError:true,status});}
function Snapshot(machineId,db){
 const s=identity.State(db),bindingId=registry.BindingId(machineId,db);
 const rows=Object.values(s.enrollments).filter(r=>r.bindingId===bindingId).map(r=>({id:r.id,keyId:r.keyId,status:r.status,assurance:r.assurance,attestedUntil:r.attestedUntil||0,rootSha256:r.rootSha256||''})).sort((a,b)=>a.id.localeCompare(b.id));
 return sha(Stable({bindingId,rows,revision:s.revision,mode:s.mode,generation:s.keyGenerations?.[bindingId]||0,trust:s.trust||null}));
}
function Candidate(publicKey,machineId,provider,db){
 try{return {key:identity.CheckBootstrapKey(publicKey,machineId,provider,db),candidate:null};}
 catch(error){if(provider!=='PLATFORM'||!['DEVICE_TPM_REQUIRED','DEVICE_RECOVERY_REQUIRED'].includes(error.message))throw error;}
 const policy=identity.BootstrapPolicy(machineId,db),s=identity.State(db);
 if(policy.keyProvider!=='PLATFORM'||!policy.trustConfigured)Fail('DEVICE_TPM_TRUST_NOT_CONFIGURED');
 const key=require('../licensing/peace.desktop-licenses').ParseKey(publicKey),bindingId=registry.BindingId(machineId,db),enrollmentId=identity.EnrollmentId(publicKey,db);
 const old=s.enrollments[enrollmentId];
 if(old&&(old.status!=='ACTIVE'||old.bindingId!==bindingId))Fail('DEVICE_KEY_REVOKED');
 const related=Object.values(s.enrollments).filter(r=>r.bindingId===bindingId),active=related.filter(r=>r.status==='ACTIVE');
 if(active.length>1)Fail('DEVICE_RECOVERY_CONFLICT',409);
 const previous=active[0]||related.sort((a,b)=>(b.revokedAt||b.enrolledAt)-(a.revokedAt||a.enrolledAt))[0];
 return {key:{keyId:key.deviceId,bindingId},candidate:{enrollmentId,bindingId,keyId:key.deviceId,
   oldEnrollmentId:previous?.id||'',oldKeyId:previous?.keyId||'',
   kind:previous&&previous.id!==enrollmentId?'REPLACE':previous?'RENEW':'ENROLL',
   snapshot:Snapshot(machineId,db)}};
}
function Assert(p,db){
 const c=p.tpmCandidate;if(!c)return;
 if(Snapshot(p.begin.machineId,db)!==c.snapshot)Fail('DEVICE_RECOVERY_CONFLICT',409);
 const policy=identity.BootstrapPolicy(p.begin.machineId,db);
 if(policy.keyProvider!=='PLATFORM'||!policy.trustConfigured)Fail('DEVICE_TPM_TRUST_NOT_CONFIGURED');
 if(p.tpmVerified&&p.tpmVerified.notAfter<=Date.now())Fail('DEVICE_TPM_REQUIRED');
}
function ActivationCanonical(p,secret){return ['COZY-KEYLESS-TPM-ACTIVATE-V1',p.id,p.begin.launcherId,p.begin.machineId,p.persistentKeyId,sha(secret)].join('\n');}
function Projection(p){
 const c=p.tpmCandidate;if(!c)return undefined;
 return {kind:c.kind,oldEnrollmentId:c.oldEnrollmentId,oldKeyId:c.oldKeyId,newKeyId:p.persistentKeyId,
   bindingId:c.bindingId,identityRevision:p.revision,hardwareAttested:!!p.tpmVerified,
   physicalPcIdentity:'ADMINISTRATOR_VERIFICATION_REQUIRED'};
}
function Approve(p,value){
 const expected=Projection(p);if(!expected)return;
 if(!p.tpmVerified||!value||Object.getPrototypeOf(value)!==Object.prototype||
   Stable(value)!==Stable({kind:expected.kind,oldEnrollmentId:expected.oldEnrollmentId,oldKeyId:expected.oldKeyId,
     newKeyId:expected.newKeyId,bindingId:expected.bindingId,identityRevision:expected.identityRevision,confirmed:true}))
   Fail('DEVICE_RECOVERY_APPROVAL_REQUIRED',400);
}
function Commit(p,db){
 const c=p.tpmCandidate;if(!c)return;
 Assert(p,db);if(!p.tpmVerified||p.tpmVerified.notAfter<=Date.now())Fail('DEVICE_TPM_REQUIRED');
 db.deviceIdentity||=identity.Empty();const s=db.deviceIdentity,at=Date.now();
 if(!s.enrollments[c.enrollmentId]&&Object.keys(s.enrollments).length>=100000)Fail('DEVICE_IDENTITY_CAPACITY',503);
 // CommitBegin runs before the new flow is inserted, so only previous sessions
 // are retired. The current launcher is still AVAILABLE and is not reset.
 registry.RetireSessions(db,c.bindingId);
 for(const r of Object.values(s.enrollments))if(r.bindingId===c.bindingId&&r.id!==c.enrollmentId&&r.status==='ACTIVE'){r.status='RETIRED';r.revokedAt=at;}
 for(const[id,binding]of Object.entries(s.legacyFlows||{}))if(binding===c.bindingId)delete s.legacyFlows[id];
 const prior=s.enrollments[c.enrollmentId];
 s.enrollments[c.enrollmentId]={id:c.enrollmentId,bindingId:c.bindingId,keyId:c.keyId,publicKey:p.persistentPublicKey,
   status:'ACTIVE',assurance:'TPM_KEY_ATTESTED',enrolledAt:prior?.enrolledAt||at,lastSeenAt:at,
   rootSha256:p.tpmVerified.rootSha256,attestedUntil:p.tpmVerified.notAfter};
 delete s.recoveryGrants[c.bindingId];
 // No wildcard grant, key namespace increment, PC unblock or license carry-over.
 // Enrollment state changes invalidate older candidates through Snapshot.
}
module.exports={Candidate,Assert,ActivationCanonical,Projection,Approve,Commit};
