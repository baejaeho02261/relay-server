'use strict';
// Real isolated server projection plus synthetic enrollment metadata. This
// tests status semantics; it is neither TPM attestation nor Windows execution.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{execFileSync}=require('node:child_process');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-capabilities-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_RECOVERY_WITNESS_REQUIRED:'0',ADMIN_SECRET:'SYNTHETIC-CAPABILITY-TEST'});
require("../../core/peace.utilities.js").EnsureDirs();
const capability=require("../../services/runtime/peace.desktop-capabilities"),store=require("../../services/bootstrap/peace.desktop-bootstrap-store");
const ops=require("../../services/security/peace.desktop-security-operations"),authority=require("../../services/security/peace.desktop-security-authority"),recovery=require("../../services/recovery/peace.desktop-recovery");
let checks=0;function test(name,run){run();checks++;console.log('PASS '+name);}
const feature=(s,id)=>s.features.find(x=>x.id===id);
const identity=(patch={})=>({deviceIdentity:{version:2,revision:5,mode:'COMPATIBLE',requireForEnrolled:true,enrollments:{},...patch}});
(async()=>{try{
 // Generated temporary test CAs are never installed as application trust.
 function root(name){execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',name+'.key','-out',name+'.pem','-subj','/CN=SYNTHETIC CAPABILITY TEST '+name,'-days','1','-addext','basicConstraints=critical,CA:TRUE'],{cwd:temp,stdio:'pipe',timeout:10000});const pem=fs.readFileSync(path.join(temp,name+'.pem'),'utf8'),cert=new crypto.X509Certificate(pem);return {pem,cert,id:crypto.createHash('sha256').update(cert.raw).digest('hex')};}
 const firstRoot=root('one'),secondRoot=root('two'),now=Date.now();
 const trust=()=>({validUntil:now+60000,roots:[firstRoot.pem],revokedCertificateSha256:[]});
 test('Defaults expose implemented optional TPM instead of falsely claiming it absent',()=>{
  const status=capability.DeviceState(identity(),now);
  assert.equal(status.tpmImplemented,true);assert.equal(status.tpmRequired,false);
  assert.equal(status.clientPersistence,'OS_CNG_NAMED_DEVICE_KEY_OPTIONAL');
  assert.equal(status.tpmAttestation,'AVAILABLE_TRUST_NOT_CONFIGURED');
  assert.equal(status.verification.status,'NOT_RECORDED');
  assert.equal(status.persistentKeyRequired,false);assert.equal(status.persistentKeyRequiredForEnrolled,true);assert.equal(status.persistentKeyRequirementScope,'ENROLLED_DEVICES');
 });
 test('Compatible mode distinguishes enrolled-only requirement from globally optional keys',()=>{
  const status=capability.DeviceState(identity({requireForEnrolled:false}),now);
  assert.equal(status.persistentKeyRequired,false);assert.equal(status.persistentKeyRequiredForEnrolled,false);assert.equal(status.persistentKeyRequirementScope,'OPTIONAL');
 });
 test('Persistent mode and enrollment metadata never imply TPM or Windows verification',()=>{
  const status=capability.DeviceState(identity({mode:'PERSISTENT',enrollments:{a:{status:'ACTIVE',assurance:'PERSISTENT_KEY_POSSESSION',publicKey:'DO_NOT_EXPOSE',machineId:'DO_NOT_EXPOSE'}}}),now);
  assert.equal(status.persistentKeyRequired,true);assert.equal(status.activeEnrollments,1);
  assert.equal(status.tpmActiveEnrollments,0);assert.equal(status.trustConfigured,false);
  assert.equal(status.clientPersistence,'OS_CNG_NAMED_DEVICE_KEY_REQUIRED');
  assert.equal(status.persistentKeyRequirementScope,'ALL_DEVICES');assert.equal(status.persistentKeyRequiredForEnrolled,true);
  assert(!JSON.stringify(status).includes('DO_NOT_EXPOSE'));
 });
 test('TPM requirement, available trust and expiring enrollment are independent values',()=>{
  const db=identity({mode:'TPM_ATTESTED',trust:{...trust(),validUntil:now+1000},enrollments:{a:{status:'ACTIVE',assurance:'TPM_KEY_ATTESTED',attestedUntil:now+500,rootSha256:firstRoot.id},b:{status:'REVOKED',assurance:'TPM_KEY_ATTESTED',attestedUntil:now+2000,rootSha256:firstRoot.id}}});
  let s=capability.DeviceState(db,now);assert.equal(s.tpmRequired,true);assert.equal(s.trustConfigured,true);assert.equal(s.tpmActiveEnrollments,1);assert.equal(s.tpmUnexpiredEnrollments,1);assert.equal(s.tpmCurrentRootEnrollments,1);assert.equal(s.tpmAttestation,'REQUIRED_BY_POLICY');
  s=capability.DeviceState(db,now+500);assert.equal(s.tpmUnexpiredEnrollments,0);assert.equal(s.tpmActiveEnrollments,1);assert.equal(s.trustConfigured,true);
  s=capability.DeviceState(db,now+1000);assert.equal(s.trustConfigured,false);assert.equal(s.tpmAttestation,'REQUIRED_TRUST_UNAVAILABLE');assert.equal(s.verification.status,'NOT_RECORDED');
  assert(!JSON.stringify(s).includes('BEGIN CERTIFICATE'));
 });
 test('Removed, replaced, revoked and expired roots cannot count as currently trusted enrollment roots',()=>{
  const db=identity({trust:trust(),enrollments:{a:{status:'ACTIVE',assurance:'TPM_KEY_ATTESTED',attestedUntil:now+30000,rootSha256:firstRoot.id}}});
  for(const current of [{...trust(),roots:[]},{...trust(),roots:[secondRoot.pem]},{...trust(),revokedCertificateSha256:[firstRoot.id]},{...trust(),validUntil:now}]){
   db.deviceIdentity.trust=current;const s=capability.DeviceState(db,now);assert.equal(s.tpmUnexpiredEnrollments,1);assert.equal(s.tpmCurrentRootEnrollments,0);assert.equal(s.tpmAttestation,'ENROLLED_REQUIRES_REVALIDATION');
  }
  const afterCertificateExpiry=Date.parse(firstRoot.cert.validTo);
  db.deviceIdentity.trust={...trust(),validUntil:afterCertificateExpiry+60000};db.deviceIdentity.enrollments.a.attestedUntil=afterCertificateExpiry+30000;
  let s=capability.DeviceState(db,afterCertificateExpiry);assert.equal(s.tpmUnexpiredEnrollments,1);assert.equal(s.tpmCurrentRoots,0);assert.equal(s.tpmCurrentRootEnrollments,0);
  db.deviceIdentity.trust=trust();db.deviceIdentity.enrollments.a.attestedUntil=now+30000;s=capability.DeviceState(db,now);assert.equal(s.tpmCurrentRoots,1);assert.equal(s.tpmCurrentRootEnrollments,1);assert.equal(s.tpmAttestation,'ENROLLED_OPTIONAL');
 });
 test('Live policy projection is read-only and manual publication never manufactures test results',()=>{
  const db=store.Load();require("../../services/licensing/peace.desktop-licenses").DB();authority.Policy();ops.State();
  // Simulate a loaded legacy runtime policy; a GET must not migrate it.
  const old=db.securityOperations;db.securityOperations=structuredClone(ops.State());db.securityOperations.releaseGovernance.requireManifest=true;
  try{
   const before=JSON.stringify(db),s=capability.Status();assert.equal(JSON.stringify(db),before);
   assert.deepEqual(s.features.map(x=>x.id),Array.from({length:14},(_,i)=>String(i+1)));
   assert.equal(feature(s,'4').configured.requirements.requireReleaseSignature,true);
   assert.equal(feature(s,'4').configured.runtime.requireManifest,true);
   assert.equal(s.windowsVerification,'NOT_RECORDED');assert.equal(s.evidencePolicy,'NO_AUTOMATIC_PASS');
   assert(s.features.every(x=>x.verification.status==='NOT_RECORDED'&&x.verification.evidenceCreated===false));
   assert.equal(feature(s,'5').implementation,'PARTIAL');assert.equal(feature(s,'13').configured.requiredForPublication,false);
   assert(!JSON.stringify(s).includes(db.secret));
  }finally{if(old===undefined)delete db.securityOperations;else db.securityOperations=old;}
 });
 test('Recovery and capability views track current identity mode without cached hardcoded labels',()=>{
  const db=store.Load(),old=db.deviceIdentity;
  try{
   db.deviceIdentity=identity({mode:'PERSISTENT'}).deviceIdentity;
   let s=recovery.Status();assert.equal(s.clientPersistence,'OS_CNG_NAMED_DEVICE_KEY_REQUIRED');assert.equal(s.deviceIdentity.mode,'PERSISTENT');
   db.deviceIdentity=identity({mode:'TPM_ATTESTED',trust:trust()}).deviceIdentity;
   s=recovery.Status();assert.equal(s.tpmAttestation,'REQUIRED_BY_POLICY');assert.equal(feature(capability.Status(),'12').configured.mode,'TPM_ATTESTED');
   db.deviceIdentity=identity().deviceIdentity;s=recovery.Status();assert.equal(s.clientPersistence,'OS_CNG_NAMED_DEVICE_KEY_OPTIONAL');assert.equal(s.tpmAttestation,'AVAILABLE_TRUST_NOT_CONFIGURED');
  }finally{if(old===undefined)delete db.deviceIdentity;else db.deviceIdentity=old;}
 });
 const route=require("../../web/routes/web/peace.desktop-server-state-routes"),auth=require("../../web/authentication/peace.web-auth");
 const req={headers:{},socket:{remoteAddress:'127.0.0.1',encrypted:true}};
 async function get(session){let status,body;const res={writeHead(value){status=value;},end(text){body=JSON.parse(text);}};assert.equal(await route.Handle({method:'GET',pathname:'/api/desktop/bootstrap/server-state/capabilities',req,res,session}),true);return {status,body};}
 const anonymous=await get(null);assert.equal(anonymous.status,403);
 const viewer=await get({id:'VIEWER',role:'viewer'});assert.equal(viewer.status,403);
 const expired=auth.CreateSession(req,'admin');expired.expiresAt=Date.now()-1;assert.equal((await get(expired)).status,401);
 const admin=auth.CreateSession(req,'admin'),result=await get(admin);assert.equal(result.status,200);assert.equal(result.body.features.length,14);assert.equal(result.body.windowsVerification,'NOT_RECORDED');auth.RevokeAllSessions();assert.equal((await get(admin)).status,401);
 checks++;console.log('PASS Capability route requires current admin session and refuses revoked sessions');
 console.log(`Server capabilities: ${checks} passed; Windows / deployment verification NOT_RECORDED.`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}})().catch(error=>{console.error(error);process.exitCode=1;});
