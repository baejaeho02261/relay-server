'use strict';
// Real authenticated A/B sessions, RSA proofs, CRC comparison, authority/report
// handlers and persisted findings. Synthetic PE fixtures are not Windows runs.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-crc-confidence-'));
Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',DESKTOP_PUBLIC_HOST:'127.0.0.1',DESKTOP_PUBLIC_PORT:'29131'});
require('../../core/peace.utilities').EnsureDirs();
const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),authority=require('../../services/security/peace.desktop-security-authority'),integrity=require('../../services/integrity/peace.desktop-integrity-reports'),detections=require('../../services/security/peace.security-detections'),store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
process.once('exit',()=>{boot.Stop();fs.rmSync(temp,{recursive:true,force:true});});
fixture.CurrentCohort({version:'90.0.2'});
function subject(){const a=fixture.Device(),start=fixture.Begin(a),b=fixture.Child(a);fixture.Download(start.begin);const session=fixture.Claim(a,start.begin,fixture.Finish(a,start.begin),b);const auth={stage:'B',sessionId:session.sessionId,sessionToken:session.sessionToken,machineId:b.machineId};return {b,session,flow:start.begin.flowId,auth,artifact:boot.AuthenticateIntegrityReport(auth).integrityArtifact};}
function value(s){const a=s.artifact;return {version:1,hashVersion:3,measurement:'MEASURED',fileSha512:a.sha512,fileCrc64:a.crc64,codeSha512:a.codeSha512,codeCrc64:a.codeCrc64,codeXxh3_128:a.codeXxh3_128,codeBlake3:a.codeBlake3,crcLayers:structuredClone(a.crcLayers),apiSealed:true,apiSlots:60,dynamicCode:'ALLOWED',cfg:'DISABLED'};}
function changeCrc(v,kind){const role=Object.keys(v.crcLayers).find(k=>v.crcLayers[k]?.status==='measured'),old=v.crcLayers[role];assert.ok(role);if(kind==='MISMATCH')old.digest=(old.digest[0]==='0'?'1':'0')+old.digest.slice(1);else v.crcLayers[role]={algorithm:old.algorithm,role:old.role,status:'failed',reason:kind};}
function signedAuthority(s,v){const body={...s.auth,intent:'verify',binding:authority.Binding('crc-test',crypto.randomUUID())},challenge=authority.Execute({...body,action:'challenge'}),payload=JSON.stringify(v);return {...body,action:'submit',challengeId:challenge.challengeId,payload,signature:fixture.Sign(s.b,authority.Canonical(body,challenge,payload))};}
function finding(s,id,confirmed,sensor,invalidated){const found=detections.ForFlow(s.flow).filter(x=>x.detectionId===id);assert.equal(found.length,1);assert.equal(found[0].confidence,confirmed?100:0);assert.equal(found[0].correlation,confirmed);assert.equal(found[0].localOnly,!confirmed);assert.equal(found[0].sensor,sensor);assert.equal(found[0].invalidated,invalidated);detections.Validate(store.Load().securityDetections,store.Load());}
for(const kind of ['READ_ERROR','CANCELLED','MISMATCH']){
 const s=subject(),v=value(s);changeCrc(v,kind);const response=authority.Execute(signedAuthority(s,v));assert.equal(response.reason,'CRC_ROLE_MISMATCH');assert.equal(response.status,'MISMATCH');assert.equal(response.proceed,false);assert.equal(store.Load().flows[s.flow].status,'CLAIMED','report classification does not alter existing enforcement');finding(s,'CRC_ROLE_MISMATCH',kind==='MISMATCH','peace.desktop-security-authority',false);
}
// Isolate only missing legacy baseline metadata after real authentication.
// The signed payload, parser, comparison, decision and store are production.
{
 const s=subject(),v=value(s),original=boot.AuthenticateIntegrityReport;
 boot.AuthenticateIntegrityReport=body=>{const row=original(body);return body.sessionId===s.session.sessionId?{...row,integrityArtifact:{...row.integrityArtifact,crcLayers:undefined}}:row;};
 try{const response=authority.Execute(signedAuthority(s,v));assert.equal(response.reason,'CRC_BASELINE_UNAVAILABLE');assert.equal(response.status,'MISMATCH');assert.equal(response.proceed,false);finding(s,'CRC_BASELINE_UNAVAILABLE',false,'peace.desktop-security-authority',false);}finally{boot.AuthenticateIntegrityReport=original;}
}
for(const kind of ['READ_ERROR','MISMATCH']){
 const s=subject(),v=value(s);changeCrc(v,kind);const a=s.artifact,payload=JSON.stringify({version:1,hashVersion:3,check:'OWN_IMAGE',reason:'PERIODIC',crcLayers:v.crcLayers,own:{status:'MEASURED',codeSha512:a.codeSha512,codeCrc64:a.codeCrc64,fileXxh3_128:a.fileXxh3_128,fileBlake3:a.fileBlake3,codeXxh3_128:a.codeXxh3_128,codeBlake3:a.codeBlake3}}),challenge=integrity.Execute({...s.auth,action:'challenge'}),request={...s.auth,action:'submit',reportId:challenge.reportId,payload,signature:fixture.Sign(s.b,integrity.Canonical(s.auth.sessionId,challenge,payload))};
 const response=integrity.Execute(request);assert.equal(response.status,'REJECTED');assert.equal(response.terminate,true);assert.equal(store.Load().flows[s.flow].status,'REVOKED','existing integrity revocation remains');finding(s,'CRC_ROLE_MISMATCH',kind==='MISMATCH','peace.desktop-integrity-reports',true);
}
{
 const s=subject(),v=value(s);changeCrc(v,'MISMATCH');const request=signedAuthority(s,v);request.signature=Buffer.alloc(256).toString('base64');assert.throws(()=>authority.Execute(request),/SECURITY_SIGNATURE_INVALID/);assert.equal(detections.ForFlow(s.flow).length,0,'unsigned measurement cannot attach detection');
}
console.log('CRC detection confidence PASS: failed-only/absent baseline stay unconfirmed, real mismatch confirmed, unsigned excluded, authority/integrity enforcement unchanged.');
