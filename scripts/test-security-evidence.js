'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {Record,Template}=require('../tools/record-release-tests');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'release-evidence-')),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';require('../core/utils').EnsureDirs();
const {ValidateEvidence}=require('../services/desktopSecurityOperations');
let count=0;const test=(name,fn)=>{fn();count++;console.log('PASS '+name);};
try{
 const paths=['A.exe','B.exe','source.json','checks.json'].map(n=>path.join(temp,n));
 fs.writeFileSync(paths[0],'synthetic A - NOT a Windows executable');fs.writeFileSync(paths[1],'synthetic B - NOT a Windows executable');fs.writeFileSync(paths[2],'{"source":"test"}');
 const c={version:1,aSha256:sha(fs.readFileSync(paths[0])),bSha256:sha(fs.readFileSync(paths[1])),sourceManifestSha256:sha(fs.readFileSync(paths[2])),checks:Object.fromEntries(['nativeBuild','apiProbe','integration'].map(n=>[n,{status:'NOT_RUN',logs:[]}])),note:'Synthetic tooling fixture. No Windows execution.'};
 const write=()=>fs.writeFileSync(paths[3],JSON.stringify(c));write();
 test('Template captures actual artifact digests but never creates a PASS result',()=>{const out=Template(...paths.slice(0,3));assert.equal(out.aSha256,c.aSha256);assert.ok(Object.values(out.checks).every(x=>x.status==='NOT_RUN'&&x.logs.length===0));});
 test('Unexecuted checks remain NOT_RUN with an exact artifact/source binding',()=>{const out=Record(...paths);assert.equal(out.report.nativeBuild,'NOT_RUN');assert.equal(out.report.integration,'NOT_RUN');ValidateEvidence({...out.report,recordedAt:Date.now(),recordedBy:'TEST',evidenceType:'OPERATOR_RECORDED'});});
 test('Marking a check executed requires log evidence',()=>{c.checks.nativeBuild.status='PASS';write();assert.throws(()=>Record(...paths),/EXECUTED_CHECK_REQUIRES_LOG/);});
 test('Tool hashes logs without claiming to independently verify their truth',()=>{fs.writeFileSync(path.join(temp,'build.log'),'Synthetic test log');c.checks.nativeBuild.logs=['build.log'];write();const out=Record(...paths);assert.equal(out.report.nativeBuild,'PASS');assert.equal(out.report.integration,'NOT_RUN');assert.equal(out.logManifest.trust,'OPERATOR_RECORDED_NOT_ATTESTATION');assert.ok(!JSON.stringify(out.report).includes(temp));});
 test('Changing the log changes the recorded evidence digest',()=>{const before=Record(...paths).report.logsSha256;fs.appendFileSync(path.join(temp,'build.log'),'change');assert.notEqual(Record(...paths).report.logsSha256,before);});
 test('Stale report cannot be silently reassigned to new executable bytes',()=>{fs.appendFileSync(paths[0],'change');assert.throws(()=>Record(...paths),/CHECKS_ARTIFACT_OR_SOURCE_MISMATCH/);fs.writeFileSync(paths[0],'synthetic A - NOT a Windows executable');});
 test('Unknown flags and log paths on NOT_RUN checks are rejected',()=>{c.extra=true;write();assert.throws(()=>Record(...paths),/CHECKS_INVALID/);delete c.extra;c.checks.integration.logs=['build.log'];write();assert.throws(()=>Record(...paths),/NOT_RUN_MUST_HAVE_NO_EXECUTION_LOG/);});
 console.log(`Release evidence tooling: ${count} passed (synthetic inputs; not Windows results)`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
