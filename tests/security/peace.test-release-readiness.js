'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const crypto = require('node:crypto'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { AuditBytes, AuditActive, MAX_TOTAL_BYTES } = require('../../services/security/peace.release-readiness');
const { crcPeFixture } = require('../fixtures/artifacts/peace.crc-pe-fixture');
const hash = bytes => crypto.createHash('sha512').update(bytes).digest('hex');
const image = () => { const b = crcPeFixture('GAME-AUTHORITY-V2'); b.writeUInt16LE(0x160,0x80+24+70); return b; };
const artifact = bytes => ({ id:'A'.repeat(24), component:'A', version:'1.0.0', size:bytes.length, sha512:hash(bytes), compiledCfg:false });
const policy = {requireCfg:false,requireReleaseSignature:false,revokedSha512:[]};

test('exact bytes are measured with no fabricated native execution or Windows trust', () => {
  const bytes=image(), row=artifact(bytes), before=Buffer.from(bytes), result=AuditBytes(row,bytes,{policy});
  assert.equal(result.staticStatus,'CHECKED'); assert.equal(result.checks.fileIdentity.status,'MATCH');
  assert.equal(result.checks.pe.status,'VALID'); assert.equal(result.checks.pe.dep,true);
  assert.equal(result.checks.cfg.compiledCfg,false); assert.equal(result.checks.cfg.callSiteCoverage,'NOT_VERIFIED');
  assert.equal(result.checks.authenticode.status,'ABSENT'); assert.equal(result.checks.authenticode.windowsTrust,'NOT_VERIFIED');
  assert.equal(result.checks.releaseApproval.status,'MISSING'); assert.deepEqual(bytes,before);
});
test('same-size artifact replacement invalidates file identity and never verifies stored digest alone', () => {
  const bytes=image(), row={...artifact(bytes),releaseApproval:{signature:'test'}}; bytes[600]^=1; let invoked=false;
  const result=AuditBytes(row,bytes,{policy,verifyApproval:()=>{invoked=true;return true;}});
  assert.equal(result.checks.fileIdentity.status,'MISMATCH'); assert.equal(invoked,false);
  assert.equal(result.checks.releaseApproval.status,'NOT_CHECKED'); assert.ok(result.issues.includes('RELEASE_FILE_IDENTITY_MISMATCH'));
});
test('real detached Ed25519 approval binds measured role, version and SHA512', () => {
  const bytes=image(), row=artifact(bytes), keys=crypto.generateKeyPairSync('ed25519');
  const canonical=r=>Buffer.from(['GAME-RELEASE-APPROVAL-V2',r.component,r.version,r.sha512].join('\n'));
  row.releaseApproval={signature:crypto.sign(null,canonical(row),keys.privateKey).toString('base64')};
  const verifyApproval=r=>crypto.verify(null,canonical(r),keys.publicKey,Buffer.from(r.releaseApproval.signature,'base64'));
  assert.equal(AuditBytes(row,bytes,{policy,verifyApproval}).checks.releaseApproval.status,'VALID');
  for(const change of [{version:'2.0.0'},{component:'B'}])
    assert.equal(AuditBytes({...row,...change},bytes,{policy,verifyApproval}).checks.releaseApproval.status,'INVALID');
  assert.ok(AuditBytes(row,bytes,{policy,verifyApproval:()=>false}).issues.includes('SECURITY_RELEASE_SIGNATURE'));
});
test('CFG stored flag cannot mask actual missing metadata or silently lower policy', () => {
  const bytes=image(), row={...artifact(bytes),compiledCfg:true}, p={...policy,requireCfg:true};
  const result=AuditBytes(row,bytes,{policy:p});
  assert.ok(result.issues.includes('SECURITY_CFG_BUILD_REQUIRED'));
  assert.ok(result.issues.includes('RELEASE_CFG_REGISTRATION_MISMATCH')); assert.equal(p.requireCfg,true);
  bytes.writeUInt16LE(bytes.readUInt16LE(0x80+24+70)|0x4000,0x80+24+70);
  const forged=AuditBytes(artifact(bytes),bytes,{policy:p}); assert.equal(forged.checks.cfg.status,'INVALID');
  assert.ok(forged.issues.includes('RELEASE_CFG_METADATA_INVALID'));
});
test('malformed PE and writable executable sections cannot be reported clean', () => {
  const short=Buffer.from('MZ');assert.equal(AuditBytes(artifact(short),short,{policy}).checks.pe.status,'INVALID');
  const bytes=image(), table=0x80+24+240; bytes.writeUInt32LE(0xe0000020,table+36);
  // Preserve an independent immutable executable section so the PE parser can
  // distinguish the writable-code finding from no protected code at all.
  bytes.writeUInt32LE(0x60000040,table+40+36);bytes.writeUInt32LE(0,0x80+24+136);bytes.writeUInt32LE(0,0x80+24+140);
  const result=AuditBytes(artifact(bytes),bytes,{policy});
  assert.equal(result.checks.pe.writableExecutableSections,1);assert.ok(result.issues.includes('RELEASE_WRITABLE_EXECUTABLE_SECTION'));
});
function withCertificate({length=16,type=2,revision=0x200,offset=1536,size=16}={}) {
  const bytes=Buffer.concat([image(),Buffer.alloc(16)]), opt=0x80+24;
  bytes.writeUInt32LE(offset,opt+144);bytes.writeUInt32LE(size,opt+148);
  bytes.writeUInt32LE(length,1536);bytes.writeUInt16LE(revision,1540);bytes.writeUInt16LE(type,1542);bytes.fill(0x42,1544);
  return bytes;
}
test('certificate-shaped garbage is only structure and never a verified Authenticode signature', () => {
  const bytes=withCertificate(), result=AuditBytes(artifact(bytes),bytes,{policy});
  assert.equal(result.checks.authenticode.status,'PRESENT_STRUCTURE_ONLY');
  assert.equal(result.checks.authenticode.windowsTrust,'NOT_VERIFIED'); assert.equal(result.checks.authenticode.certificateCount,1);
});
test('certificate table range, type, length, alignment and overlap are rejected', () => {
  for(const options of [{length:0},{length:8},{length:32},{type:1},{revision:0x100},{offset:1537},{offset:512},{size:0},{size:17}]){
    const bytes=withCertificate(options), result=AuditBytes(artifact(bytes),bytes,{policy});
    assert.equal(result.checks.authenticode.status,'INVALID',JSON.stringify(options));
    assert.ok(result.issues.includes('RELEASE_CERTIFICATE_TABLE_INVALID'));
  }
});
test('missing required approval and revoked measured digest are explicit', () => {
  const bytes=image(), row=artifact(bytes), result=AuditBytes(row,bytes,{policy:{...policy,requireReleaseSignature:true,revokedSha512:[hash(bytes)]}});
  assert.ok(result.issues.includes('SECURITY_RELEASE_SIGNATURE'));assert.ok(result.issues.includes('SECURITY_RELEASE_REVOKED'));
});
test('legacy SHA256 revocations use actual bytes even with missing or forged registration metadata', () => {
  const bytes=image(), measured=crypto.createHash('sha256').update(bytes).digest('hex');
  for(const extra of [{},{legacyRevocationSha256:'0'.repeat(64)}]){
    const result=AuditBytes({...artifact(bytes),...extra},bytes,{policy:{...policy,revokedLegacySha256:[measured]}});
    assert.ok(result.issues.includes('SECURITY_RELEASE_REVOKED'));
  }
  const allowed=AuditBytes({...artifact(bytes),legacyRevocationSha256:'0'.repeat(64)},bytes,
    {policy:{...policy,revokedLegacySha256:['0'.repeat(64)]}});
  assert.ok(!allowed.issues.includes('SECURITY_RELEASE_REVOKED'),'untrusted metadata cannot invent a match');
});
test('malformed input projection does not disclose injected paths or fields', () => {
  const result=AuditBytes({id:'../../secret',component:'A',version:'secret\n',sha512:'private',file:'/secret',token:'never-output'},Buffer.alloc(0));
  assert.equal(result.staticStatus,'ISSUES_FOUND');assert.equal(result.id,'');
  assert.doesNotMatch(JSON.stringify(result),/secret|private|never-output/);
});

test('active audit uses production verifier, bounds IO, preserves records and rejects file replacement', async () => {
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'peace-release-readiness-'));
  Object.assign(process.env,{DATA_DIR:temp,STORAGE_ENGINE:'json',HA_ENABLED:'0',ADMIN_SECRET:'synthetic-readiness-secret'});
  try {
    require('../../core/peace.utilities').EnsureDirs();
    const store=require('../../services/bootstrap/peace.desktop-bootstrap-store');
    const auth=require('../../services/security/peace.desktop-security-authority');
    const boot=require('../../services/bootstrap/peace.desktop-bootstrap');
    const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture');
    const keys=crypto.generateKeyPairSync('ed25519'),publicKey=keys.publicKey.export({type:'spki',format:'pem'}).toString();
    const keyId=crypto.createHash('sha256').update(keys.publicKey.export({type:'spki',format:'der'})).digest('hex');
    auth.SetPolicy({expectedRevision:auth.Policy().revision,trustedReleaseKeys:[{keyId,publicKey}]},'SYNTHETIC_READINESS_TEST');
    const issuer=crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
    const signing=require('../../services/bootstrap/peace.issued-a-signing');
    process.env[signing.ENV]=Buffer.from(issuer.privateKey.export({type:'pkcs8',format:'pem'})).toString('base64');
    const bytes=require('../fixtures/bootstrap/peace.issued-a-fixture').WithAnchor(fixture.PE('A','readiness synthetic fixture'),issuer.publicKey);
    const approval={keyId,signature:crypto.sign(null,Buffer.from(auth.ReleaseCanonical('A','1.0.0',hash(bytes))),keys.privateKey).toString('base64')};
    const published=boot.Publish('A','1.0.0',bytes,approval);
    const file=store.ArtifactPath(published.id),authorityFile=path.join(store.DIR,'authority.json');
    const before=fs.readFileSync(authorityFile),original=fs.readFileSync(file),result=await AuditActive();
    assert.equal(result.readOnly,true);assert.equal(result.authorizesPublication,false);
    assert.equal(result.nativeExecution,'NOT_RUN');assert.equal(result.windowsPublisherTrust,'NOT_VERIFIED');
    assert.equal(result.releases.length,3);assert.equal(result.releases[0].checks.releaseApproval.status,'VALID');
    assert.equal(result.releases[0].checks.issuedAApplicationSignature.status,'READY');
    assert.equal(result.releases[0].checks.issuedAApplicationSignature.finalIssuedFile,'NOT_CHECKED');
    assert.equal(Object.keys(store.Load().launchers).length,0);
    assert.equal(result.releases[1].staticStatus,'NOT_REGISTERED');assert.equal(result.releases[2].staticStatus,'NOT_REGISTERED');
    assert.deepEqual(fs.readFileSync(authorityFile),before);assert.deepEqual(fs.readFileSync(file),original);
    assert.doesNotMatch(JSON.stringify(result),/BEGIN PUBLIC KEY|BEGIN PRIVATE KEY|synthetic-readiness-secret/);
    const damaged=Buffer.from(original);damaged[600]^=1;fs.writeFileSync(file,damaged);
    assert.equal((await AuditActive()).releases[0].checks.fileIdentity.status,'MISMATCH');fs.writeFileSync(file,original);
    const backup=file+'.audit-original';fs.renameSync(file,backup);
    try {fs.symlinkSync(backup,file);assert.ok((await AuditActive()).releases[0].issues.includes('RELEASE_FILE_UNAVAILABLE_OR_CHANGED'));}
    finally {fs.rmSync(file,{force:true});fs.renameSync(backup,file);}
    const load=store.Load, snapshot=load();
    try {
      const big={...snapshot,active:{},artifacts:{}};
      for(const [i,role]of ['A','B','O'].entries()){const id=String(i+1).repeat(24);big.active[role]=id;big.artifacts[id]={...snapshot.artifacts[published.id],id,component:role,size:64*1024*1024};}
      store.Load=()=>big;assert.equal(MAX_TOTAL_BYTES,128*1024*1024);
      assert.ok((await AuditActive()).releases[2].issues.includes('RELEASE_AUDIT_BUDGET_EXCEEDED'));
    } finally {store.Load=load;}
    assert.deepEqual(fs.readFileSync(authorityFile),before);
    // Selection/approval/policy changes while bytes are in a worker invalidate
    // the snapshot; unrelated runtime bookkeeping does not fabricate conflict.
    const originalLoad=store.Load,originalPolicy=auth.Policy,stable=store.Load();
    try {
      let view=stable,policyView=auth.Policy();store.Load=()=>view;auth.Policy=()=>structuredClone(policyView);
      const staleCases=[
        ()=>{view={...stable,active:{...stable.active,A:''}};},
        ()=>{view={...stable,artifacts:{...stable.artifacts,[published.id]:{...stable.artifacts[published.id],version:'2.0.0'}}};},
        ()=>{view={...stable,securityOperations:{...stable.securityOperations,revision:(stable.securityOperations?.revision||0)+1}};},
        ()=>{policyView={...policyView,revision:policyView.revision+1};}
      ];
      for(const mutate of staleCases){view=stable;policyView=originalPolicy();const job=AuditActive();mutate();await assert.rejects(job,{message:'RELEASE_AUDIT_STALE',status:409});}
      view=stable;policyView=originalPolicy();const job=AuditActive();view={...stable,revision:stable.revision+1};
      assert.equal((await job).releases[0].checks.fileIdentity.status,'MATCH');
    } finally {store.Load=originalLoad;auth.Policy=originalPolicy;}
  } finally {fs.rmSync(temp,{recursive:true,force:true});}
});
