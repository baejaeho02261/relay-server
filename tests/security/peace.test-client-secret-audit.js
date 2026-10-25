'use strict';
// Synthetic PE data and ephemeral test keys only. No EXE is executed.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const audit=require('../../tools/security/peace.audit-client-secrets'),engine=require('../../services/artifacts/peace.cozy-protection-engine');
const TOOL=require.resolve('../../tools/security/peace.audit-client-secrets'),SLOT=1024,TABLE=392;
function PE(slot=true){
 const b=Buffer.alloc(5120);b.write('MZ');b.writeUInt32LE(128,60);b.write('PE\0\0',128);b.writeUInt16LE(0x8664,132);b.writeUInt16LE(2,134);b.writeUInt16LE(240,148);b.writeUInt16LE(0x22,150);
 b.writeUInt16LE(0x20b,152);b.writeUInt32LE(0x1000,168);b.writeUInt32LE(0x3000,208);b.writeUInt32LE(512,212);b.writeUInt32LE(16,260);
 for(const [p,rva,size,off,flags]of [[TABLE,0x1000,512,512,0x60000020],[TABLE+40,0x2000,4096,SLOT,0xc0000040]]){b.writeUInt32LE(size,p+8);b.writeUInt32LE(rva,p+12);b.writeUInt32LE(size,p+16);b.writeUInt32LE(off,p+20);b.writeUInt32LE(flags,p+36);}
 b.write('SYNTHETIC DATA NEVER EXECUTED',512);
 if(slot)engine.CreateUnsealedSlot().copy(b,SLOT);return b;
}
function Codes(bytes,role='A'){return audit.InspectBytes(bytes,role).findings.map(x=>x.code);}
function Fixture(fn){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'client-secret-audit-'));try{const files=['A','B','O'].map(role=>path.join(dir,role+'.exe'));for(const file of files)fs.writeFileSync(file,PE(),{mode:0o600});return fn({dir,files});}finally{fs.rmSync(dir,{recursive:true,force:true});}}
function Cli(files){const r=cp.spawnSync(process.execPath,[TOOL,...files],{encoding:'utf8',timeout:15000,maxBuffer:65536});assert.equal(r.error,undefined);assert.equal(r.stderr,'');return {exit:r.status,report:JSON.parse(r.stdout),text:r.stdout};}
test('unsealed known slots and ordinary PE files pass without a secrecy guarantee',()=>{
 for(const bytes of [PE(),PE(false)])assert.equal(audit.InspectBytes(bytes,'A').status,'PASS');
 Fixture(({files})=>{const {exit,report}=Cli(files);assert.equal(exit,0);assert.equal(report.status,'PASS');assert.equal(report.guaranteesAbsenceOfSecrets,false);assert.equal(report.unknownOrEncodedSecretsVerified,false);assert.equal(report.publicTrustAnchorsAreSecrets,false);assert.equal(report.executablesRun,false);assert.equal(report.filesWritten,false);assert.equal(report.artifacts.length,3);});
});
test('real VM packing is detected for all three roles without exposing embedded keys',()=>{
 for(const role of ['A','B','O']){
  const b=engine.Pack(PE(),role).bytes,key=b.subarray(SLOT+40,SLOT+72),r=audit.InspectBytes(b,role),text=JSON.stringify(r);
  assert.equal(r.status,'BLOCKED');assert.deepEqual(r.findings.map(x=>x.code),['COZY_VM_V1_EMBEDDED_KEY']);assert.equal(r.sha512,crypto.createHash('sha512').update(b).digest('hex'));
  for(const x of r.findings)assert.deepEqual(Object.keys(x).sort(),['code','role','sha512']);
  assert(!text.includes(key.toString('hex')));assert(!text.includes(key.toString('base64')));b.fill(0);
 }
});
test('ordinary marker literals do not constitute a mapped data slot',()=>{const b=PE(false);b.write('COZY-VM-SLOT-V1\0 parser COZY-VM-END--V1\0',512);assert.equal(audit.InspectBytes(b,'A').status,'PASS');});
test('damaged ciphertext/tag does not hide a recognizable serialized key',()=>{for(const offset of [84,128]){const b=engine.Pack(PE(),'A').bytes;b[SLOT+offset]^=1;assert(Codes(b).includes('COZY_VM_V1_EMBEDDED_KEY'));}});
test('malformed, mismatched or improperly mapped known slots are blocked',()=>{
 for(const change of [b=>b[SLOT+4080]^=1,b=>b.writeUInt16LE(2,SLOT+16),b=>b.writeUInt32LE(0xe0000060,TABLE+40+36),b=>b[SLOT+25]=2,b=>b.fill(0,SLOT+40,SLOT+72)]){const b=engine.Pack(PE(),'A').bytes;change(b);assert(Codes(b).includes('COZY_VM_V1_SLOT_INVALID'));}
 assert(Codes(engine.Pack(PE(),'B').bytes,'A').includes('COZY_VM_V1_ROLE_MISMATCH'));
 const residue=PE();residue[SLOT+40]=7;assert(Codes(residue).includes('COZY_VM_V1_SLOT_INVALID'));
});
test('private PEM and credential findings reuse production coverage and redact matches',()=>{
 const pair=crypto.generateKeyPairSync('ed25519'),pem=pair.privateKey.export({format:'pem',type:'pkcs8'}),token='ghp_'+'x'.repeat(36);
 for(const encoding of ['utf8','utf16le']){
  const b=Buffer.concat([PE(),Buffer.from(pem+'\n'+token,encoding)]),r=audit.InspectBytes(b,'A'),text=JSON.stringify(r);
  assert(r.findings.some(x=>x.code==='PRIVATE_KEY_PEM'));assert(r.findings.some(x=>x.code==='GITHUB_TOKEN'));assert(!text.includes(pem.split('\n')[1]));assert(!text.includes(token));b.fill(0);
 }
});
test('public verification keys, certificate pins and hashes are not treated as private secrets',()=>{
 const pub=crypto.generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'});
 const b=Buffer.concat([PE(),Buffer.from(pub+'\ntlsCertificateSha256='+('ab'.repeat(32))+'\nsha512='+('cd'.repeat(64)))]);
 assert.equal(audit.InspectBytes(b,'A').status,'PASS');
});
test('bounded malformed PE input is rejected rather than given a clean audit result',()=>{
 for(const b of [Buffer.alloc(0),Buffer.alloc(512),Buffer.alloc(audit.MAX_BYTES+1)])assert.throws(()=>audit.InspectBytes(b,'A'),/CLIENT_AUDIT_/);
 const b=PE();b.writeUInt32LE(0xffffffff,60);assert.throws(()=>audit.InspectBytes(b,'A'),/PE_INVALID/);
 assert.throws(()=>audit.InspectBytes(PE(),'X'),/ROLE_INVALID/);
});
test('CLI blocks packed EXE and leaves all input files and directories unchanged',()=>Fixture(({dir,files})=>{
 fs.writeFileSync(files[1],engine.Pack(PE(),'B').bytes);const before=files.map(file=>fs.readFileSync(file)),names=fs.readdirSync(dir).sort();
 const {exit,report,text}=Cli(files);assert.equal(exit,1);assert.equal(report.status,'BLOCKED');assert.equal(report.artifacts[1].role,'B');assert(!text.includes(dir));
 assert.deepEqual(fs.readdirSync(dir).sort(),names);files.forEach((file,i)=>assert.deepEqual(fs.readFileSync(file),before[i]));
}));
test('CLI input failures use redacted structured errors and never downgrade to PASS',()=>Fixture(({dir,files})=>{
 for(const args of [[],files.slice(0,2),[...files,'extra']]){const r=Cli(args);assert.equal(r.exit,2);assert.equal(r.report.error,'CLIENT_AUDIT_ARGUMENTS_INVALID');}
 const missing=path.join(dir,'PRIVATE_TOKEN_filename.exe'),r=Cli([missing,files[1],files[2]]);assert.equal(r.exit,2);assert.equal(r.report.status,'ERROR');assert(!r.text.includes(missing));assert(!r.text.includes('PRIVATE_TOKEN_filename'));
 const bad=path.join(dir,'bad.exe');fs.writeFileSync(bad,Buffer.alloc(512));assert.equal(Cli([bad,files[1],files[2]]).exit,2);
 const large=path.join(dir,'large.exe');const fd=fs.openSync(large,'w');try{fs.ftruncateSync(fd,audit.MAX_BYTES+1);}finally{fs.closeSync(fd);}assert.equal(Cli([large,files[1],files[2]]).report.artifacts[0].error,'CLIENT_AUDIT_SIZE_INVALID');
}));
test('file symlinks, directory symlinks and hardlinks are refused',{skip:process.platform==='win32'},()=>{
 Fixture(({dir,files})=>{
  const link=path.join(dir,'link.exe');fs.symlinkSync(files[0],link);assert.equal(Cli([link,files[1],files[2]]).report.artifacts[0].error,'CLIENT_AUDIT_LINK_FORBIDDEN');
  const folder=path.join(dir,'linked');fs.symlinkSync(dir,folder);assert.equal(Cli([path.join(folder,'A.exe'),files[1],files[2]]).report.artifacts[0].error,'CLIENT_AUDIT_LINK_FORBIDDEN');
  const hard=path.join(dir,'hard.exe');fs.linkSync(files[0],hard);assert.equal(Cli([hard,files[1],files[2]]).report.artifacts[0].error,'CLIENT_AUDIT_FILE_INVALID');
 });
});
test('file growth during the audit is rejected before a finding is accepted',()=>Fixture(({files})=>{
 const read=fs.readSync;let changed=false;
 fs.readSync=function(fd,buffer,...args){const n=read.call(fs,fd,buffer,...args);if(!changed&&buffer.length===5120){changed=true;fs.appendFileSync(files[0],Buffer.alloc(1));}return n;};
 try{const r=audit.Run(files);assert.equal(changed,true);assert.equal(r.status,'ERROR');assert.equal(r.artifacts[0].error,'CLIENT_AUDIT_FILE_CHANGED');}
 finally{fs.readSync=read;}
}));
