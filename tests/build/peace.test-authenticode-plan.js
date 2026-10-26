'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const tool=require('../../ci/pipeline/peace.authenticode-plan');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-authenticode-lineage-'));
function Pe(){const b=require('../fixtures/artifacts/peace.crc-pe-fixture').crcPeFixture('SYNTHETIC AUTHENTICODE LINEAGE DATA');b.writeUInt16LE(0x22,b.readUInt32LE(60)+22);return b;}
function SyntheticCertificate(input,payloadBytes=9){
 // Deliberately NOT a valid PKCS#7 signature: tests validate byte lineage, not
 // Windows trust. This object must never become signature/approval evidence.
 const at=(input.length+7)&~7,length=8+payloadBytes,size=(length+7)&~7,b=Buffer.alloc(at+size);input.copy(b);
 const opt=b.readUInt32LE(60)+24;b.writeUInt32LE(123,opt+64);b.writeUInt32LE(at,opt+144);b.writeUInt32LE(size,opt+148);
 b.writeUInt32LE(length,at);b.writeUInt16LE(0x200,at+4);b.writeUInt16LE(2,at+6);b.fill(0x33,at+8,at+length);return b;
}
test('accepts only signature metadata delta without claiming Windows trust or approval',()=>{
 const input=Pe(),output=SyntheticCertificate(input),report=tool.CompareBytes(input,output,'B');
 assert.equal(report.onlySignatureMetadataChanged,true);assert.equal(report.certificateEntries,1);assert.notEqual(report.inputSha512,report.outputSha512);
 for(const k of ['signatureCryptographicallyVerified','windowsProductExecuted','productionApproved','publicationPerformed'])assert.equal(report[k],false);
});
test('rejects changed code, read-only data and non-signature PE headers',()=>{
 const input=Pe();for(const at of [512,1030,0x80+24+16]){const b=SyntheticCertificate(input);b[at]^=1;assert.throws(()=>tool.CompareBytes(input,b,'B'),/NON_SIGNATURE_BYTES_CHANGED|CLIENT_AUDIT_PE_INVALID/);}
});
test('rejects incomplete, unsupported, padded and unexplained certificate payload layouts',()=>{
 const input=Pe(),opt=input.readUInt32LE(60)+24,at=input.length;
 for(const change of [b=>b.writeUInt32LE(8,at),b=>b.writeUInt16LE(0x100,at+4),b=>b.writeUInt16LE(1,at+6),b=>b[b.length-1]=1,b=>b.writeUInt32LE(64,opt+148),b=>b.writeUInt32LE(at+8,opt+144)]){
  const b=SyntheticCertificate(input);change(b);assert.throws(()=>tool.CompareBytes(input,b,'B'),/CI_AUTHENTICODE_/);
 }
 const appended=Buffer.concat([SyntheticCertificate(input),Buffer.from('unexplained')]);assert.throws(()=>tool.CompareBytes(input,appended,'B'),/CERTIFICATE_APPEND_INVALID/);
});
test('rejects signed source, issued launcher trailers and absence of a security directory',()=>{
 const input=Pe(),signed=SyntheticCertificate(input);assert.throws(()=>tool.CompareBytes(signed,SyntheticCertificate(signed),'B'),/UNSIGNED_INPUT_REQUIRED/);
 for(const magic of ['GAMEA80CONFIG!','COZYA2CONFIG!','COZYA3CONFIG!']){const b=Buffer.concat([input,Buffer.from(magic)]);assert.throws(()=>tool.CompareBytes(b,SyntheticCertificate(b),'A'),/ISSUED_LAUNCHER_NOT_TEMPLATE/);}
 const b=Pe();b.writeUInt32LE(4,b.readUInt32LE(60)+24+108);assert.throws(()=>tool.CompareBytes(b,SyntheticCertificate(b),'A'),/PE_SECURITY_DIRECTORY_REQUIRED/);
});
test('permits zero alignment only and retains literal payload bytes of original PE',()=>{
 const input=Buffer.concat([Pe(),Buffer.from('one')]),signed=SyntheticCertificate(input);assert.equal(tool.CompareBytes(input,signed,'O').onlySignatureMetadataChanged,true);
 signed[input.length]=1;assert.throws(()=>tool.CompareBytes(input,signed,'O'),/CERTIFICATE_ALIGNMENT_INVALID/);
});
test('rejects known embedded VM key before any signing preparation',()=>{
 // Fixed legacy layout, not the current packer's output. No real production
 // key is used; even a deliberately invalid encrypted payload must be blocked.
 const slot=Buffer.alloc(4096);slot.write('COZY-VM-SLOT-V1\0',0,'ascii');slot.write('COZY-VM-END--V1\0',4080,'ascii');slot.writeUInt16LE(1,16);slot.writeUInt16LE(128,18);slot.writeUInt32LE(4096,20);slot[24]=2;slot[25]=1;slot.writeUInt32LE(16,28);slot.writeUInt32LE(1,32);slot.writeUInt32LE(1024,36);require('node:crypto').randomBytes(32).copy(slot,40);slot.writeUInt32LE(1,100);
 const original=Pe(),input=Buffer.concat([original,slot]);
 const pe=input.readUInt32LE(60),opt=pe+24,last=opt+input.readUInt16LE(pe+20)+40,size=input.readUInt32LE(last+16)+4096;
 input.writeUInt32LE(size,last+8);input.writeUInt32LE(size,last+16);input.writeUInt32LE(Math.ceil((input.readUInt32LE(last+12)+size)/4096)*4096,opt+56);
 assert.throws(()=>tool.CompareBytes(input,SyntheticCertificate(input),'B'),/CLIENT_SECRET_OR_EXPOSURE_BLOCKED/);slot.fill(0);input.fill(0);
});
test('local file check rejects links and never writes sidecars or reports',()=>{
 const a=path.join(temp,'input.exe'),b=path.join(temp,'signed.exe'),link=path.join(temp,'link.exe');fs.writeFileSync(a,Pe());fs.writeFileSync(b,SyntheticCertificate(Pe()));
 const before=fs.readdirSync(temp);assert.equal(tool.Inspect(a,'A').executed,false);assert.equal(tool.Compare(a,b,'A').productionApproved,false);assert.deepEqual(fs.readdirSync(temp),before);
 assert.throws(()=>tool.Inspect('relative.exe','A'),/ABSOLUTE_LOCAL_FILE_REQUIRED/);fs.symlinkSync(a,link,'file');assert.throws(()=>tool.Inspect(link,'A'),/LINK_FORBIDDEN/);fs.unlinkSync(link);
 fs.linkSync(a,link);assert.throws(()=>tool.Inspect(link,'A'),/AUDIT_FILE_INVALID/);fs.unlinkSync(link);
});
test('Windows wrapper requires separate signing provider and keeps final evidence boundaries',()=>{
 const ps=fs.readFileSync(path.join(__dirname,'../../ci/pipeline/Invoke-AuthenticodePreparation.ps1'),'utf8');
 assert.match(ps,/SignToolSha512/);assert.match(ps,/NodeSha512/);assert.match(ps,/CertificateSha256/);assert.match(ps,/SIGNTOOL_HASH_MISMATCH/);assert.match(ps,/NODE_HASH_MISMATCH/);assert.match(ps,/'verify','\/q','\/pa','\/all','\/tw'/);
 assert.match(ps,/TimeStamperCertificate/);assert.match(ps,/NON_SIGNATURE|onlySignatureMetadataChanged/);assert.match(ps,/windowsProductExecuted=\$false/);assert.match(ps,/productionApproved=\$false/);assert.match(ps,/publicationPerformed=\$false/);
 assert.doesNotMatch(ps,/Export-PfxCertificate|ConvertTo-SecureString|Set-ExecutionPolicy|\/p\b|\/f\b/);
 assert.match(ps,/\[IO.Directory\]::Move\(\$signed,\$destination\)/);assert.match(ps,/PRIVATE_CLEANUP_FAILED/);
 assert.match(ps,/Run-Owned 'node-version'/);assert.doesNotMatch(ps,/\$actualNode=&/);assert.match(ps,/lineage\.outputSha512 -cne \$verifiedHash/);assert.match(ps,/\$signatureLock=\[IO.File\]::Open/);
 assert.doesNotMatch(ps,/::HashData|::ToHexString/);assert.match(ps,/AtomicDirectory\]::CreateDirectoryW/);assert.match(ps,/if\(\$privateCreated\)/);assert.match(ps,/Join-Path \$destinationParent/);
});
test.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
