'use strict';
const sha512=value=>require('node:crypto').createHash('sha512').update(value).digest('hex');
// Existing publishing accepts numeric versions up to 40 characters.
{ const a = require('../services/desktopSecurityAuthority');
  require('node:assert/strict').equal(a.VersionAtLeast('12345678901234567890', '0'), true);
  require('node:assert/strict').equal(a.VersionAtLeast('9007199254740992', '9007199254740993'), false);
}

const assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'security-tools-'));
process.env.DATA_DIR=temp;process.env.HA_ENABLED='0';
const a=require('../services/desktopSecurityAuthority'),{PE,sha256}=require('./desktop-bootstrap-fixture');
const {SignRelease}=require('../tools/sign-release-approval'),{Audit}=require('../tools/audit-release-capabilities');
const worker=name=>fs.readFileSync(path.join(__dirname,'../tools',name),'utf8').split("$script:Worker = @'")[1].split("\n'@")[0];
let count=0;function Test(name,fn){fn();count++;console.log('PASS '+name);}
try{
 Test('Standalone approval workers embed identical bounded PE preflight',()=>{
  const block=text=>text.replace(/\r\n/g,'\n').split('// BEGIN STANDALONE PE PREFLIGHT\n')[1].split('// END STANDALONE PE PREFLIGHT')[0];
  const create=block(worker('Create_Approval.bat')),check=block(worker('Check_Approval.bat'));
  assert.equal(check,create);assert.match(create,/PE_EXCEPTION_TABLE_UNSORTED/);
 });
 Test('Create embeds the unchanged strict normalizer and prepares O before key selection and signing',()=>{
  const text=fs.readFileSync(path.join(__dirname,'../tools/Create_Approval.bat'),'utf8').replace(/\r\n/g,'\n');
  const canonical=fs.readFileSync(path.join(__dirname,'../../GameConnect_Win64/imgui/bridge/Normalize-PE-Unwind.ps1'),'utf8').replace(/\r\n/g,'\n');
  const core=(source,name)=>source.split(name+" = @'\n")[1].split("\n'@")[0];
  assert.equal(core(text,'$script:OverlayNormalizerSource'),core(canonical,'$source'));
  const main=text.slice(text.indexOf('function Main {'));
  const prepare=main.indexOf('Prepare-OverlayImage'),key=main.indexOf('Choose-Key'),sign=main.indexOf("GC_APPROVAL_ACTION='sign'");
  assert(prepare>=0&&key>prepare&&sign>key,'Finalize selected O before choosing key/signing');
  assert.match(main.slice(0,prepare),/\$component -eq 'O'/);
  assert.match(main,/GC_APPROVAL_PREPARED_SHA512/);
  for(const name of ['Create_Approval.bat','Check_Approval.bat'])assert.doesNotMatch(fs.readFileSync(path.join(__dirname,'../tools',name),'utf8'),/Finalize_Overlay\.bat|Normalize-PE-Unwind\.ps1/,'Two BATs are standalone');
 });
 Test('Signing tool exports only public approval; inputs remain unchanged',()=>{
  const pair=crypto.generateKeyPairSync('ed25519'); const privatePem=pair.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  const keyFile=path.join(temp,'offline.pem'),file=path.join(temp,'test.exe');fs.writeFileSync(keyFile,privatePem,{mode:0o600});const bytes=PE('B',a.DOMAIN);fs.writeFileSync(file,bytes);
  const out=SignRelease('B','87.1.0',file,keyFile);
  assert.ok(!JSON.stringify(out).includes('PRIVATE KEY'));assert.ok(!JSON.stringify(out).includes(privatePem));
  assert.deepEqual(fs.readFileSync(file),bytes);assert.equal(fs.readFileSync(keyFile,'utf8'),privatePem);
  const policy={...a.Defaults(),requireReleaseSignature:true,trustedReleaseKeys:[out.trustedKey]};a.ValidatePolicy(policy);
  assert.equal(a.VerifyApproval({component:'B',version:'87.1.0',sha512:sha512(bytes),releaseApproval:out.approval},policy),true);
  assert.equal(Audit(file).authorityVersion,1);assert.equal(Audit(file).compiledCfg,false);
  assert.throws(()=>a.ValidatePolicy({...policy,trustedReleaseKeys:[{...out.trustedKey,publicKey:privatePem}]}));
 });
 Test('Overlay approvals match both offline batch workers and the server V2 canonical',()=>{
  const pair=crypto.generateKeyPairSync('ed25519'),keyFile=path.join(temp,'overlay-signing.pem'),file=path.join(temp,'overlay.exe'),approvalFile=path.join(temp,'overlay.approval.json');
  fs.writeFileSync(keyFile,pair.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});fs.writeFileSync(file,PE('O',a.DOMAIN));
  const env={...process.env,GC_APPROVAL_ACTION:'sign',GC_APPROVAL_KEY:keyFile,GC_APPROVAL_EXE:file,GC_APPROVAL_OUTPUT:approvalFile,GC_APPROVAL_COMPONENT:'O',GC_APPROVAL_VERSION:'93.0.0',GC_APPROVAL_PREPARED_SHA512:sha512(fs.readFileSync(file))};
  const signed=require('node:child_process').spawnSync(process.execPath,['-e',worker('Create_Approval.bat')],{env,encoding:'utf8'});assert.equal(signed.status,0,signed.stderr);
  const approval=JSON.parse(fs.readFileSync(approvalFile,'utf8'));assert.equal(approval.sha512,sha512(fs.readFileSync(file)));assert.match(approval.trustedKey.keyId,/^[a-f0-9]{64}$/);
  const checked=require('node:child_process').spawnSync(process.execPath,['-e',worker('Check_Approval.bat')],{env:{...env,GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_JSON:approvalFile},encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);assert.equal(JSON.parse(checked.stdout).ok,true);assert.equal(JSON.parse(checked.stdout).pePreflightChecked,true);
  assert.equal(a.VerifyApproval({component:'O',version:'93.0.0',sha512:approval.sha512,releaseApproval:approval.approval},{...a.Defaults(),requireReleaseSignature:true,trustedReleaseKeys:[approval.trustedKey]}),true);
  fs.appendFileSync(file,'tampered');const bad=require('node:child_process').spawnSync(process.execPath,['-e',worker('Check_Approval.bat')],{env:{...env,GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_JSON:approvalFile},encoding:'utf8'});assert.notEqual(bad.status,0);assert.match(bad.stderr,/EXE_SHA512_MISMATCH/);
 });
 Test('Approval inspection rejects a valid legacy signature over an unsorted EXE without changing either input',()=>{
  const pair=crypto.generateKeyPairSync('ed25519'),bytes=PE('O',a.DOMAIN),pdata=1280,first=Buffer.from(bytes.subarray(pdata,pdata+12));bytes.copy(bytes,pdata,pdata+12,pdata+24);first.copy(bytes,pdata+12);
  const keyId=crypto.createHash('sha256').update(pair.publicKey.export({type:'spki',format:'der'})).digest('hex'),digest=sha512(bytes);
  const canonical=a.ReleaseCanonical('O','93.0.0',digest),signature=crypto.sign(null,Buffer.from(canonical),pair.privateKey).toString('base64');
  assert.equal(crypto.verify(null,Buffer.from(canonical),pair.publicKey,Buffer.from(signature,'base64')),true);
  const json=JSON.stringify({component:'O',version:'93.0.0',sha512:digest,trustedKey:{keyId,publicKey:pair.publicKey.export({type:'spki',format:'pem'}).toString()},approval:{keyId,signature}});
  const file=path.join(temp,'legacy-unsorted.exe'),approvalFile=path.join(temp,'legacy-unsorted.approval.json');fs.writeFileSync(file,bytes);fs.writeFileSync(approvalFile,json);
  const result=require('node:child_process').spawnSync(process.execPath,['-e',worker('Check_Approval.bat')],{encoding:'utf8',env:{...process.env,GC_APPROVAL_ACTION:'inspect',GC_APPROVAL_COMPONENT:'O',GC_APPROVAL_VERSION:'93.0.0',GC_APPROVAL_EXE:file,GC_APPROVAL_JSON:approvalFile}});
  assert.equal(result.status,1);assert.equal(result.stderr.trim(),'PE_EXCEPTION_TABLE_UNSORTED');assert.equal(result.stdout,'');
  assert.deepEqual(fs.readFileSync(file),bytes);assert.equal(fs.readFileSync(approvalFile,'utf8'),json);
 });
 Test('O signing binds to final preparation bytes before opening the key; missing or stale receipt cannot create approval',()=>{
  const bytes=PE('O',a.DOMAIN),file=path.join(temp,'prepared-binding.exe');fs.writeFileSync(file,bytes);
  for(const [name,prepared,code] of [['missing','', 'OVERLAY_PREPARATION_REQUIRED'],['malformed','invalid','OVERLAY_PREPARATION_REQUIRED'],['stale','0'.repeat(128),'OVERLAY_PREPARED_IMAGE_CHANGED']]){
   const output=path.join(temp,name+'-preparation.approval.json');
   const result=require('node:child_process').spawnSync(process.execPath,['-e',worker('Create_Approval.bat')],{encoding:'utf8',env:{...process.env,GC_APPROVAL_ACTION:'sign',GC_APPROVAL_COMPONENT:'O',GC_APPROVAL_VERSION:'93.0.0',GC_APPROVAL_EXE:file,GC_APPROVAL_KEY:path.join(temp,'must-not-be-opened.pem'),GC_APPROVAL_OUTPUT:output,GC_APPROVAL_PREPARED_SHA512:prepared}});
   assert.equal(result.status,1);assert.equal(result.stderr.trim(),code);assert.equal(fs.existsSync(output),false);assert.deepEqual(fs.readFileSync(file),bytes);
  }
 });
 Test('Approval preflight rejects unsorted and malformed unwind tables before opening a key or writing JSON',()=>{
  const original=PE('O',a.DOMAIN),pe=original.readUInt32LE(0x3c),opt=pe+24,pdata=1280;
  const cases=[
   ['unsorted','PE_EXCEPTION_TABLE_UNSORTED',b=>{const first=Buffer.from(b.subarray(pdata,pdata+12));b.copy(b,pdata,pdata+12,pdata+24);first.copy(b,pdata+12);}],
   ['overlap','PE_EXCEPTION_TABLE_INVALID',b=>b.writeUInt32LE(0x1030,pdata+4)],
   ['unwind-code','PE_EXCEPTION_TABLE_INVALID',b=>b.writeUInt32LE(0x1000,pdata+8)],
   ['directory-bounds','PE_EXCEPTION_TABLE_INVALID',b=>b.writeUInt32LE(0x2ff0,opt+136)],
   ['incomplete-directory','PE_EXCEPTION_TABLE_INVALID',b=>b.writeUInt32LE(0,opt+140)]
  ];
  for(const [name,code,mutate] of cases){
   const bytes=Buffer.from(original);mutate(bytes);
   const file=path.join(temp,name+'.exe'),output=path.join(temp,name+'.approval.json');fs.writeFileSync(file,bytes);
   const result=require('node:child_process').spawnSync(process.execPath,['-e',worker('Create_Approval.bat')],{encoding:'utf8',env:{...process.env,GC_APPROVAL_ACTION:'sign',GC_APPROVAL_COMPONENT:'O',GC_APPROVAL_VERSION:'93.0.0',GC_APPROVAL_EXE:file,GC_APPROVAL_KEY:path.join(temp,'must-not-be-opened.pem'),GC_APPROVAL_OUTPUT:output}});
   assert.equal(result.status,1,name);assert.equal(result.stderr.trim(),code,name);assert.equal(result.stdout,'',name);
   assert.equal(fs.existsSync(output),false,name);assert.deepEqual(fs.readFileSync(file),bytes,name);
   assert.throws(()=>require('../services/desktopIntegrity').CodeImage(bytes),/CRC_CHECKER_PLAN_INVALID/,name);
  }
 });
 Test('Approval preflight preserves A/B/O signatures and leaves absent unwind coverage to the server',()=>{
  const pair=crypto.generateKeyPairSync('ed25519'),keyFile=path.join(temp,'preflight.pem'),keyBytes=Buffer.from(pair.privateKey.export({type:'pkcs8',format:'pem'}));fs.writeFileSync(keyFile,keyBytes,{mode:0o600});
  for(const component of ['A','B','O']){
   const bytes=PE(component,a.DOMAIN);
   for(const missing of [false,true]){
    const image=Buffer.from(bytes),name=component+(missing?'-absent':'-sorted');
    if(missing){const opt=image.readUInt32LE(0x3c)+24;image.writeUInt32LE(0,opt+136);image.writeUInt32LE(0,opt+140);}
    const file=path.join(temp,name+'.exe'),output=path.join(temp,name+'.approval.json');fs.writeFileSync(file,image);
    const result=require('node:child_process').spawnSync(process.execPath,['-e',worker('Create_Approval.bat')],{encoding:'utf8',env:{...process.env,GC_APPROVAL_ACTION:'sign',GC_APPROVAL_COMPONENT:component,GC_APPROVAL_VERSION:'93.0.0',GC_APPROVAL_EXE:file,GC_APPROVAL_KEY:keyFile,GC_APPROVAL_OUTPUT:output,GC_APPROVAL_PREPARED_SHA512:component==='O'?sha512(image):'ignored-for-A-B'}});
    assert.equal(result.status,0,result.stderr);const approval=JSON.parse(fs.readFileSync(output,'utf8'));
    assert.equal(approval.sha512,sha512(image));assert.equal(approval.approval.signature,SignRelease(component,'93.0.0',file,keyFile).approval.signature);
    assert.deepEqual(fs.readFileSync(file),image);assert.deepEqual(fs.readFileSync(keyFile),keyBytes);
    const crc=require('../services/desktopIntegrity').CodeImage(image).crcLayers;assert.equal(crc.jones.status,missing?'unavailable':'measured');
   }
  }
 });
 Test('CFG metadata needs both image flag and bounded load-config fields',()=>{
  const b=PE('B',a.DOMAIN),pe=b.readUInt32LE(0x3c),opt=pe+24,lc=768;
  b.writeUInt16LE(b.readUInt16LE(opt+70)|0x4000,opt+70);b.writeUInt32LE(0x1100,opt+112+80);b.writeUInt32LE(148,opt+116+80);
  b.writeUInt32LE(148,lc);b.writeBigUInt64LE(1n,lc+136);b.writeUInt32LE(0x500,lc+144);
  assert.equal(a.PeCapabilities(b).compiledCfg,true);
  const small=Buffer.from(b);small.writeUInt32LE(140,opt+116+80);assert.equal(a.PeCapabilities(small).compiledCfg,false);
  const pointer=Buffer.from(b);pointer.writeUInt32LE(0xfffffff0,opt+112+80);assert.equal(a.PeCapabilities(pointer).compiledCfg,false);
  const flag=Buffer.from(b);flag.writeUInt16LE(flag.readUInt16LE(opt+70)&~0x4000,opt+70);assert.equal(a.PeCapabilities(flag).compiledCfg,false);
  const empty=Buffer.from(b);empty.writeBigUInt64LE(0n,lc+136);assert.equal(a.PeCapabilities(empty).compiledCfg,false);
 });
 Test('Evidence has exact bounded types and cannot supply its own policy',()=>{
  const v={version:1,hashVersion:3,codeXxh3_128:'c'.repeat(32),codeBlake3:'d'.repeat(64),crcLayers:require('../services/desktopIntegrity').CodeImage(PE('B')).crcLayers,measurement:'MEASURED',fileSha512:'a'.repeat(128),fileCrc64:'A'.repeat(16),codeSha512:'b'.repeat(128),codeCrc64:'B'.repeat(16),apiSealed:true,apiSlots:167,dynamicCode:'ALLOWED',cfg:'DISABLED'};
  assert.equal(a.Payload(JSON.stringify(v)).apiSlots,167);
  for(const patch of [{apiSlots:1025},{apiSealed:1},{version:2},{mode:'observe'},{dynamicCode:'IGNORE'},{codeSha512:'short'}])assert.throws(()=>a.Payload(JSON.stringify({...v,...patch})));
  assert.throws(()=>a.Payload(' '.repeat(2049)));
 });
 Test('Challenge/canonical Delphi field contract stays in sync',()=>{
  const client=path.resolve(__dirname,'../../GameConnect_Win64/Game.ServerAuthority.pas');
  const text=fs.readFileSync(client,'utf8');assert.match(text,/Challenge\.Count <> 8/);assert.match(text,/Reply\.Count <> 8/);assert.ok(text.includes(a.DOMAIN));
  const fields=[...text.matchAll(/Evidence\.AddPair\('([^']+)'/g)].map(x=>x[1]);assert.equal(fields.length,14);assert.equal(new Set(fields).size,14);
  for(const name of ['version','hashVersion','codeXxh3_128','codeBlake3','crcLayers','measurement','fileSha512','fileCrc64','codeSha512','codeCrc64','apiSealed','apiSlots','dynamicCode','cfg'])assert.ok(fields.includes(name));
  const body={stage:'B',sessionId:'SID',intent:'verify',binding:'BIND'},c={challengeId:'CID',nonce:'NONCE',epoch:'EPOCH',sequence:7,revision:2,expiresAt:12345};
  assert.equal(a.Canonical(body,c,'{}'),[a.DOMAIN,'B','SID','verify','BIND','CID','NONCE','EPOCH','7','2','12345',sha512('{}')].join('\n'));
 });
 console.log(`Security tooling tests: ${count} passed`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
