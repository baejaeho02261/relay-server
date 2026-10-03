'use strict';
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
let count=0;function Test(name,fn){fn();count++;console.log('PASS '+name);}
try{
 Test('Signing tool exports only public approval; inputs remain unchanged',()=>{
  const pair=crypto.generateKeyPairSync('ed25519'); const privatePem=pair.privateKey.export({type:'pkcs8',format:'pem'}).toString();
  const keyFile=path.join(temp,'offline.pem'),file=path.join(temp,'test.exe');fs.writeFileSync(keyFile,privatePem,{mode:0o600});const bytes=PE('B',a.DOMAIN);fs.writeFileSync(file,bytes);
  const out=SignRelease('B','87.1.0',file,keyFile);
  assert.ok(!JSON.stringify(out).includes('PRIVATE KEY'));assert.ok(!JSON.stringify(out).includes(privatePem));
  assert.deepEqual(fs.readFileSync(file),bytes);assert.equal(fs.readFileSync(keyFile,'utf8'),privatePem);
  const policy={...a.Defaults(),requireReleaseSignature:true,trustedReleaseKeys:[out.trustedKey]};a.ValidatePolicy(policy);
  assert.equal(a.VerifyApproval({component:'B',version:'87.1.0',sha256:sha256(bytes),releaseApproval:out.approval},policy),true);
  assert.equal(Audit(file).authorityVersion,1);assert.equal(Audit(file).compiledCfg,false);
  assert.throws(()=>a.ValidatePolicy({...policy,trustedReleaseKeys:[{...out.trustedKey,publicKey:privatePem}]}));
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
  const v={version:1,measurement:'MEASURED',fileSha256:'a'.repeat(64),fileCrc64:'A'.repeat(16),codeSha256:'b'.repeat(64),codeCrc64:'B'.repeat(16),apiSealed:true,apiSlots:167,dynamicCode:'ALLOWED',cfg:'DISABLED'};
  assert.equal(a.Payload(JSON.stringify(v)).apiSlots,167);
  for(const patch of [{apiSlots:1025},{apiSealed:1},{version:2},{mode:'observe'},{dynamicCode:'IGNORE'},{codeSha256:'short'}])assert.throws(()=>a.Payload(JSON.stringify({...v,...patch})));
  assert.throws(()=>a.Payload(' '.repeat(2049)));
 });
 Test('Challenge/canonical Delphi field contract stays in sync',()=>{
  const client=path.resolve(__dirname,'../../GameConnect_Win64/Game.ServerAuthority.pas');
  const text=fs.readFileSync(client,'utf8');assert.match(text,/Challenge\.Count <> 8/);assert.match(text,/Reply\.Count <> 8/);assert.ok(text.includes(a.DOMAIN));
  const fields=[...text.matchAll(/Evidence\.AddPair\('([^']+)'/g)].map(x=>x[1]);assert.equal(fields.length,10);assert.equal(new Set(fields).size,10);
  for(const name of ['version','measurement','fileSha256','fileCrc64','codeSha256','codeCrc64','apiSealed','apiSlots','dynamicCode','cfg'])assert.ok(fields.includes(name));
  const body={stage:'B',sessionId:'SID',intent:'verify',binding:'BIND'},c={challengeId:'CID',nonce:'NONCE',epoch:'EPOCH',sequence:7,revision:2,expiresAt:12345};
  assert.equal(a.Canonical(body,c,'{}'),[a.DOMAIN,'B','SID','verify','BIND','CID','NONCE','EPOCH','7','2','12345',sha256('{}')].join('\n'));
 });
 console.log(`Security tooling tests: ${count} passed`);
}finally{fs.rmSync(temp,{recursive:true,force:true});}
