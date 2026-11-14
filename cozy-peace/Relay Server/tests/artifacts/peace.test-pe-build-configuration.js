'use strict';
const assert=require('node:assert/strict');
const {ReadBuildConfiguration,AssertProductionConfiguration}=require("../../services/artifacts/peace.pe-build-configuration");
function Fixture(names=['GAME_BUILD_RELEASE_V1']) {
  const bytes=require('./peace.test-desktop-pe-exports').Fixture();
  const pe=bytes.readUInt32LE(60),opt=pe+24;
  bytes.fill(0,1024);bytes.writeUInt32LE(512,opt+116);
  for(const [offset,value]of [[12,8256],[16,1],[20,names.length],[24,names.length],[28,8232],[32,8240],[36,8248]])bytes.writeUInt32LE(value,1024+offset);
  bytes.write('probe.exe\0',1088,'ascii');
  names.forEach((name,i)=>{
    bytes.writeUInt32LE(4096+i*4,1064+i*4);
    bytes.writeUInt32LE(8192+96+i*96,1072+i*4);
    bytes.writeUInt16LE(i,1080+i*2);
    bytes.write(name+'\0',1120+i*96,'ascii');
  });return bytes;
}
if(require.main===module) {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const data=fs.mkdtempSync(path.join(os.tmpdir(),'game-build-configuration-'));
  process.env.DATA_DIR=data;process.env.HA_ENABLED='0';
  process.on('exit',()=>fs.rmSync(data,{recursive:true,force:true}));
  assert.deepEqual(ReadBuildConfiguration(Fixture()),{configuration:'RELEASE',markerVersion:1});
  const debug=Fixture(['GAME_BUILD_DEBUG_V1']);
  assert.equal(ReadBuildConfiguration(debug).configuration,'DEBUG');
  assert.throws(()=>AssertProductionConfiguration(debug),/SECURITY_DEBUG_BUILD_NOT_PUBLISHABLE/);
  assert.throws(()=>require("../../services/security/peace.desktop-security-authority").PublishMetadata('O','1.0.0',debug,null),/SECURITY_DEBUG_BUILD_NOT_PUBLISHABLE/);
  const legacy=require("../fixtures/bootstrap/peace.desktop-bootstrap-fixture").PE('B');
  assert.equal(AssertProductionConfiguration(legacy).configuration,'UNMARKED');
  assert.throws(()=>AssertProductionConfiguration(legacy,{requireMarker:true}),/SECURITY_BUILD_CONFIGURATION_REQUIRED/);
  const textOnly=Buffer.from(legacy);textOnly.write('GAME_BUILD_RELEASE_V1',512,'ascii');
  assert.equal(ReadBuildConfiguration(textOnly).configuration,'UNMARKED','Only named exports count');
  for(const encoding of ['ascii','utf16le']) {
    const fault=Buffer.concat([Fixture(),Buffer.from('GAME-PRODUCT-FAULT-TEST-V1',encoding)]);
    const build=require("../../services/artifacts/peace.pe-build-configuration");
    process.env.GAME_PRODUCT_FAULT_FIXTURE='1';
    assert.throws(()=>build.AssertProductionConfiguration(fault),/SECURITY_TEST_BUILD_NOT_PUBLISHABLE/);
    assert.throws(()=>require("../../services/security/peace.desktop-security-authority").PublishMetadata('O','1.0.0',fault,null),/SECURITY_TEST_BUILD_NOT_PUBLISHABLE/);
    assert.equal(build.AssertIsolatedTestConfiguration(fault).configuration,'RELEASE');
    delete process.env.GAME_PRODUCT_FAULT_FIXTURE;
  }
  assert.throws(()=>require("../../services/artifacts/peace.pe-build-configuration").AssertIsolatedTestConfiguration(Fixture()),/SECURITY_PRODUCT_FAULT_MARKER_REQUIRED/);
  for(const names of [['GAME_BUILD_DEBUG_V1','GAME_BUILD_RELEASE_V1'],['GAME_BUILD_RELEASE_V1','GAME_BUILD_RELEASE_V1'],['GAME_BUILD_RELEASE_V2']])
    assert.throws(()=>ReadBuildConfiguration(Fixture(names)),/SECURITY_BUILD_CONFIGURATION_INVALID/);
  const pe=debug.readUInt32LE(60),opt=pe+24,section=opt+debug.readUInt16LE(pe+20);
  for(const mutate of [
    b=>b.writeUInt32LE(0,1064),
    b=>b.writeUInt32LE(8256,1064),
    b=>b.writeUInt32LE(0xa0000020,section+36),
    b=>b.writeUInt32LE(0x40000040,section+36),
    b=>{b.writeUInt32LE(1024,section+8);b.writeUInt32LE(4096+600,1064);},
    b=>b.writeUInt16LE(8,1080),
    b=>b.writeUInt32LE(0xffffffff,opt+116)
  ]){const bad=Fixture();mutate(bad);assert.throws(()=>ReadBuildConfiguration(bad),/SECURITY_BUILD_CONFIGURATION_INVALID/);}
  console.log('BUILD CONFIGURATION PASS: marked release/debug, server rejection, legacy compatibility, duplicates/version, bounds, forwarders, physical executable targets.');
}
module.exports={Fixture};
