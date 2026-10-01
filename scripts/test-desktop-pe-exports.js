'use strict';
const assert=require('node:assert/strict');
const {PE}=require('./desktop-bootstrap-fixture');
const {CodeImage}=require('../services/desktopIntegrity');
const {ExportTable}=require('../services/desktopPeExports');
function Fixture(){
 const bytes=Buffer.alloc(1536);PE('B').copy(bytes);
 const pe=bytes.readUInt32LE(60),opt=pe+24,table=opt+bytes.readUInt16LE(pe+20);
 bytes.writeUInt16LE(2,pe+6);bytes.writeUInt16LE(bytes.readUInt16LE(pe+22)|0x2000,pe+22);bytes.writeUInt32LE(0x3000,opt+56);
 const section=table+40;bytes.write('.rdata\0\0',section,'ascii');
 for(const [offset,value]of [[8,512],[12,8192],[16,512],[20,1024],[36,0x40000040]])bytes.writeUInt32LE(value,section+offset);
 bytes.writeUInt32LE(8192,opt+112);bytes.writeUInt32LE(256,opt+116);
 const at=1024;
 for(const [offset,value]of [[12,8256],[16,1],[20,2],[24,2],[28,8232],[32,8240],[36,8248]])bytes.writeUInt32LE(value,at+offset);
 bytes.writeUInt32LE(4096,1064);bytes.writeUInt32LE(8296,1068);
 bytes.writeUInt32LE(8272,1072);bytes.writeUInt32LE(8288,1076);bytes.writeUInt16LE(0,1080);bytes.writeUInt16LE(1,1082);
 bytes.write('sample.dll\0',1088,'ascii');bytes.write('ReadFile\0',1104,'ascii');bytes.write('OpenFile\0',1120,'ascii');bytes.write('KERNELBASE.ReadFile\0',1128,'ascii');return bytes;
}
if(require.main===module){
 const good=Fixture(),baseline=ExportTable(good),code=CodeImage(good);assert.equal(baseline.status,'MEASURED');assert.equal(baseline.exportCount,2);assert.equal(baseline.codeExportCount,1);assert.equal(baseline.forwardedExportCount,1);
 const redirect=Buffer.from(good);redirect.writeUInt32LE(4100,1064);assert.equal(CodeImage(redirect).sha256,code.sha256,'EAT redirect outside executable sections must not be mistaken for code change');assert.notEqual(ExportTable(redirect).sha256,baseline.sha256);
 const forward=Buffer.from(good);forward[1128]^=1;assert.notEqual(ExportTable(forward).sha256,baseline.sha256);
 const pe=good.readUInt32LE(60),opt=pe+24;
 for(const change of [b=>b.writeUInt32LE(0xffffffff,opt+116),b=>b.writeUInt32LE(0xffffffff,1024+20),b=>b.writeUInt32LE(0x3000,1064),b=>b.writeUInt32LE(0x2200,1024+32),b=>b.writeUInt16LE(2,1080),b=>b[1088]=0,b=>b[1128]=32,b=>b[1088]=255]){
  const bad=Buffer.from(good);change(bad);assert.equal(ExportTable(bad).status,'UNSUPPORTED_EXPORT_LAYOUT');
 }
 assert.equal(ExportTable(PE('B')).status,'NO_EXPORTS');
 console.log('PE EXPORT TABLE PASS: direct/forwarded API coverage, EAT tamper independent of code hash, bounds/ASCII/ordinal validation');
 console.log('PE EXPORT VECTOR '+JSON.stringify({sha256:baseline.sha256,crc64:baseline.crc64,directoryOffset:baseline.directoryOffset,rva:baseline.rva,span:baseline.span}));
}
module.exports={Fixture};
