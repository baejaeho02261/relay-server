'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const bootstrap=require('../../services/bootstrap/peace.desktop-bootstrap');
const report={chunks:32,reused:29,chunkMs:51000,tlsMs:1800,wireMs:32000,cryptoMs:1200,fileMs:1600,verifyMs:3000,nhwMs:150,nhwChecks:1};
test('only bounded non-sensitive bootstrap client timing is accepted',()=>{
 assert.equal(bootstrap.ValidClientTiming(report,'chunk',32*262144),true);
 assert.equal(bootstrap.ValidClientTiming(report,'finish',undefined),true);
 assert.equal(bootstrap.ValidClientTiming(report,'abort',undefined),true);
 for(const altered of [
  {...report,chunks:257},{...report,reused:33},{...report,cryptoMs:900001},
  {...report,nhwMs:-1},{...report,nhwChecks:0.5},
  {...report,deviceId:'secret'},{...report,downloadTicket:'secret'},
  {...report,privatePath:'/sensitive/path'},
  {...report,tlsMs:Infinity},{...report,verifyMs:'5'},
  Object.assign(Object.create(null),report)
 ])assert.equal(bootstrap.ValidClientTiming(altered,'chunk',32*262144),false);
 for(const offset of [1,-1,262144,15*262144,null,'0',NaN])assert.equal(bootstrap.ValidClientTiming(report,'chunk',offset),false);
});

const protocol=require('../../services/protocol/peace.packet-schema');
test('real wire schema admits only explicit non-sensitive clientTiming on A bootstrap transitions',()=>{
 for(const action of ['chunk','finish','abort']){
  const template=protocolFixtures.find(x=>x.operation==='bootstrap'&&x.body.action===action);
  assert.ok(template,action);
  assert.doesNotThrow(()=>protocol.ValidateEnvelope({...template,body:{...template.body,clientTiming:report}}));
  for(const changed of [
    {...report,deviceId:'leak'}, {...report,nhwMs:-1}, {...report,chunks:257},
    {...report,cryptoMs:900001},{...report,privatePath:'C:/secret'}
  ])assert.throws(()=>protocol.ValidateEnvelope({...template,body:{...template.body,clientTiming:changed}}),/PROTOCOL_SCHEMA_INVALID/);
 }
});
const protocolFixtures=require('../fixtures/protocol/peace.packet-schema-cases.json').cases;
