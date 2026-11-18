'use strict';
// The receipt/expiry checks below execute real server handlers and encrypted
// sockets. Native fallback wiring is a source contract, not Windows execution.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {ReadContractFile}=require('../fixtures/source/peace.native-string-contract');
const native=path.resolve(__dirname,'../../../Railway'),available=fs.existsSync(native);
const read=p=>ReadContractFile(path.join(native,p),'utf8').replace(/\r\n/g,'\n');
const roles=[
 ['Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas','TBootstrapClient',30000,'FFlowStarted + 290000'],
 ['Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas','TOverlayClient',15000,'RequestDeadlineTick']
];
for(const [file,role,budget,bound]of roles)test(role+' narrows only a failed large transport receive inside its original request budget',{skip:!available},()=>{
 const source=read(file),chunk=source.split('function '+role+'.ChunkCore(')[1].split('\nend;')[0];
 assert.ok(chunk.indexOf('Deadline := CozyTick + '+budget)<chunk.indexOf('while True do'));
 assert.ok(chunk.indexOf(bound)<chunk.indexOf('while True do'));
 const loop=chunk.slice(chunk.indexOf('while True do'));
 assert.doesNotMatch(loop,/Deadline\s*:=|Ticket\s*:=|Offset\s*:=|Flow\.\w+\s*:=/);
 assert.match(chunk,/BatchRequest := not FChunkBatchDisabled and/);
 const fail=loop.split('on E: EConnectTransport do')[1].split('end;')[0];
 assert.deepEqual([...fail.matchAll(/E\.Code <> '([^']+)'/g)].map(m=>m[1]),['CONNECT_TIMEOUT','CONNECT_RECEIVE_FAILED']);
 assert.match(fail,/if not BatchRequest or[\s\S]*then raise;/);
 assert.match(fail,/FChunkBatchDisabled := True;\s*BatchRequest := False;/);
 assert.match(fail,/RemovePair\('count'\)/);
 assert.match(fail,/RemovePair\('action'\)/);
 assert.match(loop,/Post\([\s\S]*Deadline,[\s\S]*BatchRequest\)/);
 assert.ok(chunk.indexOf("BootstrapInteger(Data, 'offset') <> Offset")>chunk.indexOf('while True do'));
 assert.ok(chunk.indexOf("BootstrapInteger(Data, 'size') <> Expected")>chunk.indexOf('while True do'));
 assert.match(source,/if SingleAttempt then (?:MaxAttempts|Attempts) := 1;/);
 const transport=read('Cozy.Source/Cozy.Network/Cozy.Transport.pas');
 assert.match(transport,/if RequestBudgetMs > RequestTimeoutMs then RequestBudgetMs := RequestTimeoutMs;/);
});

test('a lost authorized batch can be reread as single chunks without new authority or extra receipts',async()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-download-size-recovery-'));
 process.env.DATA_DIR=temp;process.env.STORAGE_ENGINE='json';process.env.HA_ENABLED='0';process.env.DESKTOP_PUBLIC_HOST='127.0.0.1';process.env.DESKTOP_PUBLIC_PORT='29131';
 require('../../core/peace.utilities').EnsureDirs();
 const fixture=require('../fixtures/bootstrap/peace.desktop-bootstrap-fixture'),boot=require('../../services/bootstrap/peace.desktop-bootstrap'),transport=require('../../services/network/peace.desktop-connect');
 let server;
 try{
  const cohort=fixture.CurrentCohort({version:'88.1.0',paddingBytesByRole:{B:2*262144+32768}});
  const {begin}=fixture.Begin(fixture.Device()),row=boot.Initialize().flows[begin.flowId],size=begin.chunkSize;
  const original={id:row.id,expiresAt:row.expiresAt,createdAt:row.createdAt,downloadHash:row.downloadHash};
  server=transport.CreateServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  process.env.DESKTOP_PUBLIC_PORT=String(server.address().port);
  const profile=require('../../services/network/peace.connect-transport-key').Profile();
  const body=offset=>({action:'chunk',flowId:begin.flowId,downloadTicket:begin.downloadTicket,offset});
  // Discard this valid response, as if its receipt had reached the server but
  // the client had not received a complete authenticated response frame.
  const lost=await fixture.TcpBootstrap(profile,{...body(0),count:2});
  assert.equal(lost.size,2*size);
  assert.deepEqual(boot.Initialize().flows[begin.flowId].chunkOffsets,[0,size]);
  const chunks=[];
  for(let offset=0;offset<begin.release.size;){
   const response=await fixture.TcpBootstrap(profile,body(offset)),bytes=Buffer.from(response.data,'base64');
   assert.equal(response.offset,offset);assert.equal(response.size,Math.min(size,begin.release.size-offset));
   chunks.push(bytes);offset+=bytes.length;
  }
  const bytes=Buffer.concat(chunks),current=boot.Initialize().flows[begin.flowId];
  assert.deepEqual(bytes,cohort.outputs.B.bytes);
  assert.equal(fixture.sha512(bytes),begin.release.sha512);assert.equal(fixture.Crc64(bytes),begin.release.crc64);
  assert.deepEqual(current.chunkOffsets,[0,size,2*size]);
  assert.deepEqual({id:current.id,expiresAt:current.expiresAt,createdAt:current.createdAt,downloadHash:current.downloadHash},original);
  assert.throws(()=>boot.Execute({...body(0),downloadTicket:'invalid'}),/BOOTSTRAP_FLOW_INVALID/);
  const realNow=Date.now;
  try{Date.now=()=>original.expiresAt+1;assert.throws(()=>boot.Execute(body(0)),/BOOTSTRAP_EXPIRED/);}
  finally{Date.now=realNow;}
 }finally{
  await transport.Stop();if(server)await new Promise(resolve=>server.close(resolve));
  require('../../storage/sqlite/peace.sqlite-database').Close();fs.rmSync(temp,{recursive:true,force:true});
 }
});
