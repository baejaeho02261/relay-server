'use strict';
// Executable fixture tests + source ABI/ownership contracts. This suite does
// not compile Delphi and never reports production WinSock/SChannel execution.
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),tls=require('node:tls'),crypto=require('node:crypto');
const {Cases,Serve,Evaluate}=require('../../tools/network/peace.native-socket-fixture');
const {Run}=require('../../tools/network/peace.native-socket-tests');
const {Certificates}=require('../../tools/integrity/peace.native-receive-fixture');
const native=path.resolve(__dirname,'../../../Railway'),unit=path.join(native,'Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas');
const read=p=>fs.readFileSync(p,'utf8').replaceAll('\r','');
test('production resolver owns synchronous provider lifetime and bounded address candidates',{skip:!fs.existsSync(unit)},()=>{
 const source=read(unit),resolve=source.split('procedure THostResolution.Resolve;')[1].split('function THostResolution.Wait(')[0];
 assert.match(source,/MaxResolvedCandidates = 8;/);assert.match(source,/MaxResolverEntries = 64;/);assert.match(source,/MaxOutstandingResolvers = 4;/);
 assert.match(source,/Entry\^\.Family = AF_INET6\) and \(Entry\^\.AddressLength = 28/);
 assert.match(source,/CompareMem\(@Result\[I\]\.Bytes\[0\], @Candidate\.Bytes\[0\], Candidate\.Length\)/);
 assert.match(resolve,/GetAddrInfoExW\([\s\S]*?nil, @Hints, Results, nil, nil, nil, nil\)/);
 assert.doesNotMatch(source,/gethostbyname|GetAddrInfoExCancel|TerminateThread/);
 assert(resolve.indexOf('Error := GetAddrInfoExW')<resolve.indexOf('FreeAddrInfoExW(Results)'));
 assert(resolve.indexOf('FreeAddrInfoExW(Results)')<resolve.indexOf('WSACleanup'));
 assert.match(source,/if FAdmitted then TInterlocked\.Decrement\(ResolverCount\)/);
 assert.match(source,/if State <> nil then State\.Cancel;\s*State := nil;/);
});
test('one deadline, terminal Close and serialized TLS ownership remain production paths',{skip:!fs.existsSync(unit)},()=>{
 const source=read(unit),connect=source.split('function TRelaySocketClient.ConnectTCP(')[1].split('procedure TRelaySocketClient.CloseSocket;')[0];
 assert.equal((connect.match(/FDeadline :=/g)||[]).length,1);
 assert.match(source,/WaitSocket\(True, AttemptDeadline\)/);
 assert.match(source,/MaxConnectAttemptMs = 1000/);
 assert.match(source,/TInterlocked\.Exchange\(FCloseRequested, 1\);[\s\S]*?FOperationLock\.Acquire/);
 assert.match(source,/OwnedSocket := FSock; FSock := INVALID_SOCKET;/);
 assert.match(source,/FTls\.Handshake\(ServerName, CertificateSha256, AlternateSha256\)/);
 assert.match(source,/Line := DecodeProtocolUTF8\(RawLine\);\s*if RemainingTimeout\(1\) = 0 then begin Line := ''; Exit; end;/);
 const meta=read(path.join(native,'Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc'));
 assert.match(meta,/IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS[\s\S]*?MESSAGE FATAL/);
 const probe=read(path.join(native,'Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc'));
 for(const token of ['DNS_ADMISSION_RETAINED_WHILE_PROVIDER_PENDING','LATE_CANCELLED_RESULT_REJECTED','REPEATED_FAILURE_NO_OWNER_LEAK','RESOLVER_ADMISSION_CAP','CANCEL_BEATS_READY','PROVIDER_CYCLE_SCAN_BOUND_AND_DEDUP'])assert(probe.includes(token),token);
});
test('non-Windows native runner explicitly returns NOT_RUN',async()=>{
 if(process.platform==='win32')return;
 assert.deepEqual(await Run('/not/a/windows/probe.exe'),{version:1,outcome:'NOT_RUN',nativeExecuted:false,reason:'WINDOWS_X64_REQUIRED'});
});
test('result evaluation requires native marker, nonce, deadline and wire observations',()=>{
 const row=Cases().find(x=>x.id==='ipv4-fragmented'),nonce='a'.repeat(32);
 const observed={version:1,nativeSocketExecuted:true,caseId:row.id,nonce,connected:true,sent:true,received:true,closed:false,line:JSON.stringify({value:'한글',nonce}),elapsedMs:100};
 const wire={connections:1,tlsAccepted:1,requestAccepted:true,fragments:10};
 assert.equal(Evaluate(row,observed,wire,nonce).outcome,'PASS');
 for(const patch of [{nativeSocketExecuted:false},{nonce:'b'.repeat(32)},{elapsedMs:2401},{line:'{}'},{received:false}])assert.throws(()=>Evaluate(row,{...observed,...patch},wire,nonce),/SOCKET_/);
 assert.throws(()=>Evaluate(row,observed,{...wire,requestAccepted:false},nonce),/SOCKET_FIXTURE_NOT_EXERCISED/);
 const cancel=Cases().find(x=>x.cancelAfter===0);
 assert.throws(()=>Evaluate(cancel,{...observed,caseId:cancel.id,connected:false,received:false,closed:true},{...wire,connections:1},nonce),/SOCKET_CANCELLED_PHASE_STARTED/);
});
async function NodeFixtureClient(server,identity,pin,nonce,{cancelAfter=0}={}){
 return new Promise((resolve,reject)=>{
  const socket=tls.connect({host:'127.0.0.1',port:server.port,servername:'localhost',ca:identity.cert,minVersion:'TLSv1.2',maxVersion:'TLSv1.2'});let data=Buffer.alloc(0),settled=false,cancelTimer;
  const timer=setTimeout(()=>finish(Error('FIXTURE_TIMEOUT')),2000);
  function finish(error,value){if(settled)return;settled=true;clearTimeout(timer);clearTimeout(cancelTimer);socket.destroy();error?reject(error):resolve(value);}
  socket.once('secureConnect',()=>{const peer=socket.getPeerCertificate();if(crypto.createHash('sha256').update(peer.raw).digest('hex')!==pin)return finish(Error('FIXTURE_PIN'));socket.write(JSON.stringify({nonce})+'\n');if(cancelAfter)cancelTimer=setTimeout(()=>finish(null,{cancelled:true}),cancelAfter);});
  socket.on('data',b=>{data=Buffer.concat([data,b]);if(data.includes(10))finish(null,{line:data.toString('utf8').trim()});});socket.on('error',error=>finish(error));
 });
}
test('real loopback TLS fixture delivers fragmented UTF-8 with unchanged certificate pin',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-socket-fixture-'));let server;
 try{const {identity,pin}=Certificates(root),nonce='c'.repeat(32),row=Cases()[0];server=await Serve(row,identity,nonce);const result=await NodeFixtureClient(server,identity,pin,nonce);assert.deepEqual(JSON.parse(result.line),{value:'한글',nonce});assert(server.wire.fragments>20);assert.equal(server.wire.requestAccepted,true);}
 finally{if(server)await server.close();fs.rmSync(root,{recursive:true,force:true});}
});
test('real loopback fixture releases stalled connection after client cancellation',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'cozy-socket-fixture-'));let server;
 try{const {identity,pin}=Certificates(root),nonce='d'.repeat(32),row=Cases().find(x=>x.stall);server=await Serve(row,identity,nonce);const result=await NodeFixtureClient(server,identity,pin,nonce,{cancelAfter:30});assert.equal(result.cancelled,true);assert.equal(server.wire.requestAccepted,true);assert.equal(server.wire.fragments,0);}
 finally{if(server)await server.close();fs.rmSync(root,{recursive:true,force:true});}
});
