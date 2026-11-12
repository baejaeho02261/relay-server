'use strict';
// Static contract checks of optional Delphi sources in a full Cozy source tree.
// The server-only Railway Docker image legitimately has no Delphi compiler.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const project=path.resolve(__dirname,'../../..'),read=part=>fs.readFileSync(path.join(project,part),'utf8');
const unit='Railway/Cozy.Source/Cozy.Application/Cozy.Launcher.pas';
test('A reissue preserves original bounded deadlines and performs mandatory pre-B verification',t=>{
 if(!fs.existsSync(path.join(project,unit))){t.skip('Delphi source not included in server-only image');return;}
 const launch=read(unit),boot=read('Railway/Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas');
 assert.match(boot,/FFlowStarted\s*>=\s*290000/);
 assert.match(launch,/DownloadDeadlineMS\s*=\s*300000/);
 assert.match(launch,/RequireLauncherWatch\(Watch\)/);
 assert.match(launch,/if\s*\(Watch <> nil\)\s*and Watch\.ConsumeRevalidationRequest/);
 assert.match(launch,/CurrentLauncher\s*:=\s*Config\.ImageIntegrity\.VerifyNow/);
 assert.match(launch,/Client\.ReportIntegrity\(Flow, Security, Config\.CodeIntegrity/);
 assert.match(boot,/Action\s*=\s*CozyText_Bootstrap_chunk_77e594ae/);
 assert.match(boot,/Body\.AddPair\('clientTiming', TransferTiming\)/);
 assert.match(boot,/Client\.NoteValidationTiming/); // public instrumentation signature
});
test('A TLS reuse opt-in is one request at a time and requires fresh cryptography',t=>{
 if(!fs.existsSync(path.join(project,unit))){t.skip('Delphi source not included in server-only image');return;}
 const transport=read('Railway/Cozy.Source/Cozy.Network/Cozy.Transport.pas');
 const socket=read('Railway/Cozy.Source/Cozy.Network/Cozy.Relay.Socket.pas');
 assert.match(transport,/Frame\.AddPair\('keepAlive', TJSONNumber\.Create\(1\)\)/);
 assert.match(transport,/Frame\.AddPair\(CozyText_Transport_requestId_d67f3acd, RequestID\)/);
 assert.match(transport,/BCryptGenRandom\(0, Scope\.Buffer\.Write\(0, 32\)/);
 assert.match(transport,/Socket\.BeginNextRequest\(Cardinal\(SocketBudget\)\)/);
 assert.match(transport,/FProfile\.CheckTlsPeer\(PeerPin\)/);
 assert.match(transport,/if \(VersionValue is TJSONBool\) and \(VersionValue\.Value = 'true'\)/);
 assert.match(socket,/function TRelaySocketClient\.BeginNextRequest/);
 assert.match(socket,/FBuffer <> ''/);
 assert.match(socket,/RequestTimeoutMs > 10000/);
});
test('NHW source and detection/authority policy cannot be removed as a performance shortcut',t=>{
 if(!fs.existsSync(path.join(project,unit))){t.skip('Delphi source not included in server-only image');return;}
 const nhwDir=path.join(project,'Railway/Cozy.Source/Cozy.Security.NHW');
 const all=fs.readdirSync(nhwDir).filter(x=>x.endsWith('.pas'));
 assert.ok(all.length>=200,`unexpected NHW unit loss: ${all.length}`);
 const launch=read(unit),guard=read('Railway/Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Guard.pas');
 assert.match(guard,/function TCozyNHWGuard\.Confirmed: Boolean/);
 assert.match(guard,/function TCozyNHWGuard\.ConsumeRevalidationRequest: Boolean/);
 assert.match(launch,/procedure RequireLauncherWatch/);
 assert.match(launch,/Watch\.Confirmed/);
});
test('B_NOT_STARTED is never presented as confirmed residue',()=>{
 const file=read('Relay Server/public/scripts/desktop/peace.admin-desktop-server-state.js');
 assert.match(file,/B_NOT_STARTED'\?'B 시작 미확인'/);
 assert.doesNotMatch(file,/<strong>B 잔류 원인/);
});
