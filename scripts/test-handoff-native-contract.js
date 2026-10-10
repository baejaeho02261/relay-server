'use strict';
// Cross-language fixtures + native source security contracts. This does not
// execute Delphi, Windows handles, CNG, or the A/B/O lifecycle.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../GameConnect_Win64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8');
const security=read('Game.Security.pas'),handoff=read('Game.Handoff.pas'),cipher=read('Game.Handoff.Crypto.pas');
const bootstrap=read('Game.Bootstrap.pas'),overlay=read('Game.Overlay.Client.pas');
const vector=JSON.parse(read('tests/HandoffV3Vector.json'));
const delegation=require('../services/desktopHandoffDelegation');
let count=0;
function check(name,run){run();count++;console.log('PASS '+name);}
check('Native known-answer fixture agrees with production server canonical',()=>{
 assert.equal(delegation.Canonical('DELEGATION',vector.role,vector.claim,vector.childKeyId,vector.nonce),vector.delegationCanonical);
 assert.equal(delegation.Canonical('CLAIM',vector.role,vector.claim,vector.childKeyId,vector.nonce),vector.claimCanonical);
 assert.ok(read('tests/DeviceSecurityHandoffProbe.dpr').includes("ClaimHash = '"+vector.claimSha512+"'"));
 assert.match(security,/ClaimHash := IntegritySHA512Text\(Claim\)/);
 assert.match(security,/'GAME-HANDOFF-' \+ Purpose \+ '-V3' \+ #10 \+ Role \+ #10/);
});
check('Native runtime has no private key export, import, or cloned-key field',()=>{
 for(const s of [security,handoff])assert.doesNotMatch(s,/ExportPrivateKey|CreateFromPrivateBlob|FieldPrivateKey|RSAFULLPRIVATEBLOB|NCryptAllowExport/);
 assert.doesNotMatch(security,/NCryptSetProperty\(FKey, 'Export Policy'/);
 assert.match(handoff,/ChildSecurity := TDeviceSecurity\.Create/);
});
check('Both claims require V3 parent authorization plus independent child proof',()=>{
 for(const [s,role] of [[bootstrap,'B'],[overlay,'O']]){
  for(const field of ['childPublicKey','childKeyId','childNonce','delegationSignature'])assert.ok(s.includes("Body.AddPair('"+field+"'"));
  assert.ok(s.includes("Security.SignHandoffClaim('"+role+"',"));
  assert.ok(s.includes('Security.ParentDeviceID'));
  assert.ok(s.includes('Security.CompleteHandoff'));
 }
 assert.match(bootstrap,/Body\.AddPair\('handoffVersion', TJSONNumber\.Create\(3\)\)/);
});
check('Authenticated IPC uses single-use wrapping and rejects old wire',()=>{
 assert.match(handoff,/HandoffVersion = 3/);
 assert.match(cipher,/HandoffProtocolMarker: AnsiString = 'GAME-HANDOFF-V3'/);
 assert.match(cipher,/TInterlocked\.CompareExchange\(FConsumed, 1, 0\)/);
 assert.match(cipher,/Padding\.Algorithm := 'SHA256'/);
 assert.match(cipher,/SetLength\(Secret, 32\)/);
 assert.match(cipher,/GcmMode = 'ChainingModeGCM'/);
 assert.match(cipher,/except\s+WipeBytes\(Result\); raise;/);
 assert.match(handoff,/Payload := Cipher\.Decrypt\(Envelope, AAD\)/);
});
check('Fresh hello and exact child handle stay bound to encrypted payload',()=>{
 assert.match(handoff,/InheritedHandles: array\[0\.\.3\] of THandle/);
 assert.match(handoff,/InheritedHandles\[3\] := ReplyWrite/);
 assert.match(handoff,/Close\(ReplyWrite\);\s+WritePublicFrame\(WritePipe, PublicBootstrap\);\s+Hello := ReadHello/);
 assert.match(handoff,/GetProcessId\(Process\.hProcess\) = Process\.dwProcessId/);
 assert.match(handoff,/PayloadNonce = Nonce/);
 assert.match(handoff,/AAD := Transcript\(PublicBootstrap, Hello\)/);
 assert.doesNotMatch(handoff,/CommandLine := .*?(?:HandoffToken|PrivateKey|Profile\.ToJSON)/);
});
check('Child environment is explicit and role delegation is irreversibly consumed',()=>{
 assert.match(handoff,/Environment := ChildEnvironment/);
 assert.match(handoff,/ExtendedStartupInfoPresent or UnicodeEnvironmentFlag, PWideChar\(Environment\)/);
 assert.match(handoff,/Entries\[Count\] := 'PATH='/);
 assert.match(security,/if FHandoffAccepted or not IsUpperHex64/);
 assert.match(security,/FHandoffAccepted := True/);
 const done=security.split('procedure TDeviceSecurity.CompleteHandoff;')[1];
 assert.doesNotMatch(done,/FHandoffAccepted := False/);
 assert.match(done,/WipeText\(FDelegationSignature\)/);
});
console.log('Native Handoff V3 contracts: '+count+' passed; dcc64/Windows/CNG runtime NOT tested.');
