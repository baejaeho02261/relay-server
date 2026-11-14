'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Source boundary contracts supplement real Windows probes and server behavior
// tests. They do not execute Delphi, Windows object lifetimes or pipe handles.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(MODULE_RESOURCE_ROOT,'../../Railway');
const read=name=>ReadContractFile(path.join(base,name),'utf8').replaceAll('\r','');
const api=read("Cozy.Source/Cozy.Platform/Cozy.Api.pas"),bootstrap=read("Cozy.Source/Cozy.Application/Cozy.Bootstrap.pas"),overlay=read("Cozy.Source/Cozy.Overlay/Cozy.Overlay.Client.pas"),handoff=read("Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas"),security=read("Cozy.Source/Cozy.Security/Cozy.Security.pas"),cipher=read("Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas"),authority=read("Cozy.Source/Cozy.Security/Cozy.ServerAuthority.pas");
let count=0;
function check(name,run){run();count++;console.log('PASS '+name);}
function wrapper(source,cls,name){
 const start=source.search(new RegExp('^(?:function|procedure) '+cls.replaceAll('.','\\.')+'\\.'+name+'(?=[(:;])','m'));
 assert.ok(start>=0,cls+'.'+name+' missing');
 const body=source.slice(start,source.indexOf('\nend;',start)+5);
 assert.match(body,/begin\s+FGate\.Enter;/);
 assert.match(body,/finally FGate\.Leave; end;/);
 return body;
}
check('Six security owners drain admitted operations before resource destruction',()=>{
 for(const [s,c,release] of [[security,'TDeviceSecurity','WipeText(FPublicKeyBlob)'],[cipher,'THandoffCipher','BCryptDestroyKey(FKey)'],[api,'TGameApi','FSecurity.Free'],[bootstrap,'TBootstrapClient','FTransport.Free'],[overlay,'TOverlayClient','FTransport.Free'],[handoff,'THandoffContext','Security.Free']]){
  const d=s.split('destructor '+c+'.Destroy;')[1].split('\nend;')[0];
  const close=d.includes('FGate.CloseAndWait')?d.indexOf('FGate.CloseAndWait'):d.indexOf('Close;');
  assert.ok(close>=0&&close<d.indexOf(release),c+' must drain first');
  assert.ok(d.indexOf('FGate.Free')>d.indexOf(release),c+' frees gate last');
 }
 assert.ok(api.includes('RequestStopCore;\n  if FGate <> nil then FGate.CloseAndWait;'));
});
check('Public key, crypto, client and handoff calls admit exactly at their outer boundary',()=>{
 for(const name of ['Sign','SignHandoffClaim','AcceptDelegation','CompleteHandoff','ReadField'])assert.ok(security.includes('TDeviceSecurity.'+name));
 assert.match(security,/Result := SignSpanUnlocked\(Scope\.Buffer\)/);
 for(const name of ['StartOverlay','Redeem','Verify','Release','CheckIntegrity','ContinueModuleInventory'])assert.ok(wrapper(api,'TGameApi',name).includes('RequireRunning;'));
 for(const name of ['Claim','Close','AbortChild','Verify','ReportIntegrity'])wrapper(overlay,'TOverlayClient',name);
 for(const name of ['Claim','Close','AbortFlow','ReportIntegrity'])wrapper(bootstrap,'TBootstrapClient',name);
 for(const name of ['ParentIsAlive','ConfirmOverlayReady','CleanupTransferredParent','TakeImageIntegrity'])wrapper(handoff,'THandoffContext',name);
 assert.match(overlay,/if FClosed then raise EBootstrap.Create\('CLIENT_CLOSED'\)/);
 assert.match(bootstrap,/if FClosed then raise EBootstrap.Create\('CLIENT_CLOSED'\)/);
});
check('Overlay preparation keeps the same request identity and signed execute body',()=>{
 assert.match(api,/PrepareRequestID := RequestID;\s+Reply := ExecuteProof\('overlay', PayloadText, PrepareRequestID\)/);
 assert.match(api,/Result := PostJSON\('execute', ExecuteBody, \(Action = 'overlay'\) or\s*\(Action = 'redeem'\) or \(Action = 'release'\)\)/);
 const retry=api.split('function TGameApi.PostJSON(')[1].split('function TGameApi.ExecuteProof(')[0];
 assert.ok(retry.includes('Attempts := 2'));
 assert.ok(retry.includes('Deadline := CozyTick + 15000'));
 assert.ok(retry.indexOf('for Attempt := 1 to Attempts')<retry.indexOf('Response := FTransport.PostJSON(Operation, Body, Budget)'));
 assert.ok(retry.indexOf('Break;')<retry.indexOf("Response.GetValue('ok')"));
 assert.doesNotMatch(retry,/on E: EGameApi do\s*(?:begin)?\s*Continue/);
});
check('Unknown preparation abort uses its original request; transferred O survives lost commit',()=>{
 assert.match(api,/AbortPrepareID := PrepareRequestID/);
 assert.match(api,/TransferClient\.AbortChild\(FSecurity,/);
 assert.match(api,/if RecoveredTransfer and \(FailureReason = 'OVERLAY_TRANSFER_FAILED'\) then/);
 assert.match(overlay,/'GAME-OVERLAY-ABORT-V3' \+ #10 \+ ParentSessionID \+ #10 \+ Scope \+ #10 \+ Identifier/);
 assert.match(overlay,/Scope := 'PREPARE'/);
 assert.match(overlay,/if Status(?:Core)? = 'NOT_PREPARED'/); // Status local unchanged or private-core rename
 assert.match(overlay,/ReturnedID <> ''/);
});
check('Report retries reuse the signed submit while challenges remain single attempt',()=>{
 assert.match(api,/PostJSON\('report', SubmitBody, True, Cancelled\)/);
 for(const s of [bootstrap,overlay]){
  assert.ok(s.includes('ReportPost(ChallengeBody, False)'));
  assert.ok(s.includes('ReportPost(SubmitBody, True)'));
  assert.ok(s.includes('if ExactSubmitRetry then Attempts := 2'));
  const r=s.split('function ReportPost(')[1].split('procedure Send(')[0];
  assert.ok(r.indexOf('for Attempt := 1 to Attempts')<r.indexOf("FTransport.PostJSON('report', Body"));
  assert.ok(r.indexOf('Break;')<r.indexOf("Response.GetValue('ok')"));
 }
});
check('Authority receipt retries require local transport provenance, never server error text',()=>{
 const post=authority.split('function Post(')[1].split('function SubmitExact(')[0];
 const submit=authority.split('function SubmitExact(')[1].split('function AuthorityBinding(')[0];
 assert.match(authority,/EAuthorityTransportFailure = class\(EGameApi\)/);
 assert.equal((authority.match(/raise EAuthorityTransportFailure\.Create/g)||[]).length,1);
 assert.match(post,/on E: EConnectTransport do\s+raise EAuthorityTransportFailure\.Create/);
 const responseValidation=post.slice(post.indexOf("if not IsTrue(Response, 'ok')"));
 assert.match(responseValidation,/raise EGameApi\.Create\(Code,/);
 assert.doesNotMatch(responseValidation,/EAuthorityTransportFailure/);
 assert.match(submit,/for Attempt := 1 to 2 do/);
 assert.match(submit,/on E: EAuthorityTransportFailure do\s+if \(Attempt = 2\) or not E\.Retryable or/);
 assert.doesNotMatch(submit,/on E: (?:Exception|EGameApi) do/);
 for(const code of ['CONNECT_TIMEOUT','CONNECT_UNAVAILABLE','CONNECT_SEND_FAILED','CONNECT_RECEIVE_FAILED','NETWORK_UNAVAILABLE'])assert.ok(submit.includes("E.Code = '"+code+"'"));
 assert.match(submit,/Result := Post\(Transport, Body, Clock, Cancelled\)/);
 assert.doesNotMatch(submit,/\.Sign\(|AddPair\(|ObserveOnce\(|Body :=|StartNew/);
 assert.ok(authority.includes('Reply := SubmitExact(Transport, SubmitBody, Clock, Cancelled);'));
});
check('Authority and each signed report retry share one monotonic deadline across attempts',()=>{
 const observe=authority.slice(authority.lastIndexOf('procedure RequireServerObservation('));
 assert.equal((authority.match(/Clock := TStopwatch\.StartNew/g)||[]).length,1);
 assert.ok(observe.indexOf('Clock := TStopwatch.StartNew')<observe.indexOf('for Attempt := 1 to 2'));
 assert.match(authority,/ObservationBudgetMs - Clock\.ElapsedMilliseconds/);
 assert.match(authority,/Transport\.PostJSON\('security', Body, RemainingBudget\(Clock, Cancelled\)\)/);
 assert.match(observe,/const Runtime: ICozyRuntimeMeasurement/);
 assert.match(observe,/FileSHA512, FileCRC64, Clock, Cancelled, OwnImage, Runtime, Extension\)/);
 assert.match(observe,/Extension\.ConfigureResponses\(Transport, Security, Stage, SessionID, SessionToken\)/);
 assert(observe.indexOf("Extension.ConfigureResponses") < observe.indexOf("for Attempt :="), "Independent response paths are configured before the ordinary observation retry loop");
 const once=authority.split('procedure ObserveOnce(')[1].split('procedure RequireServerObservation(')[0];
 assert.match(once,/CurrentImage, Code, CrcLayers, MeasurementState, Runtime\)/);
 assert.doesNotMatch(observe,/Runtime :=|\.Measurement\(/,'Retries retain the same admitted runtime context and lifetime');
 const retries=[api.split('function TGameApi.PostJSON(')[1].split('function TGameApi.ExecuteProof(')[0],...[bootstrap,overlay].map(s=>s.split('function ReportPost(')[1].split('procedure Send(')[0])];
 for(const retry of retries){
  const loop=retry.indexOf('for Attempt := 1 to Attempts');
  assert.ok(loop>0);
  assert.equal((retry.match(/Deadline :=/g)||[]).length,1);
  assert.ok(retry.indexOf('Deadline := CozyTick + 15000')<loop);
  const attempts=retry.slice(loop,retry.indexOf('Response.GetValue('));
  assert.match(attempts,/NowTick := CozyTick/);
  assert.match(attempts,/NowTick >= Deadline/);
  assert.match(attempts,/Deadline - NowTick/);
  assert.match(attempts,/on E: EConnectTransport do/);
  assert.doesNotMatch(attempts,/\.Sign\(|AddPair\(|Body :=|Deadline :=/);
 }
});
check('Owned signing and handoff plaintext intermediates are cleared on exceptional paths',()=>{
 const sign=security.split('function TDeviceSecurity.SignUnlocked(')[1].split('function IsUpperHex64(')[0];
 assert.ok(sign.indexOf('try')<sign.indexOf('Plain := TApiSensitiveBuffer.CreateUtf8(Text)'));
 assert.match(sign,/PlainScope := Plain\.OpenRead;\s+Result := SignSpanUnlocked\(PlainScope\.Buffer\)/);
 assert.match(sign,/finally\s+try PlainScope\.Free; finally Plain\.Free; end/);
 const ownedSign=security.split('function TDeviceSecurity.SignSpanUnlocked(')[1].split('function TDeviceSecurity.SignUnlocked(')[0];
 assert.match(ownedSign,/Digest, Signature: TApiSensitiveBuffer/);
 assert.match(ownedSign,/Digest := Sha256Owned\(Text\)/);
 assert.match(ownedSign,/try SignatureScope\.Free;[\s\S]*?try DigestScope\.Free;[\s\S]*?try Signature\.Free; finally Digest\.Free/);
 assert.doesNotMatch(sign,/TEncoding\.UTF8\.GetBytes|Plain, Digest/);
 const contracts=read('Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas');
 const retire=contracts.split('procedure TApiSensitiveState.Retire;')[1].split('destructor TApiSensitiveState.Destroy;')[0];
 assert.ok(retire.indexOf('FillChar(')>=0&&retire.indexOf('FillChar(')<retire.indexOf('FreeMem('));
 assert.match(contracts,/if FClosed and not FActive then Retire;/);
 assert.match(contracts,/if FClosed or not FActive or \(Token <> FToken\)/);
 assert.match(contracts,/procedure TApiSensitiveScope.Close;[\s\S]*?FLease\.Release;[\s\S]*?FBuffer := Default\(TApiBuffer\)/);
 const utf8=contracts.split('procedure TApiSensitiveBuffer.InitializeUtf8(')[1].split('function TApiSensitiveBuffer.OpenScope(')[0];
 assert.match(utf8,/TApiEncodingAccess\.EncodeUtf8\(Prefix, Text, Suffix, MaximumBytes\)/);
 assert.match(utf8,/State := TApiSensitiveState.TakeEncoded\(Encoded\)/);
 assert.match(utf8,/finally[\s\S]*FillChar\(Encoded\[0\], Length\(Encoded\), 0\)/);
 assert.doesNotMatch(utf8.replace(/\{[\s\S]*?\}/g,''),/Move\(|GetBytes\(Text\)/);

 const verify=api.split('function TGameApi.VerifyCore:')[1].split('procedure TGameApi.ReleaseCore;')[0];
 assert.match(verify,/PayloadText := Payload\.ToJSON;\s+Data := ExecuteProof\('verify', PayloadText\)/);
 assert.match(verify,/finally\s+WipeText\(PayloadText\)/);
 const payload=handoff.split('function BuildPayload(')[1].split('function LaunchWithHandoff(')[0];
 assert.match(payload,/except\s+WipeBytes\(Result\);\s+raise;/);
 assert.match(payload,/finally\s+for I := 0 to FieldCount - 1 do\s+WipeBytes\(Fields\[I\]\)/);
});
check('Actual Windows probes exercise I/O corruption, CNG bounds and post-close refusal',()=>{
 const pipe=read("Cozy.Tests/Cozy.Handoff/Cozy.HandoffPipeContracts.inc"),key=read("Cozy.Tests/Cozy.Handoff/Cozy.DeviceSecurityHandoffProbe.dpr"),cng=read("Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr");
 for(const name of ['ReadExact','RequirePipeEnd','ReadHello','WritePublicFrame','DecodeField'])assert.ok(pipe.includes(name+'('));
 assert.ok(pipe.includes('Header.SigningBytes := High(DWORD)'));
 assert.ok(pipe.includes('CreatePipe(ReadPipe, WritePipe'));
 assert.ok(key.includes('MustRejectClosed'));
 assert.ok(cng.includes('Cipher.Close;'));
 assert.ok(cng.includes('for I := 0 to 9 do RunCase(I)'));
});
console.log('Handoff completion source contracts: '+count+' passed; Windows runtime remains separate.');
