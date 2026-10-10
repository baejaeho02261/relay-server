'use strict';
// Source boundary contracts supplement real Windows probes and server behavior
// tests. They do not execute Delphi, Windows object lifetimes or pipe handles.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const base=path.resolve(__dirname,'../../GameConnect_Win64');
const read=name=>fs.readFileSync(path.join(base,name),'utf8').replaceAll('\r','');
const api=read('Game.Api.pas'),bootstrap=read('Game.Bootstrap.pas'),overlay=read('Game.Overlay.Client.pas'),handoff=read('Game.Handoff.pas'),security=read('Game.Security.pas'),cipher=read('Game.Handoff.Crypto.pas'),authority=read('Game.ServerAuthority.pas');
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
 assert.match(security,/Result := SignUnlocked\(Canonical\)/);
 for(const name of ['StartOverlay','Redeem','Verify','Release','CheckIntegrity','ContinueModuleInventory'])assert.ok(wrapper(api,'TGameApi',name).includes('RequireRunning;'));
 for(const name of ['Claim','Close','AbortChild','Verify','ReportIntegrity'])wrapper(overlay,'TOverlayClient',name);
 for(const name of ['Claim','Close','AbortFlow','ReportIntegrity'])wrapper(bootstrap,'TBootstrapClient',name);
 for(const name of ['ParentIsAlive','ConfirmOverlayReady','CleanupTransferredParent','TakeImageIntegrity'])wrapper(handoff,'THandoffContext',name);
 assert.match(overlay,/if FClosed then raise EBootstrap.Create\('CLIENT_CLOSED'\)/);
 assert.match(bootstrap,/if FClosed then raise EBootstrap.Create\('CLIENT_CLOSED'\)/);
});
check('Overlay preparation keeps the same request identity and signed execute body',()=>{
 assert.match(api,/PrepareRequestID := RequestID;\s+Reply := ExecuteProof\('overlay', PayloadText, PrepareRequestID\)/);
 assert.match(api,/Result := PostJSON\('execute', ExecuteBody, Action = 'overlay'\)/);
 const retry=api.split('function TGameApi.PostJSON(')[1].split('function TGameApi.ExecuteProof(')[0];
 assert.ok(retry.includes('Attempts := 2'));
 assert.ok(retry.includes('Deadline := GetTickCount64 + 15000'));
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
 assert.match(api,/PostJSON\('report', SubmitBody, True\)/);
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
 assert.match(observe,/FileSHA512, FileCRC64, Clock, Cancelled\)/);
 const retries=[api.split('function TGameApi.PostJSON(')[1].split('function TGameApi.ExecuteProof(')[0],...[bootstrap,overlay].map(s=>s.split('function ReportPost(')[1].split('procedure Send(')[0])];
 for(const retry of retries){
  const loop=retry.indexOf('for Attempt := 1 to Attempts');
  assert.ok(loop>0);
  assert.equal((retry.match(/Deadline :=/g)||[]).length,1);
  assert.ok(retry.indexOf('Deadline := GetTickCount64 + 15000')<loop);
  const attempts=retry.slice(loop,retry.indexOf('Response.GetValue('));
  assert.match(attempts,/NowTick := GetTickCount64/);
  assert.match(attempts,/NowTick >= Deadline/);
  assert.match(attempts,/Deadline - NowTick/);
  assert.match(attempts,/on E: EConnectTransport do/);
  assert.doesNotMatch(attempts,/\.Sign\(|AddPair\(|Body :=|Deadline :=/);
 }
});
check('Owned signing and handoff plaintext intermediates are cleared on exceptional paths',()=>{
 const sign=security.split('function TDeviceSecurity.SignUnlocked(')[1].split('function IsUpperHex64(')[0];
 assert.ok(sign.indexOf('try')<sign.indexOf('Plain := TEncoding.UTF8.GetBytes(Text)'));
 assert.match(sign,/finally\s+Wipe\(Plain\);\s+Wipe\(Digest\);\s+Wipe\(Signature\)/);
 const verify=api.split('function TGameApi.VerifyCore:')[1].split('procedure TGameApi.ReleaseCore;')[0];
 assert.match(verify,/PayloadText := Payload\.ToJSON;\s+Data := ExecuteProof\('verify', PayloadText\)/);
 assert.match(verify,/finally\s+WipeText\(PayloadText\)/);
 const payload=handoff.split('function BuildPayload(')[1].split('function LaunchWithHandoff(')[0];
 assert.match(payload,/except\s+WipeBytes\(Result\);\s+raise;/);
 assert.match(payload,/finally\s+for I := 0 to FieldCount - 1 do\s+WipeBytes\(Fields\[I\]\)/);
});
check('Actual Windows probes exercise I/O corruption, CNG bounds and post-close refusal',()=>{
 const pipe=read('tests/HandoffPipeContracts.inc'),key=read('tests/DeviceSecurityHandoffProbe.dpr'),cng=read('tests/HandoffCryptoProbe.dpr');
 for(const name of ['ReadExact','RequirePipeEnd','ReadHello','WritePublicFrame','DecodeField'])assert.ok(pipe.includes(name+'('));
 assert.ok(pipe.includes('Header.SigningBytes := High(DWORD)'));
 assert.ok(pipe.includes('CreatePipe(ReadPipe, WritePipe'));
 assert.ok(key.includes('MustRejectClosed'));
 assert.ok(cng.includes('Cipher.Close;'));
 assert.ok(cng.includes('for I := 0 to 9 do RunCase(I)'));
});
console.log('Handoff completion source contracts: '+count+' passed; Windows runtime remains separate.');
