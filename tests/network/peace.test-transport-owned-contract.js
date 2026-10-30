'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../../Railway');
const available=fs.existsSync(root);
const read=p=>available?fs.readFileSync(path.join(root,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n'):'';
const source=read('Cozy.Source/Cozy.Network/Cozy.Transport.pas');
const encoder=read('Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas');
const probe=read('Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr');
const post=(source.split('function TConnectTransport.PostJSON(')[1]||'').split('function TConnectTransport.PerformPostJSON')[0];
const perform=(source.split('function TConnectTransport.PerformPostJSON(')[1]||'').split('\ninitialization')[0];
test('key/request/reply plaintext use scoped owners; tag verification precedes UTF8 and JSON',{skip:!available},()=>{
 assert.match(perform,/KeyBytes, PlainBytes, ReplyPlain: TApiSensitiveBuffer/);
 assert.doesNotMatch(perform,/(?:KeyBytes|PlainBytes|ReplyPlain): TBytes/);
 assert.match(perform,/PlainBytes := EncodeRequestEnvelopeOwned/);
 assert(perform.indexOf('CONNECT_AUTHENTICATION_FAILED')<perform.indexOf('PlainText := DecodeUTF8'));
 assert.match(perform,/finally WipeText\(PlainText\); end/);
 assert.match(perform,/Scope.Free;\s+KeyBytes.Free;\s+PlainBytes.Free;\s+ReplyPlain.Free/);
});
test('owned encoder bounds bytes before sensitive allocation and preserves caller JSON ownership',{skip:!available},()=>{
 const owned=encoder.split('function EncodeRequestEnvelopeOwned(').at(-1);
 assert(owned.indexOf('TEncoding.UTF8.GetByteCount(Text)')<owned.indexOf('TApiSensitiveBuffer.CreateUtf8(Text)'));
 assert(owned.indexOf('REQUEST_ENVELOPE_LIMIT')<owned.indexOf('TApiSensitiveBuffer.CreateUtf8(Text)'));
 assert.doesNotMatch(owned,/Body\.(?:Free|Clone)|Body :=|TJSONObject\.Create/);
 assert.match(owned,/OutputScope.Free; BodyScope.Free; BodyOwner.Free; Envelope.Free/);
 assert.match(encoder,/function EncodeRequestEnvelope\([\s\S]*MaximumBytes: Integer\): TBytes/);
 assert.match(probe,/CompareMem\(@Old\[0\],Scope.Buffer.Read/);
 assert.match(probe,/Length\(Old\)-1/);
});
test('generation, request admission and early-reset rejection share one lock',{skip:!available},()=>{
 const cancel=source.split('procedure TConnectTransport.CancelPending;')[1].split('procedure TConnectTransport.ResetCancellationAfterJoin')[0];
 const reset=source.split('procedure TConnectTransport.ResetCancellationAfterJoin;')[1].split('procedure TConnectTransport.RequireActiveLocked')[0];
 assert.match(cancel,/FStateLock.Acquire;[\s\S]*FCancelled := True;[\s\S]*Inc\(FGeneration\)/);
 assert.match(reset,/FStateLock.Acquire;[\s\S]*FGate.IsClosing[\s\S]*FGate.ActiveCount <> 0[\s\S]*FCancelled := False/);
 assert.match(post,/FStateLock.Acquire;\s+try\s+FGate.Enter; Admitted := True;\s+Generation := FGeneration/);
 assert.match(source,/FCancelled or \(Generation <> FGeneration\) or FGate.IsClosing/);
 assert.match(perform,/function: Boolean begin Result := IsCancelled\(Generation\); end/);
 assert.match(post,/finally\s+Candidate.Free;\s+if Admitted then FGate.Leave/);
});
test('JSON transfer follows successful temporary cleanup and locked final validation',{skip:!available},()=>{
 assert(perform.indexOf('ReplyPlain.Free')<perform.indexOf('Result := TJSONObject(DecodedValue)'));
 assert.match(perform,/except DecodedValue.Free; raise; end;[\s\S]*Result := TJSONObject\(DecodedValue\)/);
 assert(post.indexOf('Candidate := PerformPostJSON')<post.indexOf("TestStage('before-publication'"));
 const commit=post.slice(post.indexOf('{ Linearization point'));
 assert(commit.indexOf('RequireActiveLocked')<commit.indexOf('Result := Candidate; Candidate := nil'));
 assert.match(commit,/finally FStateLock.Release; end/);
});
test('pin-plan commit uses request guard and rejected responses cannot mutate shared trust',{skip:!available},()=>{
 assert.doesNotMatch(perform,/LearnTlsPlan/);
 const commit=post.slice(post.indexOf('{ Linearization point'));
 assert.match(commit,/LearnTlsPlan\(PlanJSON, PeerPin,\s+procedure begin RequireActiveLocked\(Generation, RequestClock, RequestBudgetMs\); end\)/);
 assert.doesNotMatch(commit.slice(commit.indexOf('{ Pin-plan commit')),/RequireActive|CONNECT_TIMEOUT|CONNECT_CANCELLED/);
 for(const text of ['CANCELLED_PLAN_CHANGED_SHARED_TRUST','EXPIRED_PLAN_CHANGED_SHARED_TRUST','UNPINNED_PEER_CHANGED_SHARED_TRUST'])assert(probe.includes(text),text);
});
test('v1 ID/direction/key AAD and nonce separation plus real TLS pin validation remain mandatory',{skip:!available},()=>{
 for(const text of ["ProtocolName = 'GAME-CONNECT-4'","Reply.Count <> 5","VersionValue.Value <> '1'","RequiredString(Reply, 'requestId') <> RequestID","CompareMem(@Nonce[0], @ReplyNonce[0], 12)","'RESPONSE' + #10 +\n          RequestID + #10 + FProfile.ServerKeyId"])
  assert(source.includes(text),text);
 assert.match(perform,/FProfile.SelectTlsPins\(PrimaryPin,SecondaryPin\)/);
 assert.match(perform,/Socket.ConnectTLS\(FProfile.Host, FProfile.Port/);
 assert.match(post,/FProfile.CheckTlsPeer\(PeerPin\)/);
});
test('native test adapter is compile-guarded and probe uses ephemeral RSA and actual CNG',{skip:!available},()=>{
 for(const text of ['BCryptGenerateKeyPair','BCryptFinalizeKeyPair','BCryptDecrypt(FKey','BCryptDecrypt(K','BCryptEncrypt(K','ParseProtocolRequest(TEncoding.UTF8.GetString(Plain)','rmWrongID','rmWrongDirection','rmWrongKey','rmBadTag','rmInvalidUTF8','rmDuplicateJSON','rmReplay','UNAUTHENTICATED_PLAINTEXT_EXPOSED'])assert(probe.includes(text),text);
 assert.doesNotMatch(probe,/PRIVATE KEY|RSAPRIVATEBLOB|-----BEGIN/);
 assert.match(source,/\{\$IFDEF GAME_TRANSPORT_TESTS\}\s+if Assigned\(FTestExchange\)/);
 assert.match(read('Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc'),/\{\$IFDEF GAME_TRANSPORT_TESTS\}[\s\S]*?FATAL/);
});
test('native overlap/reset/late reply/failure paths check revocation and thread drain',{skip:!available},()=>{
 for(const text of ['class(TThread)','Worker.Start;Started:=True','F.Entered.WaitFor','F.Transport.CancelPending','TRANSPORT_STILL_IN_USE','Worker.WaitFor','LATE_REPLY_PUBLISHED',"F.Mode:=rmReplay;ExpectFailure(F,'CONNECT_INVALID_RESPONSE')",'RequireRevoked(RequestView','RequireRevoked(ReplyView','DEADLINE_STAGE_NOT_REACHED','PARTIAL_CONSTRUCTOR_CLEANUP','DESTROY_FREED_ADMITTED_CRYPTO','DESTROY_PUBLISHED_REPLY'])assert(probe.includes(text),text);
 assert.match(probe,/inherited Destroy;Returned.Free;Done.Free/);
 assert.match(probe,/FreeAndNil\(FTransport\);Cancelled.Free;Done.Free/);
 assert.match(probe,/F.ReleaseStage.SetEvent;if Started then Worker.WaitFor;Worker.Free/);
});
