'use strict';
// Source ownership and independent wire fixtures. Actual Delphi/CNG execution
// belongs to the native DeviceSecurityOwnedProbe and is never implied here.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const native=path.resolve(__dirname,'../../../Railway');
const present=fs.existsSync(native);
const read=p=>present?fs.readFileSync(path.join(native,p),'utf8').replace(/\r/g,'').replace(/^\uFEFF/,''):'';
const source=read('Cozy.Source/Cozy.Security/Cozy.Security.pas');
const probe=read('Cozy.Tests/Cozy.Security/Cozy.DeviceSecurityOwnedProbe.dpr');
function method(name,next){const s=source.slice(source.indexOf(name));return next?s.slice(0,s.indexOf(next,1)):s;}
const sign=method('function TDeviceSecurity.SignSpanUnlocked(','function TDeviceSecurity.SignUnlocked(');
const text=method('function TDeviceSecurity.SignUnlocked(','function IsUpperHex64(');
const accepted=method('procedure TDeviceSecurity.AcceptDelegation(','function TDeviceSecurity.SignHandoffClaim(');
const claim=method('function TDeviceSecurity.SignHandoffClaim(','procedure TDeviceSecurity.CompleteHandoff;');
test('signing bytes, digest and signature remain in scoped owners with nested cleanup',{skip:!present},()=>{
 assert.match(sign,/Digest, Signature: TApiSensitiveBuffer/);
 assert.match(sign,/Digest := Sha256Owned\(Text\)/);
 assert.match(sign,/Signature := TApiSensitiveBuffer.Create\(Size\)/);
 assert.match(sign,/RequireCngBuffers\(DigestScope.Buffer, SignatureScope.Buffer, 32, Size, False\)/);
 assert.match(sign,/try SignatureScope.Free;[\s\S]*?try DigestScope.Free;[\s\S]*?try Signature.Free; finally Digest.Free/);
 assert.match(sign,/Result := Encoded; Encoded := '';\s+finally WipeText\(Encoded\)/);
 assert.doesNotMatch(sign,/TBytes|SetLength\(Signature|@Digest\[|@Signature\[/);
 assert.match(text,/CreateUtf8\(Text\)/);
 assert.match(text,/finally\s+try PlainScope.Free; finally Plain.Free/);
 assert.doesNotMatch(text,/WipeText\(Text\)|TEncoding.UTF8.GetBytes/);
});
test('hash output is owned before native write and partial failures release provider and owner',{skip:!present},()=>{
 const hash=method('function Sha256Owned(','function Sha256Span(');
 assert(hash.indexOf('TApiSensitiveBuffer.Create(32)')<hash.indexOf('BCryptFinishHash'));
 assert.match(hash,/try FreeAndNil\(Scope\);[\s\S]*finally\s+try if Hash <> 0 then BCryptDestroyHash\(Hash\);[\s\S]*finally if Algorithm <> 0 then BCryptCloseAlgorithmProvider/);
 assert.match(hash,/Result := Digest; Digest := nil;\s+finally Digest.Free/);
 assert.match(hash,/High\(DWORD\)/);
});
test('delegation validates once and retains only its intentional live binding',{skip:!present},()=>{
 assert.match(accepted,/ValidateHandoff\('DELEGATION', Role, Claim, FDeviceID, Nonce\)/);
 assert.equal((accepted.match(/HandoffClaimHash\(Claim\)/g)||[]).length,1);
 assert.doesNotMatch(accepted,/Canonical :=|HandoffCanonical\(/);
 assert.match(accepted,/FHandoffClaimHash := ClaimHash/);
 assert.match(accepted,/if FHandoffAccepted then ClaimHash := '' else WipeText\(ClaimHash\)/);
 assert.match(accepted,/FHandoffAccepted := True/);
 assert.doesNotMatch(source,/FHandoffAccepted := False|ExportPrivateKey|RSAFULLPRIVATEBLOB|NCryptAllowExport/);
});
test('child claim signs the same canonical bytes without a complete temporary Unicode envelope',{skip:!present},()=>{
 assert.match(claim,/Canonical: TApiSensitiveBuffer/);
 assert.match(claim,/HandoffCanonicalOwned\('CLAIM', Role, ClaimHash, FDeviceID, FHandoffNonce\)/);
 assert.match(claim,/Result := SignSpanUnlocked\(Scope.Buffer\)/);
 assert.match(claim,/Role <> FHandoffRole/);
 assert.match(claim,/ClaimHash <> FHandoffClaimHash/);
 assert.match(claim,/try Scope.Free;[\s\S]*finally try Canonical.Free; finally WipeText\(ClaimHash\)/);
 const hash=method('function HandoffClaimHash(','function HandoffCanonicalOwned(');
 assert.match(hash,/Hash.Update\(Scope.Buffer.Read\(0, Plain.Capacity\)\^, Plain.Capacity\)/);
 assert.doesNotMatch(hash,/TBytes|GetBytes/);
});
test('Close checkpoints and observation-only hooks cannot release a live key',{skip:!present},()=>{
 assert.match(source,/if FGate.IsClosing then raise EInvalidOpException.Create\('OBJECT_CLOSING'\)/);
 assert.match(source,/procedure TDeviceSecurity.Close;\s+begin\s+if FGate <> nil then FGate.CloseAndWait/);
 const destroy=method('destructor TDeviceSecurity.Destroy;','procedure TDeviceSecurity.ExportPublicKey;');
 assert(destroy.indexOf('Close;')<destroy.indexOf('NCryptFreeObject(FKey)'));
 assert.equal((sign.match(/RequireOpen;/g)||[]).length,6);
 assert.match(sign,/\{\$IFDEF GAME_DEVICE_SECURITY_TESTS\}\s+ObserveTestStage\('sign-input'/);
 assert.match(sign,/CheckStatus\(NCryptSignHash/);
 assert.doesNotMatch(source,/TestSign|TestHash|FakeSign|MockCng/);
});
test('Windows probe covers actual signatures, exceptions, revoked views and deterministic Close races',{skip:!present},()=>{
 for(const x of ['BCryptVerifySignature','CANONICAL_BASE64','ALTERED_DIGEST_ACCEPTED','CALLER_TEXT_MUTATED','FAULT_PUBLISHED_SIGNATURE','OWNED_CANONICAL_CHANGED_WIRE_SIGNATURE','CLOSE_DID_NOT_DRAIN_ADMITTED_SIGNER','CLOSE_PUBLISHED_SIGNATURE','CLOSED_SIGNER_REUSED','SCOPED_VIEW_NOT_REVOKED']) assert(probe.includes(x),x);
 assert.match(probe,/if SignStarted then Signer.WaitFor/);
 assert.match(probe,/if CloseStarted then Closer.WaitFor/);
 assert.match(probe,/Closer.Start;CloseStarted:=True/);
 assert.match(probe,/while not F.Security.TestIsClosing/);
 assert.match(probe,/Check\(Closer.Done.WaitFor\(0\)=wrTimeout/);
});
test('independent production server canonical keeps Korean claim, purpose and role separation',()=>{
 const handoff=require('../../services/bootstrap/peace.desktop-handoff-delegation');
 const claim='GAME-B85-CLAIM-V2\ncontract-vector\nUTF-8: 한글';
 const digest=crypto.createHash('sha512').update(claim,'utf8').digest('hex');
 assert.equal(digest,'9f6355aa784240522451364bb147aef5b8ff2c70ff3b266ab0e3994fd6fe50fd44bfbe39c4a2b98a8a23c115b64a84f9a7d8583c9ab6c8c7b9dec5336ba5541b');
 const messages=[];
 for(const purpose of ['DELEGATION','CLAIM']) for(const role of ['B','O']){
  const expected=['GAME-HANDOFF-'+purpose+'-V3',role,digest,'A'.repeat(64),'B'.repeat(64)].join('\n');
  assert.equal(handoff.Canonical(purpose,role,claim,'A'.repeat(64),'B'.repeat(64)),expected);
  messages.push(expected);
 }
 assert.equal(new Set(messages).size,4);
});
