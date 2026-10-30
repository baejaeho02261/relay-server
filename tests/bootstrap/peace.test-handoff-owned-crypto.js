'use strict';
// Native source/wire-fixture contracts, never a native CNG execution attestation.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'../../../Railway');
if(!fs.existsSync(root)){console.log('SKIP private native source unavailable; no CNG execution claim');process.exit(0);}
const read=n=>fs.readFileSync(path.join(root,n),'utf8');
const source=read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas'),kdf=read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.Kdf.pas'),handoff=read('Cozy.Source/Cozy.Handoff/Cozy.Handoff.pas'),probe=read('Cozy.Tests/Cozy.Handoff/Cozy.HandoffCryptoProbe.dpr');
const decrypt=source.split('function THandoffCipher.Decrypt(')[1].split('function HandoffDecryptAes256Gcm(')[0],encrypt=source.split('class function THandoffCipher.Encrypt(')[1].split('function THandoffCipher.Decrypt(')[0],generic=source.split('function HandoffDecryptAes256Gcm(')[2].split('procedure THandoffCipher.Close;')[0];
let cases=0;const check=(label,fn)=>{fn();cases++;console.log('PASS '+label);};
check('Single-use admission precedes input validation and cancellation; every admitted call drains',()=>{
 assert(decrypt.indexOf('CompareExchange(FConsumed, 1, 0)')<decrypt.indexOf('RequireActive(IsCancelled)'));
 assert(decrypt.indexOf('CompareExchange(FConsumed, 1, 0)')<decrypt.indexOf('Length(Envelope)'));
 assert.match(decrypt,/finally FGate\.Leave; end/);
 assert.match(source,/CheckCancellation\(IsCancelled\);\s+if FGate\.IsClosing then/);
});
check('Unwrapped key and unauthenticated plaintext use scoped owned allocations',()=>{
 assert.match(decrypt,/Secret := TApiSensitiveBuffer\.Create\(256\)/);
 assert.match(decrypt,/Plain := TApiSensitiveBuffer\.Create\(Header\.CipherBytes\)/);
 assert.match(decrypt,/Scope\.Buffer\.Write\(0, Header\.CipherBytes\), Header\.CipherBytes, Actual/);
 assert(decrypt.indexOf('if Actual <> Header.CipherBytes')<decrypt.indexOf('Result := PublishPlain'));
 assert.match(decrypt,/finally Scope\.Free; end;\s+RequireActive\(IsCancelled\);\s+Result := PublishPlain/);
 assert.match(decrypt,/Result := PublishPlain\(Plain, Header\.CipherBytes\);\s+RequireActive\(IsCancelled\);\s+except\s+WipeBytes\(Result\); raise;/);
 assert.doesNotMatch(decrypt,/@Result\[|SetLength\(Result/);
 assert.match(decrypt,/finally\s+Secret\.Free; Plain\.Free;/);
});
check('Encrypt borrows caller plaintext and retires dedicated seed/key immediately',()=>{
 assert.match(encrypt,/Seed := TApiSensitiveBuffer\.Create\(32\)/);
 assert.match(encrypt,/DeriveHandoffContentKeyOwned\(Scope\.Buffer, AuthenticatedTranscript\)/);
 assert.match(encrypt,/finally Scope\.Free; end;\s+FreeAndNil\(Seed\)/);
 assert.match(encrypt,/finally Scope\.Free; end;\s+FreeAndNil\(Secret\)/);
 assert.doesNotMatch(encrypt,/WipeBytes\(Plain\)|Copy\(Plain|Secret, Seed: TBytes/);
 assert.match(encrypt,/except\s+WipeBytes\(Result\); raise;/);
});
check('KDF domain and order stay stable; temporary hasher digest is erased',()=>{
 assert.match(kdf,/cozy\.Client\.Handoff\.V3\.AES256GCM\.ContentKey\.v1/);
 assert.match(kdf,/Hasher\.Update\(Seed\.Read\(0, 32\)\^, 32\);\s+Hasher\.Update\(AuthenticatedTranscript\[0\], Length\(AuthenticatedTranscript\)\)/);
 assert.match(kdf,/finally\s+if Length\(Digest\) <> 0 then FillChar\(Digest\[0\], Length\(Digest\), 0\);\s+Digest := nil;/);
 assert.match(kdf,/except\s+Result\.Free; Result := nil; raise;/);
});
check('Generic GCM follows the same verified-output and finally-owned-scope contract',()=>{
 assert.match(generic,/Plain := TApiSensitiveBuffer\.Create\(Length\(Cipher\)\)/);
 assert.match(generic,/if Actual <> DWORD\(Length\(Cipher\)\)/);
 assert(generic.indexOf('Check(BCryptDecrypt(')<generic.indexOf('Result := PublishPlain'));
 assert.match(generic,/FreeAndNil\(PlainScope\);\s+CheckCancellation\(IsCancelled\);\s+Result := PublishPlain/);
 assert.match(generic,/KeyScope\.Free; NonceScope\.Free; TagScope\.Free; AuthScope\.Free; PlainScope\.Free;\s+KeyCopy\.Free; NonceCopy\.Free; TagCopy\.Free; AuthCopy\.Free; Plain\.Free;/);
 assert.doesNotMatch(generic,/@Result\[|SetLength\(Result|Result := Plain;/);
});
check('Actual handoff call sites bind synchronous crypto to existing deadline and child',()=>{
 assert.match(handoff,/Payload := Cipher\.Decrypt\(Envelope, AAD,\s+function: Boolean\s+begin Result := Remaining\(Deadline\) = 0;/);
 assert.match(handoff,/Envelope := THandoffCipher\.Encrypt\(Wrapping, Payload, AAD,[\s\S]*?WaitForSingleObject\(Process\.hProcess, 0\) <> WAIT_TIMEOUT/);
});
check('Native probes overlap real calls and preserve caller ownership until every join',()=>{
 for(const token of ['RejectGoodAfterBad','ConcurrentCase(False)','ConcurrentCase(True)','GenericGcmCases','First.Done.WaitFor(5000)','Second.Failure = \'HANDOFF_CIPHER_ALREADY_CONSUMED\'','Closer.Done.WaitFor(0) = wrTimeout','First.Failure = \'HANDOFF_CIPHER_CANCELLED\''])assert(probe.includes(token),token);
 assert.match(probe,/if FirstStarted then First\.WaitFor;\s+if SecondStarted then Second\.WaitFor;\s+if CloserStarted then Closer\.WaitFor;\s+First\.Free/);
 assert.doesNotMatch(probe,/TerminateThread/);
 assert.match(probe,/destructor TDecryptWorker\.Destroy;[\s\S]*?inherited;\s+WipeBytes\(Output\)/);
 assert.match(probe,/destructor TCloseWorker\.Destroy;\s+begin inherited; Done\.Free; end;/);
});
check('Embedded native GCM fixture agrees with independent OpenSSL and rejects altered tag',()=>{
 const key=Buffer.from(Array.from({length:32},(_,i)=>i)),nonce=Buffer.from(Array.from({length:12},(_,i)=>i)),aad=Buffer.from('handoff-probe-public-aad'),plain=Buffer.from('private-test-data');
 const c=crypto.createCipheriv('aes-256-gcm',key,nonce);c.setAAD(aad);const cipher=Buffer.concat([c.update(plain),c.final()]),tag=c.getAuthTag();
 assert(probe.includes("Cipher := BytesHex('"+cipher.toString('hex')+"')"));assert(probe.includes("Tag := BytesHex('"+tag.toString('hex')+"')"));
 const d=crypto.createDecipheriv('aes-256-gcm',key,nonce);d.setAAD(aad);d.setAuthTag(tag);assert.deepEqual(Buffer.concat([d.update(cipher),d.final()]),plain);
 tag[0]^=1;const bad=crypto.createDecipheriv('aes-256-gcm',key,nonce);bad.setAAD(aad);bad.setAuthTag(tag);bad.update(cipher);assert.throws(()=>bad.final());
});
console.log('HANDOFF_OWNED_CRYPTO_SOURCE_PASS '+cases+'; native Delphi/CNG execution NOT_RUN');
