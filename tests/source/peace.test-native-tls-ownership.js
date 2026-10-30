'use strict';
// Source-only integration guards. Actual SSPI/Delphi execution belongs to the
// Windows native probes and must never be inferred from this Node test result.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const railway=path.resolve(__dirname,'../../../Railway');
const read=name=>fs.readFileSync(path.join(railway,name),'utf8').replaceAll('\r','');
const hasNative=fs.existsSync(path.join(railway,'Cozy.Source/Cozy.Network/Cozy.Tls.pas'));
const source=hasNative?read('Cozy.Source/Cozy.Network/Cozy.Tls.pas'):'';
const contracts=hasNative?read('Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc'):'';
const receive=hasNative?read('Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr'):'';
const section=(first,last)=>source.slice(source.indexOf(first),source.indexOf(last,source.indexOf(first)));
test('TLS cipher and plaintext have bounded distinct owners with no moving receive array',{skip:!hasNative},()=>{
 assert.match(source,/FCipher, FPlain: TApiSensitiveBuffer;/);
 assert.match(source,/FCipher := TApiSensitiveBuffer.Create\(MaxCipherBytes\)/);
 assert.match(source,/FPlain := TApiSensitiveBuffer.Create\(MaxTlsRecordBytes\)/);
 assert.match(source,/MaxCipherBytes = 262144/); assert.match(source,/MaxTlsRecordBytes = 65536/);
 assert.doesNotMatch(source,/SetLength\(F(?:Cipher|Plain)|Copy\(F(?:Cipher|Plain)|F(?:Cipher|Plain)\[/);
 const readCipher=section('function TGameTlsStream.ReadCipher:', 'function TGameTlsStream.KeepExtra(');
 assert.match(readCipher,/FRead\(Scope.Buffer.Write\(FCipherCount,Available\),Available\)/);
 assert.match(readCipher,/finally Scope.Free; end/);
});
test('SSPI plaintext is validated and copied while the cipher borrow remains alive',{skip:!hasNative},()=>{
 const body=section('function TGameTlsStream.PerformRead(', '{$IFDEF GAME_NATIVE_ABI_TESTS}\n{$I');
 const begin=body.indexOf('CipherScope:=FCipher.OpenWrite'),decrypt=body.indexOf('Status:=DecryptMessage'),validate=body.indexOf('if not PlainSpanValid'),copy=body.indexOf('Move(Buffers[I].Data^'),release=body.indexOf('CipherScope.Free'),compact=body.indexOf('if not KeepExtra');
 assert(begin>=0&&begin<decrypt&&decrypt<validate&&validate<copy&&copy<release&&release<compact);
 assert.match(body,/if Status=SecOk then\s*begin/);
 assert.match(body,/FillChar\(Buffers,SizeOf\(Buffers\),0\); FillChar\(Description,SizeOf\(Description\),0\);\s*CipherScope.Free/);
 assert.match(body,/PlainScope:=FPlain.OpenWrite;[\s\S]*?finally PlainScope.Free; end/);
});
test('partial reads wipe only consumed bytes and move the owned cursor',{skip:!hasNative},()=>{
 const body=section('function TGameTlsStream.PerformRead(', '{$IFDEF GAME_NATIVE_ABI_TESTS}\n{$I');
 assert.match(body,/Move\(PlainView.Read\(FPlainOffset,Part\)\^,Buffer\^,Part\);\s*FillChar\(PlainView.Write\(FPlainOffset,Part\)\^,Part,0\);\s*Inc\(FPlainOffset,Part\); Dec\(FPlainCount,Part\)/);
 assert.match(body,/if FPlainCount=0 then FPlainOffset:=0/);
 const compact=section('function TGameTlsStream.KeepExtra(', 'function TGameTlsStream.VerifyCertificate(');
 assert.match(compact,/Move\(View.Read\(OldCount-Integer\(Count\),Count\)\^,View.Write\(0,Count\)\^,Count\)/);
 assert.match(compact,/FillChar\(View.Write\(Count,OldCount-Integer\(Count\)\)\^,OldCount-Integer\(Count\),0\)/);
});
test('failed partial context ownership and token cleanup do not depend on success status',{skip:!hasNative},()=>{
 const handshake=section('function TGameTlsStream.PerformHandshake(', 'function TGameTlsStream.PerformWrite(');
 assert.match(handshake,/finally\s*\{ Failed\/partial[\s\S]*?FHaveContext:=SecurityHandleValid\(FContext\);/);
 assert.doesNotMatch(handshake,/Status >= 0 then FHaveContext/);
 assert.match(source,/Handle.Lower:=High\(NativeUInt\); Handle.Upper:=High\(NativeUInt\)/);
 assert.match(handshake,/finally\s*if OutputBuffer.Data <> nil then FreeContextBuffer\(OutputBuffer.Data\)/);
 assert.match(contracts,/partial failed handle deleted exactly once/);
 assert.match(contracts,/credentials freed despite context failure/);
 assert.match(contracts,/untouched invalid handle not deleted/);
});
test('cleanup resets counts and attempts all owners even if one release raises',{skip:!hasNative},()=>{
 const clear=section('procedure TGameTlsStream.ClearBuffers;', 'procedure TGameTlsStream.ReleaseSecurityContext;');
 assert.match(clear,/FPlainCount:=0; FPlainOffset:=0; FCipherCount:=0;\s*try\s*if FPlain<>nil then FPlain.Clear;\s*finally\s*if FCipher<>nil then FCipher.Clear;/);
 const destroy=section('destructor TGameTlsStream.Destroy;', 'function TGameTlsStream.Handshake(');
 assert.match(destroy,/FGate.CloseAndWait/);
 assert.match(destroy,/try\s*FPlain.Free;\s*finally\s*try\s*FCipher.Free;\s*finally\s*try FGate.Free; finally inherited Destroy/);
 assert.match(contracts,/second owner still wiped/);
});
test('close_notify, invalid records and failures keep the stream terminal',{skip:!hasNative},()=>{
 const body=section('function TGameTlsStream.PerformRead(', '{$IFDEF GAME_NATIVE_ABI_TESTS}\n{$I');
 assert.match(body,/if Status=SecIncompleteMessage then[\s\S]*?if not ReadCipher then Exit;\s*Continue;/);
 assert.match(body,/if Status=SecContextExpired then[\s\S]*?Exit;/);
 assert.match(body,/if Status<>SecOk then Exit/);
 assert.match(body,/if Result<0 then\s*begin\s*FAuthenticated:=False;\s*ClearBuffers;/);
 assert.match(source,/if FHandshakeStarted or/);
 assert.match(contracts,/terminal no network reuse/);
 assert.match(contracts,/no provider or plaintext before authentication/);
});
test('controlled provider fault injection is compile guarded and separately attributed',{skip:!hasNative},()=>{
 assert.match(source,/\{\$IFDEF GAME_TLS_CONTRACT_TESTS\}\nvar\n  TlsProbeCounters/);
 assert.match(source,/ProviderOverrideCalls/);
 assert.match(contracts,/Controlled provider descriptor\/status faults below are NOT real Schannel/);
 assert.match(contracts,/TlsTestDecrypt:=ControlledDecrypt/);
 assert.match(contracts,/TlsTestAcquire:=ControlledAcquire/);
 assert.match(contracts,/TlsTestAcquire:=nil; TlsTestInitialize:=nil; TlsTestDelete:=nil; TlsTestFreeCredential:=nil/);
 const meta=read('Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc');
 assert.match(meta,/IFDEF GAME_TLS_CONTRACT_TESTS[\s\S]*?MESSAGE FATAL/);
});
test('real receive probe exposes real provider counters and preserves finally cleanup',{skip:!hasNative},()=>{
 assert.match(receive,/ReadTlsProbeCounters/);
 assert.match(receive,/providerOverrideCalls/);
 assert.match(receive,/realProviderCalls/);
 assert.doesNotMatch(receive,/TlsTestDecrypt|TlsTestInitialize|Halt\(/);
 const dproj=read('Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dproj');
 assert.match(dproj,/GAME_TLS_CONTRACT_TESTS/);
});
