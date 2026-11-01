'use strict';
// Semantic native literals resolve from the current separate constant units.
const {ReadContractFile}=require("../fixtures/source/peace.native-string-contract");
// Structural contracts only. Delphi/CNG execution is covered by the existing
// optional native probes and is not claimed by this Node test.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../../Railway'),available=fs.existsSync(root);
const read=p=>available?ReadContractFile(path.join(root,p),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n'):'';
const contracts=read('Cozy.Source/Cozy.Platform/Cozy.Api.Contracts.pas');
const transport=read('Cozy.Source/Cozy.Network/Cozy.Transport.pas');
const probe=read('Cozy.Tests/Cozy.Platform/Cozy.NativeApiContractsProbe.dpr');
const section=(s,a,b)=>(s.split(a)[1]||'').split(b)[0];
test('UTF8 encoder privately transfers one backing allocation without changing borrowed source',{skip:!available},()=>{
 const encode=section(contracts,'class function TApiEncodingAccess.EncodeUtf8(', 'constructor TApiSensitiveState.Create(');
 const take=section(contracts,'constructor TApiSensitiveState.TakeEncoded(', 'procedure TApiSensitiveState.Retire;');
 const init=section(contracts,'procedure TApiSensitiveBuffer.InitializeUtf8(', 'constructor TApiSensitiveBuffer.CreateUtf8(');
 assert.match(encode,/BodySize > MaximumBytes - PrefixSize - SuffixSize/);
 assert(encode.indexOf('BodySize > MaximumBytes')<encode.indexOf('SetLength(Encoded'));
 const windows=section(encode,'{$ELSE}','{$ENDIF}');
 assert.match(windows,/GetBytes\(Text, 1, Length\(Text\), Encoded, PrefixSize\)/);
 assert.doesNotMatch(windows.replace(/\{[\s\S]*?\}/g,''),/Move\(|GetBytes\(Text\)|PWideChar|TBytes/);
 assert.match(take,/FOwnedBytes := Bytes; Bytes := nil/);
 assert.doesNotMatch(take,/Move\(|SetLength|Copy\(/);
 assert.match(init,/State := TApiSensitiveState.TakeEncoded\(Encoded\)/);
 assert.doesNotMatch(contracts.split('implementation')[0],/TakeEncoded|TakeBytes/);
 assert.doesNotMatch(encode.replace(/\{[\s\S]*?\}/g,''),/Text\s*:=|FillChar\([^\n]*Text/);
});
test('managed backing bytes preserve scoped revocation and wipe before allocator release',{skip:!available},()=>{
 const retire=section(contracts,'procedure TApiSensitiveState.Retire;', 'destructor TApiSensitiveState.Destroy;');
 assert(retire.indexOf('FillChar(FAddress^, FCapacity, 0)')<retire.indexOf('FOwnedBytes := nil'));
 assert(retire.indexOf('FillChar(FAddress^, FCapacity, 0)')<retire.indexOf('FreeMem(FAddress)'));
 assert.match(contracts,/if FClosed and not FActive then Retire/);
 assert.match(contracts,/if FClosed or not FActive or \(Token <> FToken\)/);
 assert.equal((contracts.match(/SetLength\(FOwnedBytes/g)||[]).length,0);
 assert.match(probe,/RunFramedUtf8Contracts;[\s\S]*InFlight\^ = Ord\('s'\)/);
 for(const check of ['Length(Expected)-1','MaxApiSensitiveBytes+1','Owner.Clear; Scope := Owner.OpenRead','Text = Values[Index]'])assert(probe.includes(check),check);
});
test('transport releases duplicate ciphertext and request key before response JSON publication',{skip:!available},()=>{
 const perform=section(transport,'function TConnectTransport.PerformPostJSON(', '\ninitialization');
 assert(perform.indexOf('FreeAndNil(Frame)')<perform.indexOf('Socket.ConnectTLS'));
 assert(perform.indexOf('WipeBytes(WrappedKey)')<perform.indexOf('Socket.ConnectTLS'));
 assert(perform.indexOf('WipeText(FrameText)')<perform.indexOf('Socket.ReceiveLine'));
 assert(perform.indexOf('WipeText(ReplyLine)')<perform.indexOf('Reply := TJSONObject'));
 assert(perform.indexOf('FreeAndNil(ReplyValue)')<perform.indexOf('ReplyPlain := TApiSensitiveBuffer.Create'));
 assert(perform.indexOf('CONNECT_AUTHENTICATION_FAILED')<perform.indexOf('CheckCng(BCryptDestroyKey(AESKey)); AESKey := 0'));
 assert(perform.indexOf('CheckCng(BCryptDestroyKey(AESKey)); AESKey := 0')<perform.indexOf('PlainText := DecodeUTF8'));
 for(const v of ['FrameText','ReplyLine','PlainText'])assert.match(perform.slice(perform.indexOf('finally\n      Socket.Free')),new RegExp('WipeText\\('+v+'\\)'));
});
test('failed Base64 conversion clears its partial output and canonical comparison copy',{skip:!available},()=>{
 const decode=section(transport,'function Base64Decode(', 'procedure ValidateFlatObject');
 assert.match(decode,/except\s+WipeBytes\(Result\);\s+raise/);
 assert.match(decode,/finally\s+WipeText\(Canonical\);\s+Encoding.Free/);
});
