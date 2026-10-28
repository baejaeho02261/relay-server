'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const signing=require('../../services/bootstrap/peace.issued-a-signing');
const fixture=require('../fixtures/bootstrap/issued-a-native-v1.json');
const bytes=Buffer.from(fixture.finalBase64,'base64'),anchor=Buffer.from(fixture.anchorBase64,'base64'),config=Buffer.from(fixture.configBase64,'base64');
const trust={expectedTemplateSha512:fixture.templateSha512,expectedKeyId:fixture.keyId};
const nativeRoot=path.resolve(__dirname,'../../../Railway'),present=fs.existsSync(nativeRoot);
function native(relative){return fs.readFileSync(path.join(nativeRoot,relative),'utf8');}
test('fixed public-only cross-language vector has exact wire lengths and independent RSA verification',()=>{
 assert.equal(fixture.scope,'SYNTHETIC_PUBLIC_ONLY_NATIVE_CNG_VECTOR');assert.equal(anchor.length,331);assert.equal(fixture.tailBytes,453);assert.equal(fixture.headerBytes,184);assert.equal(fixture.signatureBytes,256);assert.equal(fixture.footerBytes,13);
 const at=bytes.length-453,header=bytes.subarray(at,at+184),signature=bytes.subarray(at+184,at+440),blob=anchor.subarray(48);
 assert.equal(header.subarray(0,16).toString(),'COZY-ISSUED-A-V1');assert.equal(anchor.subarray(0,16).toString(),'COZYAISSUERKEY1!');assert.equal(bytes.subarray(-13).toString(),'COZYA4SIGNED!');
 assert.equal(header.readUInt32LE(16),fixture.templateBytes);assert.equal(header.readUInt32LE(20),config.length);assert.deepEqual(header.subarray(24,56),crypto.createHash('sha256').update(blob).digest());
 assert.deepEqual(header.subarray(56,120),crypto.createHash('sha512').update(bytes.subarray(0,fixture.templateBytes)).digest());assert.deepEqual(header.subarray(120,184),crypto.createHash('sha512').update(config).digest());
 const key=crypto.createPublicKey({format:'jwk',key:{kty:'RSA',e:blob.subarray(24,27).toString('base64url'),n:blob.subarray(27).toString('base64url')}});
 assert.equal(crypto.verify('sha256',header,{key,padding:crypto.constants.RSA_PKCS1_PADDING},signature),true);
 assert.equal(crypto.verify('sha256',header,{key,padding:crypto.constants.RSA_PKCS1_PADDING},Buffer.from(signature).reverse()),false);
 assert.equal(signing.VerifyFinal(bytes,trust).keyId,fixture.keyId);
 assert.doesNotMatch(JSON.stringify(fixture),/PRIVATE KEY|privateKey|"d"\s*:/);
});
test('fixed vector rejects template, public settings, header, signature, footer and all partial tails',()=>{
 const at=bytes.length-453;
 for(const i of [0,fixture.templateBytes-1,fixture.templateBytes,at-1,at,at+15,at+16,at+20,at+24,at+56,at+120,at+184,at+439,at+440,bytes.length-1]){const b=Buffer.from(bytes);b[i]^=1;assert.throws(()=>signing.VerifyFinal(b,trust));}
 for(let n=1;n<=453;n++)assert.throws(()=>signing.VerifyFinal(bytes.subarray(0,-n),trust));
 assert.throws(()=>signing.VerifyFinal(Buffer.concat([bytes,Buffer.from([0])]),trust));
 assert.throws(()=>signing.VerifyFinal(bytes,{...trust,expectedKeyId:'00'.repeat(32)}));
 assert.throws(()=>signing.VerifyFinal(bytes,{...trust,expectedTemplateSha512:'00'.repeat(64)}));
});
test('Native verification occurs before endpoint parsing and has no unsigned fallback',{skip:!present},()=>{
 const launcher=native('Cozy.Source/Cozy.Application/Cozy.Launcher.pas'),unit=native('Cozy.Source/Cozy.Application/Cozy.IssuedA.pas');
 assert.ok(launcher.indexOf('Bytes := ReadVerifiedIssuedAConfig(Handle, FileSize(Info))')<launcher.indexOf('Result := ParsePublicConfig(Bytes)'));
 assert.match(launcher,/if Result\.ExpiresAt <= BootstrapUTCNowMS then Fail/);assert.doesNotMatch(launcher,/ConfigMarker: AnsiString = 'COZYA3CONFIG!'/);
 assert.match(unit,/VerifyHeader\(Header, Signature, Anchor\)/);assert.match(unit,/TemplateHash := HashExtent\(Stream, TemplateBytes, Started\)/);assert.match(unit,/SameBytes\(TemplateHash, 0, Header, 56, 64\)/);assert.match(unit,/SameBytes\(ConfigHash, 0, Header, 120, 64\)/);
 assert.ok(unit.indexOf('VerifyHeader(Header, Signature, Anchor);')<unit.indexOf('Result := Config;'));
 assert.match(unit,/Move\(CozyIssuedATrustAnchor\[0\], Anchor\[0\], Length\(Anchor\)\)/);
 assert.match(unit,/SameBytes\(KeyID, 0, Anchor, 16, 32\)/);assert.match(unit,/SameBytes\(KeyID, 0, Header, 24, 32\)/);
 assert.doesNotMatch(unit,/CreatePrivateKey|NCryptSignHash|private.*pem/i);
});
test('Native verifier keeps bounded memory, restores the caller handle position and destroys CNG handles',{skip:!present},()=>{
 const unit=native('Cozy.Source/Cozy.Application/Cozy.IssuedA.pas');
 assert.match(unit,/IssuedTemplateMaximum = 64 \* 1024 \* 1024/);assert.match(unit,/IssuedConfigMaximum = 8192/);assert.match(unit,/IssuedVerificationBudgetMS = 30000/);assert.match(unit,/SetLength\(Buffer, 65536\)/);assert.match(unit,/TemplateBytes < 512/);
 assert.match(unit,/UInt64\(TemplateBytes\) \+ ConfigBytes \+ IssuedTailBytes <> FileSize/);assert.match(unit,/Stream\.Position := SavedPosition/);assert.match(unit,/if Key <> 0 then DestroyKey\(Key\)/);assert.match(unit,/if Algorithm <> 0 then CloseAlgorithm\(Algorithm, 0\)/);assert.match(unit,/Padding\.pszAlgId := 'SHA256'/);
 assert.match(unit,/RequireProcAddressHash64\('bcrypt\.dll', HASH_BCryptVerifySignature\)/);
});
test('test-only trust injection cannot compile in application builds and the CNG probe checks every tail truncation',{skip:!present},()=>{
 const unit=native('Cozy.Source/Cozy.Application/Cozy.IssuedA.pas'),probe=native('Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dpr'),project=native('Cozy.Tests/Cozy.Security/Cozy.IssuedASignatureProbe.dproj');
 assert.match(unit,/\{\$IFDEF GAME_APPLICATION_BUILD\}[\s\S]*?\{\$IFDEF GAME_ISSUED_A_TESTS\}[\s\S]*?\{\$MESSAGE FATAL/);assert.match(probe,/SealApiPointerStorage/);assert.match(probe,/for I := 1 to 453 do/);assert.match(probe,/PINNED_STREAM_POSITION_NOT_RESTORED/);assert.match(project,/<TestOnlyDefine>GAME_ISSUED_A_TESTS<\/TestOnlyDefine>/);assert.match(project,/<DCC_ExeOutput>\$\(MSBuildProjectDirectory\)<\/DCC_ExeOutput>/);
});
