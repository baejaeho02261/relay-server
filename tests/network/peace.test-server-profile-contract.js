'use strict';
// Server codec behavior and source wiring, not Delphi/Windows execution.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const fixture=require('../fixtures/network/peace.server-profile-v4.json'),codec=require('../../services/bootstrap/peace.launcher-public-config');
const profile=()=>structuredClone(fixture.profile),config=p=>({schema:3,profile:p,launcherId:'AB'.repeat(12),expiresAt:1793000000000});
const native=path.resolve(__dirname,'../../../Railway'),available=fs.existsSync(native);
const read=name=>fs.readFileSync(path.join(native,name),'utf8').replaceAll('\r','');
test('shared public profile fixture preserves exact server codec bytes and public binding fields',()=>{
 assert.equal(fixture.purpose,'PUBLIC_TEST_TRUST_MATERIAL_ONLY_NO_NETWORK');
 for(const port of [1,443,65535])for(const host of ['profile-fixture.invalid','127.0.0.1']){
  const p=profile();p.port=port;p.host=host;const input=config(p),bytes=codec.Encode(input),decoded=codec.Decode(bytes);
  assert.deepEqual(decoded,input);assert.deepEqual(codec.Encode(decoded),bytes);
 }
});
test('issuer rejects unknown fields, wrong types, key ID mismatch and invalid ports/pins',()=>{
 const mutations=[p=>p.extra=true,p=>delete p.host,p=>p.host={},p=>p.version='4',p=>p.protocol='GAME-CONNECT-3',p=>p.port='443',p=>p.port=0,p=>p.port=65536,p=>p.port=1.5,p=>p.tlsServerName='UPPER.invalid',p=>p.serverKeyId='f'.repeat(64),p=>p.serverKeyId=p.serverKeyId.toUpperCase(),p=>p.serverPublicKey+='=',p=>p.serverPublicKey='A'.repeat(376),p=>p.tlsCertificateSha256='A'.repeat(64),p=>p.tlsPinState='',p=>p.tlsPinState=0,p=>p.tlsPinState='x'.repeat(6145)];
 for(const mutate of mutations){const p=profile();mutate(p);assert.throws(()=>codec.Encode(config(p)),{message:'BOOTSTRAP_CONFIG_INVALID'});}
});
test('codec preserves exact bounded pin snapshot without inventing a clock floor',()=>{
 const p=profile(),plan={version:1,generation:1,host:p.host,port:p.port,serverKeyId:p.serverKeyId,tlsServerName:p.tlsServerName,currentPin:p.tlsCertificateSha256,nextPin:'b'.repeat(64),issuedAt:1793000000000,notBefore:1793000060000,oldNotAfter:1793000120000};
 p.tlsPinState=JSON.stringify({contract:'GAME-TLS-PIN-WINDOW-V1',plan:JSON.stringify(plan),floor:1793000090000,retiredPins:''});
 const bytes=codec.Encode(config(p)),decoded=codec.Decode(bytes);assert.equal(decoded.profile.tlsPinState,p.tlsPinState);assert.deepEqual(codec.Encode(decoded),bytes);
 // Native NewTlsPinWindow validates endpoint/history/floor; the binary codec
 // transports the snapshot and does not itself grant pin trust.
});
test('native parser writer and clone share one ordered field contract',{skip:!available},()=>{
 const source=read('Cozy.Source/Cozy.Network/Cozy.Server.Profile.pas');
 const rules=[...source.matchAll(/\(Name:'([^']+)'; Kind:(pkInteger|pkString); Required:(True|False)\)/g)].map(m=>({name:m[1],kind:m[2],required:m[3]==='True'}));
 assert.deepEqual(rules.map(r=>r.name),[...Object.keys(fixture.profile),'tlsPinState']);
 assert.deepEqual(rules.filter(r=>r.kind==='pkInteger').map(r=>r.name),['version','port']);
 assert.deepEqual(rules.filter(r=>!r.required).map(r=>r.name),['tlsPinState']);
 assert.match(source,/ValidateShape\(Obj\)/);assert.match(source,/Result := Build\(ReadFields\(Text\),nil\)/);
 assert.match(source,/Snapshot := FFields; Snapshot.PinState := FPinWindow.ExportTrusted/);
 assert.match(source,/Result := WriteFields\(Snapshot\)/);
 const clone=source.split('function TConnectServerProfile.Clone: TConnectServerProfile;')[1].split('function TConnectServerProfile.ToJSON')[0];
 assert.match(clone,/Result := Build\(FFields,FPinWindow\)/);assert.doesNotMatch(clone,/Parse\(|ToJSON|NewTlsPinWindow/);
 assert.match(source,/Result.FPinWindow := SharedWindow/);assert.match(source,/Result.FFields.PinState := ''/);
 assert.match(source,/if Result.PinState = '' then InvalidProfile/);
});
test('native probe shares public fixture and tests real clone trust rules',{skip:!available},()=>{
 const chunks=JSON.stringify(fixture.profile).match(/.{1,140}/g);
 const expected="{ Generated from tests/fixtures/network/peace.server-profile-v4.json. Public fixture only. }\nconst ServerProfileFixtureJSON =\n"+chunks.map((v,i)=>"  '"+v.replaceAll("'","''")+"'"+(i===chunks.length-1?';':' +')).join('\n')+'\n';
 assert.equal(read('Cozy.Tests/Cozy.Network/Cozy.ServerProfileFixture.inc').replace(/^\ufeff/,''),expected);
 const probe=read('Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr');
 for(const check of ['clone learns same live window','JSON copy owns independent window','trusted floor never decreases','fixed pin snapshot byte identity','clone retains retired trust after parent free','escaped duplicate field','pin state endpoint mismatch'])assert(probe.includes(check),check);
 assert.match(probe,/TConnectServerProfile.CanonicalizeJSON\(Canonical\)=Canonical/);assert.match(probe,/C.LearnTlsPlan\(PlanText,Root\)/);
});
