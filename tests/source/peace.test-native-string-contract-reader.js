'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {ReadContractFile,UnitConstants,UsedUnits,CppConstants}=require('../fixtures/source/peace.native-string-contract');
const NAME='CozyText_Example_ProtocolDomain_1234abcd',UNIT='Cozy.Strings.Example';
function Fixture(t){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'peace-string-contract-')),root=path.join(temp,'Railway');
 const folder=path.join(root,'Cozy.Source/Cozy.Configuration');fs.mkdirSync(folder,{recursive:true});
 const source=path.join(root,'Cozy.Source/Example.pas'),unitPath='Cozy.Source/Cozy.Configuration/'+UNIT+'.pas';
 const literal="'COZY-TEST'#10'한글''value'";
 const map={units:[{unit:UNIT,path:unitPath,constants:[{name:NAME,expression:literal}]}],sources:[{path:'Cozy.Source/Example.pas',unitNames:[UNIT]}]};
 const mapFile=path.join(folder,'Cozy.StringUnits.map.json'),unitFile=path.join(root,unitPath);
 function save(){fs.writeFileSync(mapFile,JSON.stringify(map));fs.writeFileSync(unitFile,'unit '+UNIT+';\ninterface\nconst\n  '+NAME+' = '+map.units[0].constants[0].expression+';\nimplementation\nend.\n');}
 save();fs.writeFileSync(source,"unit Example;\ninterface\nuses "+UNIT+";\nimplementation\nconst Domain: AnsiString = "+NAME+";\n// "+NAME+"\n{ "+NAME+" }\nconst LabelText = '"+NAME+"';\nend.\n");
 t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));return{root,source,mapFile,unitFile,map,literal,save};
}
test('reads current constants and expands identifiers while leaving comments and quoted names intact',t=>{
 const s=Fixture(t),raw=fs.readFileSync(s.source,'utf8'),resolved=ReadContractFile(s.source,'utf8');
 assert.match(resolved,/const Domain: AnsiString = 'COZY-TEST'#10'한글''value';/);
 assert(resolved.includes('// '+NAME));assert(resolved.includes('{ '+NAME+' }'));assert(resolved.includes("LabelText = '"+NAME+"'"));
 assert.equal(fs.readFileSync(s.source,'utf8'),raw);
 s.map.units[0].constants[0].expression="'CHANGED-ACTUAL-VALUE'";s.save();
 assert(ReadContractFile(s.source,'utf8').includes("Domain: AnsiString = 'CHANGED-ACTUAL-VALUE'"));
 assert(!ReadContractFile(s.source,'utf8').includes(s.literal),'the helper must not restore an old baseline');
});
test('missing uses linkage, unknown identifiers and changed unit data fail instead of hiding errors',t=>{
 const s=Fixture(t),raw=fs.readFileSync(s.source,'utf8');
 fs.writeFileSync(s.source,raw.replace('uses '+UNIT+';','uses System.SysUtils;'));
 assert.throws(()=>ReadContractFile(s.source,'utf8'),/USES_MISSING/);
 fs.writeFileSync(s.source,raw.replace(' = '+NAME+';',' = CozyText_Unknown_ProtocolDomain_abcd1234;'));
 assert.throws(()=>ReadContractFile(s.source,'utf8'),/REFERENCE/);
 fs.writeFileSync(s.source,raw);fs.writeFileSync(s.unitFile,fs.readFileSync(s.unitFile,'utf8').replace('COZY-TEST','FORGED'));
 assert.throws(()=>ReadContractFile(s.source,'utf8'),/CONSTANT_CHANGED/);
});
test('constant syntax rejects executable expressions, missing literal operands and duplicate names',()=>{
 for(const expression of ['String.Create()',"'a' +", "'a' + 12", "'a' + + 'b'"])
  assert.throws(()=>UnitConstants('unit '+UNIT+'; interface const '+NAME+' = '+expression+'; implementation end.',UNIT),/EXPRESSION/);
 assert.throws(()=>UnitConstants('unit '+UNIT+'; interface const '+NAME+" = 'a'; "+NAME+" = 'b'; implementation end.",UNIT),/DUPLICATE/);
 assert.throws(()=>UnitConstants('unit Other; interface const '+NAME+" = 'a'; implementation end.",UNIT),/UNIT_NAME/);
});
test('separate Pascal constant units cannot hide runtime initialization, imports, procedures or trailing code',()=>{
 const original='unit '+UNIT+'; interface const '+NAME+" = 'a'; implementation end.";
 for(const changed of [
  original.replace('implementation end.','implementation initialization RunHidden; end.'),
  original.replace('interface const','interface uses Hidden.Unit; const'),
  original.replace('implementation end.','implementation procedure Hidden; begin end; end.'),
  original.replace('interface const','interface {$I Hidden.inc} const'),
  original+' procedure Hidden; begin end;',
  original.replace('implementation','Unlisted = 42; implementation')
 ])assert.throws(()=>UnitConstants(changed,UNIT),/UNIT_SCAFFOLD|DECLARATION|UNIT_DIRECTIVE/);
});
test('paths cannot escape source tree and map cannot silently omit constants',t=>{
 const s=Fixture(t);s.map.units[0].path='../Other.pas';fs.writeFileSync(s.mapFile,JSON.stringify(s.map));
 assert.throws(()=>ReadContractFile(s.source,'utf8'),/PATH/);
 s.map.units[0].path='Cozy.Source/Cozy.Configuration/'+UNIT+'.pas';s.save();
 fs.writeFileSync(s.unitFile,fs.readFileSync(s.unitFile,'utf8').replace('implementation',"CozyText_Extra_Value_aabbccdd = 'extra';\nimplementation"));
 assert.throws(()=>ReadContractFile(s.source,'utf8'),/UNINDEXED_CONSTANT/);
});
test('uses parser handles path-qualified project imports; binary and nonnative files remain exact',t=>{
 assert.deepEqual([...UsedUnits("program Example; uses A in 'a.pas', "+UNIT+" in 'path.pas'; begin end.")],['a',UNIT.toLowerCase()]);
 const s=Fixture(t),bin=path.join(s.root,'image.bin');fs.writeFileSync(bin,Buffer.from([0,1,255]));assert.deepEqual(ReadContractFile(bin),Buffer.from([0,1,255]));
 assert.equal(ReadContractFile(s.mapFile,'utf8'),fs.readFileSync(s.mapFile,'utf8'));
});
test('include files require a real including owner with the required constant unit imported',t=>{
 const s=Fixture(t),inc=path.join(s.root,'Cozy.Source/Example.inc');
 fs.writeFileSync(inc,'procedure Test; begin WriteLn('+NAME+'); end;');
 s.map.sources.push({path:'Cozy.Source/Example.inc',unitNames:[UNIT],owners:['Cozy.Source/Example.pas']});s.save();
 assert.throws(()=>ReadContractFile(inc,'utf8'),/INCLUDE_OWNER/);
 const original=fs.readFileSync(s.source,'utf8');
 for(const fakeInclude of ["const Fake = '{$I Example.inc}';",'// {$I Example.inc}', '(* {$I Example.inc} *)']){
  fs.writeFileSync(s.source,original.replace('implementation','implementation\n'+fakeInclude));
  assert.throws(()=>ReadContractFile(inc,'utf8'),/INCLUDE_OWNER/);
 }
 fs.writeFileSync(s.source,original);
 fs.writeFileSync(s.source,fs.readFileSync(s.source,'utf8').replace('implementation','implementation\n{$I Example.inc}'));
 assert(ReadContractFile(inc,'utf8').includes(s.literal));
 fs.writeFileSync(s.source,fs.readFileSync(s.source,'utf8').replace('uses '+UNIT+';','uses System.SysUtils;'));
 assert.throws(()=>ReadContractFile(inc,'utf8'),/INCLUDE_USES_MISSING/);
});
test('C++ macros preserve literal prefixes/raw spelling and do not expand names inside literals/comments',t=>{
 const s=Fixture(t),dir=path.join(s.root,'Cozy.ImGui/Cozy.Strings');fs.mkdirSync(dir,{recursive:true});
 const name='COZY_TEXT_EXAMPLE_PROTOCOL_1234ABCD',unitPath='Cozy.ImGui/Cozy.Strings/Cozy.Strings.Tests.h';
 const sourcePath='Cozy.ImGui/example.cpp',source=path.join(s.root,sourcePath),header=path.join(s.root,unitPath);
 const expression='u8R"tag(한글 "quote"\nline)tag"';
 fs.writeFileSync(header,'#ifndef TEST_HEADER\n#define TEST_HEADER\n#define '+name+' '+expression+'\n#endif\n');
 fs.writeFileSync(path.join(dir,'Cozy.NativeStrings.map.json'),JSON.stringify({units:[{path:unitPath,constants:[{name,expression}]}],sources:[{path:sourcePath,unitPaths:[unitPath]}]}));
 fs.writeFileSync(source,'#include "Cozy.Strings/Cozy.Strings.Tests.h"\nconst auto* value='+name+';\n// '+name+'\nconst char* raw=R"x('+name+' "+")x";\n');
 const value=ReadContractFile(source,'utf8');assert(value.includes('value='+expression));assert(value.includes('// '+name));assert(value.includes('raw=R"x('+name));
 fs.writeFileSync(source,fs.readFileSync(source,'utf8').replace('#include "Cozy.Strings/Cozy.Strings.Tests.h"','// include removed'));
 assert.throws(()=>ReadContractFile(source,'utf8'),/CPP_INCLUDE_MISSING/);
 const headerText=expression=>'#ifndef TEST_HEADER\n#define TEST_HEADER\n#define '+name+' '+expression+'\n#endif\n';
 assert.equal(CppConstants(headerText('L"wide"')).get(name),'L"wide"');
 assert.throws(()=>CppConstants(headerText('fn("text")')),/CPP_EXPRESSION/);
 assert.throws(()=>CppConstants(headerText('"safe"').replace('#endif','int initializer=RunHidden();\n#endif')),/CPP_SCAFFOLD/);
 assert.throws(()=>CppConstants(headerText('"safe"').replace('#endif','#include "Hidden.h"\n#endif')),/CPP_SCAFFOLD/);
 const mapFile=path.join(dir,'Cozy.NativeStrings.map.json'),map=JSON.parse(fs.readFileSync(mapFile,'utf8'));
 map.sources.push(map.sources[0]);fs.writeFileSync(mapFile,JSON.stringify(map));
 assert.throws(()=>ReadContractFile(source,'utf8'),/CPP_MAP_DUPLICATE/);
});
