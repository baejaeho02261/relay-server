'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Packaging checks for the previously reported IDE source/resource errors.
// They do not replace compiling and running both programs with Delphi Win64.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(MODULE_RESOURCE_ROOT, '../../Railway');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const projectDirectory = name => path.join('Cozy.Projects', name);
const projectFile = (name, extension) => path.join(projectDirectory(name), name + extension);
const sourceDirectories = ['Cozy.Application','Cozy.Lifecycle','Cozy.Platform','Cozy.Security','Cozy.Network','Cozy.Identity','Cozy.Integrity','Cozy.Crypto','Cozy.Overlay','Cozy.Handoff','Cozy.Configuration'].map(name=>'Cozy.Source/'+name);
for(const directory of sourceDirectories){
  const files=fs.readdirSync(path.join(root,directory));
  assert(files.some(name=>/\.(?:pas|inc)$/i.test(name)),'Functional source group must contain actual source: '+directory);
}
for(const entry of fs.readdirSync(root,{withFileTypes:true}))assert(!entry.isFile()||!/\.(?:pas|dpr|dproj|inc|bat|targets)$/i.test(entry.name),'No flat native source aliases: '+entry.name);
const contained = (directory, relative) => {
  const target=path.resolve(directory,...relative.split(/[\\/]+/));
  const rel=path.relative(root,target);
  assert(rel && rel!=='..' && !rel.startsWith('..'+path.sep) && !path.isAbsolute(rel),'Project reference escapes native root');
  assert(fs.statSync(target).isFile(),'Missing project reference '+relative);return target;
};
for (const [name, role] of [["Cozy.Client", 'B'], ["Cozy.Launcher", 'A'], ["Cozy.Overlay",'O']]) {
  const project = read(projectFile(name, '.dproj'));
  const directory=path.join(root,projectDirectory(name));
  assert.ok(!/GAME_(?:(?:LICENSE|TLS|HANDOFF)_CONTRACT_TESTS|NATIVE_ABI_TESTS)/i.test(project), 'Probe-only hooks must not be enabled in an application project');
  assert.match(project, /<DCC_Define>GAME_APPLICATION_BUILD;/, 'Application builds must reject probe hooks');
  for (const unit of ["Cozy.Source/Cozy.Application/Cozy.Startup.pas", "Cozy.Source/Cozy.Handoff/Cozy.Handoff.Crypto.pas"]) {
    const references=[...project.matchAll(/DCCReference\s+Include="([^"]+)"/g)].map(m=>contained(directory,m[1]));
    assert(references.includes(path.join(root,unit)), 'Missing required unit '+unit);
  }
  const entries = [...project.matchAll(/<DelphiCompile\s+Include="([^"]+)"\s*>([\s\S]*?)<\/DelphiCompile>/g)];
  assert.equal(entries.length, 1, 'Exactly one primary Delphi compile item');
  assert.equal(entries[0][1], name + '.dpr');
  assert.match(entries[0][2], /<MainSource>MainSource<\/MainSource>/);
  assert.ok(project.includes('<MainSource>' + name + '.dpr</MainSource>'));
  assert.match(project, /<FrameworkType>None<\/FrameworkType>/);
  assert.ok(project.includes('<DCC_ConsoleTarget>false</DCC_ConsoleTarget>'));
  assert.match(project, /<Platform value="Win64">True<\/Platform>/);
  assert.match(project, /<Target Name="PublishRandomExecutable" AfterTargets="Build;Rebuild">/);
  assert.ok(project.includes("<RandomArtifactName>" + role + "_$(Config)_$([System.Guid]::NewGuid().ToString('N')).exe</RandomArtifactName>"));
  assert.ok(project.includes('<RandomArtifactDirectory>$(CozyNativeRoot)\\bin</RandomArtifactDirectory>'));
  assert.ok(project.includes('<DCC_DcuOutput>$(CozyNativeRoot)\\build\\' + role + '\\$(Platform)\\$(Config)\\dcu</DCC_DcuOutput>'), 'Compiler units must remain role-isolated');
  assert.match(project, /<Move SourceFiles="\$\(CompiledArtifact\)"/);
  const localProperties=project.match(/TreatAsLocalProperty="([^"]+)"/)[1].split(';');
  for(const property of ['CozyNativeRoot','RandomArtifactName','RandomArtifactDirectory','CompiledArtifact'])assert(localProperties.includes(property),'Global build properties must not redirect '+property);
  for(const property of ['DCC_UnitSearchPath','DCC_IncludePath']){
    const listed=project.match(new RegExp('<'+property+'>([^<]+)</'+property+'>'))[1].split(';');
    assert.deepEqual(listed.slice(0,-1),sourceDirectories.map(x=>'$(CozyNativeRoot)\\'+x.replaceAll('/','\\')));
    assert.equal(listed.at(-1),'$('+property+')');
  }
  if(role==='O')assert(project.includes('<DCC_ObjPath>$(CozyNativeRoot)\\Cozy.BuildOutputs\\Cozy.ImGui;$(DCC_ObjPath)</DCC_ObjPath>'));
  for(const entry of fs.readdirSync(directory))assert(!/\.(?:pas|inc)$/i.test(entry),'Product project must not shadow functional source units');
  for (const configuration of ['Debug', 'Release']) {
    const finalName = project.match(/<RandomArtifactName>([^<]+)<\/RandomArtifactName>/)[1].replace('$(Config)', configuration).replace(/\$\(\[System\.Guid\]::NewGuid\(\)\.ToString\('N'\)\)/, 'a'.repeat(32));
    assert.equal(finalName, `${role}_${configuration}_${'a'.repeat(32)}.exe`);
  }
  assert.match(project, /<Icon_MainIcon\s*\/>/);
  assert.ok(!/\.ico\b/i.test(project));
  for (const [, file] of project.matchAll(/(?:DCCReference|None)\s+Include="([^"]+)"/g)) {
    contained(directory,file);
  }
  const dpr = read(projectFile(name, '.dpr'));
  assert.ok(!/GAME_(?:(?:LICENSE|TLS|HANDOFF)_CONTRACT_TESTS|NATIVE_ABI_TESTS)/i.test(dpr), 'Probe-only hooks must not be enabled in an application entry point');
  assert.ok(dpr.indexOf('{$DEFINE GAME_APPLICATION_BUILD}') >= 0 && dpr.indexOf('{$DEFINE GAME_APPLICATION_BUILD}') < dpr.search(/\{\$I [^}]*Cozy\.Metadata\.inc\}/), 'Direct compiler builds must reject probe hooks');
  const expectedRole = {"Cozy.Launcher":'gcrLauncher',"Cozy.Client":'gcrConnect',"Cozy.Overlay":'gcrOverlay'}[name];
  const seal = dpr.indexOf('SealApiPointerStorage;'), startup = dpr.indexOf('RequireNativeStartup('+expectedRole+');');
  assert.ok(seal >= 0 && startup > seal, 'Native startup validation must follow API sealing');
  assert.match(dpr.slice(startup), /RequireNativeStartup\(gcr(?:Launcher|Connect|Overlay)\);\s+ExitCode := Run/, 'Role-specific startup checks must precede application execution');
  assert.ok(dpr.includes('{$APPTYPE GUI}'));
  assert.match(dpr, /function GameBuildConfiguration: LongWord; stdcall;\s*begin\s*\{\$IFDEF RELEASE\}\s*Result := 2;\s*\{\$ELSE\}\s*Result := 1;/, 'Marker value must follow the actual compiler configuration');
  assert.match(dpr, /exports\s*\{\$IFDEF RELEASE\}\s*GameBuildConfiguration name 'GAME_BUILD_RELEASE_V1';\s*\{\$ELSE\}\s*GameBuildConfiguration name 'GAME_BUILD_DEBUG_V1';/, 'Debug must not carry the Release export marker');
  for (const [, res] of dpr.matchAll(/\{\$R\s+'([^']+)'\}/g)) {
    const bytes = fs.readFileSync(contained(directory,res));
    assert.ok(bytes.length > 32, 'Missing compiled resource: ' + res);
    assert.equal(bytes.readUInt32LE(4), 32, 'Expected Windows RES header: ' + res);
    const types = [];
    for (let at = 0; at < bytes.length;) {
      assert.ok(at + 8 <= bytes.length, 'Truncated resource header');
      const size = bytes.readUInt32LE(at), header = bytes.readUInt32LE(at + 4);
      assert.ok(header >= 16 && at + header + size <= bytes.length, 'Truncated resource data');
      if (bytes.readUInt16LE(at + 8) === 0xffff) types.push(bytes.readUInt16LE(at + 10));
      at += (header + size + 3) & ~3;
    }
    assert.equal(types.filter(t => t === 3).length, 0, 'Custom icon images are forbidden: ' + res);
    assert.equal(types.filter(t => t === 14).length, 0, 'Custom icon group is forbidden: ' + res);
    assert.doesNotMatch(read(projectFile(name, '.rc')), /MAINICON\s+ICON/);
    assert.ok(types.includes(16), 'Missing version resource: ' + res);
    assert.ok(types.includes(24), 'Missing application manifest: ' + res);
  }
}
assert.ok(!fs.existsSync(path.join(root, 'cozy.Client.ico')));
const metadata = read("Cozy.Source/Cozy.Configuration/Cozy.Metadata.inc");
assert.match(metadata, /Application build configuration cannot be both Debug and Release/);
assert.match(metadata, /Application build configuration must define Debug or Release/);
const isolation = read("Cozy.Build/Cozy.BuildIsolation.targets");
assert.match(isolation, /Name="GameCompileSearchPathValidator" Condition="'\$\(Config\)'=='Debug' or '\$\(Config\)'=='Release'"/);
assert.ok(isolation.includes('\\Win64\\$(Config)\\dcu'));
assert.ok(isolation.includes('\\Win64\\$(Config)'));
assert.ok(!isolation.includes('\\Win64\\Release'), 'Output validation must not hardcode the Release directory');
for (const error of ['GAME_BUILD_CONFIGURATION_INVALID', 'GAME_BUILD_RELEASE_DEFINE_MISMATCH', 'GAME_BUILD_DEBUG_DEFINE_MISMATCH', 'GAME_BUILD_TEST_DEFINE_FORBIDDEN', 'GAME_BUILD_OUTPUT_OVERRIDE_FORBIDDEN']) assert.ok(isolation.includes(error));
assert.ok(isolation.includes('Final="$(CozyNativeRoot)\\bin"'));
assert.ok(isolation.includes('ProjectDirectory="$(MSBuildProjectDirectory)"'));
assert.ok(isolation.includes('GAME_BUILD_SHADOW_SOURCE_FORBIDDEN'));
assert.doesNotMatch(isolation.match(/<Target Name="ValidateProductionIsolation"[^>]*>/)[0], /Condition=/, 'Validation must not be skipped through DesignTimeBuild or a configuration override');
assert.match(read("Cozy.Build/Cozy.Tasks/Cozy.BuildSearchPaths.cs"), /rejectReparse\(canonical\(Final\)\)/, 'Shared final folder must not redirect through a junction');
const isolationTest = read("Cozy.Tests/Cozy.Build/Cozy.Test-BuildIsolation.ps1");
assert.match(isolationTest, /foreach\(\$config in @\('Debug','Release'\)\)/);
assert.match(isolationTest, /ISOLATION_OTHER_CONFIGURATION_DAMAGED/);
assert.match(isolationTest, /ISOLATION_COMPILER_CONFIGURATION_NOT_REJECTED/);
for (const hook of ['GAME_LICENSE_CONTRACT_TESTS', 'GAME_TLS_CONTRACT_TESTS', 'GAME_NATIVE_ABI_TESTS', 'GAME_HANDOFF_CONTRACT_TESTS']) {
  assert.ok(metadata.includes('{$IFDEF '+hook+'}'), 'Missing product guard for '+hook);
}
const tls=read("Cozy.Source/Cozy.Network/Cozy.Tls.pas"), transport=read("Cozy.Source/Cozy.Network/Cozy.Transport.pas");
assert.ok(transport.includes('.ConnectTLS('),'Every native request must use TLS');
assert.ok(tls.includes('CertVerifyTimeValidity') && tls.includes('CryptHashCertificate2'));
assert.ok(tls.indexOf('if not VerifyCertificate(CertificateSha256) then Exit;') < tls.indexOf('FAuthenticated := True;'));
assert.ok(read("Cozy.Source/Cozy.Platform/Cozy.Api.pas").includes('FImageIntegrity.VerifyNow'));
for(const name of ["Cozy.Client","Cozy.Launcher","Cozy.Overlay"])assert.ok(read(projectFile(name,'.dproj')).includes("Cozy.Integrity.pas")&&read(projectFile(name,'.dproj')).includes("Cozy.Tls.pas"));

const consoleSource = read("Cozy.Source/Cozy.Application/Cozy.Console.pas");
const entry = consoleSource.slice(consoleSource.indexOf('function RunGameConsole: Integer;', consoleSource.indexOf('implementation')));
assert.ok(entry.indexOf('Context.CompleteClaimAndCleanup(') >= 0 && entry.indexOf('Context.CompleteClaimAndCleanup(') < entry.indexOf('if not AllocConsole'), 'User console must start only after authenticated handoff and cleanup');
assert.ok(entry.indexOf('Api.CheckIntegrity;') < entry.indexOf('if not AllocConsole'));
assert.ok(entry.includes('Console := TConsoleSession.Create(Api);') && entry.includes('Result := Console.Run;'));
assert.ok(consoleSource.includes('FWorker.SubmitKey(Key)'));
assert.ok(!consoleSource.includes('SERVER_ASSIGNED_V1'));
assert.ok(!read("Cozy.Source/Cozy.Platform/Cozy.Api.pas").includes('SERVER_ASSIGNED_V1'));
assert.ok(!/\b(?:WriteLn|ShowMessage|MessageBox)\s*\(/i.test(consoleSource), 'User diagnostics must remain silent');
const sources=[];
function collect(directory){
  for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
    const file=path.join(directory,entry.name);assert(!entry.isSymbolicLink(),'Native source paths must not be symbolic links');
    if(entry.isDirectory()){if(directory===root&&['build','bin','Cozy.BuildOutputs'].includes(entry.name))continue;collect(file);}
    else if(entry.isFile())sources.push(path.relative(root,file));
  }
}
collect(root);
assert(sources.filter(name=>name.endsWith('.pas')).length>=50,'Recursive checks must inspect the functional source tree');
assert(sources.filter(name=>name.endsWith('.dpr')).length>=30,'Recursive checks must inspect grouped projects and probes');
for (const name of sources) {
  if (!/\.(?:pas|dpr|dproj|bat|inc)$/.test(name)) continue;
  const source = read(name);
  assert.ok(!source.includes('%MainSource%'), 'Unresolved source macro in ' + name);
  assert.ok(!/\bBS_TYPEMASK\b/.test(source), 'Undeclared SDK mask in ' + name);
  if (/\.(?:pas|dpr|inc)$/.test(name)) {
    const executableSource=source.replace(/('(?:''|[^'])*')|\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\r\n]*/g,(match,literal)=>literal||'');
    assert.ok(!/https?:\/\//i.test(executableSource), 'Embedded HTTP endpoint: ' + name);
  }
  if (/\.(?:pas|dpr)$/.test(name)) {
    assert.ok(source.startsWith('\uFEFF'), 'Missing UTF-8 BOM: ' + name);
    assert.ok(!source.replace(/\r\n/g, '').includes('\n'), 'Mixed source line endings: ' + name);
    assert.ok(!/\b(?:Vcl|FMX)\./i.test(source), 'Retired GUI dependency: ' + name);
    if(name.endsWith('.pas')){
      const declared=source.match(/\bunit\s+([A-Za-z0-9_.]+)\s*;/i);
      assert(declared,'Pascal source must declare a unit: '+name);
      assert.equal(declared[1],path.basename(name,'.pas'),'Unit identity must exactly match grouped Cozy filename');
    }
    assert.ok(!/\b(?:CryptProtectData|CryptUnprotectData|RegSetValueEx|TRegistry)\b/.test(source), 'Persistent client credentials: ' + name);
    for (const [, block] of source.matchAll(/constructor\s+[\w.]+[^;]*;([\s\S]*?)(?=\n(?:constructor|destructor|procedure|function|class\s+function)|$)/gi)) {
      assert.ok(!/^\s*Start\s*;/m.test(block), 'Thread started inside constructor: ' + name);
    }
  }
}
for (const retired of ['Game.dproj', 'Game.Main.pas', 'Game.UI.pas']) {
  assert.ok(!fs.existsSync(path.join(root, retired)), 'Retired GUI source: ' + retired);
}
console.log('A/B/O PROJECT SOURCE CHECK PASS (actual Delphi compilation still required)');
