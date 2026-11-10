'use strict';
// Build/run source wiring only. This host does not execute a Windows binary.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {test}=require('node:test');
const gate=require('../../tools/runtime/peace.nhw-validation-gate');
const root=path.resolve(__dirname,'../../../Railway/Cozy.Tests/Cozy.NHW');
const name='Cozy.NHW.DetectionJournal';
const read=file=>fs.readFileSync(path.join(root,file),'utf8').replaceAll('\r','');
const source=read('Cozy.NHW.Validation/Cozy.NHW.Validation.Runner.dpr');
const code=text=>text.replace(/'(?:''|[^'])*'|\{[\s\S]*?\}|\(\*[\s\S]*?\*\)|\/\/[^\n]*/g,s=>s.startsWith("'")?s:'');
function assertExecution(text){
 const body=code(text).split('function RunSuite(')[1]?.split('function RunSoak(')[0];assert.ok(body,'suite body absent');
 const preflight=body.slice(0,body.indexOf('if Missing > 0 then'));
 assert.match(preflight,/Exe := TestExecutable\(Root, INTEGRATION_JOURNAL_TEST\);\s*if not FileExists\(Exe\) then\s*begin\s*Inc\(Missing\)/);
 assert.match(body,/if Missing > 0 then[\s\S]*?Exit\(2\)/);
 const rounds=body.slice(body.indexOf('for Round := 1 to Options.Rounds do'));
 assert.match(rounds,/for I := 0 to VALIDATION_TEST_COUNT - 1 do/);
 const appended=rounds.slice(rounds.indexOf('Exe := TestExecutable(Root, INTEGRATION_JOURNAL_TEST)'));
 assert.ok(appended.length>0,'integration execution not inside round');
 assert.match(appended,/R := RunValidationChild\(Exe, '', Cardinal\(Options.TimeoutSeconds\) \* 1000, False\);/);
 assert.match(appended,/PrintChild\(R\);\s*if CleanTestExit\(R\) then\s*begin\s*Inc\(Passed\); Writeln\('PASS: ', INTEGRATION_JOURNAL_TEST\)/);
 assert.match(appended,/else\s*begin\s*Inc\(Failed\); Writeln\('FAIL\/INCOMPLETE: ', INTEGRATION_JOURNAL_TEST\)/);
 assert.match(appended,/except[\s\S]*?Inc\(Failed\)/);
 assert.match(appended,/Inc\(Completed\);[\s\S]*?if Failed <> 0 then Result := 1 else Result := 0/);
}
test('journal project is built by all three FullValidation operations',()=>{
 const group=read('Cozy.NHW.FullValidation.groupproj'),ref=name+'\\'+name+'.dproj';
 assert.ok(group.includes('<Projects Include="'+ref+'">'));
 for(const action of ['Build','Clean','Make']){
  const suffix=action==='Build'?'':':'+action;
  assert.match(group,new RegExp('<Target Name="'+action+'" DependsOnTargets="[^"\\n]*'+name.replaceAll('.','\\.')+suffix+'(?:;[^"\\n]*)?"'));
  assert.ok(group.includes('<Target Name="'+name+suffix+'">\n    <MSBuild Projects="'+ref+'" Targets="'+action+'"'));
 }
 const project=read(name+'/'+name+'.dproj');
 assert.ok(project.includes('<MainSource>'+name+'.dpr</MainSource>'));
 assert.ok(project.includes('<DCC_ExeOutput>.</DCC_ExeOutput>'));
 assert.ok(fs.existsSync(path.join(root,name,name+'.dpr')));
});
test('all original79 cases plus context remain and journal execution is required by both runner and gate',()=>{
 const catalog=read('Cozy.NHW.Validation/Cozy.NHW.Validation.Catalog.inc');
 assert.match(catalog,/VALIDATION_TEST_COUNT\s*=\s*80;/);
 const original=[...catalog.matchAll(/'(Cozy\.NHW\.[A-Za-z0-9.]+)'/g)].map(m=>m[1]);
 assert.equal(original.length,80);assert.equal(original.filter(x=>x!=='Cozy.NHW.Context.Tests').length,79);assert.ok(original.includes('Cozy.NHW.Context.Tests'));assert.ok(!original.includes(name));
 assert.deepEqual(gate.RequiredNativeCases(),[...original,name]);
 assert.ok(source.includes("INTEGRATION_JOURNAL_TEST = '"+name+"'"));
 assert.match(source,/TOTAL_VALIDATION_TEST_COUNT = VALIDATION_TEST_COUNT \+ 1;/);
 assertExecution(source);
});
test('removing actual child execution is detected even when project/gate entries remain',()=>{
 const start=source.indexOf('function RunSuite('),execution=source.indexOf('Exe := TestExecutable(Root, INTEGRATION_JOURNAL_TEST);',source.indexOf('for Round :=',start));
 assert.ok(execution>start);
 const mutated=source.slice(0,execution)+source.slice(execution).replace("R := RunValidationChild(Exe, '', Cardinal(Options.TimeoutSeconds) * 1000, False);",'R := Default(TValidationRun);');
 assert.throws(()=>assertExecution(mutated));
});
test('a failed handle snapshot leaves independent probes live without advancing handle baselines',()=>{
 const enginePath=path.resolve(root,'../../Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas');
 const engine=code(fs.readFileSync(enginePath,'utf8'));
 const acquisition=engine.slice(engine.lastIndexOf('HandleSnapshotValid := CollectHolders('));
 const missing=acquisition.split('if not HandleSnapshotValid then')[1]?.split('else if Opt.ThreadWatch')[0];
 assert.ok(missing,'handle failure branch missing');
 assert.match(missing,/Unified\.MarkIncomplete;\s*BreakCorrelationCoverage;/);
 assert.match(missing,/OnHandleCoverageUnavailable\(TickStart\);/);
 assert.doesNotMatch(missing,/\b(?:Continue|Break|Exit)\b/i);
 assert.match(acquisition,/NewMonitorBaseline := LocalBaselineRemaining > 0;/);
 assert.match(acquisition,/if HandleSnapshotValid then\s*begin\s*Behavior\.BeginSnapshot/);
 assert.match(acquisition,/if NativeThreadValid and HandleSnapshotValid then[\s\S]*?Lifecycle\.ExamineInheritance/);
 assert.match(acquisition,/InspectThreadAndMemoryState;\s*InspectSystemAndSelfState;\s*InspectCodeAndInitialCorrelations;/);
 assert.match(acquisition,/RecordCycleEvidence;[\s\S]*?if HandleSnapshotValid then\s*begin\s*Keys\.Clear;[\s\S]*?Dec\(ProcessBaselineRemaining\);\s*end;\s*if LocalBaselineRemaining > 0 then Dec\(LocalBaselineRemaining\);/);
 assert.match(acquisition,/if ThreadSnapshotValid and \(ThreadBaselineRemaining > 0\) then\s*Dec\(ThreadBaselineRemaining\);\s*FinalizeSamplingAndReport;/);
});
