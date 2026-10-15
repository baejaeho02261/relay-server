'use strict';
// Exercise the actual BAT :build helpers with a controlled compiler stub.
// This is an output-lifetime contract, never a Delphi build or license test.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const assert=require('node:assert/strict'),cp=require('node:child_process');
if(process.platform!=='win32'){
 console.log('NOT_RUN: probe build-output contracts require Windows cmd.exe; no native build PASS is claimed.');
}else{
 const native=path.resolve(__dirname,'../../GameConnect_Win64/tests');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-probe-build-'));
 let cases=0;
 const definitions=[['Build_NativeProbes_Win64.bat','PROBE'],['Build_OverlayContracts_Win64.bat','OVERLAY_TEST']];
 try{
  for(const [file,prefix]of definitions){
   const source=fs.readFileSync(path.join(native,file),'utf8').replace(/\r\n/g,'\n');
   const start=source.indexOf('\n:build\n');assert(start>=0,'Actual build helper missing: '+file);
   let helper=source.slice(start+1).split('\n:failed\n')[0];
   const compiler=/^"%BDS%\\bin\\dcc64\.exe"[^\n]*$/m;
   assert(compiler.test(helper),'Actual compiler invocation missing: '+file);
   helper=helper.replace(compiler,'call :fixture_compiler');
   const roles=prefix==='PROBE'?['StartupProbe','ModuleGenerationFixture']:['OverlayFirstFrameProbe'];
   for(const role of roles)for(const mode of ['success','no-output','error-output','empty-output','wrong-output','directory-output']){
    const dir=path.join(temp,'case '+(++cases)+' ! & input'),out=path.join(dir,'out');fs.mkdirSync(out,{recursive:true});
    const expected=path.join(out,role+(role==='ModuleGenerationFixture'?'.dll':'.exe'));
    const unrelated=path.join(out,'keep.exe'),fixture=path.join(dir,'fixture.bin');
    const pe=Buffer.alloc(1024,7);pe.write('MZ');fs.writeFileSync(fixture,pe);fs.writeFileSync(unrelated,'do not change');
    if(mode==='directory-output'){fs.mkdirSync(expected);fs.writeFileSync(path.join(expected,'keep.txt'),'directory contents');}
    else fs.writeFileSync(expected,'stale output must never pass');
    const harness=path.join(dir,'harness.bat');
    const text=`@echo off\nsetlocal EnableExtensions DisableDelayedExpansion\nset "${prefix==='PROBE'?'PROBE_OUT':'OVERLAY_TEST_OUT'}=%~dp0out"\nset "PROBE_FIXTURE_FILE=%~dp0fixture.bin"\nset "PROBE_FIXTURE_DIR=%~dp0out"\nset "PROBE_FIXTURE_MODE=${mode}"\ncall :build "${role}" "RELEASE"\nexit /b %ERRORLEVEL%\n${helper}\n:fixture_compiler\nif "%PROBE_FIXTURE_MODE%"=="no-output" exit /b 0\nif "%PROBE_FIXTURE_MODE%"=="wrong-output" (\n copy /b /y "%PROBE_FIXTURE_FILE%" "%PROBE_FIXTURE_DIR%\\wrong.exe" >nul\n exit /b 0\n)\nif "%PROBE_FIXTURE_MODE%"=="empty-output" (\n type nul > "%${prefix}_EXPECTED%"\n exit /b 0\n)\ncopy /b /y "%PROBE_FIXTURE_FILE%" "%${prefix}_EXPECTED%" >nul\nif errorlevel 1 exit /b 10\nif "%PROBE_FIXTURE_MODE%"=="error-output" exit /b 9\nexit /b 0\n`;
    fs.writeFileSync(harness,text.replace(/\n/g,'\r\n'));
    const r=cp.spawnSync(process.env.ComSpec||'cmd.exe',['/d','/s','/c','""'+harness+'""'],{encoding:'utf8',timeout:15000,windowsHide:true,windowsVerbatimArguments:true});
    if(r.error)throw r.error;assert.equal(r.signal,null);const label=file+' '+role+' '+mode+'\n'+r.stdout+r.stderr;
    assert.equal(fs.readFileSync(unrelated,'utf8'),'do not change',label);
    if(mode==='success'){assert.equal(r.status,0,label);assert.deepEqual(fs.readFileSync(expected),pe,label);}
    else{
     assert.notEqual(r.status,0,label);
     if(mode==='directory-output'){assert.match(r.stdout,/PROBE_OUTPUT_IS_DIRECTORY/,label);assert.equal(fs.readFileSync(path.join(expected,'keep.txt'),'utf8'),'directory contents');}
     else assert.equal(fs.existsSync(expected),false,label);
     if(['no-output','wrong-output'].includes(mode))assert.match(r.stdout,/PROBE_NO_FRESH_OUTPUT/,label);
     if(mode==='error-output')assert.match(r.stdout,/PROBE_COMPILER_FAILED/,label);
     if(mode==='empty-output')assert.match(r.stdout,/PROBE_OUTPUT_INVALID/,label);
    }
   }
  }
  console.log('PASS: '+cases+' actual Windows BAT helper cases; stale/no/partial output blocked, fresh EXE/DLL accepted. Compiler stub only; no Delphi or license PASS.');
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
