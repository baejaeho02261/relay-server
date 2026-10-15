'use strict';
// Test the complete PE-role corpus against the separately implemented Python
// oracle. This test intentionally cannot report a native Windows execution.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const {main,parseArgs,safeOutput,snapshot,finishInput,measuredCoverage,reference,ROLES,execute}=require('./compare-native-crc-pe');
const r=main({portable:true});
assert.equal(r.status,'PASS');assert(r.cases>=46);assert.equal(r.independentRoles.length,9);
assert.equal(r.selectedRangeComparison,'NOT_RUN');assert.equal(r.nativeMappedImageComparison,'NOT_RUN');
assert.equal(r.nativeDiskComparison,'NOT_RUN');assert.equal(r.nativeExecutions,0);
assert.equal(r.finalArtifactComparison,'NOT_RUN');assert.deepEqual(r.finalArtifacts,{});assert.deepEqual(r.mappedImageRuns,[]);
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'crc-pe-input-contract-'));
try{
 const source=path.join(dir,'selected A & literal.exe'),copy=path.join(dir,'snapshot.exe'),out=path.join(dir,'report.json');
 fs.writeFileSync(source,Buffer.from('selected artifact bytes'));
 const args=['--probe',source,'--a',source,'--b',copy,'--o',path.join(dir,'O.exe'),'--out',out];
 const options=parseArgs(args);assert.equal(options.artifacts.A,source);assert.equal(options.out,out);
 for(const bad of [['--a'],['--a','--out','x'],['--unknown','x'],['--probe','a','--probe','b'],['--portable-only','--probe','x']])assert.throws(()=>parseArgs(bad));
 const before=fs.readFileSync(source);
 assert.throws(()=>safeOutput(source,options),/CRC_OUTPUT_OVERLAPS_INPUT/);
 assert.throws(()=>execute({...options,out:source}),/CRC_OUTPUT_OVERLAPS_INPUT/);
 assert.deepEqual(fs.readFileSync(source),before);
 const link=path.join(dir,'same-inode.json');fs.linkSync(source,link);
 assert.throws(()=>safeOutput(link,{probe:source}),/CRC_OUTPUT_UNSAFE/);fs.unlinkSync(link);
 const row=snapshot(source,copy);assert.match(row.beforeSha512,/^[a-f0-9]{128}$/);assert.equal(finishInput(row).unchanged,true);
 fs.appendFileSync(copy,'tampered');assert.equal(finishInput(row).unchanged,false);fs.writeFileSync(copy,before);
 fs.appendFileSync(source,'changed');assert.equal(finishInput(row).unchanged,false);fs.writeFileSync(source,before);
 const complete=Object.fromEntries(ROLES.map(role=>[role,{status:'measured'}]));
 assert.deepEqual(measuredCoverage({accepted:true,layers:complete},'A'),Object.fromEntries(ROLES.map(role=>[role,'measured'])));
 for(const status of ['partial','unavailable',undefined])assert.throws(()=>measuredCoverage({accepted:true,layers:{...complete,nvme:{status}}},'A'),/CRC_COVERAGE_INCOMPLETE/);
 const fixture=require('./crc-pe-comparison-fixtures').fixtures().find(row=>row.id==='absent-anchor');
 const incomplete=path.join(dir,'incomplete.exe');fs.writeFileSync(incomplete,fixture.bytes);
 assert.throws(()=>measuredCoverage(reference([incomplete])[0],'selected final A'),/CRC_COVERAGE_INCOMPLETE/);
 assert.throws(()=>execute({portable:true,artifacts:{A:incomplete},out}),/CRC_COVERAGE_INCOMPLETE/);
 const incompleteReport=JSON.parse(fs.readFileSync(out,'utf8'));assert.equal(incompleteReport.status,'FAIL');assert.equal(incompleteReport.finalArtifacts.A.coverage.nvme,'partial');assert.equal(incompleteReport.inputs.A.unchanged,true);
 fs.writeFileSync(out,JSON.stringify({status:'PASS'}));
 const rejected=cp.spawnSync(process.execPath,[path.join(__dirname,'compare-native-crc-pe.js'),'--out',out,'--unknown','--a',source],{encoding:'utf8'});
 assert.equal(rejected.status,1);assert.equal(JSON.parse(fs.readFileSync(out,'utf8')).status,'FAIL');assert.deepEqual(fs.readFileSync(source),before);
 const guarded=cp.spawnSync(process.execPath,[path.join(__dirname,'compare-native-crc-pe.js'),'--out',source,'--unknown','--a',source],{encoding:'utf8'});
 assert.equal(guarded.status,1);assert.deepEqual(fs.readFileSync(source),before);
 // Run the real wrapper in a disposable directory to test its default report.
 const wrapperRoot=path.join(dir,'wrapper');for(const name of ['tools','scripts'])fs.mkdirSync(path.join(wrapperRoot,name),{recursive:true});
 const wrapper=path.join(wrapperRoot,'tools/run-crc-pe-comparison.js'),defaultReport=path.join(wrapperRoot,'tools/crc-pe-comparison-result.json');
 fs.copyFileSync(path.resolve(__dirname,'../tools/run-crc-pe-comparison.js'),wrapper);
 fs.writeFileSync(path.join(wrapperRoot,'scripts/compare-native-crc-pe.js'),'module.exports=require('+JSON.stringify(path.join(__dirname,'compare-native-crc-pe.js'))+');\n');
 for(const rejectedArgs of [['--portable-only','/nopause'],['--CORPUS-ONLY','--a',source,'/nopause']]){
  fs.writeFileSync(defaultReport,JSON.stringify({status:'PASS'}));
  const failed=cp.spawnSync(process.execPath,[wrapper,...rejectedArgs],{encoding:'utf8'});
  assert.equal(failed.status,1);assert.equal(JSON.parse(fs.readFileSync(defaultReport,'utf8')).status,'FAIL');assert.deepEqual(fs.readFileSync(source),before);
 }
 // A native request in this portable test cannot execute or preserve an old PASS.
 if(process.platform!=='win32'){
  fs.writeFileSync(out,JSON.stringify({status:'PASS'}));
  assert.throws(()=>execute({probe:source,out}),/requires Windows/);
  const failed=JSON.parse(fs.readFileSync(out,'utf8'));assert.equal(failed.status,'FAIL');assert.equal(failed.nativeMappedImageComparison,'NOT_RUN');
 }
 const bat=fs.readFileSync(path.resolve(__dirname,'../tools/Run_CRC_PE_Comparison.bat'),'utf8');
 assert(bat.includes('run-crc-pe-comparison.js" %*'));assert(!bat.includes('set /p'));assert(!bat.includes('del /q'));
}finally{fs.rmSync(dir,{recursive:true,force:true});}
console.log('PASS independent PE/CRC corpus; actual Windows native comparison remains NOT_RUN');
