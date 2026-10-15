'use strict';
// Full-stream/range differential: native report is compared with the separate
// Python struct + integer-SHA512 + bitwise-CRC oracle. Production modules are
// used only as an additional system under test in portable mode, never oracle.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),cp=require('node:child_process'),crypto=require('node:crypto');
const {fixtures}=require('./crc-pe-comparison-fixtures');
const {Read}=require('../services/boundedArtifactRead');
const ROLES=['ecma182','nvme','jones','xz','we','iso','crc32c','crc16_arc','crc8_smbus'];
const ARTIFACT_ROLES=['A','B','O'];
const hash=bytes=>crypto.createHash('sha512').update(bytes).digest('hex');
function snapshot(source,destination){
 const bytes=Read(source);fs.writeFileSync(destination,bytes,{flag:'wx',mode:0o600});
 return {source:path.resolve(source),snapshot:destination,beforeSha512:hash(bytes),bytes:bytes.length};
}
function finishInput(row){
 try{const afterSha512=hash(Read(row.source)),snapshotAfterSha512=hash(Read(row.snapshot));return {...row,afterSha512,snapshotAfterSha512,unchanged:afterSha512===row.beforeSha512&&snapshotAfterSha512===row.beforeSha512};}
 catch{return {...row,unchanged:false};}
}
function measuredCoverage(expected,label){
 assert.equal(expected.accepted,true,label+' admission');
 const coverage=Object.fromEntries(ROLES.map(role=>[role,expected.layers[role]?.status]));
 for(const role of ROLES)assert.equal(coverage[role],'measured',label+' CRC_COVERAGE_INCOMPLETE '+role);
 return coverage;
}
function parseArgs(args){
 const options={images:[],artifacts:{}};const singles=new Set();
 for(let i=0;i<args.length;i++){
  const arg=args[i];
  if(arg==='--portable-only'){assert(!singles.has(arg),'CRC_ARGUMENT_DUPLICATE');singles.add(arg);options.portable=true;continue;}
  assert(['--probe','--image','--a','--b','--o','--out'].includes(arg),'CRC_ARGUMENT_UNKNOWN: '+arg);
  assert(i+1<args.length&&args[i+1]&&!args[i+1].startsWith('--'),'CRC_ARGUMENT_VALUE_REQUIRED: '+arg);
  const value=args[++i];
  if(arg==='--image'){options.images.push(value);continue;}
  assert(!singles.has(arg),'CRC_ARGUMENT_DUPLICATE: '+arg);singles.add(arg);
  if(['--a','--b','--o'].includes(arg))options.artifacts[arg.slice(2).toUpperCase()]=value;
  else options[arg.slice(2)]=value;
 }
 assert(!(options.probe&&options.portable),'CRC_NATIVE_PORTABLE_MODE_CONFLICT');return options;
}
function safeOutput(output,options){
 if(!output)return null;
 const target=path.resolve(output),key=file=>process.platform==='win32'?file.toLowerCase():file;
 const canonical=file=>{try{return fs.realpathSync(file);}catch(e){if(e.code!=='ENOENT')throw e;return path.join(canonical(path.dirname(file)),path.basename(file));}};
 const targetKey=key(canonical(target));
 for(const file of [options.probe,...(options.images||[]),...Object.values(options.artifacts||{})].filter(Boolean))
  assert.notEqual(targetKey,key(canonical(path.resolve(file))),'CRC_OUTPUT_OVERLAPS_INPUT');
 if(fs.existsSync(target)){const stat=fs.lstatSync(target);assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.nlink===1,'CRC_OUTPUT_UNSAFE');}
 return target;
}
function rejectedArguments(args,defaultOutput,defaultProbe){
 // Even malformed argv must not leave an earlier PASS at a known report path.
 // Collect every input occurrence before considering a failure-report write.
 const outputs=args.flatMap((arg,i)=>arg==='--out'?[args[i+1]]:[]);
 if(outputs.length>1||outputs.some(value=>!value||value.startsWith('--')))return null;
 const images=args.flatMap((arg,i)=>['--probe','--image','--a','--b','--o'].includes(arg)&&args[i+1]&&!args[i+1].startsWith('--')?[args[i+1]]:[]);
 return {out:outputs[0]||defaultOutput,probe:defaultProbe,images};
}
function reference(files){
 let child;
 for(const exe of [...new Set([process.env.PYTHON,'python3','python'].filter(Boolean))]){
  child=cp.spawnSync(exe,[path.join(__dirname,'crc-pe-independent-reference.py')],{input:JSON.stringify(files),encoding:'utf8',timeout:600000,maxBuffer:16*1024*1024,windowsHide:true,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
  if(child.error?.code==='ENOENT')continue;
  assert.ifError(child.error);assert.equal(child.status,0,child.stderr);return JSON.parse(child.stdout);
 }
 throw Error('CRC_PE_INDEPENDENT_PYTHON_REQUIRED');
}
function compare(actual,expected,label){
 assert.equal(actual.accepted,expected.accepted,label+' admission');
 if(!expected.accepted)return;
 for(const field of ['version','codeSha512','exportStatus','layers','ranges','inputs'])
  assert.deepEqual(actual[field],expected[field],label+' '+field);
}
function runProbe(exe,args){
 const p=cp.spawnSync(exe,args,{encoding:'utf8',timeout:180000,maxBuffer:8*1024*1024,windowsHide:true});
 assert.ifError(p.error);assert.equal(p.status,0,p.stdout+p.stderr);return JSON.parse(p.stdout.trim());
}
function invariants(rows,expected){
 const byId=Object.fromEntries(rows.map((row,i)=>[row.id,expected[i]])),base=byId['complete-checker-coverage'];
 rows.forEach((row,i)=>assert.equal(expected[i].accepted,row.accepted,row.id+' expected admission'));
 for(let i=0;i<6;i++){
  const out=byId['checker-code-'+i],role=i===0?'nvme':i<3?'jones':'iso';
  for(const changed of ['ecma182','we','crc32c',role])assert.notEqual(out.layers[changed].digest,base.layers[changed].digest,'selected '+i+'/'+changed);
  for(const stable of ['nvme','jones','iso'].filter(x=>x!==role))assert.equal(out.layers[stable].digest,base.layers[stable].digest,'independent '+i+'/'+stable);
 }
 assert.deepEqual(byId['excluded-checksum-header'],base,'excluded mutable checksum');
 assert.deepEqual(byId['excluded-section-name'],base,'section names excluded');
 assert.notEqual(byId['selected-entry-point-header'].layers.xz.digest,base.layers.xz.digest);
 assert.equal(byId['absent-anchor'].layers.nvme.status,'partial');
 assert.equal(byId['absent-anchor'].layers.jones.status,'unavailable');
 assert.equal(byId['missing-one-function-range'].layers.iso.status,'unavailable');
 assert.equal(byId['missing-ecma-function-range'].layers.nvme.status,'partial');
 assert.deepEqual(byId['dir64-code-relocation'].inputs,byId['dir64-original-value-normalized'].inputs,'relocated operands normalized');
 const combined=byId['complete-checkers-and-exports'];
 assert.equal(combined.exportStatus,'MEASURED');
 for(const id of ['export-direct-target-change','export-forwarder-change']){
  assert.notEqual(byId[id].layers.xz.digest,combined.layers.xz.digest,id+' XZ');
  assert.equal(byId[id].layers.ecma182.digest,combined.layers.ecma182.digest,id+' separate code');
 }
 assert.equal(byId['export-string-invalid-partial'].exportStatus,'UNSUPPORTED_EXPORT_LAYOUT');
 assert.equal(byId['unaligned-multiple-pages-zero-fill'].layers.crc32c.pages,2);
 const multi=byId['multiple-executable-sections-zero-fill'];
 assert.equal(multi.ranges.code.length,2);assert.equal(multi.layers.crc32c.pages,3);
 assert.notEqual(byId['second-executable-section-change'].layers.ecma182.digest,multi.layers.ecma182.digest);
 assert.equal(byId['second-executable-section-change'].layers.nvme.digest,multi.layers.nvme.digest);
 assert.deepEqual(byId['section-table-order-independent-code'].ranges.code,multi.ranges.code);
 assert.equal(byId['section-table-order-independent-code'].layers.ecma182.digest,multi.layers.ecma182.digest);
 assert.notEqual(byId['section-table-order-independent-code'].layers.xz.digest,multi.layers.xz.digest);
 // Negative control: comparator must reject omitted/tampered ranges, input
 // summaries, constants/baseline role, statuses and final digest values.
 for(const edit of [x=>x.ranges.checkers.nvme.pop(),x=>x.inputs.we.sha512='0'.repeat(128),x=>x.layers.iso.status='unavailable',x=>x.layers.nvme.digest='0'.repeat(16),x=>delete x.inputs.crc8_smbus]){
  const bad=structuredClone(base);edit(bad);assert.throws(()=>compare(bad,base,'negative-control'));
 }
}
function main(options={}){
 const probe=options.probe,portable=options.portable===true;
 assert(probe||portable,'Use --probe <actual CrcPeProbe.exe> or --portable-only');
 assert(!(probe&&portable),'CRC_NATIVE_PORTABLE_MODE_CONFLICT');
 if(probe)assert.equal(process.platform,'win32','Actual native mapped-image comparison requires Windows');
 const artifacts=options.artifacts||{};assert(Object.keys(artifacts).every(role=>ARTIFACT_ROLES.includes(role)),'CRC_ARTIFACT_ROLE_INVALID');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'crc-pe-independent-'));
 const inputRows={},artifactResults={},mappedImageRuns=[];
 try{
  const rows=fixtures();
  let nativeProbe;
  if(probe){inputRows.probe=snapshot(probe,path.join(temp,'CrcPeProbe.exe'));nativeProbe=inputRows.probe.snapshot;}
  for(const [i,image] of (options.images||[]).entries()){
   const id='image-'+i;inputRows[id]=snapshot(image,path.join(temp,id+'.exe'));
   rows.push({id,bytes:Read(inputRows[id].snapshot),accepted:true});
  }
  for(const role of ARTIFACT_ROLES.filter(role=>artifacts[role])){
   inputRows[role]=snapshot(artifacts[role],path.join(temp,role+'.exe'));
   rows.push({id:'final-'+role,selectionRole:role,bytes:Read(inputRows[role].snapshot),accepted:true});
  }
  const files=rows.map((row,i)=>{const name=path.join(temp,i+'.bin');fs.writeFileSync(name,row.bytes);return name;});
  const expected=reference(files);assert.equal(expected.length,rows.length);invariants(rows,expected);
  rows.forEach((row,i)=>{if(row.selectionRole){
   artifactResults[row.selectionRole]={selectionRole:row.selectionRole,roleIdentity:'OPERATOR_SELECTED_NOT_VERIFIED',coverage:Object.fromEntries(ROLES.map(role=>[role,expected[i].layers?.[role]?.status||'unavailable'])),nativeDiskComparison:'NOT_RUN'};
   measuredCoverage(expected[i],'selected final '+row.selectionRole);
  }});
  if(probe){
   for(let i=0;i<rows.length;i++){
    compare(runProbe(nativeProbe,['--file',files[i]]),expected[i],rows[i].id);
    if(rows[i].selectionRole)artifactResults[rows[i].selectionRole].nativeDiskComparison='PASS';
   }
   const ownExpected=reference([nativeProbe])[0];measuredCoverage(ownExpected,'actual probe linker coverage');
   // Starts a real MEM_IMAGE process twice; ASLR choices remain OS-controlled.
   // This verifies the mapped measurement, not a simulated native PASS.
   for(let i=0;i<2;i++){compare(runProbe(nativeProbe,['--own']),ownExpected,'mapped-own-image-'+i);mappedImageRuns.push({execution:i+1,comparison:'PASS'});}
  }else{
   const {CodeImage}=require('../services/desktopIntegrity');
   for(let i=0;i<rows.length;i++){
    let actual;try{actual=CodeImage(rows[i].bytes);}catch{actual=null;}
    assert.equal(!!actual,expected[i].accepted,rows[i].id+' server admission');
    if(actual)assert.deepEqual(actual.crcLayers,expected[i].layers,rows[i].id+' independent full server layer parity');
   }
  }
  const inputs=Object.fromEntries(Object.entries(inputRows).map(([id,row])=>[id,finishInput(row)]));
  assert(Object.values(inputs).every(row=>row.unchanged),'CRC_SELECTED_INPUT_CHANGED');
  const finalCount=Object.keys(artifactResults).length;
  const result={status:'PASS',scope:probe?'WINDOWS_NATIVE_CRC_FULL_PE':'PORTABLE_REFERENCE_SERVER_ONLY',cases:rows.length,independentRoles:ROLES,
   selectedRangeComparison:probe?'PASS':'NOT_RUN',nativeMappedImageComparison:probe?'PASS':'NOT_RUN',nativeDiskComparison:probe?'PASS':'NOT_RUN',
   nativeExecutions:probe?rows.length+2:0,mappedImageRuns,artifactComparisons:(options.images||[]).length+finalCount,
   finalArtifactComparison:probe&&finalCount?finalCount===3?'PASS':'PARTIAL':'NOT_RUN',finalArtifacts:artifactResults,inputs,inputsUnchanged:true,
   reference:'independent Python PE structs + integer SHA-512 + bitwise CRC9',approvalCreated:false};
  console.log(JSON.stringify(result));return result;
 }catch(error){
  const inputs=Object.fromEntries(Object.entries(inputRows).map(([id,row])=>[id,finishInput(row)]));
  error.crcReport={status:'FAIL',error:String(error.message).slice(0,1000),nativeMappedImageComparison:mappedImageRuns.length===2?'PASS':'NOT_RUN',mappedImageRuns,
   finalArtifactComparison:Object.keys(artifacts).length?'FAIL':'NOT_RUN',finalArtifacts:artifactResults,inputs,inputsUnchanged:Object.values(inputs).every(row=>row.unchanged),approvalCreated:false};
  throw error;
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
function saveReport(options,value){
 const out=safeOutput(options.out,options);
 if(!out)return;
 // Replace a report without following a late-created symlink at its path.
 const temporary=out+'.'+crypto.randomUUID()+'.tmp';
 try{fs.writeFileSync(temporary,JSON.stringify({...value,completedAt:new Date().toISOString()},null,2)+'\n',{flag:'wx',mode:0o600});fs.renameSync(temporary,out);}
 finally{fs.rmSync(temporary,{force:true});}
}
function execute(options){
 // Guard before the first RUNNING write and recheck before each replacement.
 safeOutput(options.out,options);
 try{
  saveReport(options,{status:'RUNNING',nativeMappedImageComparison:'NOT_RUN',finalArtifactComparison:'NOT_RUN',approvalCreated:false});
  const result=main(options);saveReport(options,result);return result;
 }catch(e){
  saveReport(options,e.crcReport||{status:'FAIL',error:String(e.message).slice(0,1000),nativeMappedImageComparison:'NOT_RUN',finalArtifactComparison:'NOT_RUN',approvalCreated:false});throw e;
 }
}
if(require.main===module){
 const args=process.argv.slice(2);let options;
 try{options=parseArgs(args);execute(options);}catch(e){
  if(!options){const rejected=rejectedArguments(args);if(rejected?.out)try{saveReport(rejected,{status:'FAIL',error:String(e.message).slice(0,1000),nativeMappedImageComparison:'NOT_RUN',finalArtifactComparison:'NOT_RUN',approvalCreated:false});}catch{}}
  console.error(e);process.exitCode=1;
 }
}
module.exports={main,reference,compare,ROLES,ARTIFACT_ROLES,parseArgs,safeOutput,snapshot,finishInput,measuredCoverage,execute,saveReport,rejectedArguments};
