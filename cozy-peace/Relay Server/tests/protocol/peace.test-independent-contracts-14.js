'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Independent Python integer SHA-512/nine bitwise CRCs + struct-based PE reference. No Node
// implementation is fed back as an expected result. Native execution is separate.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),path=require('node:path'),fs=require('node:fs'),os=require('node:os'),cp=require('node:child_process');
const integrity=require("../../services/integrity/peace.desktop-integrity"),protocol=require("../../services/protocol/peace.desktop-request-protocol"),delegation=require("../../services/bootstrap/peace.desktop-handoff-delegation");
const crc=require("../../services/cryptography/peace.crc-layers"),{ExportTable}=require("../../services/artifacts/peace.desktop-pe-exports");
const {crcTestFixture}=require("../fixtures/runtime/peace.crc-test-fixture"),{Fixture:exportFixture}=require("../artifacts/peace.test-desktop-pe-exports");
const corpus=require("../../contracts/artifacts/pe-corpus-v1.json"),handoff=require("../../../Railway/Cozy.Tests/Cozy.Handoff/Cozy.HandoffV3Vector.json");
const lengths=[0,1,2,3,7,15,16,31,32,55,56,63,64,65,111,112,113,127,128,129,255,256,257,511,512,513,1023,1024,1025,2048,4097];
const hashes=lengths.map(n=>Buffer.from(Array.from({length:n},(_,i)=>(i*131+n*17)%256)));hashes.push(Buffer.from('123456789'),Buffer.from('abc'),Buffer.from('UTF-8: 한글 😀\n'));
const bodies=[{}, {b:2,a:1}, {a:[true,null,-1,9007199254740991],z:{b:'\u0000\n"',a:'한글'}},{'😀':'astral','\ue000':'bmp',a:false}, {requestId:'TEST_ID_001',requestVersion:2,licenseId:'DL-1234'}, {'a':{'c':[3,2,1]},'2':'numeric','1':'first'}];
const protocols=Object.keys(protocol.catalog).flatMap(purpose=>bodies.map(body=>({purpose,body})));
// Reuse only synthetic bytes, never production-generated expected digests.
const peCases=corpus.cases.map(row=>({...row}));
function add(id,source,edit=()=>{},accepted=true,exportStatus){const bytes=Buffer.from(source);edit(bytes);peCases.push({id,bytes:bytes.toString('base64'),accepted,exportStatus});}
const checker=crcTestFixture(),exp=exportFixture(),opt=0x98,sectionTable=0x188;
add('checker-complete',checker);
add('checker-code-change',checker,b=>{b[0x421]^=1;});
add('checker-absent',checker,b=>b.fill(0,0x600,0x610));
add('checker-partial-unwind',checker,b=>b.writeUInt32LE(0x1061,0x824));
add('checker-no-unwind',checker,b=>b.fill(0,opt+136,opt+144));
add('checker-shared-span-deduplicated',checker,b=>b.writeBigUInt64LE(0x140001020n,0x628));
add('checker-readable-writable-anchor',checker,b=>b.writeUInt32LE(0xc0000040,sectionTable+40+36));
for(const [name,edit] of [
 ['duplicate-anchor',b=>b.copy(b,0x680,0x600,0x648)],
 ['anchor-version',b=>b.writeUInt32LE(2,0x610)],
 ['anchor-count',b=>b.writeUInt32LE(7,0x614)],
 ['target-data',b=>b.writeBigUInt64LE(0x140002080n,0x618)],
 ['target-overflow',b=>b.writeBigUInt64LE(0xffffffffffffffffn,0x618)],
 ['relocation-wrong-kind',b=>b.writeUInt16LE(0x3018,0xa08)],
 ['relocation-missing',b=>b.writeUInt16LE(0,0xa08)],
 ['relocation-duplicate',b=>b.writeUInt16LE(0xa018,0xa0a)],
 ['relocation-overlap',b=>b.writeUInt16LE(0xa019,0xa08)],
 ['relocation-writable',b=>b.writeUInt32LE(0xc0000040,sectionTable+3*40+36)],
 ['unwind-misaligned',b=>b.writeUInt32LE(0x2101,0x808)],
 ['pdata-overlap',b=>b.writeUInt32LE(0x101f,0x80c)],
 ['pdata-writable',b=>b.writeUInt32LE(0xc0000040,sectionTable+2*40+36)],
])add('checker-reject-'+name,checker,edit,false);
add('exports-direct-forwarded',exp,()=>{},true,'MEASURED');
add('exports-eat-redirect',exp,b=>b.writeUInt32LE(4100,1064),true,'MEASURED');
add('exports-forwarder-change',exp,b=>{b[1128]^=1;},true,'MEASURED');
add('exports-zero-target',exp,b=>b.writeUInt32LE(0,1064),true,'MEASURED');
add('exports-no-names',exp,b=>b.writeUInt32LE(0,1048),true,'MEASURED');
for(const [name,edit] of [
 ['span-limit',b=>b.writeUInt32LE(0xffffffff,opt+116)],
 ['function-count-limit',b=>b.writeUInt32LE(131073,1044)],
 ['names-over-functions',b=>b.writeUInt32LE(3,1048)],
 ['target-outside-image',b=>b.writeUInt32LE(0x3000,1064)],
 ['name-array-outside',b=>b.writeUInt32LE(0x2200,1056)],
 ['ordinal-range',b=>b.writeUInt16LE(2,1080)],
 ['dll-name-empty',b=>{b[1088]=0;}],
 ['dll-name-nonascii',b=>{b[1088]=255;}],
 ['forwarder-space',b=>{b[1128]=32;}],
 ['name-unterminated',b=>b.fill(65,1104,1280)],
 ['writable-export-section',b=>b.writeUInt32LE(0xc0000040,sectionTable+40+36)],
 ['relocation-in-export',b=>{b.writeUInt32LE(0x21c0,opt+152);b.writeUInt32LE(10,opt+156);b.writeUInt32LE(0x2000,1472);b.writeUInt32LE(10,1476);b.writeUInt16LE(0xa000,1480);}]
])add('exports-unsupported-'+name,exp,edit,true,'UNSUPPORTED_EXPORT_LAYOUT');
// One image has both complete checker coverage and measured exports.
const combined=Buffer.from(checker);combined.writeUInt32LE(0x2050,opt+112);combined.writeUInt32LE(0xb0,opt+116);
for(const [offset,value] of [[12,0x20a0],[16,1],[20,2],[24,2],[28,0x2078],[32,0x2080],[36,0x2088]])combined.writeUInt32LE(value,0x650+offset);
combined.writeUInt32LE(0x1000,0x678);combined.writeUInt32LE(0x20d0,0x67c);combined.writeUInt32LE(0x20b0,0x680);combined.writeUInt32LE(0x20c0,0x684);combined.writeUInt16LE(0,0x688);combined.writeUInt16LE(1,0x68a);
for(const [at,text] of [[0x6a0,'combined.dll\0'],[0x6b0,'Direct\0'],[0x6c0,'Forward\0'],[0x6d0,'MODULE.Target\0']])combined.write(text,at,'ascii');
add('checker-and-export-complete',combined,()=>{},true,'MEASURED');
// Non-aligned code pages cross 4 KiB while retaining zero-fill normalization.
const paged=Buffer.from(checker);paged.writeUInt32LE(0x1008,sectionTable+8);paged.writeUInt32LE(0x1ff8,sectionTable+12);
paged.writeUInt32LE(0x5000,sectionTable+40+12);paged.writeUInt32LE(0x6000,sectionTable+80+12);paged.writeUInt32LE(0x7000,sectionTable+120+12);paged.writeUInt32LE(0x8000,opt+56);
paged.fill(0,opt+136,opt+144);paged.fill(0,opt+152,opt+160);paged.fill(0,0x600,0x610);
add('unaligned-multiple-page-zero-fill',paged);
// File digests also come from Python, so an actual Delphi probe is never
// compared against the production Node hashing code as its only oracle.
const referenceHashes=hashes.concat(peCases.map(row=>Buffer.from(row.bytes,'base64')));
const pageInputs=[[[0x1000,4096]],[[0x1fff,8193]],[[0x1800,0x1801]],[[0x1001,17],[0x3000,4097]]].map(sections=>{
 const prefix=Buffer.from('GAME-CODE-V1\0'),head=Buffer.alloc(prefix.length+4);prefix.copy(head);head.writeUInt32LE(sections.length,prefix.length);
 return Buffer.concat([head,...sections.flatMap(([rva,size])=>{const meta=Buffer.alloc(8),bytes=Buffer.alloc(size);meta.writeUInt32LE(rva);meta.writeUInt32LE(size,4);for(let i=0;i<size;i++)bytes[i]=(i*29+size)%256;return[meta,bytes];})]);
});
const payload={hashes:referenceHashes.map(x=>x.toString('base64')),pe:peCases.map(x=>x.bytes),crcPages:pageInputs.map(x=>x.toString('base64')),protocols,handoff};
let result,executable;
for(const python of [...new Set([process.env.PYTHON,'python3','python'].filter(Boolean))]){
 const p=cp.spawnSync(python,[path.join(MODULE_RESOURCE_ROOT,"protocol/independent-contract-reference.py")],{input:JSON.stringify(payload),encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});
 if(p.error?.code==='ENOENT')continue;result=p;executable=python;break;
}
assert(result,'REFERENCE_PYTHON_UNAVAILABLE');assert.equal(result.status,0,result.stderr||result.error?.message);const independent=JSON.parse(result.stdout);
assert.equal(independent.hashes.length,referenceHashes.length);
referenceHashes.forEach((bytes,i)=>{assert.equal(independent.hashes[i].sha512,crypto.createHash('sha512').update(bytes).digest('hex'),'sha512 '+bytes.length);assert.equal(independent.hashes[i].crc64,integrity.Crc64(bytes),'crc64 '+bytes.length);for(const kind of Object.keys(crc.registry)){assert.equal(independent.hashes[i].crcs[kind],crc.crcHex(kind,bytes),kind+' '+bytes.length);}});
assert.equal(independent.hashes[31].crc64,'6C40DF5F0B497347');
assert.deepEqual(independent.hashes[31].crcs,{ecma182:'6C40DF5F0B497347',nvme:'AE8B14860A799888',jones:'CAA717168609F281',xz:'995DC9BBDF1939FA',we:'62EC59E3F1A4F00A',iso:'B90956C775A41001',crc32c:'E3069283',crc16_arc:'BB3D',crc8_smbus:'F4'});
assert.deepEqual(independent.crcConstants,{parameters:crc.crcHex('we',crc.parameterBytes()),tables:crc.crcHex('we',crc.allTableBytes())});
assert.equal(independent.crcPageManifests.length,pageInputs.length);
pageInputs.forEach((value,i)=>assert.equal(independent.crcPageManifests[i],crc.codePageManifest(value).toString('hex').toUpperCase(),'Python page manifest '+i));
assert.equal(independent.pe.length,peCases.length);assert.equal(independent.exports.length,peCases.length);
const exportFields=['status','sha512','crc64','directoryOffset','rva','span','exportCount','codeExportCount','forwardedExportCount'];
peCases.forEach((row,i)=>{
 const bytes=Buffer.from(row.bytes,'base64');let actual;
 try{const c=integrity.CodeImage(bytes);actual={accepted:true,codeSha512:c.sha512,codeCrc64:c.crc64,crcLayers:c.crcLayers,checkerStatus:crc.checkerPlan(bytes).status};}catch(_){actual={accepted:false};}
 assert.deepEqual(independent.pe[i],actual,row.id);assert.equal(independent.pe[i].accepted,row.accepted,row.id+' stored decision');
 if(row.codeSha512){assert.equal(independent.pe[i].codeSha512,row.codeSha512);assert.equal(independent.pe[i].codeCrc64,row.codeCrc64);}
 const measured=ExportTable(bytes),selected=Object.fromEntries(exportFields.filter(k=>Object.hasOwn(measured,k)).map(k=>[k,measured[k]]));
 assert.deepEqual(independent.exports[i],selected,row.id+' independent export');if(row.exportStatus)assert.equal(independent.exports[i].status,row.exportStatus,row.id+' stored export status');
});
const measuredById=id=>independent.pe[peCases.findIndex(row=>row.id===id)];
const baseChecker=measuredById('checker-complete'),changedChecker=measuredById('checker-code-change');
assert.notEqual(baseChecker.crcLayers.jones.digest,changedChecker.crcLayers.jones.digest);
assert.equal(baseChecker.crcLayers.nvme.digest,changedChecker.crcLayers.nvme.digest);assert.equal(baseChecker.crcLayers.iso.digest,changedChecker.crcLayers.iso.digest);
const direct=measuredById('exports-direct-forwarded'),redirect=measuredById('exports-eat-redirect');
assert.equal(direct.codeSha512,redirect.codeSha512);assert.notEqual(direct.crcLayers.xz.digest,redirect.crcLayers.xz.digest);
assert.equal(measuredById('checker-and-export-complete').checkerStatus,'measured');
assert.equal(measuredById('checker-partial-unwind').checkerStatus,'partial');
assert.equal(measuredById('checker-absent').checkerStatus,'unavailable');
assert.equal(measuredById('unaligned-multiple-page-zero-fill').crcLayers.crc32c.pages,2);
protocols.forEach((v,i)=>assert.equal(independent.protocols[i],protocol.Fingerprint(v.purpose,v.body),'purpose '+v.purpose));
for(const name of ['claimSha512','delegationCanonical','claimCanonical'])assert.equal(independent.handoff[name],handoff[name],name);
assert.equal(delegation.Canonical('DELEGATION',handoff.role,handoff.claim,handoff.childKeyId,handoff.nonce),independent.handoff.delegationCanonical);assert.equal(delegation.Canonical('CLAIM',handoff.role,handoff.claim,handoff.childKeyId,handoff.nonce),independent.handoff.claimCanonical);
// Optional actual Win64 threaded probe: no stdout fixture can silently count as a run.
const nativeIndex=process.argv.indexOf('--native');let nativeExecuted=false;
if(nativeIndex>=0){const target=process.argv[nativeIndex+1];assert(target&&fs.existsSync(target),'NATIVE_PROBE_REQUIRED');const p=cp.spawnSync(path.resolve(target),[],{encoding:'utf8',timeout:120000});assert.equal(p.status,0,p.stderr||p.stdout);const r=JSON.parse(p.stdout.trim());assert.equal(r.status,'PASS');assert.deepEqual(r.observedTransitionMasks,[18,20,24,16,32,0]);assert.equal(r.stateChecks,36);assert.equal(r.scheduleChecks,512);assert.equal(r.gpuExecuted,false);nativeExecuted=true;}
function actualWin64Probe(index,kind){
 const supplied=process.argv[index+1];assert(supplied&&!supplied.startsWith('--'),'NATIVE_'+kind+'_PROBE_REQUIRED');
 const target=path.resolve(supplied);assert(fs.existsSync(target)&&fs.statSync(target).isFile(),'NATIVE_'+kind+'_PROBE_REQUIRED');
 assert.equal(process.platform,'win32','NATIVE_'+kind+'_PROBE_REQUIRES_ACTUAL_WINDOWS');
 const header=Buffer.alloc(4096),handle=fs.openSync(target,'r');let headerSize;
 try{headerSize=fs.readSync(handle,header,0,header.length,0);}finally{fs.closeSync(handle);}
 assert(headerSize>=64&&header.readUInt16LE(0)===0x5a4d,'NATIVE_'+kind+'_PROBE_IMAGE_REQUIRED');
 const peOffset=header.readUInt32LE(60);
 assert(peOffset>=64&&peOffset+24<=headerSize&&header.readUInt32LE(peOffset)===0x4550&&header.readUInt16LE(peOffset+4)===0x8664,'NATIVE_'+kind+'_PROBE_AMD64_REQUIRED');
 return target;
}
// cozy.PeCorpusProbe accepts ONE file path and emits ONE JSON object. It reads PE
// bytes only; fixtures are never LoadLibrary/CreateProcess targets themselves.
// This is separate from --native, whose contract is the threaded state probe.
const nativePeIndex=process.argv.indexOf('--native-pe');let nativePeCrcCompared=false,nativePeVectors=0,nativeExportVectors=0;
if(nativePeIndex>=0){
 // The option must point at an AMD64 PE, not a script/stdout fixture.
 const target=actualWin64Probe(nativePeIndex,'PE');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-independent-native-pe-'));
 try{
  for(let i=0;i<peCases.length;i++){
   const row=peCases[i],expected=independent.pe[i],expectedExport=independent.exports[i],expectedFile=independent.hashes[hashes.length+i];
   const file=path.join(temp,String(i).padStart(3,'0')+'.pe');fs.writeFileSync(file,Buffer.from(row.bytes,'base64'),{flag:'wx'});
   const run=cp.spawnSync(target,[file],{encoding:'utf8',timeout:35000,maxBuffer:1024*1024,windowsHide:true});
   if(run.error)throw run.error;
   assert.equal(run.signal,null,row.id+' native probe signal');
   let actual;try{actual=JSON.parse(run.stdout.trim());}catch(_){assert.fail(row.id+' native probe did not return one JSON object (exit '+run.status+'): '+(run.stderr||run.stdout).slice(0,2048));}
   assert(actual&&typeof actual==='object'&&!Array.isArray(actual)&&typeof actual.accepted==='boolean',row.id+' native probe schema');
   assert.equal(actual.accepted,expected.accepted,row.id+' Python/Delphi accepted');
   // A structured rejection is a valid negative test, not a native crash.
   // cozy.PeCorpusProbe currently exits 0; also permit conventional exit 1 ONLY
   // with the matching accepted:false/errorClass result. All other failures
   // (signals, timeout, access violations, malformed JSON) stay failures.
   if(!actual.accepted){
    assert.equal(typeof actual.errorClass,'string',row.id+' rejection error class');assert(actual.errorClass.length>0,row.id+' empty rejection error class');
    assert(run.status===0||run.status===1,row.id+' native rejection process exit '+run.status);
   }else{
    assert.equal(run.status,0,row.id+' native process exit: '+run.stderr);
    for(const field of ['codeSha512','codeCrc64'])assert.equal(actual[field],expected[field],row.id+' Python/Delphi '+field);
    assert.equal(actual.fileSha512,expectedFile.sha512,row.id+' Python/Delphi fileSha512');
    assert.equal(actual.fileCrc64,expectedFile.crc64,row.id+' Python/Delphi fileCrc64');
    assert.equal(actual.exportStatus,expectedExport.status,row.id+' Python/Delphi exportStatus');
    if(expectedExport.status==='MEASURED'){
     assert.equal(actual.exportSha512,expectedExport.sha512,row.id+' Python/Delphi exportSha512');
     assert.equal(actual.exportCrc64,expectedExport.crc64,row.id+' Python/Delphi exportCrc64');nativeExportVectors++;
    }else{
     assert(!Object.hasOwn(actual,'exportSha512')&&!Object.hasOwn(actual,'exportCrc64'),row.id+' unmeasured export digest must not be reported');
    }
   }
   nativePeVectors++;
  }
  nativePeCrcCompared=true;
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
// cozy.CrcProbe prints the nine named primitive checksums, then parameters/tables
// as CRC64/WE checksums. Its --pages mode prints an exact framed byte stream.
// None of these measurements claims native PE checker/auxiliary coverage.
const nativeCrcIndex=process.argv.indexOf('--native-crc');
let nativeCrcPrimitiveCompared=false,nativeCrcVectors=0,nativeCrcComparisons=0,nativeCrcPageVectors=0,nativeCrcConstantsCompared=false;
if(nativeCrcIndex>=0){
 const target=actualWin64Probe(nativeCrcIndex,'CRC'),temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-independent-native-crc-'));
 const names={ecma182:'CRC-64/ECMA-182',nvme:'CRC-64/NVME',jones:'CRC-64/JONES',xz:'CRC-64/XZ',we:'CRC-64/WE',iso:'CRC-64/GO-ISO',crc32c:'CRC-32/ISCSI',crc16_arc:'CRC-16/ARC',crc8_smbus:'CRC-8/SMBUS'};
 const allowed=[...Object.values(names),'parameters','tables'].sort();
 function invoke(args,label){
  const run=cp.spawnSync(target,args,{encoding:'utf8',timeout:35000,maxBuffer:1024*1024,windowsHide:true});if(run.error)throw run.error;
  assert.equal(run.signal,null,label+' native CRC signal');assert.equal(run.status,0,label+' native CRC exit: '+(run.stderr||run.stdout).slice(0,2048));
  return run.stdout.trim();
 }
 try{
  for(let i=0;i<hashes.length;i++){
   const file=path.join(temp,String(i).padStart(3,'0')+'.bin');fs.writeFileSync(file,hashes[i],{flag:'wx'});
   const output=invoke([file],'vector '+i),values=new Map();
   for(const line of output.split(/\r?\n/)){const match=/^([^=]+)=([0-9A-F]+)$/.exec(line);assert(match,'NATIVE_CRC_OUTPUT_INVALID');assert(!values.has(match[1]),'NATIVE_CRC_OUTPUT_DUPLICATE');values.set(match[1],match[2]);}
   assert.deepEqual([...values.keys()].sort(),allowed,'native CRC output field set');
   for(const [kind,name] of Object.entries(names)){assert.equal(values.get(name),independent.hashes[i].crcs[kind],'Python/Delphi '+kind+' vector '+i);nativeCrcComparisons++;}
   assert.equal(values.get('parameters'),independent.crcConstants.parameters,'Python/Delphi parameter constants');
   assert.equal(values.get('tables'),independent.crcConstants.tables,'Python/Delphi lookup tables');nativeCrcVectors++;
  }
  nativeCrcConstantsCompared=true;
  for(let i=0;i<pageInputs.length;i++){
   const file=path.join(temp,'pages-'+i+'.bin');fs.writeFileSync(file,pageInputs[i],{flag:'wx'});
   assert.equal(invoke(['--pages',file],'pages '+i),'pages='+independent.crcPageManifests[i],'Python/Delphi framed page manifest '+i);nativeCrcPageVectors++;
  }
  nativeCrcPrimitiveCompared=true;
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
// Floating-point numbers have their own exact-rational oracle; do not send
// JS-serialized numbers to the integer-only PE/hash reference as expectations.
const nativeJsonIndex=process.argv.indexOf('--native-json'),floatArgs=[path.join(MODULE_RESOURCE_ROOT,"cryptography/peace.test-float-canonicalization-14.js")];
if(nativeJsonIndex>=0){const supplied=process.argv[nativeJsonIndex+1];assert(supplied&&!supplied.startsWith('--'),'NATIVE_JSON_PROBE_REQUIRED');floatArgs.push('--native-json',supplied);}
const floatRun=cp.spawnSync(process.execPath,floatArgs,{encoding:'utf8',timeout:180000,maxBuffer:4*1024*1024});
if(floatRun.error)throw floatRun.error;
assert.equal(floatRun.status,0,floatRun.stderr||floatRun.stdout);const floats=JSON.parse(floatRun.stdout);
assert.equal(floats.suite,'FLOAT_CANONICALIZATION_14');assert.equal(floats.status,'PASS');assert.equal(floats.floatCanonicalizationCompared,true);
const nativeScopes=[];if(nativeExecuted)nativeScopes.push('STATE_TRANSITIONS');if(nativePeCrcCompared)nativeScopes.push('PE_SHA512_CRC64');if(nativeCrcPrimitiveCompared)nativeScopes.push('CRC9_PRIMITIVES_CONSTANTS_PAGES');if(floats.nativeExecuted)nativeScopes.push('FLOAT_JSON_WIRE_CANONICAL');
const nativeReferenceScope=nativeScopes.length?nativeScopes.join('_AND_'):'NOT_RUN';
console.log(JSON.stringify({suite:'INDEPENDENT_CONTRACTS_14',python:executable,hashVectors:hashes.length,peFileHashVectors:peCases.length,crcVariants:9,peVectors:peCases.length,exportVectors:independent.exports.length,auxiliaryCrcVectors:independent.pe.filter(row=>row.accepted).length,protocolVectors:protocols.length,handoffVectors:1,sha512Reference:'PURE_PYTHON_INTEGER_NOT_OPENSSL',crcReference:'BIT_AT_A_TIME_NOT_TABLE',peReference:'PYTHON_STRUCT_INDEPENDENT',nativeExecuted:nativeExecuted||nativePeCrcCompared||nativeCrcPrimitiveCompared||floats.nativeExecuted,nativeStateExecuted:nativeExecuted,nativeReferenceScope,nativePeCrcCompared,nativePeOutcome:nativePeCrcCompared?'PASS':'NOT_RUN',nativePeVectors,nativeExportVectors,nativeCrcPrimitiveCompared,nativeCrcPrimitiveOutcome:nativeCrcPrimitiveCompared?'PASS':'NOT_RUN',nativeCrcVariants:nativeCrcPrimitiveCompared?9:0,nativeCrcVectors,nativeCrcComparisons,nativeCrcConstantsCompared,nativeCrcPageVectors,nativeAuxiliaryCrcCompared:false,auxiliaryExportCrcCompared:true,floatCanonicalizationCompared:true,floatCases:floats.cases,floatProtocolVectors:floats.protocolVectors,floatRejections:floats.rejections,floatFormatterOnlyVectors:floats.formatterOnlyVectors,floatReference:floats.numericOracle,nativeFloatOutcome:floats.nativeOutcome,nativeFloatVectors:floats.nativeVectors,status:'PASS'}));
