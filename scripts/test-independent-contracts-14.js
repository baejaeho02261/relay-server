'use strict';
// Independent Python integer SHA-512/CRC64 + struct-based PE reference. No Node
// implementation is fed back as an expected result. Native execution is separate.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),path=require('node:path'),fs=require('node:fs'),cp=require('node:child_process');
const integrity=require('../services/desktopIntegrity'),protocol=require('../services/desktopRequestProtocol'),delegation=require('../services/desktopHandoffDelegation');
const corpus=require('../contracts/pe-corpus-v1.json'),handoff=require('../../GameConnect_Win64/tests/HandoffV3Vector.json');
const lengths=[0,1,2,3,7,15,16,31,32,55,56,63,64,65,111,112,113,127,128,129,255,256,257,511,512,513,1023,1024,1025,2048,4097];
const hashes=lengths.map(n=>Buffer.from(Array.from({length:n},(_,i)=>(i*131+n*17)%256)));hashes.push(Buffer.from('123456789'),Buffer.from('abc'),Buffer.from('UTF-8: 한글 😀\n'));
const bodies=[{}, {b:2,a:1}, {a:[true,null,-1,9007199254740991],z:{b:'\u0000\n"',a:'한글'}},{'😀':'astral','\ue000':'bmp',a:false}, {requestId:'TEST_ID_001',requestVersion:2,licenseId:'DL-1234'}, {'a':{'c':[3,2,1]},'2':'numeric','1':'first'}];
const protocols=Object.keys(protocol.catalog).flatMap(purpose=>bodies.map(body=>({purpose,body})));
const payload={hashes:hashes.map(x=>x.toString('base64')),pe:corpus.cases.map(x=>x.bytes),protocols,handoff};
let result,executable;
for(const python of [...new Set([process.env.PYTHON,'python3','python'].filter(Boolean))]){
 const p=cp.spawnSync(python,[path.join(__dirname,'independent-contract-reference.py')],{input:JSON.stringify(payload),encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});
 if(p.error?.code==='ENOENT')continue;result=p;executable=python;break;
}
assert(result,'REFERENCE_PYTHON_UNAVAILABLE');assert.equal(result.status,0,result.stderr||result.error?.message);const independent=JSON.parse(result.stdout);
assert.equal(independent.hashes.length,hashes.length);
hashes.forEach((bytes,i)=>{assert.equal(independent.hashes[i].sha512,crypto.createHash('sha512').update(bytes).digest('hex'),'sha512 '+bytes.length);assert.equal(independent.hashes[i].crc64,integrity.Crc64(bytes),'crc64 '+bytes.length);});
assert.equal(independent.hashes[31].crc64,'6C40DF5F0B497347');
corpus.cases.forEach((row,i)=>{let actual;try{const c=integrity.CodeImage(Buffer.from(row.bytes,'base64'));actual={accepted:true,codeSha512:c.sha512,codeCrc64:c.crc64};}catch(_){actual={accepted:false};}assert.deepEqual(independent.pe[i],actual,row.id);assert.equal(independent.pe[i].accepted,row.accepted,row.id+' stored decision');if(row.accepted){assert.equal(independent.pe[i].codeSha512,row.codeSha512);assert.equal(independent.pe[i].codeCrc64,row.codeCrc64);}});
protocols.forEach((v,i)=>assert.equal(independent.protocols[i],protocol.Fingerprint(v.purpose,v.body),'purpose '+v.purpose));
for(const name of ['claimSha512','delegationCanonical','claimCanonical'])assert.equal(independent.handoff[name],handoff[name],name);
assert.equal(delegation.Canonical('DELEGATION',handoff.role,handoff.claim,handoff.childKeyId,handoff.nonce),independent.handoff.delegationCanonical);assert.equal(delegation.Canonical('CLAIM',handoff.role,handoff.claim,handoff.childKeyId,handoff.nonce),independent.handoff.claimCanonical);
// Optional actual Win64 threaded probe: no stdout fixture can silently count as a run.
const nativeIndex=process.argv.indexOf('--native');let nativeExecuted=false;
if(nativeIndex>=0){const target=process.argv[nativeIndex+1];assert(target&&fs.existsSync(target),'NATIVE_PROBE_REQUIRED');const p=cp.spawnSync(path.resolve(target),[],{encoding:'utf8',timeout:120000});assert.equal(p.status,0,p.stderr||p.stdout);const r=JSON.parse(p.stdout.trim());assert.equal(r.status,'PASS');assert.deepEqual(r.observedTransitionMasks,[18,20,24,16,32,0]);assert.equal(r.stateChecks,36);assert.equal(r.scheduleChecks,512);assert.equal(r.gpuExecuted,false);nativeExecuted=true;}
console.log(JSON.stringify({suite:'INDEPENDENT_CONTRACTS_14',python:executable,hashVectors:hashes.length,peVectors:corpus.cases.length,protocolVectors:protocols.length,handoffVectors:1,sha512Reference:'PURE_PYTHON_INTEGER_NOT_OPENSSL',crcReference:'BIT_AT_A_TIME_NOT_TABLE',peReference:'PYTHON_STRUCT_INDEPENDENT',nativeExecuted,auxiliaryExportCrcCompared:false,floatCanonicalizationCompared:false,status:'PASS'}));
