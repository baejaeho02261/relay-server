'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Differential test only. Expected numeric bits, canonical bytes and digests
// originate in Python's exact rational / pure-integer SHA-512 test oracle.
// No production serializer output is supplied as its expected answer.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),cp=require('node:child_process');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const protocol=require("../../services/protocol/peace.desktop-request-protocol"),strict=require("../../services/protocol/peace.strict-json");
const reference=path.join(MODULE_RESOURCE_ROOT,"cryptography/float-canonical-reference.py");
let python;
function oracle(args=[],input){
 for(const target of python?[python]:[...new Set([process.env.PYTHON,'python3','python'].filter(Boolean))]){
  const run=cp.spawnSync(target,[reference,...args],{input:input===undefined?undefined:JSON.stringify(input),encoding:'utf8',timeout:60000,maxBuffer:16*1024*1024,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
  if(run.error?.code==='ENOENT'&&!python)continue;
  if(run.error)throw run.error;
  assert.equal(run.status,0,run.stderr||'FLOAT_REFERENCE_FAILED');python=target;return JSON.parse(run.stdout);
 }
 assert.fail('FLOAT_REFERENCE_PYTHON_UNAVAILABLE');
}
function bits(value){const bytes=Buffer.alloc(8);bytes.writeDoubleBE(value);return bytes.toString('hex');}
function sha(bytes){return crypto.createHash('sha512').update(bytes).digest('hex');}
function compare(raw,expected,label){
 let actual,error;try{actual=strict.Parse(Buffer.from(raw,'utf8'));}catch(e){error=e;}
 assert.equal(!error,expected.accepted,label+' protocol acceptance');
 if(!expected.accepted)return;
 const canonical=protocol.Stable(actual),bytes=Buffer.from(canonical,'utf8');
 assert.equal(canonical,expected.canonical,label+' canonical text');
 assert.equal(bytes.toString('hex'),expected.canonicalHex,label+' exact UTF-8 bytes');
 assert.equal(sha(bytes),expected.canonicalSha512,label+' independent canonical SHA-512');
 assert.equal(sha(Buffer.from(raw,'utf8')),expected.wireSha512,label+' independent raw SHA-512');
 assert.equal(protocol.Fingerprint('bootstrap.begin',actual),expected.fingerprint,label+' actual receipt fingerprint');
 if(expected.bits)assert.equal(bits(actual.n),expected.bits,label+' independently rounded binary64');
 return actual;
}
const generated=oracle();
assert.equal(generated.version,1);assert.equal(generated.oracle,'EXACT_RATIONAL_BINARY64_SHORTEST_INTERVAL');
const cases=generated.cases;assert(cases.length>=400,'FLOAT_CORPUS_TRUNCATED');
assert.equal(new Set(cases.map(row=>row.id)).size,cases.length,'FLOAT_CORPUS_DUPLICATE');
let protocolVectors=0,rejections=0,formatterOnlyVectors=0,numberFormattingVectors=0;
for(const row of cases){
 compare(row.raw,row,row.id);
 if(row.accepted)protocolVectors++;else rejections++;
 if(row.formatBits){
  const number=Buffer.from(row.formatBits,'hex').readDoubleBE();
  assert(Number.isFinite(number),row.id+' nonfinite must be explicitly unsupported');
  assert.equal(JSON.stringify(number),row.numberText,row.id+' actual JS number formatting');
  assert.equal(protocol.Stable({n:number}),'{"n":'+row.numberText+'}',row.id+' actual Stable formatting');
  numberFormattingVectors++;
  if(!row.accepted){assert.equal(row.scope,'FORMAT_ONLY_PROTOCOL_REJECTED');formatterOnlyVectors++;}
 }
}
// Non-JSON JavaScript values are outside this wire contract. JSON.stringify
// would map these to null; that behavior must never count as numeric parity.
for(const token of ['NaN','Infinity','-Infinity'])assert.throws(()=>strict.Parse('{"n":'+token+'}'));
const categories=Object.fromEntries([...new Set(cases.map(row=>row.category))].map(key=>[key,cases.filter(row=>row.category===key).length]));
for(const category of ['ROUNDING_TIE','DECIMAL_NEIGHBOR','BINARY_BOUNDARY','SEEDED_BITS','INVALID','NESTED'])assert(categories[category]>0);
// A fractional primitive is accepted by the JSON boundary, while actual
// action-specific schemas remain responsible for validating each field.
assert.equal(strict.Parse('{"n":1.5}').n,1.5);
assert.throws(()=>protocol.RequestId(strict.Parse('{"requestVersion":1.5}')),/INPUT_INVALID/);

let nativeExecuted=false,nativeVectors=0,nativeWireVectors=0,nativeRejections=0;
const nativeIndex=process.argv.indexOf('--native-json');
const unknown=process.argv.slice(2).filter((arg,index,list)=>arg!=='--native-json'&&list[index-1]!=='--native-json');
assert.equal(unknown.length,0,'FLOAT_TEST_ARGUMENT_INVALID');
if(nativeIndex>=0){
 const supplied=process.argv[nativeIndex+1];assert(supplied&&!supplied.startsWith('--'),'NATIVE_JSON_PROBE_REQUIRED');
 assert.equal(process.platform,'win32','NATIVE_JSON_PROBE_REQUIRES_ACTUAL_WINDOWS');
 const target=path.resolve(supplied);assert(fs.existsSync(target)&&fs.statSync(target).isFile(),'NATIVE_JSON_PROBE_REQUIRED');
 const header=Buffer.alloc(4096),handle=fs.openSync(target,'r');let count;
 try{count=fs.readSync(handle,header,0,header.length,0);}finally{fs.closeSync(handle);}
 assert(count>=64&&header.readUInt16LE(0)===0x5a4d,'NATIVE_JSON_PROBE_PE_REQUIRED');
 const offset=header.readUInt32LE(60);
 assert(offset>=64&&offset+24<=count&&header.readUInt32LE(offset)===0x4550&&header.readUInt16LE(offset+4)===0x8664,'NATIVE_JSON_PROBE_AMD64_REQUIRED');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'game-native-json-'));
 try{
  const input=path.join(temp,'numbers.jsonl');fs.writeFileSync(input,cases.map(row=>row.raw).join('\n')+'\n',{flag:'wx'});
  const run=cp.spawnSync(target,[input],{encoding:'utf8',timeout:120000,maxBuffer:16*1024*1024,windowsHide:true});
  if(run.error)throw run.error;
  assert.equal(run.signal,null,'NATIVE_JSON_PROBE_SIGNAL');assert.equal(run.status,0,run.stderr||run.stdout);
  const lines=run.stdout.trim().split(/\r?\n/).map(line=>JSON.parse(line));assert.equal(lines.length,cases.length,'NATIVE_JSON_PROBE_RESULT_COUNT');
  const wires=[],accepted=[];
  for(let i=0;i<cases.length;i++){
   const expected=cases[i],actual=lines[i];
   assert.equal(actual.index,i,'NATIVE_JSON_PROBE_RESULT_ORDER');assert.equal(typeof actual.accepted,'boolean');
   // A Delphi underflow/parser disagreement is an unsupported numeric semantic
   // and a failing run, not a skipped/matched canonicalization case.
   assert.equal(actual.accepted,expected.accepted,'NATIVE_PROTOCOL_NUMERIC_UNSUPPORTED '+expected.id);
   if(!actual.accepted){assert.equal(typeof actual.errorClass,'string');assert(actual.errorClass);nativeRejections++;continue;}
   for(const field of ['bodyHex','envelopeHex'])assert(/^(?:[0-9a-f]{2})+$/.test(actual[field]),expected.id+' native '+field);
   const body=Buffer.from(actual.bodyHex,'hex').toString('utf8'),envelope=Buffer.from(actual.envelopeHex,'hex').toString('utf8');
   if(expected.bits)assert.equal(actual.numberBits,expected.bits,'NATIVE_PROTOCOL_NUMERIC_UNSUPPORTED '+expected.id+' Double value');
   wires.push(body,envelope);accepted.push({expected,actual,body,envelope});
  }
  const normalized=oracle(['--evaluate'],wires);
  for(let i=0;i<accepted.length;i++){
   const {expected,actual,body,envelope}=accepted[i],bodyRef=normalized[2*i],envelopeRef=normalized[2*i+1];
   assert(bodyRef.accepted&&envelopeRef.accepted,'NATIVE_PROTOCOL_WIRE_UNSUPPORTED '+expected.id);
   assert.equal(bodyRef.canonicalHex,expected.canonicalHex,expected.id+' native wire changed canonical bytes');
   assert.equal(bodyRef.canonicalSha512,expected.canonicalSha512,expected.id+' native wire changed canonical SHA-512');
   assert.equal(bodyRef.fingerprint,expected.fingerprint,expected.id+' native wire changed receipt hash');
   compare(body,bodyRef,expected.id+' Delphi body');const outer=compare(envelope,envelopeRef,expected.id+' Delphi envelope');
   assert.equal(outer.operation,'bootstrap');assert.equal(outer.tlsPinVersion,1);
   assert.equal(protocol.Stable(outer.body),expected.canonical,expected.id+' envelope body semantics');
   assert.equal(actual.bodySha512,bodyRef.wireSha512,expected.id+' native/Python body wire SHA-512');
   assert.equal(actual.envelopeSha512,envelopeRef.wireSha512,expected.id+' native/Python envelope wire SHA-512');
   nativeWireVectors++;
  }
  nativeVectors=lines.length;nativeExecuted=true;
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
}
console.log(JSON.stringify({suite:'FLOAT_CANONICALIZATION_14',status:'PASS',python,cases:cases.length,protocolVectors,rejections,
 numberFormattingVectors,formatterOnlyVectors,categories,floatCanonicalizationCompared:true,
 numericOracle:generated.oracle,hashOracle:generated.hashOracle,nonfinite:'REJECTED_AT_WIRE_BOUNDARY',
 unsafeIntegers:'FORMAT_ONLY_PROTOCOL_REJECTED',productionCanonicalizationChanged:false,
 nativeExecuted,nativeOutcome:nativeExecuted?'PASS':'NOT_RUN',nativeVectors,nativeWireVectors,nativeRejections,
 nativeScope:nativeExecuted?'DELPHI_PARSE_DOUBLE_AND_ENVELOPE_WIRE_TO_PYTHON_JS_CANONICAL_BYTES_AND_HASHES':'NOT_RUN',
 nativeCanonicalSerializer:'NOT_PRESENT_IN_PRODUCT_SERVER_CANONICALIZES_RECEIPTS'}));
