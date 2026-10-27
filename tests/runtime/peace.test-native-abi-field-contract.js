'use strict';
const MODULE_RESOURCE_ROOT = require('node:path').resolve(__dirname, "..");

// Executes the exact parser used by Cozy.Compare-NativeAbi.ps1, with SYNTHETIC
// numbers. This cannot establish actual Delphi / SDK record sizes or offsets.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const sourceLayout=require('../fixtures/source/peace.project-layout');
const abi=require(path.resolve(MODULE_RESOURCE_ROOT, "../../Railway/Cozy.Tests/Cozy.Platform/Cozy.compare-native-abi.js")),fields=abi.Contract().fields;
const lines=fields.map((k,i)=>k+'='+(i+1)),bytes=Buffer.from(lines.join('\n')+'\n');
let groups=0,missingCases=0,mismatchCases=0;function test(name,fn){fn();groups++;console.log('PASS '+name);}
function reject(fn,code){assert.throws(fn,e=>e.message===code);}
test(`5.1 independent SDK and production Delphi exporters cover all ${fields.length} field names exactly`,()=>{
 const cpp=fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT, "../../Railway/Cozy.Tests/Cozy.Platform/Cozy.NativeAbiSdkProbe.cpp"),'utf8');
 const pas=['Cozy.Win64AbiContract.inc','Cozy.TlsAbiContract.inc'].map(x=>fs.readFileSync(sourceLayout.NativeFile(x),'utf8')).join('\n');
 const actual=[...cpp.matchAll(/printf\("([A-Za-z0-9_]+\.[A-Za-z0-9_]+)=/g)].map(x=>x[1]);
 const delphi=[...pas.matchAll(/System\.Writeln\('([A-Za-z0-9_]+\.[A-Za-z0-9_]+)=/g)].map(x=>x[1]);
 assert.deepEqual(actual.sort(),fields);assert.deepEqual(delphi.sort(),fields);
});
test('5.1 complete equal synthetic data matches, with either native CRLF or LF',()=>{assert.equal(abi.Compare(bytes,Buffer.from(lines.join('\r\n')+'\r\n')).match,true);});
test('5.1 every field missing from BOTH compilers is rejected, not equal-subset PASS',()=>{
 for(let i=0;i<lines.length;i++){const partial=lines.filter((_,j)=>j!==i).join('\n');reject(()=>abi.Compare(partial,partial),'ABI_FIELD_MISSING');missingCases++;}
});
test('5.1 every unequal field is named in comparison output',()=>{
 for(let i=0;i<lines.length;i++){const changed=lines.slice();changed[i]=fields[i]+'=9999';const result=abi.Compare(bytes,changed.join('\n'));assert.equal(result.match,false);assert.equal(result.differences.length,1);assert.equal(result.differences[0].field,fields[i]);mismatchCases++;}
});
test('5.1 duplicate, additional, empty and malformed outputs fail closed',()=>{
 reject(()=>abi.Parse(lines.concat(lines[0]).join('\n')),'ABI_FIELD_DUPLICATE');
 reject(()=>abi.Parse(lines.concat('Unexpected.sizeof=1').join('\n')),'ABI_FIELD_UNEXPECTED');
 for(const bad of ['', '\n', 'not a layout', 'SecBuffer.sizeof=-1', 'SecBuffer.sizeof=1.5', 'SecBuffer.sizeof=NaN', 'SecBuffer.sizeof=1\r'])reject(()=>abi.Parse(bad),'ABI_OUTPUT_FORMAT');
});
test('5.1 no floating-point rounding when a malicious probe emits large integer values',()=>{
 const a=lines.slice(),b=lines.slice();a[0]=fields[0]+'=9007199254740992';b[0]=fields[0]+'=9007199254740993';assert.equal(abi.Compare(a.join('\n'),b.join('\n')).match,false);
 a[0]=fields[0]+'=18446744073709551616';reject(()=>abi.Parse(a.join('\n')),'ABI_VALUE_RANGE');
});
test('5.1 malformed UTF-8/BOM and overlong output are rejected',()=>{
 reject(()=>abi.Parse(Buffer.from([0xff])),'ABI_OUTPUT_UTF8');reject(()=>abi.Parse(Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),bytes])),'ABI_OUTPUT_FORMAT');reject(()=>abi.Parse(Buffer.alloc(65537)),'ABI_OUTPUT_LIMIT');
});
test('5.1 PowerShell and manual Windows tests use this comparator rather than a separate permissive parser',()=>{
 const ps=fs.readFileSync(path.resolve(MODULE_RESOURCE_ROOT, "../../Railway/Cozy.Tests/Cozy.Platform/Cozy.Compare-NativeAbi.ps1"),'utf8'),manual=fs.readFileSync(sourceLayout.RelayFile('peace.manual-windows-tests.js'),'utf8');
 assert(ps.includes('Cozy.compare-native-abi.js'));assert(ps.includes('$LASTEXITCODE -ne 0'));assert(manual.includes('Cozy.compare-native-abi.js'));
});
console.log(JSON.stringify({scope:'REAL_ABI_PARSER_WITH_SYNTHETIC_NUMBERS_AND_EXPORTER_SOURCE_CHECK',groups,fields:fields.length,missingCases,mismatchCases,nativeExecuted:false,windowsExecuted:false}));
