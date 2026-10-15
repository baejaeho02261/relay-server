'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { validateNative, validateBinding } = require('../tools/cfg-enforcement-report');
const copy = value => JSON.parse(JSON.stringify(value));
// Static regression for the Windows runner. A foreach iterator shares its
// function scope with parameters, and PowerShell variable names ignore case.
// This checks the source contract only; it does not execute PowerShell or CFG.
const runner = fs.readFileSync(path.join(__dirname, '../tools/cfg-enforcement.ps1'), 'utf8');
const runnerFunctions = [...runner.matchAll(/^function ([\w-]+)\(([^\r\n]*)\) \{([\s\S]*?)^\}/gm)];
assert(runnerFunctions.some(match => match[1] === 'Invoke-Tool'));
for (const [, functionName, parameters, body] of runnerFunctions) {
  const parameterNames = new Set([...parameters.matchAll(/\$([\w]+)/g)].map(match => match[1].toLowerCase()));
  for (const [, iterator] of body.matchAll(/\bforeach\s*\(\s*\$([\w]+)\s+in\b/gi)) {
    assert(!parameterNames.has(iterator.toLowerCase()),
      `${functionName}: foreach iterator $${iterator} overwrites a case-insensitive parameter`);
  }
}
function validReport() {
  const control = id => ({ id, launched:true, ready:true, policyQuerySucceeded:true,
    controlFlowGuardEnabled:true, exited:true, timedOut:false, exitCode:0,
    exceptionCode:0, secondChance:false, fastFailCode:0, expectedExceptionCount:0,
    unexpectedException:0, win32Error:0 });
  const cases = ['guarded-valid-target','guarded-invalid-target','unguarded-invalid-target'].map(control);
  Object.assign(cases[1], {exitCode:0xC0000409,exceptionCode:0xC0000409,secondChance:true,
    fastFailCode:10,expectedExceptionCount:1});
  cases[2].controlFlowGuardEnabled = false;
  return {version:1,kind:'CFG_ENFORCEMENT_PROBE',scope:'MSVC_PROBE_ONLY',
    productionCoverage:false,outcome:'PASS',cases};
}
const valid = validReport();
assert.equal(validateNative(valid,0),true);
const mutations = [
  r => {r.cases[1].exceptionCode=0xC0000005;},
  r => {r.cases[1].fastFailCode=7;},
  r => {r.cases[1].secondChance=false;},
  r => {r.cases[1].exitCode=0;},
  r => {r.cases[1].controlFlowGuardEnabled=false;},
  r => {r.cases[1].ready=false;},
  r => {r.cases[1].expectedExceptionCount=2;},
  r => {r.cases[0].policyQuerySucceeded=false;},
  r => {r.cases[0].exitCode=103;},
  r => {r.cases[2].exitCode=0xC0000409;},
  r => {r.cases[2].timedOut=true;},
  r => {r.cases[1].unexpectedException=0xC0000005;},
  r => {r.cases[1].win32Error=5;},
  r => {r.cases=[];},
  r => {r.cases.reverse();},
  r => {r.productionCoverage=true;},
  r => {r.outcome='NOT_RUN';},
];
for (const mutate of mutations) { const changed=copy(valid);mutate(changed);assert.throws(()=>validateNative(changed,0)); }
assert.throws(()=>validateNative(valid,1));
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cfg-acceptance-'));
try {
  const bindings={};
  for (const name of ['source','compiler','linker','guardedProbe','unguardedProbe']) {
    const file=path.join(directory,name);const bytes=Buffer.from(name);fs.writeFileSync(file,bytes);
    bindings[name]={path:file,sha512:crypto.createHash('sha512').update(bytes).digest('hex')};
  }
  const report={version:1,kind:'CFG_RUNTIME_ENFORCEMENT',scope:'MSVC_PROBE_ONLY',outcome:'PASS',windowsExecuted:true,
    productionCfgCoverage:false,ciEvidenceCreated:false,publicationApproval:false,
    nativeReport:valid,nativeExitCode:0,bindings,
    stages:['compile-guarded','link-guarded','compile-control','link-control'].map(id=>({id,exitCode:0}))};
  assert.equal(validateBinding(report),true);
  const inconsistentScope=copy(report);inconsistentScope.scope='PRODUCTION_ABO';
  assert.throws(()=>validateBinding(inconsistentScope),/CFG_BINDING_SCOPE/);
  for (const field of ['productionCfgCoverage','ciEvidenceCreated','publicationApproval']) {
    const changed=copy(report);changed[field]=true;assert.throws(()=>validateBinding(changed));
  }
  const overwrittenStages=copy(report);
  overwrittenStages.stages.forEach(stage => {stage.id='_LINK_';});
  assert.throws(()=>validateBinding(overwrittenStages),/CFG_BUILD_STAGES/);
  fs.appendFileSync(bindings.unguardedProbe.path,'changed');
  assert.throws(()=>validateBinding(report),/CFG_BINDING_FILE_CHANGED/);
} finally { fs.rmSync(directory,{recursive:true,force:true}); }
process.stdout.write('cfg-runtime-enforcement: PASS (acceptance-policy fixtures only; Windows execution NOT_RUN)\n');
