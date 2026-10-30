'use strict';
// Wiring/lifetime source checks only. The native --contracts mode executes the
// real guards on Windows. Production server/TPM transcript tests run separately.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../../../Railway');
const read=n=>fs.readFileSync(path.join(root,n),'utf8').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n');
const source=read('Cozy.Source/Cozy.Identity/Cozy.DeviceIdentity.pas'),contract=read('Cozy.Source/Cozy.Identity/Cozy.DeviceIdentity.Contracts.pas'),probe=read('Cozy.Tests/Cozy.Identity/Cozy.DeviceIdentityProbe.dpr'),cases=read('Cozy.Tests/Cozy.Identity/Cozy.DeviceIdentityContracts.inc');
for(const name of ['ReadIdentityPolicy','ReadIdentityChallenge','ValidateIdentityActivation','ValidateIdentityActivationDomain','ValidateIdentityEnrolled'])assert(source.includes(name+'('),'Production must call '+name);
assert(source.includes("Transport.PostJSON('device',Request.Body,BudgetMs)"));
assert.match(source,/finally Envelope\.Free;FreeAndNil\(Request\);end;/);
assert.match(source,/SessionOwner\.Assign\(SessionToken\)/);
assert.match(source,/ActivationOwner\.Assign\(Secret,64\);WipeText\(Secret\)/);
assert.match(source,/Request\.AddActivationSecret\(ActivationOwner\);ActivationOwner\.Clear/);
assert.match(source,/SessionOwner\.Clear;ActivationOwner\.Clear/);
assert.doesNotMatch(source,/AuthBody\([^\n]*SessionToken/,'No raw token passed into repeated request constructors');
assert.match(source,/Response:=Exchange\(Transport,Request,Budget\);RequireTime;ActivationCompleted:=True/);
assert.match(source,/Key\.Activate\(Activation\);RequireTime;/,'Late TPM output cannot be accepted before budget check');
const close=contract.slice(contract.indexOf('procedure TDeviceIdentityRequest.Close;'),contract.indexOf('destructor TDeviceIdentityRequest.Destroy;'));
assert(close.indexOf('FreeAndNil(FBody)')<close.indexOf('WipeBoundaryText(FSecretText)'));
assert.match(close,/finally/,'JSON destruction and token buffer retirement share one lifetime');
for(const check of ["IdentityNumber(Obj, 'epoch') <> Policy.Epoch","IdentityNumber(Obj, 'revision') <> Policy.Revision","IsPlatform <> (Policy.ProviderKind = 'PLATFORM')","IdentityBoolean(Obj, 'requireTpm') <> IsPlatform","IdentityNumber(Obj, 'expiresAt') <> Challenge.ExpiresAt",'not ActivationCompleted'])assert(contract.includes(check),check);
assert.match(contract,/ElapsedMs >= 90000/);assert.match(contract,/Result > 10000/);
assert(probe.includes("ParamStr(1)='--contracts'"));assert(probe.includes('RunDeviceIdentityContracts'));
assert(probe.includes('SealApiPointerStorage;RunDeviceKeyConstructionContracts;Run;'),'Original interactive hardware proof path preserved');
assert(cases.includes('ReadIdentityChallenge(')&&cases.includes('ValidateIdentityEnrolled('));
assert(cases.includes('for CaseID:=1 to 28'));
assert(cases.includes('CLOSED_BODY')&&cases.includes('EMPTY_SESSION'));
assert(cases.includes('hardwareAttestation":false'));
console.log('NATIVE DEVICE IDENTITY SOURCE CONTRACTS PASS; actual Windows/native/TPM execution NOT_RUN');
