'use strict';
// Native source and shared protocol checks only; NOT Windows/Delphi execution.
const assert = require('node:assert/strict'), crypto = require('node:crypto');
const fs = require('node:fs'), path = require('node:path'), {test} = require('node:test');
const rpc = require('../../services/security/peace.server-policy-operations');
const root = process.env.COZY_NATIVE_SOURCE_ROOT || path.resolve(__dirname, '../../../Railway');
const read = name => fs.readFileSync(path.join(root,name),'utf8').replaceAll('\r','');
const client = read('Cozy.Source/Cozy.Security/Cozy.ServerOperations.pas');
const probe = read('Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dpr');
const sha = value => crypto.createHash('sha512').update(value).digest('hex');

test('server wire matches Native golden vectors including signed bounds and zero revisions', () => {
  const body = {stage:'B',sessionId:'A'.repeat(24),machineId:'B'.repeat(64),policyId:'c'.repeat(64),
    requestId:'11111111-2222-3333-4444-555555555555',functionId:2,args:[-2147483648,0,2147483647]};
  const challenge = {challengeId:'1'.repeat(48),nonce:'2'.repeat(48),epoch:'3'.repeat(48),
    revision:0,operationsRevision:0,expiresAt:1790000000000};
  for (const [name,value] of Object.entries({ArgsDigest:sha(JSON.stringify(body.args)),
    BindingDigest:rpc.Binding(body),CanonicalDigest:sha(rpc.Canonical(body,challenge))})) {
    assert.equal(probe.match(new RegExp(name+" = '([a-f0-9]{128})';"))[1],value);
  }
  const canonical = client.split('  Result := OperationDomain + #10 + Stage')[1].split('end;')[0];
  const fields = ['SessionID','MachineID','PolicyID','IntToStr(FunctionID)','RequestID','ArgsSHA512','Binding',
    'Challenge.ChallengeID','Challenge.Nonce','Challenge.Epoch','IntToStr(Challenge.Revision)',
    'IntToStr(Challenge.OperationsRevision)','IntToStr(Challenge.ExpiresAt)'];
  let at=-1;for(const field of fields){const next=canonical.indexOf(field,at+1);assert(next>at,field);at=next;}
  assert.match(client,/Number\(Data, 'revision', 0,/);
  assert.match(client,/Number\(Data, 'operationsRevision', 0,/);
});

test('Native rejects altered response identities and never signs server-provided canonical text', () => {
  assert.match(client,/Data.Count <> 9/); assert.match(client,/Data.Count <> 5/);
  assert.match(client,/Text\(Data, 'binding', '[^']+'\) <> Binding/);
  assert.match(client,/Text\(Data, 'argsSha512', '[^']+'\) <> ArgsSHA512/);
  assert.match(client,/Text\(Data, 'requestId', '[^']+'\) <> RequestID/);
  assert.match(client,/Text\(Data, 'policyId', '[^']+'\) <> PublicBinding.PolicyID/);
  assert.match(client,/Number\(Data, 'functionId', 2, 65535\) <> FunctionID/);
  assert.match(client,/Number\(Data, 'result', -2147483648, 2147483647\)/);
  assert(client.indexOf('RequireServerObservation(Transport') < client.indexOf('Signature := Security.Sign(Canonical)'));
  assert.match(client,/SessionID, SessionToken, 'observe', Binding/);
  assert.match(client,/end, OwnImage, Runtime\)/,'Server operations retain the same registered runtime context for authority');
  assert.match(client,/Canonical := ServerOperationCanonical\(/);
  assert.doesNotMatch(client,/Text\(Data, 'canonical'|Retry|EvaluateServerPolicy|programBase64|Decrypt|SaveToFile/);
});

test('bounded snapshot input, cancellation and transient cleanup are explicit', () => {
  assert.match(client,/Length\(Args\) > 8/); assert.match(client,/FunctionID < 2/);
  assert.match(client,/ArgsText := ServerOperationArgsJSON\(LocalArgs\)/);
  assert.match(client,/High\(LocalArgs\).*TJSONNumber.Create\(LocalArgs\[I\]\)/);
  assert.match(client,/OperationBudgetMs = 45000/);
  assert.match(client,/Clock.ElapsedMilliseconds >= OperationBudgetMs/);
  assert.match(client,/if Left > 10000 then Left := 10000/);
  assert.match(client,/FillChar\(LocalArgs\[0\], Length\(LocalArgs\) \* SizeOf\(Integer\), 0\)/);
  assert.match(client,/WipeText\(Canonical\); WipeText\(Signature\)/);
  assert.doesNotMatch(client,/MessageBox|ShowMessage|OutputDebugString|WriteLn|ShellExecute|TThread.Create/);
});

test('all role clients own calls through lifecycle locks and current report refresh', () => {
  for(const [file,type,report] of [
    ['Cozy.Application/Cozy.Bootstrap.pas','TBootstrapClient','ReportIntegrityCore'],
    ['Cozy.Platform/Cozy.Api.pas','TGameApi','CheckIntegrityCore'],
    ['Cozy.Overlay/Cozy.Overlay.Client.pas','TOverlayClient','ReportIntegrityCore']]) {
    const text=read('Cozy.Source/'+file), method=text.split('function '+type+'.InvokeServerPolicy(')[1].split('\nfunction ')[0].split('\nprocedure ')[0];
    assert(method,type);assert.match(method,/FGate.Enter/);assert.match(method,/TMonitor.Enter\(FLock\)/);
    assert(method.indexOf(report)<method.indexOf('InvokeCozyServerOperation('),type);
    assert.match(method,/OwnRuntime\(/,'Each role forwards its actual registered runtime context inside the admitted call');
    assert.match(method,/finally TMonitor.Exit\(FLock\); end/);assert.match(method,/finally FGate.Leave; end/);
  }
  assert.match(read('Cozy.Source/Cozy.Network/Cozy.Transport.pas'),/Operation <> 'policy'/);
  const envelope=read('Cozy.Source/Cozy.Handoff/Cozy.JsonEnvelope.pas');
  assert.match(envelope,/ValidateProtocolRequest\(Operation, Body\)/);
  assert(envelope.indexOf('ValidateProtocolRequest(Operation, Body)')<envelope.indexOf('Text := Body.ToJSON'),
    'Envelope validates operation/action/body against the shared contract before serialization');
  const protocol=read('Cozy.Source/Cozy.Handoff/Cozy.ProtocolJson.pas');
  const request=protocol.slice(protocol.lastIndexOf('procedure ValidateProtocolRequest(')).split('procedure ValidateProtocolEnvelope(')[0];
  assert.match(request,/Rule.GetValue\('operation'\).Value = Operation/);
  assert.match(request,/Rule.GetValue\('action'\).Value = ActionValue.Value/);
  assert.match(request,/ValidateSchema\(TJSONObject\(Rule.GetValue\('body'\)\), Body, 0\); Exit/);
  assert.match(request,/\n  SchemaInvalid;\nend;/,'Unknown commands still fail closed');
  for(const role of ['Launcher','Client','Overlay'])for(const ext of ['dpr','dproj'])
    assert.match(read(`Cozy.Projects/Cozy.${role}/Cozy.${role}.${ext}`),/Cozy.ServerOperations.pas/);
  const example=read('Cozy.Tests/Cozy.Security/Cozy.ServerOperations.Example.pas');
  assert.equal((example.match(/Result := Client.InvokeServerPolicy\(/g)||[]).length,3);
  assert.doesNotMatch(example,/X\s*\+\s*Y|initialization|programBase64|privateKey/);
});

test('Windows probe wiring includes actual execution and its required source directories', () => {
  const batch = read('Cozy.Tests/Cozy.Build/Cozy.Build_NativeProbes_Win64.bat');
  const loops = [...batch.matchAll(/for %%P in \(([^\n]+)\) do \(/g)];
  assert.equal(loops.length,2);
  for(const loop of loops) {
    assert.match(loop[1],/\bCozy.ServerOperationsProtocolProbe\b/);
    assert.match(loop[1],/\bCozy.PointerGraphProbe\b/);
  }
  assert.match(batch,/"%PROBE_OUT%\\%%P.exe"\n\s+if errorlevel 1 exit \/b 1/);
  assert.match(batch,/Cozy.ServerOperationsProtocolProbe.dpr/);
  assert.match(batch,/Cozy.PointerGraphProbe" set "PROBE_DEFINES=RELEASE;COZY_POINTER_GRAPH_PROBE"/);
  const runner = fs.readFileSync(path.resolve(__dirname,'../../tools/windows/Invoke-NativeContracts6To10.ps1'),'utf8');
  assert.match(runner,/'Cozy.ServerOperationsProtocolProbe','Cozy.PointerGraphProbe','pe-corpus'/);
  assert.match(runner,/foreach\(\$name in \$names\[4\.\.\(\$names.Count-3\)\]\).*Invoke-ContractCommand \$name/);
  const props = read('Cozy.Tests/Cozy.Build/Cozy.ManualProbe.props');
  for(const name of ['DCC_UnitSearchPath','DCC_IncludePath'])
    assert.match(props.match(new RegExp('<'+name+'>([^<]+)'))[1],/Cozy.Source\\Cozy.Protection/);
  const project = read('Cozy.Tests/Cozy.Security/Cozy.ServerOperationsProtocolProbe.dproj');
  assert.match(project,/<DCC_ExeOutput>\$\(MSBuildProjectDirectory\)<\/DCC_ExeOutput>/);
  assert.match(project,/<DCC_DcuOutput>\$\(MSBuildProjectDirectory\)\\dcu\\\$\(ProjectName\)/);
});
