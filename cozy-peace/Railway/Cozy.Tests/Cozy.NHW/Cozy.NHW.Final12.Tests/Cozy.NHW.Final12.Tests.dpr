program CozyNHWFinal12Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses System.SysUtils,
  Cozy.NHW.Final12.Contracts in 'Cozy.NHW.Final12.Contracts.pas',
  Cozy.NHW.HeapTLSRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLSRules.pas',
  Cozy.NHW.Sampling in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Sampling.pas';
type TGroup = function(out Failure: string; out Checks: Integer): Boolean;
var Total: Integer;
procedure RunGroup(const Name: string; Test: TGroup);
var Failure: string; Checks: Integer;
begin
  if not Test(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks); Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    RunGroup('Causal', TestCausalFinal12);
    RunGroup('Risk', TestRiskFinal12);
    RunGroup('AsyncRules', TestAsyncRulesFinal12);
    RunGroup('ReadRules', TestReadRulesFinal12);
    RunGroup('WriteRules', TestWriteRulesFinal12);
    RunGroup('Types', TestTypesFinal12);
    RunGroup('ETWTypes', TestETWTypesFinal12);
    RunGroup('Options', TestOptionsFinal12);
    RunGroup('Logging', TestLoggingFinal12);
    RunGroup('AdvancedRegression', TestAdvancedRegressionFinal12);
    RunGroup('HeapTLSRules', TestHeapTLSRulesFinal12);
    RunGroup('Sampling', TestSamplingFinal12);
    Writeln('PASS: Final12 assertions=', Total);
    Writeln('Synthetic contracts and read-only startup checks; not a full Windows soak test.');
  except on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end; end;
end.
