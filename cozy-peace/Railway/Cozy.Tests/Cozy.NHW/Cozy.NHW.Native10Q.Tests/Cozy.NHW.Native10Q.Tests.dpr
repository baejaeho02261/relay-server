program CozyNHWNative10QTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.ExportRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExportRules.pas',
  Cozy.NHW.FastEventRing in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FastEventRing.pas',
  Cozy.NHW.SignalCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SignalCorrelation.pas',
  Cozy.NHW.InjectionEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.InjectionEvidence.pas',
  Cozy.NHW.ObserverAttestation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ObserverAttestation.pas',
  Cozy.NHW.SensorTamperHealth in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorTamperHealth.pas',
  Cozy.NHW.EphemeralIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.EphemeralIdentity.pas',
  Cozy.NHW.PathRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PathRules.pas',
  Cozy.NHW.RegressionLab in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RegressionLab.pas',
  Cozy.NHW.AdvancedRegressionV80 in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedRegressionV80.pas';
type TGroup = function(out Failure: string; out Checks: Integer): Boolean;
var Total: Integer;
procedure RunGroup(const Name: string; Test: TGroup);
var Failure: string; Checks: Integer;
begin
  if not Test(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks);
  Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    RunGroup('ExportRules', TestExportRules10Q);
    RunGroup('FastEventRing', TestFastEventRing10Q);
    RunGroup('SignalCorrelation', TestSignalCorrelation10Q);
    RunGroup('InjectionEvidence', TestInjectionEvidence10Q);
    RunGroup('ObserverAttestation', TestObserverAttestation10Q);
    RunGroup('SensorTamperHealth', TestSensorTamperHealth10Q);
    RunGroup('EphemeralIdentity', TestEphemeralIdentity10Q);
    RunGroup('PathRules', TestPathRules10Q);
    RunGroup('RegressionLab', TestRegressionLab10Q);
    RunGroup('AdvancedRegressionV80', TestAdvancedRegressionV8010Q);
    Writeln('PASS: Native10Q assertions=', Total);
    Writeln('Synthetic tests do not replace ETW/Windows concurrency and long-run validation.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
