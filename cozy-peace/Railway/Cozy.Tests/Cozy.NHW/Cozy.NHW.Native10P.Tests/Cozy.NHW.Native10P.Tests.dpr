program CozyNHWNative10PTests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas',
  Cozy.NHW.Scheduler in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Scheduler.pas',
  Cozy.NHW.MicroburstAccess in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MicroburstAccess.pas',
  Cozy.NHW.AdaptiveInspector in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdaptiveInspector.pas',
  Cozy.NHW.TriggeredSnapshot in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TriggeredSnapshot.pas',
  Cozy.NHW.CoverageWindow in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CoverageWindow.pas',
  Cozy.NHW.HighResolutionClock in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HighResolutionClock.pas',
  Cozy.NHW.ObservationTrust in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ObservationTrust.pas',
  Cozy.NHW.ReplayValidation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReplayValidation.pas',
  Cozy.NHW.AdvancedRealtimeRegression in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdvancedRealtimeRegression.pas';
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
    RunGroup('SelfRules', TestSelfRules10P);
    RunGroup('Scheduler', TestScheduler10P);
    RunGroup('MicroburstAccess', TestMicroburstAccess10P);
    RunGroup('AdaptiveInspector', TestAdaptiveInspector10P);
    RunGroup('TriggeredSnapshot', TestTriggeredSnapshot10P);
    RunGroup('CoverageWindow', TestCoverageWindow10P);
    RunGroup('HighResolutionClock', TestHighResolutionClock10P);
    RunGroup('ObservationTrust', TestObservationTrust10P);
    RunGroup('ReplayValidation', TestReplayValidation10P);
    RunGroup('AdvancedRealtimeRegression', TestAdvancedRealtimeRegression10P);
    Writeln('PASS: Native10P assertions=', Total);
    Writeln('Synthetic tests are not a Windows concurrency, PSS or ETW soak test.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
