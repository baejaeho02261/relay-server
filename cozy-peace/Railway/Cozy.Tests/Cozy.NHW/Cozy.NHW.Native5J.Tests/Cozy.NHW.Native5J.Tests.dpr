program CozyNHW_Native5J_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5J_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5J.Tests.dproj; define must apply to every unit.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.ETW in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETW.pas',
  Cozy.NHW.HandleSharingEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HandleSharingEvidence.pas',
  Cozy.NHW.APCStyleEvidence in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.APCStyleEvidence.pas',
  Cozy.NHW.ETWLossHealth in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWLossHealth.pas',
  Cozy.NHW.AdaptiveAnomaly in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AdaptiveAnomaly.pas',
  Cozy.NHW.SensorRecovery in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SensorRecovery.pas';
type TTestGroup = function(out Failure: string; out Checks: Integer): Boolean;
var Total: Integer;
procedure RunGroup(const Name: string; Test: TTestGroup);
var Failure: string; Checks: Integer;
begin
  if not Test(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks);
  Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    // Synthetic in-memory inputs; no live ETW sessions or process modification.
    RunGroup('HandleSharingEvidence', TestSharing5J);
    RunGroup('APCStyleEvidence', TestAPC5J);
    RunGroup('ETWLossHealth', TestETWLoss5J);
    RunGroup('AdaptiveAnomaly', TestAnomaly5J);
    RunGroup('SensorRecovery', TestRecovery5J);
    Writeln('PASS: Native5J assertions=', Total);
    Writeln('Synthetic checks do not certify OS scheduling or observation completeness.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
