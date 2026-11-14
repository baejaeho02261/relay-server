program CozyNHW_Native5G_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5G_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5G.Tests.dproj; the define must apply to all units.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas',
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas',
  Cozy.NHW.PERules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PERules.pas',
  Cozy.NHW.ExceptionNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionNative.pas',
  Cozy.NHW.PEView in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PEView.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.ThreadTimeline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadTimeline.pas',
  Cozy.NHW.SectionCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SectionCorrelation.pas',
  Cozy.NHW.ExecutableLifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExecutableLifecycle.pas',
  Cozy.NHW.ControlFlowAttestation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ControlFlowAttestation.pas',
  Cozy.NHW.SectionBackingIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SectionBackingIdentity.pas';
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
    ResolveWinPointers;
    // Synthetic reads and state transitions only. Never runs NHW.Engine.
    // The fixtures do not inject code, modify files or start worker threads.
    RunGroup('ThreadTimeline', TestThreadTimelineHardening);
    RunGroup('SectionCorrelation', TestSectionCorrelationHardening);
    RunGroup('ExecutableLifecycle', TestExecutableLifecycleHardening);
    RunGroup('ControlFlowAttestation', TestControlFlowHardening);
    RunGroup('SectionBackingIdentity', TestSectionBackingHardening);
    Writeln('PASS: Native5G assertions=', Total);
    Writeln('Synthetic tests do not certify live API races, timing or complete coverage.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
