program CozyNHW_Native5H_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5H_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5H.Tests.dproj; the define must apply to all units.'}
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
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.CodeProvenanceGraph in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CodeProvenanceGraph.pas',
  Cozy.NHW.IndirectTargets in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.IndirectTargets.pas',
  Cozy.NHW.MultiEpochBaseline in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MultiEpochBaseline.pas',
  Cozy.NHW.SnapshotETWReconcile in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SnapshotETWReconcile.pas',
  Cozy.NHW.TemporalHandleGraph in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TemporalHandleGraph.pas';
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
    // Synthetic observations only; NHW.Engine is deliberately not linked.
    // No injection, external process mutation, ETW session or file writes.
    RunGroup('CodeProvenanceGraph', TestCodeProvenanceHardening);
    RunGroup('IndirectTargets', TestIndirectTargetsHardening);
    RunGroup('MultiEpochBaseline', TestMultiEpochHardening);
    RunGroup('SnapshotETWReconcile', TestSnapshotETWHardening);
    RunGroup('TemporalHandleGraph', TestTemporalHandleHardening);
    Writeln('PASS: Native5H assertions=', Total);
    Writeln('Synthetic tests do not certify real Windows scheduling or ETW completeness.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
