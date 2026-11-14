program CozyNHW_Native10M_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'Build with Delphi Win64.'}{$ENDIF}
{$IFNDEF NHW_NATIVE10M_TESTS}{$MESSAGE FATAL 'Open Cozy.NHW.Native10M.Tests.dproj.'}{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.ThreadOrigin in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadOrigin.pas',
  Cozy.NHW.MappingGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MappingGuard.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.StackGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StackGuard.pas',
  Cozy.NHW.Registry in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Registry.pas',
  Cozy.NHW.PELoader in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PELoader.pas',
  Cozy.NHW.IPC in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.IPC.pas',
  Cozy.NHW.Namespace in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Namespace.pas',
  Cozy.NHW.PathGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PathGuard.pas',
  Cozy.NHW.RealtimeFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RealtimeFusion.pas';
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
    RunGroup('ThreadOrigin', TestThreadOrigin10M);
    RunGroup('MappingGuard', TestMappingGuard10M);
    RunGroup('Lifecycle', TestLifecycle10M);
    RunGroup('StackGuard', TestStackGuard10M);
    RunGroup('Registry', TestRegistry10M);
    RunGroup('PELoader', TestPELoader10M);
    RunGroup('IPC', TestIPC10M);
    RunGroup('Namespace', TestNamespace10M);
    RunGroup('PathGuard', TestPathGuard10M);
    RunGroup('RealtimeFusion', TestRealtimeFusion10M);
    Writeln('PASS: Native10M assertions=', Total);
    Writeln('Synthetic tests do not certify Windows races, event delivery or complete security.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
