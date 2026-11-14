program CozyNHW_Native5C_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5C_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5C.Tests.dproj; its define must apply to all units.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.Process in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Process.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Threads in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Threads.pas',
  Cozy.NHW.WriteWatchNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteWatchNative.pas',
  Cozy.NHW.MappingNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MappingNative.pas',
  Cozy.NHW.SchedulerNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SchedulerNative.pas',
  Cozy.NHW.Security in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Security.pas';
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
    // Only bootstrap Win32 wrappers, e.g. GetLastError for buffer-growth tests.
    // Single-threaded synthetic API replacements; do NOT start NHW.Engine.
    ResolveWinPointers;
    RunGroup('Threads', TestThreadsHardening);
    RunGroup('WriteWatchNative', TestWriteWatchHardening);
    RunGroup('MappingNative', TestMappingHardening);
    RunGroup('SchedulerNative', TestSchedulerHardening);
    RunGroup('Security', TestSecurityHardening);
    Writeln('PASS: Native5C assertions=', Total);
    Writeln('Synthetic tests do not certify real OS delivery, concurrency or shutdown.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
