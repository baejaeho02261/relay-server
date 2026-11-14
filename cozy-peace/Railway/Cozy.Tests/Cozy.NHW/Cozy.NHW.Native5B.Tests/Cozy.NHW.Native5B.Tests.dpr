program CozyNHW_Native5B_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5B_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5B.Tests.dproj to set NHW_NATIVE5B_TESTS in all units.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.CaptureRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CaptureRules.pas',
  Cozy.NHW.FileNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileNative.pas',
  Cozy.NHW.CaptureNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.CaptureNative.pas',
  Cozy.NHW.AsyncNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AsyncNative.pas',
  Cozy.NHW.HeapTLSNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLSNative.pas',
  Cozy.NHW.StackNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StackNative.pas';
type
  TCheckGroup = function(out Failure: string; out Checks: Integer): Boolean;
var
  Total: Integer;
procedure RunGroup(const Name: string; Group: TCheckGroup);
var Failure: string; Checks: Integer;
begin
  if not Group(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks);
  Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    // Single-threaded synthetic tests with temporary API-table replacements.
    // Do not start the monitoring engine or call ResolveWinPointers here.
    RunGroup('FileNative', TestFileNativeHardening);
    RunGroup('CaptureNative', TestCaptureNativeHardening);
    RunGroup('AsyncNative', TestAsyncNativeHardening);
    RunGroup('HeapTLSNative', TestHeapTLSNativeHardening);
    RunGroup('StackNative', TestStackNativeHardening);
    Writeln('PASS: Native5B synthetic assertions=', Total);
    Writeln('This does not validate real OS API delivery, concurrency or shutdown.');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
