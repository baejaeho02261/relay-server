program CozyNHW_Native5_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build this project with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5.Tests.dproj; it defines NHW_NATIVE5_TESTS for all units.'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.IPCNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.IPCNative.pas',
  Cozy.NHW.NetworkNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NetworkNative.pas',
  Cozy.NHW.NamespaceNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NamespaceNative.pas',
  Cozy.NHW.WCTNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WCTNative.pas',
  Cozy.NHW.ETWNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWNative.pas';

type
  TCheckGroup = function(out Failure: string; out Checks: Integer): Boolean;

var
  Total: Integer;

procedure RunGroup(const Name: string; Group: TCheckGroup);
var
  Failure: string;
  Checks: Integer;
begin
  if not Group(Failure, Checks) then
    raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks);
  Writeln('PASS: ', Name, ' assertions=', Checks);
end;

begin
  Total := 0;
  try
    // Single-threaded synthetic tests. Do not bootstrap live native APIs or
    // start a monitor while the private API tables are temporarily mocked.
    RunGroup('IPCNative', TestIPCNativeHardening);
    RunGroup('NetworkNative', TestNetworkNativeHardening);
    RunGroup('NamespaceNative', TestNamespaceNativeHardening);
    RunGroup('WCTNative', TestWCTNativeHardening);
    RunGroup('ETWNative', TestETWNativeHardening);
    Writeln('PASS: Native5 synthetic assertions=', Total);
    Writeln('These are not live Windows API/ETW delivery tests.');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
