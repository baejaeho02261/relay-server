program CozyNHW_Native5D_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5D_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5D.Tests.dproj so its define applies to all units.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.SignalCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SignalCorrelation.pas',
  Cozy.NHW.ReadCanaryNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadCanaryNative.pas',
  Cozy.NHW.SelfNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfNative.pas',
  Cozy.NHW.ProcessSnapshot in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ProcessSnapshot.pas',
  Cozy.NHW.ModuleOriginVerification in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ModuleOriginVerification.pas',
  Cozy.NHW.StableIdentity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.StableIdentity.pas';
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
    ResolveNativeAPIs;
    // Isolated, single-threaded fake responses. Never run NHW.Engine here.
    // SelfNative additionally validates ordinary local heap/code addresses.
    RunGroup('ReadCanaryNative', TestReadCanaryHardening);
    RunGroup('SelfNative', TestSelfNativeHardening);
    RunGroup('ProcessSnapshot', TestProcessSnapshotHardening);
    RunGroup('ModuleOriginVerification', TestModuleOriginHardening);
    RunGroup('StableIdentity', TestStableIdentityHardening);
    Writeln('PASS: Native5D assertions=', Total);
    Writeln('Synthetic tests do not certify real OS delivery or concurrency.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
