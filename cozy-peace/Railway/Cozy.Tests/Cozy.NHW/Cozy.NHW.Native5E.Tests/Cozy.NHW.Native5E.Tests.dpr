program CozyNHW_Native5E_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5E_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5E.Tests.dproj; its define must apply to all units.'}
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
  Cozy.NHW.ImageCOWIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ImageCOWIntegrity.pas',
  Cozy.NHW.LoaderCrossView in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.LoaderCrossView.pas',
  Cozy.NHW.ThreadExecutionProvenance in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadExecutionProvenance.pas',
  Cozy.NHW.ThreadStackProvenance in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadStackProvenance.pas',
  Cozy.NHW.FileAttestation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileAttestation.pas';
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
    // Isolated, single-threaded synthetic inputs. Do not run NHW.Engine here.
    // Test hooks are compiled ONLY with NHW_NATIVE5E_TESTS; no injection,
    // memory patching, cross-process suspension or system policy changes.
    RunGroup('ImageCOWIntegrity', TestImageCOWHardening);
    RunGroup('LoaderCrossView', TestLoaderCrossViewHardening);
    RunGroup('ThreadExecutionProvenance', TestThreadExecutionHardening);
    RunGroup('ThreadStackProvenance', TestThreadStackHardening);
    RunGroup('FileAttestation', TestFileAttestationHardening);
    Writeln('PASS: Native5E assertions=', Total);
    Writeln('Synthetic tests do not certify real API delivery, concurrency or coverage.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
