program CozyNHW_Native5I_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5I_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5I.Tests.dproj; the define must apply to all units.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.NativeSafety in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NativeSafety.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.AllocationNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AllocationNative.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.ReadRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadRules.pas',
  Cozy.NHW.WriteRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteRules.pas',
  Cozy.NHW.WriteWatchNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteWatchNative.pas',
  Cozy.NHW.ReadCanaryNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadCanaryNative.pas',
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.SignalCorrelation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SignalCorrelation.pas',
  Cozy.NHW.BehaviorFingerprint in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.BehaviorFingerprint.pas',
  Cozy.NHW.ETWImageFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWImageFusion.pas',
  Cozy.NHW.WriteWatch in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WriteWatch.pas',
  Cozy.NHW.ReadAccess in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ReadAccess.pas',
  Cozy.NHW.RealtimeBenchmark in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.RealtimeBenchmark.pas';
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
    // No Engine, real ETW session, foreign process access or disk evidence.
    // Dedicated memory read/guard operations are replaced with test-only hooks.
    RunGroup('BehaviorFingerprint', TestBehavior5I);
    RunGroup('ETWImageFusion', TestETWImage5I);
    RunGroup('WriteWatch', TestWriteWatch5I);
    RunGroup('ReadAccess', TestReadAccess5I);
    RunGroup('RealtimeBenchmark', TestBenchmark5I);
    Writeln('PASS: Native5I assertions=', Total);
    Writeln('Synthetic tests do not certify real scheduling, ETW completeness or race freedom.');
  except
    on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
