program CozyNHW_Native5F_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5F_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5F.Tests.dproj; the define must apply to all units.'}
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
  Cozy.NHW.PECodeIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.PECodeIntegrity.pas',
  Cozy.NHW.ImportRedirection in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ImportRedirection.pas',
  Cozy.NHW.TLSCallbackIntegrity in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.TLSCallbackIntegrity.pas',
  Cozy.NHW.UnwindConsistency in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.UnwindConsistency.pas',
  Cozy.NHW.MemoryDelta in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.MemoryDelta.pas';
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
    // All five groups supply local synthetic views/readers. Do not run
    // NHW.Engine or concurrent sensors here; these hooks are test-only.
    RunGroup('PECodeIntegrity', TestPECodeHardening);
    RunGroup('ImportRedirection', TestImportHardening);
    RunGroup('TLSCallbackIntegrity', TestTLSHardening);
    RunGroup('UnwindConsistency', TestUnwindHardening);
    RunGroup('MemoryDelta', TestMemoryDeltaHardening);
    Writeln('PASS: Native5F assertions=', Total);
    Writeln('Synthetic tests do not certify live API races, timing or complete coverage.');
  except
    on E: Exception do
    begin Writeln('FAIL: ', E.Message); ExitCode := 1; end;
  end;
end.
