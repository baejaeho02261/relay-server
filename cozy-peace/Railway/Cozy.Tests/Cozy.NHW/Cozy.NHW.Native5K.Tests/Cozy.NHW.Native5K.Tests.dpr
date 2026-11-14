program CozyNHW_Native5K_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5K_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5K.Tests.dproj so the test define applies to every unit.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.WCTNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WCTNative.pas',
  Cozy.NHW.WaitChainRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WaitChainRules.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.SelfRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfRules.pas',
  Cozy.NHW.SelfNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfNative.pas',
  Cozy.NHW.ThreadOriginNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ThreadOriginNative.pas',
  Cozy.NHW.ETW in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETW.pas',
  Cozy.NHW.ExceptionRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionRules.pas',
  Cozy.NHW.ExceptionNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionNative.pas',
  Cozy.NHW.FileNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileNative.pas',
  Cozy.NHW.ControlFlowAttestation in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ControlFlowAttestation.pas',
  Cozy.NHW.ModuleOriginVerification in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ModuleOriginVerification.pas',
  Cozy.NHW.ProcessSnapshot in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ProcessSnapshot.pas',
  Cozy.NHW.WaitChain in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WaitChain.pas',
  Cozy.NHW.SelfGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.SelfGuard.pas',
  Cozy.NHW.ExceptionGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ExceptionGuard.pas',
  Cozy.NHW.FileGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.FileGuard.pas',
  Cozy.NHW.EventDrivenWake in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.EventDrivenWake.pas';
type TTestGroup = function(out Failure: string; out Checks: Integer): Boolean;
var Total: Integer;
procedure RunGroup(const Name: string; Test: TTestGroup);
var Failure: string; Checks: Integer;
begin
  if not Test(Failure, Checks) then raise Exception.Create(Name + ': ' + Failure);
  Inc(Total, Checks); Writeln('PASS: ', Name, ' assertions=', Checks);
end;
begin
  Total := 0;
  try
    RunGroup('WaitChain', TestWaitChain5K);
    RunGroup('SelfGuard', TestSelfGuard5K);
    RunGroup('ExceptionGuard', TestExceptionGuard5K);
    RunGroup('FileGuard', TestFileGuard5K);
    RunGroup('EventDrivenWake', TestEventDrivenWake5K);
    Writeln('PASS: Native5K assertions=', Total);
    Writeln('Synthetic checks do not certify real Windows callback timing or complete observation.');
  except on E: Exception do begin Writeln('FAIL: ', E.Message); ExitCode := 1; end; end;
end.
