program CozyNHW_Native5L_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Build with Delphi Win64.'}
{$ENDIF}
{$IFNDEF NHW_NATIVE5L_TESTS}
  {$MESSAGE FATAL 'Open Cozy.NHW.Native5L.Tests.dproj so the test define applies to every unit.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.Capture in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Capture.pas',
  Cozy.NHW.AsyncGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.AsyncGuard.pas',
  Cozy.NHW.HeapTLS in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.HeapTLS.pas',
  Cozy.NHW.ProtectionGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ProtectionGuard.pas',
  Cozy.NHW.NetworkGuard in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.NetworkGuard.pas';
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
    RunGroup('Capture', TestCapture5L);
    RunGroup('AsyncGuard', TestAsyncGuard5L);
    RunGroup('HeapTLS', TestHeapTLS5L);
    RunGroup('ProtectionGuard', TestProtectionGuard5L);
    RunGroup('NetworkGuard', TestNetworkGuard5L);
    Writeln('PASS: Native5L assertions=', Total);
    Writeln('Synthetic tests do not certify Windows callback timing or full runtime coverage.');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
