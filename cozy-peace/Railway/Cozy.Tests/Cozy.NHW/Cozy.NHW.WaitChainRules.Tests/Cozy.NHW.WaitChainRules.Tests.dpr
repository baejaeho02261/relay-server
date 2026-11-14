program CozyNHW_WaitChainRules_Tests;
{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 test only.'}
{$ENDIF}
uses
  System.SysUtils,
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas',
  Cozy.NHW.WCTNative in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WCTNative.pas',
  Cozy.NHW.WaitChainRules in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WaitChainRules.pas';

var
  Nodes: array[0..2] of TWaitChainNode;
  Facts: TWaitFacts;
  N: PWaitThreadNode;
begin
  try
    if SizeOf(TWaitChainNode) <> 280 then raise Exception.Create('ABI');
    FillChar(Nodes, SizeOf(Nodes), 0);
    Nodes[0].ObjectType := WCT_OBJECT_THREAD;
    Nodes[0].ObjectStatus := WCT_STATUS_BLOCKED;
    N := PWaitThreadNode(@Nodes[0].Payload[0]);
    N^.ProcessId := 123;
    N^.ThreadId := 111;
    Nodes[1].ObjectType := WCT_OBJECT_CRITICAL_SECTION;
    Nodes[1].ObjectStatus := 6; // WctStatusOwned
    Nodes[2].ObjectType := WCT_OBJECT_THREAD;
    Nodes[2].ObjectStatus := 2; // WctStatusRunning
    N := PWaitThreadNode(@Nodes[2].Payload[0]);
    N^.ProcessId := 123;
    N^.ThreadId := 456;
    if not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts) or
       not Facts.SameProcessOwner or not Facts.CriticalSection then
      raise Exception.Create('local wait');
    N^.ProcessId := 987;
    if not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts) or
       not Facts.ExternalOwner then raise Exception.Create('external wait');
    Nodes[1].ObjectStatus := WCT_STATUS_NO_ACCESS;
    if ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts) then
      raise Exception.Create('partial chain');
    Writeln('PASS');
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
