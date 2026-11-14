program CozyNHW_ETWFusion_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Win64 only'}
{$ENDIF}

uses
  System.SysUtils,
  Cozy.NHW.ETWTypes in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWTypes.pas',
  Cozy.NHW.ETWFusion in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.ETWFusion.pas',
  Cozy.NHW.Lifecycle in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Lifecycle.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.WinPointers in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.WinPointers.pas';

procedure Check(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('Fusion regression failure');
end;

function E(Kind: TKernelEventKind; PID, ThreadID, ParentPID: Cardinal;
  Tick: UInt64): TKernelEvent;
begin
  Result := Default(TKernelEvent);
  Result.Kind := Kind;
  Result.PID := PID;
  Result.ThreadID := ThreadID;
  Result.ParentPID := ParentPID;
  Result.Tick := Tick;
end;

var
  M: TETWFusion;
  Events: TKernelEventList;
  Threads: TThreadSampleMap;
  OutKinds: TDetectionKinds;
begin
  M := TETWFusion.Create;
  Events := TKernelEventList.Create;
  Threads := TThreadSampleMap.Create;
  try
    Events.Add(E(keThreadStart, 200, 300, 0, 1000));
    Events.Add(E(keThreadEnd, 200, 300, 0, 1050));
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, False, True, False, 1100, OutKinds);
    Check(OutKinds = []);  // no startup false positives

    M.Reset;
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, False, False, False, 1100, OutKinds);
    Check(dkTransientThread in OutKinds);
    Check(not (dkProcessLifetime in OutKinds));

    Events.Clear;
    M.Reset;
    Events.Add(E(keProcessStart, 501, 0, 200, 2000));
    Events.Add(E(keProcessEnd, 501, 0, 0, 2300));
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, False, False, False, 2400, OutKinds);
    Check(dkProcessLifetime in OutKinds);

    Events.Clear;
    M.Reset;
    Events.Add(E(keFileIO, 900, 0, 0, 3000));
    Events.Add(E(keRegistryActivity, 900, 0, 0, 3000));
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, True, False, True, 3100, OutKinds);
    // A batch spanning a known loss is not valid correlation evidence.
    Check(OutKinds = [dkTraceGap]);

    // The pre-loss batch is still stale even when the next call is healthy.
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, False, False, False, 3200, OutKinds);
    Check(OutKinds = []);

    // A genuinely fresh batch can produce the original file/registry evidence.
    Events.Clear;
    Events.Add(E(keFileIO, 900, 0, 0, 3300));
    Events.Add(E(keRegistryActivity, 900, 0, 0, 3300));
    OutKinds := [];
    M.Examine(Events, 200, Threads, True, True, False, False, 3400, OutKinds);
    Check(dkKernelFileIO in OutKinds);
    Check(dkKernelRegistry in OutKinds);
    Check(dkEventFusion in OutKinds);
    Check(not (dkTraceGap in OutKinds));
  finally
    Threads.Free;
    Events.Free;
    M.Free;
  end;
end.
