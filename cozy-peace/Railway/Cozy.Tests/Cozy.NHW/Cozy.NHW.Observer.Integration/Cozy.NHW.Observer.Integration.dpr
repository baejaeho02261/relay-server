program Cozy_NHW_Observer_Integration;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'WIN64_REQUIRED'}{$ENDIF}
{$B-}

uses
  Winapi.Windows, System.SysUtils,
  Cozy.NHW.DualObserver, Cozy.NHW.Logging,
  Cozy.NHW.Observer.Protocol,
  Cozy.NHW.Observer.Launch,
  Cozy.NHW.ObserverAuthenticator;

procedure Check(Value: Boolean; const MessageText: string);
begin
  if not Value then raise Exception.Create(MessageText);
end;

procedure RejectUnownedInvocation;
var Startup: TStartupInfo; Process: TProcessInformation;
  CommandLine, Exe: string; Code: DWORD;
begin
  Startup := Default(TStartupInfo); Startup.cb := SizeOf(Startup);
  Process := Default(TProcessInformation);
  Exe := ExpandFileName(ParamStr(0));
  CommandLine := '"' + Exe + '" --cozy-nhw-observer 0 0';
  UniqueString(CommandLine);
  Check(CreateProcessW(PWideChar(Exe), PWideChar(CommandLine), nil, nil,
    False, CREATE_NO_WINDOW, nil, nil, Startup, Process), 'invalid-child create failed');
  try
    Check(WaitForSingleObject(Process.hProcess, 5000) = WAIT_OBJECT_0,
      'invalid inherited capability did not exit');
    Check(GetExitCodeProcess(Process.hProcess, Code) and (Code <> 0),
      'invalid inherited capability accepted');
  finally
    if WaitForSingleObject(Process.hProcess, 0) = WAIT_TIMEOUT then
    begin TerminateProcess(Process.hProcess, 1); WaitForSingleObject(Process.hProcess, 1000); end;
    CloseHandle(Process.hThread); CloseHandle(Process.hProcess);
  end;
end;

procedure RunChecks;
var Guard: TDualObserver; Child: THandle; HandleValue: THandle;
  Started, Stopped, NowTick: UInt64; Ready, Available: Boolean;
  Evidence: TObserverSessionEvidence; Kinds: Cozy.NHW.Logging.TDetectionKinds;
  Shutdown: TObserverShutdownStatus;
begin
  Check(not ObserverHandleArgument('', HandleValue), 'empty handle accepted');
  Check(not ObserverHandleArgument('-1', HandleValue), 'pseudo handle accepted');
  Check(not ObserverHandleArgument('0', HandleValue), 'null handle accepted');
  Check(not ObserverHandleArgument(' 12', HandleValue), 'padded handle accepted');
  Check(not ObserverHandleArgument('18446744073709551615', HandleValue), 'overflow handle accepted');
  RejectUnownedInvocation;
  Guard := TDualObserver.Create; Child := 0;
  try
    Check(Guard.Start, 'authenticated observer could not start');
    Child := OpenProcess(OBSERVER_QUERY_LIMITED or SYNCHRONIZE, False, Guard.ObserverPID);
    Check(Child <> 0, 'owned child handle unavailable');
    Ready := False; Started := ObserverClockTick;
    repeat
      NowTick := ObserverClockTick; Kinds := [];
      Guard.Examine(False, NowTick, Kinds);
      Check(Kinds = [], 'healthy observer produced detection');
      if Guard.Ready then begin Ready := True; Break; end;
      Sleep(25);
    until ObserverClockTick - Started >= 5000;
    Check(Ready, 'authenticated observer heartbeat unavailable');
    Check(Guard.SnapshotReport(ObserverClockTick, Evidence, Available) and Available,
      'authenticated observer proof missing');
    Check((Evidence.OwnerPID = GetCurrentProcessId) and
      (Evidence.ObserverPID = Guard.ObserverPID) and (Evidence.State = 1),
      'observer proof identity mismatch');
    Started := ObserverClockTick;
    Guard.RequestStop; Guard.Stop;
    Stopped := ObserverClockTick - Started;
    Check(WaitForSingleObject(Child, 500) = WAIT_OBJECT_0, 'owned observer still running after stop');
    Check(Stopped <= 2500, 'owned observer shutdown exceeded budget');
    Check(Guard.ReadShutdownStatus(Shutdown) and Shutdown.HadChild and
      Shutdown.AuthenticatedReportObserved and Shutdown.ExitObserved and
      not Shutdown.ForcedTerminationRequested, 'observer required forced or unobserved cleanup');
    Check(not Guard.Ready, 'stopped observer still reports ready');
    Check(not Guard.Start, 'one-use retired observer restarted');
    Writeln('PASS authenticated observer, invalid launch, identity, stop ms=', Stopped);
  finally
    Guard.Free;
    if Child <> 0 then CloseHandle(Child);
  end;
end;

begin
  ExitCode := 1;
  try
    if TryRunObserverMode then Exit;
    RunChecks;
    ExitCode := 0;
  except
    on E: Exception do
    begin Writeln('FAIL ', E.Message); ExitCode := 1; end;
  end;
end.
