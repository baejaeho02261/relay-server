program CozyNHWRuntimeProbe;

{$APPTYPE CONSOLE}
{$B-}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'NHW_RUNTIME_PROBE_WIN64_REQUIRED'}
{$ENDIF}
{$IFNDEF RELEASE}
  {$MESSAGE FATAL 'NHW_RUNTIME_PROBE_RELEASE_REQUIRED'}
{$ENDIF}
{$IF CompilerVersion < 37.0}
  {$MESSAGE FATAL 'NHW_RUNTIME_PROBE_RAD13_REQUIRED'}
{$IFEND}

uses
  Winapi.Windows,
  System.SysUtils,
  System.JSON,
  Cozy.NHW.Guard,
  Cozy.NHW.ClientGuard,
  Cozy.NHW.DualObserver,
  Cozy.NHW.Validation.Process in '..\Cozy.NHW.Validation\Cozy.NHW.Validation.Process.pas';

const
  DefaultDurationMS = 7200000;
  MaximumDurationMS = 86400000;
  ShutdownBudgetMS = 4000;
  FirstCycleBudgetMS = 90000;
  MaximumKernelAgeMS = 90000;

function RoleName(Role: TCozyNHWRole): string;
begin
  case Role of
    nrLauncher: Result := 'A';
    nrClient: Result := 'B';
    nrOverlay: Result := 'O';
  else
    Result := '?';
  end;
end;

function ParseRole(const Text: string): TCozyNHWRole;
begin
  if Text = 'A' then Exit(nrLauncher);
  if Text = 'B' then Exit(nrClient);
  if Text = 'O' then Exit(nrOverlay);
  raise Exception.Create('Role must be A, B or O');
end;

function ReadDuration(const Text: string): Cardinal;
var Value: Integer;
begin
  if not TryStrToInt(Text, Value) or (Value < 10000) or
    (Value > MaximumDurationMS) then
    raise Exception.Create('Duration must be 10000..86400000 milliseconds');
  Result := Cardinal(Value);
end;

function ConsoleControl(Code: Cardinal): BOOL; stdcall;
begin
  Result := (Code = CTRL_C_EVENT) or (Code = CTRL_BREAK_EVENT);
  if Result then RequestValidationStop;
end;

procedure Emit(Document: TJSONObject);
begin
  try
    Writeln(Document.ToJSON);
    Flush(Output);
  finally
    Document.Free;
  end;
end;

function NewRecord(const Event: string; Role: TCozyNHWRole): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('schema', 'COZY_NHW_RUNTIME_PROBE_V1');
  Result.AddPair('event', Event);
  Result.AddPair('role', RoleName(Role));
  Result.AddPair('scope', 'SHARED_NHW_GUARD');
  Result.AddPair('platform', 'win32');
  Result.AddPair('architecture', 'x64');
  Result.AddPair('compilerVersion', FloatToStr(CompilerVersion, TFormatSettings.Invariant));
end;

procedure RunGuardChild(Role: TCozyNHWRole; DurationMS: Cardinal);
var
  Guard: TCozyNHWClientGuard;
  State: TCozyNHWKernelState;
  Started, NowTick, LastKernel, Samples, StaleSamples, ShutdownStarted,
    ShutdownElapsed, DurationElapsed: UInt64;
  Confirmed, DurationReached, StartupFailed, Cancelled: Boolean;
  ObserverStatusRead: Boolean;
  ObserverShutdown: TObserverShutdownStatus;
  RecordValue: TJSONObject;
begin
  Guard := nil;
  Samples := 0;
  StaleSamples := 0;
  LastKernel := 0;
  Confirmed := False;
  DurationReached := False;
  StartupFailed := False;
  Cancelled := False;
  ShutdownElapsed := 0;
  DurationElapsed := 0;
  ObserverStatusRead := False;
  ObserverShutdown := Default(TObserverShutdownStatus);
  ExitCode := 1;
  if not SetConsoleCtrlHandler(@ConsoleControl, True) then RaiseLastOSError;
  try
    Guard := TCozyNHWClientGuard.Create(Role);
    Started := GetTickCount64;
    RecordValue := NewRecord('started', Role);
    RecordValue.AddPair('requestedDurationMs', TJSONNumber.Create(Int64(DurationMS)));
    RecordValue.AddPair('fullEngine', TJSONBool.Create(True));
    Emit(RecordValue);
    try
      Guard.Start;
      repeat
        NowTick := GetTickCount64;
        Confirmed := Guard.Confirmed;
        if Confirmed then Break;
        Cancelled := ValidationStopRequested;
        if Cancelled then Break;
        if Guard.TryReadKernelState(State) then
        begin
          if (State.Tick > NowTick) or (NowTick - State.Tick > MaximumKernelAgeMS) then
          begin
            Inc(StaleSamples);
            Break;
          end;
          if State.Tick <> LastKernel then
          begin
            LastKernel := State.Tick;
            Inc(Samples);
          end;
        end
        else if NowTick - Started > FirstCycleBudgetMS then
        begin
          StartupFailed := True;
          Break;
        end;
        DurationElapsed := NowTick - Started;
        DurationReached := DurationElapsed >= DurationMS;
        if DurationReached then Break;
        Sleep(50);
      until False;
    finally
      DurationElapsed := GetTickCount64 - Started;
      ShutdownStarted := GetTickCount64;
      RecordValue := NewRecord('shutdown-begin', Role);
      Emit(RecordValue);
      Guard.RequestStop;
      Guard.StopChildObservers;
      Guard.StopAndJoin;
      Confirmed := Confirmed or Guard.Confirmed;
      ObserverStatusRead := Guard.ReadChildShutdownStatus(ObserverShutdown);
      FreeAndNil(Guard);
      ShutdownElapsed := GetTickCount64 - ShutdownStarted;
    end;
    if DurationReached and not Confirmed and not Cancelled and not StartupFailed and
      (Samples >= 2) and (StaleSamples = 0) and
      (ShutdownElapsed <= ShutdownBudgetMS) and ObserverStatusRead and
      ObserverShutdown.HadChild and ObserverShutdown.ExitObserved and
      not ObserverShutdown.ForcedTerminationRequested then ExitCode := 0;
    RecordValue := NewRecord('guard-result', Role);
    RecordValue.AddPair('requestedDurationMs', TJSONNumber.Create(Int64(DurationMS)));
    RecordValue.AddPair('durationMs', TJSONNumber.Create(Int64(DurationElapsed)));
    RecordValue.AddPair('shutdownMs', TJSONNumber.Create(Int64(ShutdownElapsed)));
    RecordValue.AddPair('kernelSamples', TJSONNumber.Create(Int64(Samples)));
    RecordValue.AddPair('staleKernelSamples', TJSONNumber.Create(Int64(StaleSamples)));
    RecordValue.AddPair('falsePositiveConfirmed', TJSONBool.Create(Confirmed));
    RecordValue.AddPair('durationReached', TJSONBool.Create(DurationReached));
    RecordValue.AddPair('startupFailed', TJSONBool.Create(StartupFailed));
    RecordValue.AddPair('cancelled', TJSONBool.Create(Cancelled));
    RecordValue.AddPair('observerChildStarted', TJSONBool.Create(ObserverStatusRead and ObserverShutdown.HadChild));
    RecordValue.AddPair('observerForcedTermination', TJSONBool.Create(ObserverShutdown.ForcedTerminationRequested));
    RecordValue.AddPair('observerExitObserved', TJSONBool.Create(ObserverStatusRead and ObserverShutdown.ExitObserved));
    RecordValue.AddPair('observerShutdownMs', TJSONNumber.Create(Int64(ObserverShutdown.ElapsedMs)));
    RecordValue.AddPair('exitCode', TJSONNumber.Create(ExitCode));
    RecordValue.AddPair('actualAboExecuted', TJSONBool.Create(False));
    Emit(RecordValue);
  finally
    Guard.Free;
    SetConsoleCtrlHandler(@ConsoleControl, False);
  end;
end;

function RunGuardParent(Role: TCozyNHWRole; DurationMS: Cardinal): Boolean;
var
  Run: TValidationRun;
  RecordValue: TJSONObject;
  Arguments: string;
begin
  Arguments := '--child-role=' + RoleName(Role) + ' --duration-ms=' + UIntToStr(DurationMS);
  // The existing runner places only its created child tree in an owned job.
  // A hung WMI query/ETW drain cannot hang this parent or count as success.
  Run := RunValidationChild(ExpandFileName(ParamStr(0)), Arguments,
    DurationMS + FirstCycleBudgetMS + ShutdownBudgetMS + 1000, False);
  if Run.Output <> '' then Write(string(Run.Output));
  Result := Run.Started and Run.Exited and (Run.ExitCode = 0) and
    not Run.TimedOut and not Run.Cancelled and not Run.ForcedTermination and
    not Run.DescendantsForced and Run.JobDrained and not Run.OutputReadError and
    not Run.OutputTruncated and (Run.ErrorText = '');
  RecordValue := NewRecord('parent-result', Role);
  RecordValue.AddPair('nativeExited', TJSONBool.Create(Run.Exited));
  RecordValue.AddPair('ownedJobDrained', TJSONBool.Create(Run.JobDrained));
  RecordValue.AddPair('forcedTermination', TJSONBool.Create(Run.ForcedTermination or Run.DescendantsForced));
  RecordValue.AddPair('timedOut', TJSONBool.Create(Run.TimedOut));
  RecordValue.AddPair('elapsedMs', TJSONNumber.Create(Int64(Run.ElapsedMS)));
  RecordValue.AddPair('exitCode', TJSONNumber.Create(Int64(Run.ExitCode)));
  if Result then RecordValue.AddPair('outcome', 'PASS')
  else RecordValue.AddPair('outcome', 'FAIL');
  RecordValue.AddPair('actualAboExecuted', TJSONBool.Create(False));
  Emit(RecordValue);
end;

var
  Role, CurrentRole: TCozyNHWRole;
  DurationMS: Cardinal;
  Child, AllRoles, OK: Boolean;
  I: Integer;
  Argument: string;
begin
  if TryRunObserverMode then Exit;
  Role := nrClient;
  DurationMS := DefaultDurationMS;
  Child := False;
  AllRoles := True;
  try
    for I := 1 to ParamCount do
    begin
      Argument := ParamStr(I);
      if Copy(Argument, 1, 13) = '--child-role=' then
      begin
        Child := True; AllRoles := False;
        Role := ParseRole(Copy(Argument, 14, MaxInt));
      end
      else if Copy(Argument, 1, 7) = '--role=' then
      begin
        AllRoles := False;
        Role := ParseRole(Copy(Argument, 8, MaxInt));
      end
      else if Argument = '--all-roles' then AllRoles := True
      else if Copy(Argument, 1, 14) = '--duration-ms=' then
        DurationMS := ReadDuration(Copy(Argument, 15, MaxInt))
      else raise Exception.Create('Use --role=A|B|O or --all-roles and --duration-ms=7200000');
    end;
    if Child then RunGuardChild(Role, DurationMS)
    else
    begin
      SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
      if not SetConsoleCtrlHandler(@ConsoleControl, True) then RaiseLastOSError;
      try
        OK := True;
        if AllRoles then
          for CurrentRole := Low(TCozyNHWRole) to High(TCozyNHWRole) do
          begin
            if not RunGuardParent(CurrentRole, DurationMS) then OK := False;
            if ValidationStopRequested then Break;
          end
        else OK := RunGuardParent(Role, DurationMS);
        if OK and not ValidationStopRequested then ExitCode := 0 else ExitCode := 1;
      finally
        SetConsoleCtrlHandler(@ConsoleControl, False);
      end;
    end;
  except
    on E: Exception do
    begin
      Writeln('NHW_RUNTIME_PROBE_ERROR ', E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.
