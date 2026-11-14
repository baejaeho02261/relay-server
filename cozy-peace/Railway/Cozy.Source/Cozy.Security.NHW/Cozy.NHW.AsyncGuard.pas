unit Cozy.NHW.AsyncGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Logging;

type
  // Observes only the completion port, work item and timer that THIS
  // executable creates. This is not a global IOCP/threadpool inspector.
  TAsyncGuardMonitor = class
  private
    FPort: THandle;
    FOriginalPort: THandle;
    FWork: Pointer;
    FTimer: Pointer;
    FOriginalWork: Pointer;
    FOriginalTimer: Pointer;
    FWorkCallbackTicket: NativeUInt;
    FTimerCallbackTicket: NativeUInt;
    FCompletionKey: NativeUInt;
    FCompletionBytes: Cardinal;
    FSubmittedWork: Integer;
    FCompletedWork: Integer;
    FCompletedTimer: Integer;
    FBadCallbackCount: Integer;
    FLastBadCallbackCount: Integer;
    FStopping: Integer;
    FPortFaultStreak: Integer;
    FPortFaultReported: Boolean;
    FCallbackFaultStreak: Integer;
    FCallbackFaultReported: Boolean;
    FPoolFaultStreak: Integer;
    FPoolFaultReported: Boolean;
    FPortBaselineReady: Boolean;
    FOwnerMissing: TDictionary<Cardinal, Integer>;
    FAnomalyTicks: TList<UInt64>;
    FBurstReported: Boolean;
    FLastPulse: UInt64;
    FLastOwnerScan: UInt64;
    FLastWorkPost: UInt64;
    FLastExternalTick: UInt64;
    function QueryPortOwners(Current: TDictionary<Cardinal, Byte>): Boolean;
    function ObserveForeignOwners(Baseline: Boolean): Boolean;
    function ExamineCompletions(Baseline: Boolean; Tick: UInt64): Integer;
    function ExamineCallbacks(Baseline: Boolean;
      var Kinds: TDetectionKinds): Integer;
    procedure RecordAnomalies(Tick: UInt64; Count: Integer;
      var Kinds: TDetectionKinds);
    procedure StopOwnedObjects;
    procedure ClearProbeState;
    procedure CreateOwnedProbes;
    procedure ExaminePort(Baseline: Boolean; Tick: UInt64;
      var NewAnomalies: Integer; var Kinds: TDetectionKinds);
    procedure SubmitWorkProbe(Tick: UInt64);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Baseline: Boolean; Tick: UInt64;
      HighExternalAccess: Boolean; var Kinds: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5L_TESTS}
function TestAsyncGuard5L(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers,
  Cozy.NHW.AsyncRules,
  Cozy.NHW.AsyncNative;

const
  PORT_PROBE_INTERVAL_MS = 1500;
  OWNER_SNAPSHOT_INTERVAL_MS = 2500;
  WORK_PROBE_INTERVAL_MS = 3000;
  ASYNC_BURST_WINDOW_MS = 5000;
  ASYNC_CORRELATION_WINDOW_MS = 8000;
  ASYNC_BURST_THRESHOLD = 3;
  MAX_COMPLETION_POLLS = 32;
  MAX_ANOMALY_SAMPLES = 64;
  SELF_COMPLETION_BYTES = $41B0;
  COMPLETION_KEY_SALT = UInt64($5361796E634B6579);

var
  // The callbacks do not blindly dereference the supplied Context pointer.
  // A single guard is owned by the console's one monitoring engine.
  GActiveGuard: TAsyncGuardMonitor = nil;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.AsyncGuard.Hooks.inc}
{$ENDIF}

procedure OwnWorkCallback(Instance, Context, Work: Pointer); stdcall;
var
  Guard: TAsyncGuardMonitor;
begin
  Guard := GActiveGuard;
  if Guard = nil then Exit;
  if TInterlocked.CompareExchange(Guard.FStopping, 0, 0) <> 0 then Exit;
  if (Context <> Pointer(Guard)) or (Work <> Guard.FOriginalWork) then
    TInterlocked.Increment(Guard.FBadCallbackCount)
  else
    TInterlocked.Increment(Guard.FCompletedWork);
end;

procedure OwnTimerCallback(Instance, Context, Timer: Pointer); stdcall;
var
  Guard: TAsyncGuardMonitor;
begin
  Guard := GActiveGuard;
  if Guard = nil then Exit;
  if TInterlocked.CompareExchange(Guard.FStopping, 0, 0) <> 0 then Exit;
  if (Context <> Pointer(Guard)) or (Timer <> Guard.FOriginalTimer) then
    TInterlocked.Increment(Guard.FBadCallbackCount)
  else
    TInterlocked.Increment(Guard.FCompletedTimer);
end;

constructor TAsyncGuardMonitor.Create;
begin
  inherited Create;
  FPort := 0;
  FOriginalPort := 0;
  FWork := nil;
  FTimer := nil;
  FOriginalWork := nil;
  FOriginalTimer := nil;
  FOwnerMissing := TDictionary<Cardinal, Integer>.Create;
  FAnomalyTicks := TList<UInt64>.Create;
end;

destructor TAsyncGuardMonitor.Destroy;
begin
  StopOwnedObjects;
  FAnomalyTicks.Free;
  FOwnerMissing.Free;
  inherited Destroy;
end;

procedure TAsyncGuardMonitor.StopOwnedObjects;
begin
  TInterlocked.Exchange(FStopping, 1);
  // Cancel and join all registered callback invocations before releasing
  // the object whose pointer was passed as a callback context.
  if FOriginalTimer <> nil then StopPoolTimer(FOriginalTimer);
  if FOriginalWork <> nil then StopPoolWork(FOriginalWork);
  FOriginalTimer := nil;
  FOriginalWork := nil;
  FTimer := nil;
  FWork := nil;
  if GActiveGuard = Self then GActiveGuard := nil;
  if FOriginalPort <> 0 then
    WinCloseHandle(FOriginalPort);
  FOriginalPort := 0;
  FPort := 0;
end;

procedure TAsyncGuardMonitor.ClearProbeState;
begin
  FOwnerMissing.Clear;
  FAnomalyTicks.Clear;
  FPortBaselineReady := False;
  FBurstReported := False;
  FPortFaultStreak := 0;
  FPortFaultReported := False;
  FCallbackFaultStreak := 0;
  FCallbackFaultReported := False;
  FPoolFaultStreak := 0;
  FPoolFaultReported := False;
  FLastPulse := 0;
  FLastOwnerScan := 0;
  FLastWorkPost := 0;
  FLastExternalTick := 0;
  TInterlocked.Exchange(FSubmittedWork, 0);
  TInterlocked.Exchange(FCompletedWork, 0);
  TInterlocked.Exchange(FCompletedTimer, 0);
  TInterlocked.Exchange(FBadCallbackCount, 0);
  FLastBadCallbackCount := 0;
  FWorkCallbackTicket := 0;
  FTimerCallbackTicket := 0;
  FCompletionBytes := SELF_COMPLETION_BYTES;
  TInterlocked.Exchange(FStopping, 0);
end;

procedure TAsyncGuardMonitor.CreateOwnedProbes;
begin
  // Failure to acquire a self-owned probe object disables only that probe.
  // It is not an indication that another process is interfering.
  FPort := NewCompletionPort;
  FOriginalPort := FPort;
  if FPort <> 0 then
    FCompletionKey := (NativeUInt(FPort) xor NativeUInt(Self) xor
      COMPLETION_KEY_SALT)
  else
    FCompletionKey := 0;

  if AsyncPoolAvailable then
  begin
    GActiveGuard := Self;
    FWorkCallbackTicket := NativeUInt(@OwnWorkCallback);
    FTimerCallbackTicket := NativeUInt(@OwnTimerCallback);
    FWork := NewPoolWork(Pointer(FWorkCallbackTicket), Self);
    FOriginalWork := FWork;
    FTimer := NewPoolTimer(Pointer(FTimerCallbackTicket), Self);
    FOriginalTimer := FTimer;
    if FTimer <> nil then StartPoolTimer(FOriginalTimer);
  end;
end;

procedure TAsyncGuardMonitor.Reset;
begin
  StopOwnedObjects;
  ResolveAsyncNative;
  ClearProbeState;
  CreateOwnedProbes;
end;

function ParsePortOwners(const Data: TBytes; OwnedPort: THandle;
  Current: TDictionary<Cardinal, Byte>): Boolean;
var
  Entry: PNativeHandleEntry;
  Count, I: NativeUInt;
  Pid: Cardinal;
  PortObject: Pointer;
  PortObjectType: Word;
  Found: Boolean;
begin
  Result := False;
  if Length(Data) < 16 then Exit;
  Count := PNativeUInt(@Data[0])^;
  // A live owned port must have a reference in this snapshot. Reject zero
  // before subtracting one from an unsigned loop bound.
  if Count = 0 then Exit;
  if Count > NativeUInt((Length(Data) - 16) div SizeOf(TNativeHandleEntry)) then Exit;

  try
    PortObject := nil;
    PortObjectType := 0;
    Found := False;
    Entry := PNativeHandleEntry(NativeUInt(@Data[0]) + 16);
    for I := 0 to Count - 1 do
    begin
      if (Entry^.OwnerPID = NativeUInt(WinCurrentProcessId)) and
         (Entry^.HandleValue = NativeUInt(OwnedPort)) and
         (Entry^.ObjectPointer <> nil) then
      begin
        PortObject := Entry^.ObjectPointer;
        PortObjectType := Entry^.ObjectTypeIndex;
        Found := True;
        Break;
      end;
      Entry := PNativeHandleEntry(NativeUInt(Entry) + SizeOf(TNativeHandleEntry));
    end;
    if not Found then Exit;

    Entry := PNativeHandleEntry(NativeUInt(@Data[0]) + 16);
    for I := 0 to Count - 1 do
    begin
      if (Entry^.ObjectPointer = PortObject) and
         (Entry^.ObjectTypeIndex = PortObjectType) and
         (Entry^.OwnerPID <> NativeUInt(WinCurrentProcessId)) and
         (Entry^.OwnerPID > 0) and
         (Entry^.OwnerPID <= High(Cardinal)) then
      begin
        Pid := Cardinal(Entry^.OwnerPID);
        Current.AddOrSetValue(Pid, 1);
      end;
      Entry := PNativeHandleEntry(NativeUInt(Entry) + SizeOf(TNativeHandleEntry));
    end;
    Result := True;
  finally
    // Do not expose a partially assembled owner list after allocation failure.
    if not Result then Current.Clear;
  end;
end;

function TAsyncGuardMonitor.QueryPortOwners(
  Current: TDictionary<Cardinal, Byte>): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
begin
  Result := False;
  if Current = nil then Exit;
  Current.Clear;
  if (FPort = 0) or (FOriginalPort = 0) or
     (FPort <> FOriginalPort) then Exit;
  if SizeOf(TNativeHandleEntry) <> 40 then Exit;
  if not FetchSnapshot(Data, Failure) then Exit;
  Result := ParsePortOwners(Data, FOriginalPort, Current);
end;

function TAsyncGuardMonitor.ObserveForeignOwners(Baseline: Boolean): Boolean;
var
  Current: TDictionary<Cardinal, Byte>;
  OldIDs: TList<Cardinal>;
  Pid: Cardinal;
  Missing: Integer;
begin
  Result := False;
  Current := nil;
  OldIDs := nil;
  try
    // Both allocations belong to this finally, including failure of the second.
{$IFDEF NHW_NATIVE5L_TESTS}
    Current := NewAsyncOwnerMap5L;
    OldIDs := NewAsyncOwnerIDs5L;
{$ELSE}
    Current := TDictionary<Cardinal, Byte>.Create;
    OldIDs := TList<Cardinal>.Create;
{$ENDIF}
    if not QueryPortOwners(Current) then Exit;
    for Pid in Current.Keys do
    begin
      if not FOwnerMissing.ContainsKey(Pid) then
      begin
        // The first completed snapshot establishes the baseline, even if
        // the global startup-baseline phase has already elapsed.
        if FPortBaselineReady and not Baseline then Result := True;
      end;
      FOwnerMissing.AddOrSetValue(Pid, 0);
    end;
    for Pid in FOwnerMissing.Keys do OldIDs.Add(Pid);
    for Pid in OldIDs do
      if not Current.ContainsKey(Pid) then
      begin
        Missing := FOwnerMissing[Pid] + 1;
        if Missing >= 2 then FOwnerMissing.Remove(Pid)
        else FOwnerMissing.AddOrSetValue(Pid, Missing);
      end;
    FPortBaselineReady := True;
  finally
    OldIDs.Free;
    Current.Free;
  end;
end;

function TAsyncGuardMonitor.ExamineCompletions(
  Baseline: Boolean; Tick: UInt64): Integer;
var
  Bytes: Cardinal;
  Key: NativeUInt;
  Overlapped: Pointer;
  Success: Boolean;
  I: Integer;
begin
  Result := 0;
  if FPort = 0 then Exit;
  // Private heartbeat packet: a test of our own completion port.
  if (FLastPulse = 0) or (Tick - FLastPulse >= PORT_PROBE_INTERVAL_MS) then
  begin
    FLastPulse := Tick;
    if (FPort = FOriginalPort) and
       PostCompletionPacket(FOriginalPort, FCompletionBytes, FCompletionKey) then
    begin
      FPortFaultStreak := 0;
      FPortFaultReported := False;
    end
    else
      Inc(FPortFaultStreak);
  end;
  for I := 0 to MAX_COMPLETION_POLLS - 1 do
  begin
    Success := PollCompletionPacket(FOriginalPort, Bytes, Key, Overlapped);
    if not Success and (Overlapped = nil) then Break;
    if not ExpectedCompletion(Key, FCompletionKey, Bytes,
      FCompletionBytes, Overlapped) and not Baseline then
      Inc(Result);
  end;
end;

function TAsyncGuardMonitor.ExamineCallbacks(Baseline: Boolean;
  var Kinds: TDetectionKinds): Integer;
var
  Bad, Done, Sent: Integer;
  CallbackProblem, PoolProblem: Boolean;
begin
  Result := 0;
  Bad := TInterlocked.CompareExchange(FBadCallbackCount, 0, 0);
  if Bad < FLastBadCallbackCount then
    FLastBadCallbackCount := Bad;
  if Bad > FLastBadCallbackCount then
  begin
    if not Baseline then
    begin
      Include(Kinds, dkAsyncCallback);
      Result := Bad - FLastBadCallbackCount;
      if Result > MAX_ANOMALY_SAMPLES then Result := MAX_ANOMALY_SAMPLES;
    end;
    FLastBadCallbackCount := Bad;
  end;

  CallbackProblem := (FOriginalWork <> nil) and
    (FWorkCallbackTicket <> NativeUInt(@OwnWorkCallback));
  CallbackProblem := CallbackProblem or ((FOriginalTimer <> nil) and
    (FTimerCallbackTicket <> NativeUInt(@OwnTimerCallback)));
  if CallbackProblem and not Baseline then
    Inc(FCallbackFaultStreak)
  else
  begin
    FCallbackFaultStreak := 0;
    FCallbackFaultReported := False;
  end;
  if (FCallbackFaultStreak >= 2) and not FCallbackFaultReported then
  begin
    Include(Kinds, dkAsyncCallback);
    Inc(Result);
    FCallbackFaultReported := True;
  end;

  Sent := TInterlocked.CompareExchange(FSubmittedWork, 0, 0);
  Done := TInterlocked.CompareExchange(FCompletedWork, 0, 0);
  PoolProblem := not WorkCountersConsistent(Sent, Done);
  PoolProblem := PoolProblem or ((FOriginalWork <> nil) and
    (FWork <> FOriginalWork));
  PoolProblem := PoolProblem or ((FOriginalTimer <> nil) and
    (FTimer <> FOriginalTimer));
  if PoolProblem and not Baseline then
    Inc(FPoolFaultStreak)
  else
  begin
    FPoolFaultStreak := 0;
    FPoolFaultReported := False;
  end;
  if (FPoolFaultStreak >= 2) and not FPoolFaultReported then
  begin
    Include(Kinds, dkThreadpool);
    Inc(Result);
    FPoolFaultReported := True;
  end;
end;

procedure TAsyncGuardMonitor.RecordAnomalies(Tick: UInt64; Count: Integer;
  var Kinds: TDetectionKinds);
var
  I: Integer;
begin
  for I := 1 to Count do
  begin
    if FAnomalyTicks.Count >= MAX_ANOMALY_SAMPLES then
      FAnomalyTicks.Delete(0);
    FAnomalyTicks.Add(Tick);
  end;
  while (FAnomalyTicks.Count > 0) and
    ((Tick < FAnomalyTicks[0]) or
     ((Tick - FAnomalyTicks[0]) > ASYNC_BURST_WINDOW_MS)) do
    FAnomalyTicks.Delete(0);
  if (FAnomalyTicks.Count >= ASYNC_BURST_THRESHOLD) then
  begin
    if not FBurstReported then Include(Kinds, dkAsyncBurst);
    FBurstReported := True;
  end
  else
    FBurstReported := False;
end;

procedure TAsyncGuardMonitor.ExaminePort(Baseline: Boolean; Tick: UInt64;
  var NewAnomalies: Integer; var Kinds: TDetectionKinds);
var
  Observed: Boolean;
begin
  if FOriginalPort <> 0 then
  begin
    if (FPort <> FOriginalPort) and not Baseline then
      Inc(FPortFaultStreak);
    if (FLastOwnerScan = 0) or
       (Tick >= FLastOwnerScan + OWNER_SNAPSHOT_INTERVAL_MS) then
    begin
      FLastOwnerScan := Tick;
      Observed := ObserveForeignOwners(Baseline);
      if Observed then
      begin
        Include(Kinds, dkCompletionPort);
        Inc(NewAnomalies);
      end;
    end;
    if ExamineCompletions(Baseline, Tick) > 0 then
    begin
      Include(Kinds, dkCompletionKey);
      Inc(NewAnomalies);
    end;
    if (FPortFaultStreak >= 2) and not FPortFaultReported and
      not Baseline then
    begin
      Include(Kinds, dkCompletionPort);
      Inc(NewAnomalies);
      FPortFaultReported := True;
    end;
  end;
end;

procedure TAsyncGuardMonitor.SubmitWorkProbe(Tick: UInt64);
begin
  if FOriginalWork <> nil then
    if (FLastWorkPost = 0) or
       (Tick >= FLastWorkPost + WORK_PROBE_INTERVAL_MS) then
    begin
      FLastWorkPost := Tick;
      // Increment BEFORE posting: a callback may run immediately.
      TInterlocked.Increment(FSubmittedWork);
      PostPoolWork(FOriginalWork);
    end;
end;

procedure TAsyncGuardMonitor.Examine(Baseline: Boolean; Tick: UInt64;
  HighExternalAccess: Boolean; var Kinds: TDetectionKinds);
var
  NewAnomalies: Integer;
begin
  if HighExternalAccess and not Baseline then
    FLastExternalTick := Tick;
  NewAnomalies := 0;

  ExaminePort(Baseline, Tick, NewAnomalies, Kinds);

  SubmitWorkProbe(Tick);

  Inc(NewAnomalies, ExamineCallbacks(Baseline, Kinds));
  if Baseline then Exit;
  RecordAnomalies(Tick, NewAnomalies, Kinds);
  if (NewAnomalies > 0) and
    InRecentWindow(Tick, FLastExternalTick,
      ASYNC_CORRELATION_WINDOW_MS) then
    Include(Kinds, dkAsyncCorrelation);
end;

{$IFDEF NHW_NATIVE5L_TESTS}
{$I Cozy.NHW.Native5L.AsyncGuard.inc}
{$ENDIF}

end.
