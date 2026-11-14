unit Cozy.NHW.ThreadOrigin;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.ThreadOriginNative,
  Cozy.NHW.Logging;

type
  TThreadOriginState = record
    CreateTime: UInt64;
    FirstSeenTick: UInt64;
    LastQueryTick: UInt64;
    QueryAttempted: Boolean;
    StartKnown: Boolean;
    StartEvaluated: Boolean;
    OriginEligible: Boolean; // created AFTER the startup baseline
    Region: TThreadOriginRegion;
  end;

  TThreadOriginMonitor = class
  private
    // Last Examine only: known failed collection, not a throttled/pending pass.
    FObservationFailed: Boolean;
    FKnown: TDictionary<Cardinal, TThreadOriginState>;
    FRecentStart: TDictionary<Cardinal, UInt64>;
    FSpawnTimes: TList<UInt64>;
    FLastBurstTick: UInt64;
    FLastCreateAccess: UInt64;
    FLastSuspiciousOriginTick: UInt64;
    FPrimed: Boolean;
    procedure CountSpawn(ThreadID: Cardinal; EventTick, Tick: UInt64;
      Baseline: Boolean);
    procedure ExpireSpawnHistory(Tick: UInt64);
    procedure SynchronizeVisibleThreads(const Threads: TThreadSampleMap;
      Baseline: Boolean; Tick: UInt64);
    procedure InspectThreadOrigin(TargetPID, Key: Cardinal;
      ProcessHandle: THandle; Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure ReportSpawnBurst(Baseline: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds);
  public
    property ObservationFailed: Boolean read FObservationFailed;
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(TargetPID: Cardinal; const Threads: TThreadSampleMap;
      ThreadsValid: Boolean; const Events: TKernelEventList;
      Tick: UInt64; Baseline, FreshCreateThreadAccess: Boolean;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestThreadOrigin10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.Types,
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers,
  System.Generics.Defaults;

const
  MAX_ORIGIN_QUERIES_PER_SCAN = 64;
  REGION_RESAMPLE_MS = 1500;
  START_OBSERVATION_WINDOW_MS = 3000;
  THREAD_SPAWN_WINDOW_MS = 2000;
  THREAD_SPAWN_THRESHOLD = 8;
  THREAD_SPAWN_COOLDOWN_MS = 3000;
  EXTERNAL_CREATE_CORRELATION_MS = 3000;

type
  TOriginQueryCandidate = record
    ThreadID: Cardinal;
    Attempted: Boolean;
    LastTick: UInt64;
  end;

function OriginQueryOrder(const Known: TDictionary<Cardinal, TThreadOriginState>;
  Tick: UInt64): TArray<Cardinal>;
var
  Candidates: TList<TOriginQueryCandidate>;
  Entry: TPair<Cardinal, TThreadOriginState>;
  C: TOriginQueryCandidate;
  I: Integer;
begin
  Result := nil;
  Candidates := TList<TOriginQueryCandidate>.Create;
  try
    for Entry in Known do
    begin
      if Entry.Value.QueryAttempted then
      begin
        // Never spend the native-call budget twice at the same observation tick.
        if Tick = Entry.Value.LastQueryTick then Continue;
        if Entry.Value.StartKnown and (Tick > Entry.Value.LastQueryTick) and
           (Tick - Entry.Value.LastQueryTick < REGION_RESAMPLE_MS) then Continue;
      end;
      C.ThreadID := Entry.Key;
      C.Attempted := Entry.Value.QueryAttempted;
      C.LastTick := Entry.Value.LastQueryTick;
      Candidates.Add(C);
    end;
    Candidates.Sort(TComparer<TOriginQueryCandidate>.Construct(
      function(const L, R: TOriginQueryCandidate): Integer
      begin
        if L.Attempted <> R.Attempted then
        begin
          if L.Attempted then Exit(1) else Exit(-1);
        end;
        if L.LastTick < R.LastTick then Exit(-1);
        if L.LastTick > R.LastTick then Exit(1);
        if L.ThreadID < R.ThreadID then Exit(-1);
        if L.ThreadID > R.ThreadID then Exit(1);
        Result := 0;
      end));
    I := Candidates.Count;
    if I > MAX_ORIGIN_QUERIES_PER_SCAN then I := MAX_ORIGIN_QUERIES_PER_SCAN;
    SetLength(Result, I);
    for I := 0 to Length(Result) - 1 do Result[I] := Candidates[I].ThreadID;
  finally
    Candidates.Free;
  end;
end;

constructor TThreadOriginMonitor.Create;
begin
  inherited Create;
  FKnown := TDictionary<Cardinal, TThreadOriginState>.Create;
  FRecentStart := TDictionary<Cardinal, UInt64>.Create;
  FSpawnTimes := TList<UInt64>.Create;
  Reset;
end;

destructor TThreadOriginMonitor.Destroy;
begin
  FSpawnTimes.Free;
  FRecentStart.Free;
  FKnown.Free;
  inherited Destroy;
end;

procedure TThreadOriginMonitor.Reset;
begin
  FObservationFailed := False;
  FKnown.Clear;
  FRecentStart.Clear;
  FSpawnTimes.Clear;
  FLastBurstTick := 0;
  FLastCreateAccess := 0;
  FLastSuspiciousOriginTick := 0;
  FPrimed := False;
end;

procedure TThreadOriginMonitor.CountSpawn(ThreadID: Cardinal;
  EventTick, Tick: UInt64; Baseline: Boolean);
var
  Previous: UInt64;
begin
  if Baseline or (ThreadID = 0) or (EventTick > Tick) then Exit;
  if Tick - EventTick > THREAD_SPAWN_WINDOW_MS then Exit;
  if FRecentStart.TryGetValue(ThreadID, Previous) and
     (EventTick >= Previous) and
     (EventTick - Previous < THREAD_SPAWN_WINDOW_MS) then Exit;
  FRecentStart.AddOrSetValue(ThreadID, EventTick);
  FSpawnTimes.Add(EventTick);
end;

procedure TThreadOriginMonitor.ExpireSpawnHistory(Tick: UInt64);
var
  I: Integer;
  Keys: TList<Cardinal>;
  Item: TPair<Cardinal, UInt64>;
begin
  for I := FSpawnTimes.Count - 1 downto 0 do
    if (Tick < FSpawnTimes[I]) or
       (Tick - FSpawnTimes[I] > THREAD_SPAWN_WINDOW_MS) then
      FSpawnTimes.Delete(I);
  Keys := TList<Cardinal>.Create;
  try
    for Item in FRecentStart do
      if (Tick >= Item.Value) and
         (Tick - Item.Value > THREAD_SPAWN_WINDOW_MS) then
        Keys.Add(Item.Key);
    for I := 0 to Keys.Count - 1 do
      FRecentStart.Remove(Keys[I]);
  finally
    Keys.Free;
  end;
end;

procedure TThreadOriginMonitor.SynchronizeVisibleThreads(const Threads: TThreadSampleMap;
  Baseline: Boolean; Tick: UInt64);
var
  Pair: TPair<Cardinal, TThreadSample>;
  Existing: TThreadOriginState;
  NewThread: Boolean;
  KnownKeys: TList<Cardinal>;
  Entry: TPair<Cardinal, TThreadOriginState>;
  I: Integer;
begin
  // Seed every visible ID before choosing the bounded query set. Failed
  // reads also get an attempt time, so inaccessible IDs cannot monopolize it.
  for Pair in Threads do
  begin
    NewThread := not FKnown.TryGetValue(Pair.Key, Existing);
    if NewThread then
    begin
      Existing := Default(TThreadOriginState);
      Existing.FirstSeenTick := Tick;
      Existing.OriginEligible := (not Baseline) and FPrimed;
      CountSpawn(Pair.Key, Tick, Tick, Baseline or not FPrimed);
      FKnown.Add(Pair.Key, Existing);
    end;
  end;
  KnownKeys := TList<Cardinal>.Create;
  try
    for Entry in FKnown do
      if not Threads.ContainsKey(Entry.Key) then KnownKeys.Add(Entry.Key);
    for I := 0 to KnownKeys.Count - 1 do FKnown.Remove(KnownKeys[I]);
  finally
    KnownKeys.Free;
  end;
end;

procedure TThreadOriginMonitor.InspectThreadOrigin(TargetPID, Key: Cardinal;
  ProcessHandle: THandle; Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Existing: TThreadOriginState;
  Current: TThreadOriginRegion;
  ThreadHandle: THandle;
  EvaluatingStart: Boolean;
  Start: NativeUInt;
  CreateTime: UInt64;
  Created, Exited, KernelTime, UserTime: TFileTime;
begin
  Existing := FKnown[Key];
  Existing.LastQueryTick := Tick;
  Existing.QueryAttempted := True;
  // Commit the attempt even when a lower layer raises an exception.
  FKnown.AddOrSetValue(Key, Existing);
  ThreadHandle := OpenNativeThread(TargetPID, Key,
    THREAD_QUERY_INFORMATION_RIGHT);
  if ThreadHandle = 0 then
    ThreadHandle := OpenNativeThread(TargetPID, Key,
      THREAD_QUERY_LIMITED_INFORMATION_RIGHT);
  if ThreadHandle <> 0 then
  try
    CreateTime := 0;
    if WinGetThreadTimes(ThreadHandle, Created, Exited,
      KernelTime, UserTime) then
      CreateTime := (UInt64(Created.dwHighDateTime) shl 32) or
        UInt64(Created.dwLowDateTime);
    if CreateTime = 0 then FObservationFailed := True;
    if (Existing.CreateTime <> 0) and (CreateTime <> 0) and
       (Existing.CreateTime <> CreateTime) then
    begin
      Existing := Default(TThreadOriginState);
      Existing.FirstSeenTick := Tick;
      Existing.OriginEligible := (not Baseline) and FPrimed;
      Existing.LastQueryTick := Tick;
      Existing.QueryAttempted := True;
      CountSpawn(Key, Tick, Tick, Baseline or not FPrimed);
    end;
    if CreateTime <> 0 then Existing.CreateTime := CreateTime;
    Start := 0;
    if QueryWin32ThreadStart(ThreadHandle, Start) and
       QueryThreadStartRegion(ProcessHandle, Start, Current) then
    begin
      EvaluatingStart := Existing.OriginEligible and
        (not Existing.StartEvaluated) and
        (Tick >= Existing.FirstSeenTick) and
        (Tick - Existing.FirstSeenTick <= START_OBSERVATION_WINDOW_MS);
      if (not Baseline) and FPrimed and EvaluatingStart and
         IsNonImageExecutableStart(Current) then
      begin
        Include(Detected, dkThreadStart);
        // An ordinary thread burst is never sufficient evidence of an
        // external origin. Remember only a newly observed non-image start.
        FLastSuspiciousOriginTick := Tick;
        if IsPrivateExecutableStart(Current) then
          Include(Detected, dkPrivateThread);
        if (FLastCreateAccess <> 0) and
           (Tick >= FLastCreateAccess) and
           (Tick - FLastCreateAccess <= EXTERNAL_CREATE_CORRELATION_MS) then
          Include(Detected, dkRemoteThread);
      end;
      if Existing.StartKnown and not Baseline and
         IsThreadRegionChanged(Existing.Region, Current) then
        Include(Detected, dkThreadRegion);
      Existing.Region := Current;
      Existing.StartKnown := True;
      Existing.StartEvaluated := True;
    end
    else FObservationFailed := True;
  finally
    CloseNativeProcess(ThreadHandle);
    FKnown.AddOrSetValue(Key, Existing);
  end
  else FObservationFailed := True;
end;

function QualifiesThreadSpawn(Count: Integer; Baseline, Primed,
  ObservationFailed: Boolean; Tick, LastSuspiciousOriginTick: UInt64): Boolean;
begin
  // The thread count alone includes legitimate A/B/O startup workers.
  // Require an observed non-image executable origin in the same bounded
  // episode; a held CREATE_THREAD access mask alone is insufficient.
  Result := (not Baseline) and Primed and (not ObservationFailed) and
    (Count >= THREAD_SPAWN_THRESHOLD) and
    (LastSuspiciousOriginTick <> 0) and (Tick >= LastSuspiciousOriginTick) and
    (Tick - LastSuspiciousOriginTick <= THREAD_SPAWN_WINDOW_MS + REGION_RESAMPLE_MS);
end;

procedure TThreadOriginMonitor.ReportSpawnBurst(Baseline: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if QualifiesThreadSpawn(FSpawnTimes.Count, Baseline, FPrimed,
       FObservationFailed, Tick, FLastSuspiciousOriginTick) and
     ((FLastBurstTick = 0) or
      ((Tick >= FLastBurstTick) and
       (Tick - FLastBurstTick >= THREAD_SPAWN_COOLDOWN_MS))) then
  begin
    Include(Detected, dkThreadSpawn);
    FLastBurstTick := Tick;
  end;
end;

procedure TThreadOriginMonitor.Examine(TargetPID: Cardinal;
  const Threads: TThreadSampleMap; ThreadsValid: Boolean;
  const Events: TKernelEventList; Tick: UInt64;
  Baseline, FreshCreateThreadAccess: Boolean;
  var Detected: TDetectionKinds);
var
  Ev: TKernelEvent;
  ProcessHandle: THandle;
  OwnProcessHandle: Boolean;
  QueryIDs: TArray<Cardinal>;
  Key: Cardinal;
begin
  FObservationFailed := False;
  FObservationFailed := (not ThreadsValid) or (Threads = nil);
  if FreshCreateThreadAccess and not Baseline then
    FLastCreateAccess := Tick;
  ExpireSpawnHistory(Tick);
  if (not Baseline) and (Events <> nil) then
    for Ev in Events do
      if (Ev.Kind = keThreadStart) and (Ev.PID = TargetPID) and
         (Ev.ThreadID <> 0) then
        CountSpawn(Ev.ThreadID, Ev.Tick, Tick, False);

  if ThreadsValid and (Threads <> nil) then
  begin
    // No result from an incomplete/invalid native snapshot may be treated
    // as evidence of a terminated or newly started thread.
    if Threads.Count > MAX_TARGET_THREADS then
    begin
      FObservationFailed := True;
      Exit;
    end;
    OwnProcessHandle := False;
    ProcessHandle := 0;
    if TargetPID = WinCurrentProcessId then
      ProcessHandle := WinCurrentProcess // local pseudo-handle
    else
    begin
      ProcessHandle := OpenNativeProcess(TargetPID, ACCESS_QUERY_INFORMATION);
      OwnProcessHandle := ProcessHandle <> 0;
    end;
    try
      SynchronizeVisibleThreads(Threads, Baseline, Tick);

      if (ProcessHandle <> 0) and ThreadOriginNativeAvailable then
      begin
        QueryIDs := OriginQueryOrder(FKnown, Tick);
        for Key in QueryIDs do
        begin
          InspectThreadOrigin(TargetPID, Key, ProcessHandle, Baseline, Tick, Detected);
        end;
      end
      else FObservationFailed := True;
      FPrimed := True;
    finally
      if OwnProcessHandle then CloseNativeProcess(ProcessHandle);
    end;
  end;

  ReportSpawnBurst(Baseline, Tick, Detected);
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.ThreadOrigin.inc}
{$ENDIF}

end.
