unit Cozy.NHW.SnapshotETWReconcile;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.Generics.Collections,
  Cozy.NHW.Logging, Cozy.NHW.ETWTypes, Cozy.NHW.Lifecycle;

type
  TReconcilePending = record
    ThreadID: Cardinal;
    Kind: TKernelEventKind;
    FirstSeen, EarliestEvent: UInt64;
  end;
  TReconcileEvent = record
    Tick: UInt64;
    Used: Boolean;
  end;

  // Observation mismatch, never proof of injection or an ETW bypass.
  // IDs have no creation timestamp in TThreadSample: same-ID reuse entirely
  // between two snapshots cannot be resolved by this sensor.
  // Single engine owner; the ETW producer must not mutate Events during Examine.
  TSnapshotETWReconciler = class
  private
    FPrevious: TDictionary<Cardinal, Byte>;
    FPending: TDictionary<UInt64, TReconcilePending>;
    FEvents: TDictionary<UInt64, TReconcileEvent>;
    FPrimed: Boolean;
    FTargetPID: Cardinal;
    FPreviousTick, FLastReport: UInt64;
    procedure InvalidateObservations;
    procedure SeedSnapshot(Threads: TThreadSampleMap; Tick: UInt64);
    function AddPending(ID: Cardinal; Kind: TKernelEventKind;
      Tick: UInt64): Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(TargetPID: Cardinal; Threads: TThreadSampleMap;
      ThreadsValid, TraceAvailable, TraceLost, Baseline,
      IndependentEvidence: Boolean; Events: TKernelEventList;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function ReconcileCandidate(ValidSnapshot, TraceHealthy,
  IndependentEvidence: Boolean; UnmatchedAgeMS: UInt64): Boolean;
{$IFDEF NHW_NATIVE5H_TESTS}
function TestSnapshotETWHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Types {$IFDEF NHW_NATIVE5H_TESTS}, System.SysUtils{$ENDIF};

const
  RECONCILE_WAIT_MS = 2500;
  RECONCILE_RETAIN_MS = 15000;
  RECONCILE_COOLDOWN_MS = 60000;
  MAX_RECONCILE_ENTRIES = MAX_TARGET_THREADS * 2;
  MAX_RECONCILE_EVENTS_PER_STEP = 32768;

function ReconcileKey(ID: Cardinal; Kind: TKernelEventKind): UInt64;
begin
  Result := UInt64(ID) shl 1;
  if Kind = keThreadEnd then Result := Result or UInt64(1);
end;

function ReconcileCandidate(ValidSnapshot, TraceHealthy,
  IndependentEvidence: Boolean; UnmatchedAgeMS: UInt64): Boolean;
begin
  Result := ValidSnapshot and TraceHealthy and IndependentEvidence and
    (UnmatchedAgeMS >= RECONCILE_WAIT_MS);
end;

constructor TSnapshotETWReconciler.Create;
begin
  inherited Create;
  FPrevious := TDictionary<Cardinal, Byte>.Create;
  FPending := TDictionary<UInt64, TReconcilePending>.Create;
  FEvents := TDictionary<UInt64, TReconcileEvent>.Create;
  Reset;
end;

destructor TSnapshotETWReconciler.Destroy;
begin
  FEvents.Free;
  FPending.Free;
  FPrevious.Free;
  inherited Destroy;
end;

procedure TSnapshotETWReconciler.InvalidateObservations;
begin
  FPrevious.Clear;
  FPending.Clear;
  FEvents.Clear;
  FPrimed := False;
  FPreviousTick := 0;
  // Retain report cooldown across collection gaps for the same target.
end;

procedure TSnapshotETWReconciler.Reset;
begin
  InvalidateObservations;
  FTargetPID := 0;
  FLastReport := 0;
end;

procedure TSnapshotETWReconciler.SeedSnapshot(Threads: TThreadSampleMap;
  Tick: UInt64);
var ID: Cardinal;
begin
  FPrevious.Clear;
  for ID in Threads.Keys do FPrevious.Add(ID, 0);
  FPreviousTick := Tick;
  FPrimed := True;
end;

function TSnapshotETWReconciler.AddPending(ID: Cardinal;
  Kind: TKernelEventKind; Tick: UInt64): Boolean;
var P: TReconcilePending; Key: UInt64;
begin
  Key := ReconcileKey(ID, Kind);
  // An opposite change cancels the old pending observation for this ID.
  FPending.Remove(Key xor UInt64(1));
  if not FPending.ContainsKey(Key) and
     (FPending.Count >= MAX_RECONCILE_ENTRIES) then Exit(False);
  P := Default(TReconcilePending);
  P.ThreadID := ID;
  P.Kind := Kind;
  P.FirstSeen := Tick;
  // Event Tick is local receive time, not the kernel occurrence timestamp.
  // Bounded lookback covers an event delivered after a snapshot was captured
  // but before that snapshot was handed to this sensor in the previous scan.
  if FPreviousTick > RECONCILE_WAIT_MS then
    P.EarliestEvent := FPreviousTick - RECONCILE_WAIT_MS;
  FPending.AddOrSetValue(Key, P);
  Result := True;
end;

procedure TSnapshotETWReconciler.Examine(TargetPID: Cardinal;
  Threads: TThreadSampleMap; ThreadsValid, TraceAvailable,
  TraceLost, Baseline, IndependentEvidence: Boolean;
  Events: TKernelEventList; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Sample: TPair<Cardinal, TThreadSample>;
  Ready: TList<UInt64>;
  CapacityOK: Boolean;

  procedure ExpireCachedEvents;
  var
    Key: UInt64;
    Cached: TReconcileEvent;
  begin
    // Expire events, retaining consumed markers until expiry so a duplicate
    // event cannot explain a second change of the same ID and direction.
    for Key in FEvents.Keys.ToArray do
    begin
      Cached := FEvents[Key];
      if (Tick < Cached.Tick) or (Tick - Cached.Tick > RECONCILE_RETAIN_MS) then
        FEvents.Remove(Key);
    end;
  end;

  function CacheRelevantEvents: Boolean;
  var
    E: TKernelEvent;
    Cached: TReconcileEvent;
    Key: UInt64;
  begin
    Result := False;
    for E in Events do
    begin
      if (E.PID <> TargetPID) or (E.ThreadID = 0) or
         not (E.Kind in [keThreadStart, keThreadEnd]) or
         (E.Tick = 0) or (E.Tick > Tick) then Continue;
      if Tick - E.Tick > RECONCILE_RETAIN_MS then Continue;
      Key := ReconcileKey(E.ThreadID, E.Kind);
      if FEvents.TryGetValue(Key, Cached) then
      begin
        if E.Tick <= Cached.Tick then Continue;
      end
      else if FEvents.Count >= MAX_RECONCILE_ENTRIES then
      begin InvalidateObservations; SeedSnapshot(Threads, Tick); Exit; end;
      Cached.Tick := E.Tick;
      Cached.Used := False;
      FEvents.AddOrSetValue(Key, Cached);
    end;
    Result := True;
  end;

  procedure StageSnapshotChanges(out CapacityOK: Boolean);
  var
    ID: Cardinal;
  begin
    CapacityOK := True;
    for ID in Threads.Keys do
      if not FPrevious.ContainsKey(ID) then
        if not AddPending(ID, keThreadStart, Tick) then CapacityOK := False;
    for ID in FPrevious.Keys do
      if not Threads.ContainsKey(ID) then
        if not AddPending(ID, keThreadEnd, Tick) then CapacityOK := False;
  end;

  procedure MatchPendingChanges;
  var
    Key: UInt64;
    Cached: TReconcileEvent;
    P: TReconcilePending;
    CurrentPresence: Boolean;
  begin
    for Key in FPending.Keys.ToArray do
    begin
      P := FPending[Key];
      CurrentPresence := Threads.ContainsKey(P.ThreadID);
      if (Tick < P.FirstSeen) or
         (Tick - P.FirstSeen > RECONCILE_RETAIN_MS) or
         ((P.Kind = keThreadStart) and not CurrentPresence) or
         ((P.Kind = keThreadEnd) and CurrentPresence) then
      begin FPending.Remove(Key); Continue; end;
      if FEvents.TryGetValue(Key, Cached) then
        if not Cached.Used and (Cached.Tick >= P.EarliestEvent) and
           (Cached.Tick <= Tick) then
        begin
          Cached.Used := True;
          FEvents[Key] := Cached;
          FPending.Remove(Key);
          Continue;
        end;
      if ReconcileCandidate(True, True, IndependentEvidence,
           Tick - P.FirstSeen) then Ready.Add(Key);
    end;
  end;

  procedure ReportUnmatchedChanges;
  var
    Key: UInt64;
  begin
    if (Ready.Count > 0) and ((FLastReport = 0) or
       ((Tick >= FLastReport) and
        (Tick - FLastReport >= RECONCILE_COOLDOWN_MS))) then
    begin
      Include(Detected, dkSnapshotETW);
      FLastReport := Tick;
      for Key in Ready do FPending.Remove(Key);
    end;
  end;

begin
  if TargetPID <> FTargetPID then
  begin Reset; FTargetPID := TargetPID; end;
  if (TargetPID = 0) or not ThreadsValid or (Threads = nil) or
     not TraceAvailable or TraceLost or (Events = nil) then
  begin InvalidateObservations; Exit; end;
  if (Threads.Count > MAX_TARGET_THREADS) or
     (Events.Count > MAX_RECONCILE_EVENTS_PER_STEP) then
  begin InvalidateObservations; Exit; end;
  for Sample in Threads do
    if (Sample.Key = 0) or (Sample.Value.ThreadID <> Sample.Key) then
    begin InvalidateObservations; Exit; end;
  if FPrimed and ((Tick < FPreviousTick) or
     (Tick - FPreviousTick > RECONCILE_RETAIN_MS)) then
    InvalidateObservations;
  Ready := nil;
  try
    try
      if Baseline or not FPrimed then
      begin
        InvalidateObservations;
        SeedSnapshot(Threads, Tick);
        Exit;
      end;
      ExpireCachedEvents;
      if not CacheRelevantEvents then Exit;
      StageSnapshotChanges(CapacityOK);
      if not CapacityOK then
      begin InvalidateObservations; SeedSnapshot(Threads, Tick); Exit; end;
      Ready := TList<UInt64>.Create;
      MatchPendingChanges;
      SeedSnapshot(Threads, Tick);
      ReportUnmatchedChanges;
    except
      InvalidateObservations;
      raise;
    end;
  finally
    Ready.Free;
  end;
end;

{$IFDEF NHW_NATIVE5H_TESTS}
{$I Cozy.NHW.Native5H.SnapshotETW.inc}
{$ENDIF}
end.
