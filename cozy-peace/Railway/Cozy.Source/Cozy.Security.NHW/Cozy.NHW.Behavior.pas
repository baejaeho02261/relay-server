unit Cozy.NHW.Behavior;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types,
  Cozy.NHW.Logging;

type
  // All events below are inferences from snapshots, not observed API calls.
  // The monitor neither reads nor modifies other processes' memory.
  TBehaviorMonitor = class
  private type
    TThreadEvent = record
      Tick: UInt64;
      ObjectIdentity: NativeUInt;
    end;

    TCountSample = record
      Tick: UInt64;
      Count: Integer;
    end;

    TCrossEntry = record
      Tick: UInt64;
      OwnerKey: string;
    end;

    TOwnerState = class
    public
      LastSeenTick: UInt64;
      HasBeenSeen: Boolean;
      LastThreadDataValid: Boolean;
      ThreadAlertActive: Boolean;
      ChurnAlertActive: Boolean;
      AccessAlertActive: Boolean;
      ThreadEvents: TList<TThreadEvent>;
      ChurnEvents: TList<UInt64>;
      CountHistory: TList<TCountSample>;
      constructor Create;
      destructor Destroy; override;
    end;

    TOwnerSnapshot = class
    public
      TotalHandleCount: Integer;
      AnyRightsAdded: Boolean;
      HasReappearance: Boolean;
      NewThreadObjects: TList<NativeUInt>;
      constructor Create;
      destructor Destroy; override;
    end;

  private
    FStates: TObjectDictionary<string, TOwnerState>;
    FCurrent: TObjectDictionary<string, TOwnerSnapshot>;
    FCrossEvents: TList<TCrossEntry>;
    FTick: UInt64;
    FProcessBaseline: Boolean;
    FThreadBaseline: Boolean;
    FThreadValid: Boolean;
    FCrossAlertActive: Boolean;
    procedure ExpireCrossEvents;
    procedure TrackOwnerArrival(const Key: string; State: TOwnerState);
    procedure AnalyzeThreadBurst(State: TOwnerState; Sample: TOwnerSnapshot;
      var Detected: TDetectionKinds);
    procedure AnalyzeChurn(State: TOwnerState; Sample: TOwnerSnapshot;
      var Detected: TDetectionKinds);
    procedure AnalyzeAccessBurst(State: TOwnerState; Sample: TOwnerSnapshot;
      var Detected: TDetectionKinds);
    procedure ReportCrossAccess(var Detected: TDetectionKinds);
    procedure ExpireOwnerStates;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure BeginSnapshot(Tick: UInt64; ProcessBaseline,
      ThreadBaseline, ThreadSnapshotValid: Boolean);
    procedure Observe(const H: TTargetHolder; NewlySeen,
      WasInactive, RightsAdded, InBaseline: Boolean);
    procedure EndSnapshot(var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestBehavior10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10N_TESTS}
var
  BehaviorFailSample10N, BehaviorFailState10N: Boolean;
  BehaviorSamplesFreed10N, BehaviorStatesFreed10N: Integer;
{$ENDIF}

const
  THREAD_BURST_WINDOW_MS = 2000;
  THREAD_BURST_MIN_OBJECTS = 8;
  CHURN_WINDOW_MS = 10000;
  CHURN_MIN_REAPPEARANCES = 3;
  CROSS_WINDOW_MS = 3000;
  CROSS_MIN_OWNERS = 3;
  ACCESS_WINDOW_MS = 2000;
  ACCESS_BURST_HANDLES = 8;
  ACCESS_BURST_WITH_RIGHTS_HANDLES = 4;
  OWNER_REENTRY_GAP_MS = 2500;

function OwnerKey(const H: TTargetHolder): string;
begin
  Result := IntToStr(H.PID) + ':' + IntToStr(Int64(H.CreateTime));
end;

function IsFresh(Tick, EarlierTick, WindowMS: UInt64): Boolean;
begin
  Result := (Tick >= EarlierTick) and (Tick - EarlierTick <= WindowMS);
end;

constructor TBehaviorMonitor.TOwnerState.Create;
begin
  inherited Create;
  ThreadEvents := TList<TThreadEvent>.Create;
  ChurnEvents := TList<UInt64>.Create;
  CountHistory := TList<TCountSample>.Create;
end;

destructor TBehaviorMonitor.TOwnerState.Destroy;
begin
  {$IFDEF NHW_NATIVE10N_TESTS}
  Inc(BehaviorStatesFreed10N);
  {$ENDIF}
  CountHistory.Free;
  ChurnEvents.Free;
  ThreadEvents.Free;
  inherited Destroy;
end;

constructor TBehaviorMonitor.TOwnerSnapshot.Create;
begin
  inherited Create;
  NewThreadObjects := TList<NativeUInt>.Create;
end;

destructor TBehaviorMonitor.TOwnerSnapshot.Destroy;
begin
  {$IFDEF NHW_NATIVE10N_TESTS}
  Inc(BehaviorSamplesFreed10N);
  {$ENDIF}
  NewThreadObjects.Free;
  inherited Destroy;
end;

constructor TBehaviorMonitor.Create;
begin
  inherited Create;
  FStates := TObjectDictionary<string, TOwnerState>.Create([doOwnsValues]);
  FCurrent := TObjectDictionary<string, TOwnerSnapshot>.Create([doOwnsValues]);
  FCrossEvents := TList<TCrossEntry>.Create;
end;

destructor TBehaviorMonitor.Destroy;
begin
  FCrossEvents.Free;
  FCurrent.Free;
  FStates.Free;
  inherited Destroy;
end;

procedure TBehaviorMonitor.Reset;
begin
  FCurrent.Clear;
  FStates.Clear;
  FCrossEvents.Clear;
  FCrossAlertActive := False;
end;

procedure TBehaviorMonitor.BeginSnapshot(Tick: UInt64; ProcessBaseline,
  ThreadBaseline, ThreadSnapshotValid: Boolean);
begin
  FTick := Tick;
  FProcessBaseline := ProcessBaseline;
  FThreadBaseline := ThreadBaseline;
  FThreadValid := ThreadSnapshotValid;
  FCurrent.Clear;
end;

procedure TBehaviorMonitor.Observe(const H: TTargetHolder;
  NewlySeen, WasInactive, RightsAdded, InBaseline: Boolean);
var
  Key: string;
  Sample: TOwnerSnapshot;
  I: Integer;
  Present: Boolean;
begin
  if H.IsThread and not FThreadValid then Exit;
  Key := OwnerKey(H);
  if not FCurrent.TryGetValue(Key, Sample) then
  begin
    Sample := TOwnerSnapshot.Create;
    try
      {$IFDEF NHW_NATIVE10N_TESTS}
      if BehaviorFailSample10N then raise EOutOfMemory.Create('Native10N test');
      {$ENDIF}
      FCurrent.Add(Key, Sample);
    except
      Sample.Free;
      raise;
    end;
  end;
  Inc(Sample.TotalHandleCount, H.HandleCount);
  if RightsAdded and not InBaseline then Sample.AnyRightsAdded := True;
  if WasInactive and not InBaseline then Sample.HasReappearance := True;
  if H.IsThread and not InBaseline and (NewlySeen or WasInactive) then
  begin
    Present := False;
    for I := 0 to Sample.NewThreadObjects.Count - 1 do
      if Sample.NewThreadObjects[I] = H.ObjectIdentity then
      begin
        Present := True;
        Break;
      end;
    if not Present then Sample.NewThreadObjects.Add(H.ObjectIdentity);
  end;
end;

procedure TBehaviorMonitor.ExpireCrossEvents;
var
  I: Integer;
begin
  for I := FCrossEvents.Count - 1 downto 0 do
    if not IsFresh(FTick, FCrossEvents[I].Tick, CROSS_WINDOW_MS) then
      FCrossEvents.Delete(I);
end;

procedure TBehaviorMonitor.TrackOwnerArrival(const Key: string; State: TOwnerState);
var
  I: Integer;
  Arrival: TCrossEntry;
  ReEntry, Duplicate: Boolean;
begin
  ReEntry := not State.HasBeenSeen;
  if State.HasBeenSeen and (FTick >= State.LastSeenTick) and
     (FTick - State.LastSeenTick > OWNER_REENTRY_GAP_MS) then
    ReEntry := True;

  // A new owner in the initial baseline is not a new post-startup access.
  if ReEntry and not FProcessBaseline and
     (not FThreadValid or not FThreadBaseline) then
  begin
    Duplicate := False;
    for I := 0 to FCrossEvents.Count - 1 do
      if FCrossEvents[I].OwnerKey = Key then
      begin
        Duplicate := True;
        Break;
      end;
    if not Duplicate then
    begin
      Arrival.Tick := FTick;
      Arrival.OwnerKey := Key;
      FCrossEvents.Add(Arrival);
    end;
  end;

  State.HasBeenSeen := True;
  State.LastSeenTick := FTick;
end;

procedure TBehaviorMonitor.AnalyzeThreadBurst(State: TOwnerState;
  Sample: TOwnerSnapshot; var Detected: TDetectionKinds);
var
  I, J: Integer;
  NewThread: TThreadEvent;
  Duplicate, HasThreadBurst: Boolean;
begin
  // Thread Burst: 8 distinct newly observed target THREAD objects held by
  // one external owner during a 2-second window. Baseline is excluded.
  for I := State.ThreadEvents.Count - 1 downto 0 do
    if not IsFresh(FTick, State.ThreadEvents[I].Tick,
      THREAD_BURST_WINDOW_MS) then State.ThreadEvents.Delete(I);
  if FThreadValid and not FThreadBaseline then
    for I := 0 to Sample.NewThreadObjects.Count - 1 do
    begin
      Duplicate := False;
      for J := 0 to State.ThreadEvents.Count - 1 do
        if State.ThreadEvents[J].ObjectIdentity =
          Sample.NewThreadObjects[I] then
        begin
          Duplicate := True;
          Break;
        end;
      if not Duplicate then
      begin
        NewThread.Tick := FTick;
        NewThread.ObjectIdentity := Sample.NewThreadObjects[I];
        State.ThreadEvents.Add(NewThread);
      end;
    end;
  HasThreadBurst := State.ThreadEvents.Count >= THREAD_BURST_MIN_OBJECTS;
  if HasThreadBurst and not State.ThreadAlertActive then
    Include(Detected, dkThreadBurst);
  State.ThreadAlertActive := HasThreadBurst;
end;

procedure TBehaviorMonitor.AnalyzeChurn(State: TOwnerState;
  Sample: TOwnerSnapshot; var Detected: TDetectionKinds);
var
  I: Integer;
  HasChurnBurst: Boolean;
begin
  // Churn: repeated disappearance/reappearance observed by the v10
  // two-missing-snapshot rule, not a count of actual CloseHandle calls.
  for I := State.ChurnEvents.Count - 1 downto 0 do
    if not IsFresh(FTick, State.ChurnEvents[I], CHURN_WINDOW_MS) then
      State.ChurnEvents.Delete(I);
  if Sample.HasReappearance then
    State.ChurnEvents.Add(FTick); // max one reappearance event per owner/snapshot
  HasChurnBurst := State.ChurnEvents.Count >= CHURN_MIN_REAPPEARANCES;
  if HasChurnBurst and not State.ChurnAlertActive then
    Include(Detected, dkHandleChurn);
  State.ChurnAlertActive := HasChurnBurst;
end;

procedure TBehaviorMonitor.AnalyzeAccessBurst(State: TOwnerState;
  Sample: TOwnerSnapshot; var Detected: TDetectionKinds);
var
  I, MinCount, Delta: Integer;
  NewCount: TCountSample;
  HasValidCountBasis, HasAccessBurst: Boolean;
begin
  // Access Burst: changes in *granted handle counts*, never API call rates.
  // When thread coverage starts/stops, seed a fresh count basis to avoid
  // reporting a false surge solely from changing observability.
  HasValidCountBasis := not FProcessBaseline and
    (not FThreadValid or not FThreadBaseline);
  if State.LastThreadDataValid <> FThreadValid then
  begin
    State.CountHistory.Clear;
    State.AccessAlertActive := False;
  end;
  State.LastThreadDataValid := FThreadValid;
  for I := State.CountHistory.Count - 1 downto 0 do
    if not IsFresh(FTick, State.CountHistory[I].Tick, ACCESS_WINDOW_MS) then
      State.CountHistory.Delete(I);

  HasAccessBurst := False;
  if HasValidCountBasis and (State.CountHistory.Count > 0) then
  begin
    MinCount := State.CountHistory[0].Count;
    for I := 1 to State.CountHistory.Count - 1 do
      if State.CountHistory[I].Count < MinCount then
        MinCount := State.CountHistory[I].Count;
    Delta := Sample.TotalHandleCount - MinCount;
    HasAccessBurst := (Delta >= ACCESS_BURST_HANDLES) or
      ((Delta >= ACCESS_BURST_WITH_RIGHTS_HANDLES) and
       Sample.AnyRightsAdded);
  end;
  if HasAccessBurst and not State.AccessAlertActive then
    Include(Detected, dkAccessBurst);
  State.AccessAlertActive := HasAccessBurst;
  NewCount.Tick := FTick;
  NewCount.Count := Sample.TotalHandleCount;
  State.CountHistory.Add(NewCount);
end;

procedure TBehaviorMonitor.ReportCrossAccess(var Detected: TDetectionKinds);
begin
  ExpireCrossEvents;
  if (FCrossEvents.Count >= CROSS_MIN_OWNERS) and
     not FCrossAlertActive then
    Include(Detected, dkCrossAccess);
  FCrossAlertActive := FCrossEvents.Count >= CROSS_MIN_OWNERS;
end;

procedure TBehaviorMonitor.ExpireOwnerStates;
var
  StatePair: TPair<string, TOwnerState>;
  RemoveKeys: TList<string>;
  I: Integer;
begin
  // Keep bounded history without ever needing to persist data to disk.
  RemoveKeys := TList<string>.Create;
  try
    for StatePair in FStates do
      if not FCurrent.ContainsKey(StatePair.Key) and
         (FTick >= StatePair.Value.LastSeenTick) and
         (FTick - StatePair.Value.LastSeenTick > TRACK_RETENTION_MS) then
        RemoveKeys.Add(StatePair.Key);
    for I := 0 to RemoveKeys.Count - 1 do
      FStates.Remove(RemoveKeys[I]);
  finally
    RemoveKeys.Free;
  end;
end;

procedure TBehaviorMonitor.EndSnapshot(var Detected: TDetectionKinds);
var
  Entry: TPair<string, TOwnerSnapshot>;
  State: TOwnerState;
  Sample: TOwnerSnapshot;
begin
  ExpireCrossEvents;
  for Entry in FCurrent do
  begin
    Sample := Entry.Value;
    if not FStates.TryGetValue(Entry.Key, State) then
    begin
      State := TOwnerState.Create;
      try
        {$IFDEF NHW_NATIVE10N_TESTS}
        if BehaviorFailState10N then raise EOutOfMemory.Create('Native10N test');
        {$ENDIF}
        FStates.Add(Entry.Key, State);
      except
        State.Free;
        raise;
      end;
    end;

    TrackOwnerArrival(Entry.Key, State);

    AnalyzeThreadBurst(State, Sample, Detected);

    AnalyzeChurn(State, Sample, Detected);

    AnalyzeAccessBurst(State, Sample, Detected);
  end;

  ReportCrossAccess(Detected);

  ExpireOwnerStates;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.Behavior.inc}
{$ENDIF}

end.
