unit Cozy.NHW.StackGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Lifecycle, Cozy.NHW.Logging, Cozy.NHW.StackNative;

type
  TStackSignal = (ssBounds, ssGuard, ssExecute, ssAllocation, ssGrowth);
  TStackSignals = set of TStackSignal;

  TThreadStackState = record
    Snapshot: TNativeStackSnapshot;
    LastTick: UInt64;
    WindowTick: UInt64;
    WindowCommit: UInt64;
    GuardMissing: Integer;
    BoundsMissing: Integer;
    GuardReported: Boolean;
    BoundsReported: Boolean;
    ObservationGap: Boolean;
    GuardReference, BoundsReference: Boolean;
  end;

  TStackGuardMonitor = class
  private
    FKnown: TDictionary<Cardinal, TThreadStackState>;
    FNextIndex: Integer;
    FLastExternalTick: UInt64;
    FPrimed: Boolean;
    procedure InvalidateCandidate(ThreadID: Cardinal);
    procedure InvalidateCandidates;
    procedure ApplyStackSample(ID: Cardinal; var State: TThreadStackState;
      const Sample: TNativeStackSnapshot; WasKnown, Baseline: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(TargetPID: Cardinal; const Threads: TThreadSampleMap;
      ThreadsValid: Boolean; Tick: UInt64;
      Baseline, ExternalHandleEvent: Boolean;
      var Detected: TDetectionKinds);
  end;

// Pure, synthetic-testable anomaly policy. Guard and bounds require 3
// consecutive comparable observations; a normal moving guard is not an alarm.
function AnalyzeStackTransition(var State: TThreadStackState;
  const Current: TNativeStackSnapshot; Tick: UInt64): TStackSignals;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestStackGuard10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.Native, Cozy.NHW.Types, Cozy.NHW.WinPointers;

const
  STACK_QUERY_INTERVAL_MS = 1500;
  STACK_MAX_THREADS_PER_PASS = 12;
  STACK_GROWTH_WINDOW_MS = 2000;
  STACK_GROWTH_BYTES = UInt64(256) * 1024;
  STACK_CORRELATION_MS = 3000;
  STACK_MISSING_CONFIRMATIONS = 3;

procedure BreakStackObservation(var State: TThreadStackState);
begin
  State.GuardReference := State.Snapshot.HasGuard or
    (State.GuardMissing > 0);
  State.BoundsReference := State.Snapshot.BoundsValid or
    (State.BoundsMissing > 0);
  State.GuardMissing := 0;
  State.BoundsMissing := 0;
  State.WindowTick := 0;
  State.WindowCommit := 0;
  State.LastTick := 0;
  State.ObservationGap := True;
  // Keep the accepted snapshot and report suppression until a successful read.
end;

procedure ResumeStackObservation(var State: TThreadStackState;
  const Current: TNativeStackSnapshot; Tick: UInt64);
begin
  // The first fresh observation can START a new confirmation run, never
  // finish the run from before the gap. No cross-gap transition is emitted.
  if State.BoundsReference and not Current.BoundsValid then State.BoundsMissing := 1;
  if State.GuardReference and Current.BoundsValid and not Current.HasGuard and
     (Current.StackLimit = State.Snapshot.StackLimit) and
     (Current.CommittedBytes <= State.Snapshot.CommittedBytes) then State.GuardMissing := 1;
  State.Snapshot := Current;
  State.LastTick := Tick;
  State.WindowTick := Tick;
  State.WindowCommit := Current.CommittedBytes;
  State.ObservationGap := False;
  if Current.HasGuard then State.GuardReported := False;
  if Current.BoundsValid then State.BoundsReported := False;
end;

procedure UpdateStackBounds(var State: TThreadStackState;
  const Previous, Current: TNativeStackSnapshot; var Signals: TStackSignals);
begin
  if (not Current.BoundsValid) and
     (Previous.BoundsValid or (State.BoundsMissing > 0)) then
  begin
    if State.BoundsMissing < STACK_MISSING_CONFIRMATIONS then Inc(State.BoundsMissing);
  end
  else if Current.BoundsValid then
    State.BoundsMissing := 0;
  if (State.BoundsMissing >= STACK_MISSING_CONFIRMATIONS) and
     (not State.BoundsReported) then
  begin
    Include(Signals, ssBounds);
    State.BoundsReported := True;
  end;
  if Current.BoundsValid then State.BoundsReported := False;
end;

procedure UpdateStackGuard(var State: TThreadStackState;
  const Previous, Current: TNativeStackSnapshot; StableLimit: Boolean;
  var Signals: TStackSignals);
begin
  // Only alert on guard removal while the stack has NOT expanded.
  if (Previous.HasGuard or (State.GuardMissing > 0)) and
     (not Current.HasGuard) and StableLimit and
     (Current.CommittedBytes <= Previous.CommittedBytes) then
  begin
    if State.GuardMissing < STACK_MISSING_CONFIRMATIONS then Inc(State.GuardMissing);
  end
  else if Current.HasGuard then
  begin
    State.GuardMissing := 0;
    State.GuardReported := False;
  end
  else
    State.GuardMissing := 0;
  if (State.GuardMissing >= STACK_MISSING_CONFIRMATIONS) and
     not State.GuardReported then
  begin
    Include(Signals, ssGuard);
    State.GuardReported := True;
  end;
end;

procedure UpdateStackGrowth(var State: TThreadStackState;
  const Previous, Current: TNativeStackSnapshot; Tick: UInt64;
  var Signals: TStackSignals);
begin
  if (State.WindowTick = 0) or (Tick < State.WindowTick) or
     (Tick - State.WindowTick > STACK_GROWTH_WINDOW_MS) then
  begin
    State.WindowTick := Tick;
    State.WindowCommit := Previous.CommittedBytes;
  end;
  if (Current.CommittedBytes >= State.WindowCommit) and
     (Current.CommittedBytes - State.WindowCommit >= STACK_GROWTH_BYTES) and
     (Tick >= State.WindowTick) and
     (Tick - State.WindowTick <= STACK_GROWTH_WINDOW_MS) then
  begin
    Include(Signals, ssGrowth);
    // Re-arm only for a future independent growth interval.
    State.WindowTick := Tick;
    State.WindowCommit := Current.CommittedBytes;
  end;
end;

function AnalyzeStackTransition(var State: TThreadStackState;
  const Current: TNativeStackSnapshot; Tick: UInt64): TStackSignals;
var
  Previous: TNativeStackSnapshot;
  StableLimit: Boolean;
begin
  Result := [];
  if not Current.Known then
  begin
    BreakStackObservation(State);
    Exit;
  end;
  if (State.Snapshot.CreateTime <> Current.CreateTime) or
     (State.Snapshot.CreateTime = 0) then Exit;
  if State.ObservationGap then
  begin
    ResumeStackObservation(State, Current, Tick);
    Exit; // recovery is a reference, not an observed transition across the gap
  end;
  Previous := State.Snapshot;
  StableLimit := (Current.StackLimit = Previous.StackLimit);

  UpdateStackBounds(State, Previous, Current, Result);

  if Current.BoundsValid and Previous.BoundsValid then
  begin
    if (Current.StackBase <> Previous.StackBase) or
       (Current.AllocationBase <> Previous.AllocationBase) or
       (Current.ReservedBytes <> Previous.ReservedBytes) then
      Include(Result, ssAllocation);

    UpdateStackGuard(State, Previous, Current, StableLimit, Result);

    if (not Previous.HasExecutablePage) and Current.HasExecutablePage then
      Include(Result, ssExecute);

    UpdateStackGrowth(State, Previous, Current, Tick, Result);
  end
  else
  begin
    State.GuardMissing := 0;
    State.GuardReported := False;
    State.WindowTick := 0;
  end;

  State.Snapshot := Current;
  State.LastTick := Tick;
end;

constructor TStackGuardMonitor.Create;
begin
  inherited Create;
  FKnown := TDictionary<Cardinal, TThreadStackState>.Create;
  Reset;
end;

destructor TStackGuardMonitor.Destroy;
begin
  FKnown.Free;
  inherited Destroy;
end;

procedure TStackGuardMonitor.Reset;
begin
  FKnown.Clear;
  FNextIndex := 0;
  FLastExternalTick := 0;
  FPrimed := False;
end;

procedure TStackGuardMonitor.InvalidateCandidate(ThreadID: Cardinal);
var State: TThreadStackState;
begin
  if not FKnown.TryGetValue(ThreadID, State) then Exit;
  BreakStackObservation(State);
  FKnown.AddOrSetValue(ThreadID, State);
end;

procedure TStackGuardMonitor.InvalidateCandidates;
var IDs: TArray<Cardinal>; ID: Cardinal;
begin
  IDs := FKnown.Keys.ToArray;
  for ID in IDs do InvalidateCandidate(ID);
  FLastExternalTick := 0;
end;

procedure TStackGuardMonitor.ApplyStackSample(ID: Cardinal; var State: TThreadStackState;
  const Sample: TNativeStackSnapshot; WasKnown, Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Signals: TStackSignals;
  CanAlert: Boolean;
begin
  if not WasKnown or (State.Snapshot.CreateTime <> Sample.CreateTime) then
  begin
    State := Default(TThreadStackState);
    State.Snapshot := Sample;
    State.LastTick := Tick;
    State.WindowTick := Tick;
    State.WindowCommit := Sample.CommittedBytes;
    FKnown.AddOrSetValue(ID, State);
    Exit;
  end;
  Signals := AnalyzeStackTransition(State, Sample, Tick);
  FKnown.AddOrSetValue(ID, State);
  CanAlert := (not Baseline) and FPrimed;
  if CanAlert then
  begin
    if ssBounds in Signals then Include(Detected, dkStackBounds);
    if ssGuard in Signals then Include(Detected, dkStackGuard);
    if ssExecute in Signals then Include(Detected, dkStackExecute);
    if ssAllocation in Signals then Include(Detected, dkStackAllocation);
    if ssGrowth in Signals then Include(Detected, dkStackGrowth);
    if (Signals <> []) and (FLastExternalTick <> 0) and
       (Tick >= FLastExternalTick) and
       (Tick - FLastExternalTick <= STACK_CORRELATION_MS) then
      Include(Detected, dkStackCorrelation);
  end;
end;

procedure TStackGuardMonitor.Examine(TargetPID: Cardinal;
  const Threads: TThreadSampleMap; ThreadsValid: Boolean;
  Tick: UInt64; Baseline, ExternalHandleEvent: Boolean;
  var Detected: TDetectionKinds);
var
  Handle, ProcessHandle: THandle;
  OwnHandle: Boolean;
  Ids, ToRemove: TList<Cardinal>;
  Pair: TPair<Cardinal, TThreadSample>;
  OldPair: TPair<Cardinal, TThreadStackState>;
  State: TThreadStackState;
  Sample: TNativeStackSnapshot;
  ID: Cardinal;
  I, Count, Index: Integer;
  WasKnown: Boolean;
begin
  if (not ThreadsValid) or (Threads = nil) then
  begin
    InvalidateCandidates;
    Exit;
  end;
  if Threads.Count > MAX_TARGET_THREADS then
  begin
    InvalidateCandidates;
    Exit;
  end;
  if ExternalHandleEvent and not Baseline then FLastExternalTick := Tick;
  if not StackNativeAvailable then
  begin
    InvalidateCandidates;
    Exit;
  end;
  Ids := nil;
  ToRemove := nil;
  try
    Ids := TList<Cardinal>.Create;
    ToRemove := TList<Cardinal>.Create;
    for Pair in Threads do Ids.Add(Pair.Key);
    Ids.Sort;
    Count := Ids.Count;
    if Count = 0 then
    begin
      FKnown.Clear; // a complete empty snapshot really has no live IDs
      FNextIndex := 0;
      FPrimed := True;
      Exit;
    end;

    if FNextIndex >= Count then FNextIndex := 0;
    ProcessHandle := 0;
    OwnHandle := False;
    if TargetPID = WinCurrentProcessId then
      ProcessHandle := WinCurrentProcess
    else
    begin
      ProcessHandle := OpenNativeProcess(TargetPID,
        ACCESS_QUERY_INFORMATION or ACCESS_VM_READ);
      OwnHandle := ProcessHandle <> 0;
    end;
    if ProcessHandle = 0 then
    begin
      InvalidateCandidates;
      Exit;
    end;
    try
      for I := 0 to STACK_MAX_THREADS_PER_PASS - 1 do
      begin
        if I >= Count then Break;
        Index := (FNextIndex + I) mod Count;
        ID := Ids[Index];
        WasKnown := FKnown.TryGetValue(ID, State);
        if WasKnown and (Tick >= State.LastTick) and
           (Tick - State.LastTick < STACK_QUERY_INTERVAL_MS) then Continue;
        Handle := OpenNativeThread(TargetPID, ID, THREAD_QUERY_INFORMATION_RIGHT);
        if Handle = 0 then
          Handle := OpenNativeThread(TargetPID, ID, THREAD_QUERY_LIMITED_INFORMATION_RIGHT);
        if Handle = 0 then
        begin
          InvalidateCandidate(ID);
          Continue;
        end;
        try
          try
            if not QueryNativeThreadStack(ProcessHandle, Handle, Sample) or
               not Sample.Known then
            begin
              InvalidateCandidate(ID);
              Continue;
            end;
          except
            InvalidateCandidate(ID);
            raise;
          end;
        finally
          CloseNativeProcess(Handle);
        end;
        ApplyStackSample(ID, State, Sample, WasKnown, Baseline, Tick, Detected);
      end;
      FNextIndex := (FNextIndex + STACK_MAX_THREADS_PER_PASS) mod Count;
    finally
      if OwnHandle then CloseNativeProcess(ProcessHandle);
    end;

    // A complete native thread snapshot is required before pruning retired IDs.
    for OldPair in FKnown do
      if not Threads.ContainsKey(OldPair.Key) then ToRemove.Add(OldPair.Key);
    for I := 0 to ToRemove.Count - 1 do FKnown.Remove(ToRemove[I]);
    FPrimed := True;
  finally
    ToRemove.Free;
    Ids.Free;
  end;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.StackGuard.inc}
{$ENDIF}

end.
