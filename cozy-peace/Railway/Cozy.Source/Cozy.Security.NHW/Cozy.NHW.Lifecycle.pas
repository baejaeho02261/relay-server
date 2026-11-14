unit Cozy.NHW.Lifecycle;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types,
  Cozy.NHW.Lifecycle.Snapshot,
  Cozy.NHW.Logging;

type
  TThreadSample = Cozy.NHW.Lifecycle.Snapshot.TThreadSample;
  TProcessParentMap = Cozy.NHW.Lifecycle.Snapshot.TProcessParentMap;
  TThreadSampleMap = Cozy.NHW.Lifecycle.Snapshot.TThreadSampleMap;
  TCreationTimeMap = TDictionary<Cardinal, UInt64>;

  TLifecycleMonitor = class
  private
    FKnown: TThreadSampleMap;
    FSeenCounts: TDictionary<Cardinal, Integer>;
    FInheritedPairs: TDictionary<string, Byte>;
    FLastExternalTick: UInt64;
    FPrimed: Boolean;
    function ExternalNear(Tick: UInt64): Boolean;
    procedure ReconcileExitedThreads(const Threads: TThreadSampleMap;
      Gone: TList<Cardinal>; var ExitedThread: Boolean);
    procedure ApplyThreadSamples(const Threads: TThreadSampleMap;
      var NewThread, SuspendedTransition: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure InvalidateThreadBaseline;
    // Events are correlated with *recently newly observed* external access.
    // No actual operation, causality, or handle inheritance is attested.
    procedure ExamineThreads(const Threads: TThreadSampleMap;
      Tick: UInt64; Baseline: Boolean; ExternalEvent: Boolean;
      var Detected: TDetectionKinds);
    procedure ExamineInheritance(const Handles: TList<TObservedHandle>;
      const Parents: TProcessParentMap; const Creations: TCreationTimeMap;
      ProcessBaseline, ThreadBaseline: Boolean;
      var Detected: TDetectionKinds);
  end;

// Caller owns these dictionaries and keeps them until processing finishes.
// Returns False for incomplete/inconsistent native snapshots.
function ReadSystemThreadSnapshot(TargetPID: Cardinal;
  Parents: TProcessParentMap; Threads: TThreadSampleMap): Boolean;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestLifecycle10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

const
  // Observed native handle attribute: OBJ_INHERIT. May be altered later.
  HANDLE_OBJ_INHERIT = $00000002;
  CORRELATION_WINDOW_MS = 3000;

function ReadSystemThreadSnapshot(TargetPID: Cardinal;
  Parents: TProcessParentMap; Threads: TThreadSampleMap): Boolean;
begin
  Result := Cozy.NHW.Lifecycle.Snapshot.ReadSystemThreadSnapshot(TargetPID, Parents, Threads);
end;

constructor TLifecycleMonitor.Create;
begin
  inherited Create;
  FKnown := TThreadSampleMap.Create;
  FSeenCounts := TDictionary<Cardinal, Integer>.Create;
  FInheritedPairs := TDictionary<string, Byte>.Create;
  Reset;
end;

destructor TLifecycleMonitor.Destroy;
begin
  FInheritedPairs.Free;
  FSeenCounts.Free;
  FKnown.Free;
  inherited Destroy;
end;

procedure TLifecycleMonitor.Reset;
begin
  FKnown.Clear;
  FSeenCounts.Clear;
  FInheritedPairs.Clear;
  FLastExternalTick := 0;
  FPrimed := False;
end;

procedure TLifecycleMonitor.InvalidateThreadBaseline;
begin
  // An unavailable native sample is NOT evidence that all threads exited.
  FKnown.Clear;
  FSeenCounts.Clear;
  FPrimed := False;
  FLastExternalTick := 0;
end;

function TLifecycleMonitor.ExternalNear(Tick: UInt64): Boolean;
begin
  Result := (FLastExternalTick <> 0) and (Tick >= FLastExternalTick) and
    (Tick - FLastExternalTick <= CORRELATION_WINDOW_MS);
end;

function SuspendedWait(const S: TThreadSample): Boolean;
begin
  // A waiting thread with either Suspended or WrSuspended reason.
  Result := (S.ThreadState = 5) and
    ((S.WaitReason = 5) or (S.WaitReason = 12));
end;

procedure TLifecycleMonitor.ReconcileExitedThreads(const Threads: TThreadSampleMap;
  Gone: TList<Cardinal>; var ExitedThread: Boolean);
var
  ThreadID: Cardinal;
  Counts, I: Integer;
begin
  if FPrimed then
  begin
    for ThreadID in FKnown.Keys do
      if not Threads.ContainsKey(ThreadID) then
      begin
        if FSeenCounts.TryGetValue(ThreadID, Counts) and (Counts >= 2) then
          ExitedThread := True;
        Gone.Add(ThreadID);
      end;
    for I := 0 to Gone.Count - 1 do
    begin
      FKnown.Remove(Gone[I]);
      FSeenCounts.Remove(Gone[I]);
    end;
  end;
end;

procedure TLifecycleMonitor.ApplyThreadSamples(const Threads: TThreadSampleMap;
  var NewThread, SuspendedTransition: Boolean);
var
  Item: TPair<Cardinal, TThreadSample>;
  Old: TThreadSample;
  Counts: Integer;
begin
  for Item in Threads do
  begin
    if FKnown.TryGetValue(Item.Key, Old) then
    begin
      if Old.StartAddress <> Item.Value.StartAddress then
      begin
        NewThread := True; // TID reuse with different start address
        FSeenCounts.AddOrSetValue(Item.Key, 1);
      end
      else
      begin
        if SuspendedWait(Item.Value) and not SuspendedWait(Old) then
          SuspendedTransition := True;
        if FSeenCounts.TryGetValue(Item.Key, Counts) then
        begin
          if Counts < 3 then Inc(Counts);
          FSeenCounts.AddOrSetValue(Item.Key, Counts);
        end;
      end;
    end
    else
    begin
      if FPrimed then NewThread := True;
      FSeenCounts.AddOrSetValue(Item.Key, 1);
    end;
    FKnown.AddOrSetValue(Item.Key, Item.Value);
  end;
end;

procedure TLifecycleMonitor.ExamineThreads(const Threads: TThreadSampleMap;
  Tick: UInt64; Baseline: Boolean; ExternalEvent: Boolean;
  var Detected: TDetectionKinds);
var
  NewThread, ExitedThread, SuspendedTransition, HasAccess: Boolean;
  Gone: TList<Cardinal>;
begin
  // Only valid snapshots call this method. An unavailable snapshot must
  // NOT be treated as if every thread had exited.
  if ExternalEvent and not Baseline then
    FLastExternalTick := Tick;
  HasAccess := ExternalNear(Tick);
  NewThread := False;
  ExitedThread := False;
  SuspendedTransition := False;
  Gone := TList<Cardinal>.Create;
  try
    ReconcileExitedThreads(Threads, Gone, ExitedThread);
    ApplyThreadSamples(Threads, NewThread, SuspendedTransition);
  finally
    Gone.Free;
  end;
  FPrimed := True;
  // Start-up snapshots seed the baseline. External correlation is also
  // required to reduce normal application thread churn false positives.
  if Baseline or not HasAccess then Exit;
  if NewThread then Include(Detected, dkThreadCreation);
  if ExitedThread then Include(Detected, dkThreadExit);
  if SuspendedTransition then Include(Detected, dkThreadState);
  if NewThread or ExitedThread or SuspendedTransition then
  begin
    Include(Detected, dkLifecycle);
  end;
end;

procedure TLifecycleMonitor.ExamineInheritance(
  const Handles: TList<TObservedHandle>;
  const Parents: TProcessParentMap;
  const Creations: TCreationTimeMap;
  ProcessBaseline, ThreadBaseline: Boolean;
  var Detected: TDetectionKinds);
var
  ParentCandidates: TDictionary<string, TObservedHandle>;
  I: Integer;
  H, ParentHandle: TObservedHandle;
  ParentPID: Cardinal;
  ParentCreate, ChildCreate: UInt64;
  ParentKey, EvidenceKey: string;
begin
  // A matching pointer, handle VALUE, granted mask, parent-child relation
  // and inheritable parent handle is still only an inheritance CANDIDATE.
  // DuplicateHandle or concurrent independent opens could resemble it.
  if Handles.Count > 32768 then Exit; // bounded work on busy machines
  ParentCandidates := TDictionary<string, TObservedHandle>.Create;
  try
    for I := 0 to Handles.Count - 1 do
    begin
      H := Handles[I];
      if (H.Attributes and HANDLE_OBJ_INHERIT) = 0 then Continue;
      ParentKey := IntToStr(H.OwnerPID) + ':' +
        IntToHex(UInt64(H.ObjectIdentity), 16) + ':' +
        IntToHex(UInt64(H.HandleValue), 16) + ':' +
        IntToStr(Ord(H.IsThread));
      ParentCandidates.AddOrSetValue(ParentKey, H);
    end;

    for I := 0 to Handles.Count - 1 do
    begin
      H := Handles[I];
      if not Parents.TryGetValue(H.OwnerPID, ParentPID) then Continue;
      if (ParentPID = 0) or (ParentPID = H.OwnerPID) then Continue;
      if not Creations.TryGetValue(ParentPID, ParentCreate) or
         not Creations.TryGetValue(H.OwnerPID, ChildCreate) then Continue;
      if (ParentCreate = 0) or (ChildCreate = 0) or
         (ParentCreate >= ChildCreate) then Continue;
      ParentKey := IntToStr(ParentPID) + ':' +
        IntToHex(UInt64(H.ObjectIdentity), 16) + ':' +
        IntToHex(UInt64(H.HandleValue), 16) + ':' +
        IntToStr(Ord(H.IsThread));
      if not ParentCandidates.TryGetValue(ParentKey, ParentHandle) then Continue;
      if ParentHandle.GrantedAccess <> H.GrantedAccess then Continue;
      EvidenceKey := IntToStr(ParentPID) + ':' + IntToStr(H.OwnerPID) + ':' +
        ParentKey + ':' + IntToStr(Int64(ChildCreate));
      if not FInheritedPairs.ContainsKey(EvidenceKey) then
      begin
        FInheritedPairs.AddOrSetValue(EvidenceKey, 1);
        if ((H.IsThread and not ThreadBaseline) or
            ((not H.IsThread) and not ProcessBaseline)) then
          Include(Detected, dkHandleInherit);
      end;
    end;
    // The index of previously seen candidates stays for the process lifetime
    // to avoid duplicate notifications on stable inherited handles.
  finally
    ParentCandidates.Free;
  end;
end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestLifecycle10M(out Failure: string; out Checks: Integer): Boolean;
begin
  Result := Cozy.NHW.Lifecycle.Snapshot.TestLifecycle10M(Failure, Checks);
end;
{$ENDIF}

end.
