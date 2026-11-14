unit Cozy.NHW.WaitChain;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.SyncObjs,
  System.Generics.Collections,
  Cozy.NHW.Logging, Cozy.NHW.Lifecycle, Cozy.NHW.WCTNative, Cozy.NHW.WaitChainRules;

type
  TWaitState = record
    LastTick: UInt64;
    LocalStart: UInt64;
    ExternalStart: UInt64;
    CriticalStart: UInt64;
    LocalEmitted: Boolean;
    ExternalEmitted: Boolean;
    CriticalEmitted: Boolean;
    CycleEmitted: Boolean;
  end;

  TContentionState = record
    LastRoot: Cardinal;
    LastTick: UInt64;
    LastEmitted: UInt64;
  end;

  // Asynchronous WCT prevents wait-chain collection from blocking v26's
  // existing 500-ms native handle monitor. All state stays in RAM.
  TWaitChainMonitor = class
  private
    FGuard: TCriticalSection;
    FSession: THandle;
    FTargetPID: Cardinal;
    FEpoch: Cardinal;
    FLastSubmit: UInt64;
    FRoundRobin: Integer;
    FPending: TDetectionKinds;
    FRequests: TDictionary<NativeUInt, Pointer>;
    FPool: TList<Pointer>; // stable native buffers kept until session close
    FInFlight: TDictionary<Cardinal, Byte>;
    FStates: TDictionary<Cardinal, TWaitState>;
    FBlocked: TDictionary<Cardinal, UInt64>;
    FOwners: TDictionary<string, TContentionState>;
    FBurstActive: Boolean;
    procedure OnWCTResult(Context: Pointer; Status: Cardinal;
      Count: Cardinal; Nodes: PWaitChainNode; Cycle: Boolean);
    procedure StopSession;
    procedure ApplyWaitObservation(TID: Cardinal; const Facts: TWaitFacts;
      Baseline: Boolean; Tick: UInt64);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(TargetPID: Cardinal);
    procedure Examine(const Threads: TThreadSampleMap;
      Valid: Boolean; TargetPID: Cardinal; Baseline: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5K_TESTS}
function TestWaitChain5K(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.WinPointers;

const
  POLL_MS = 2000;
  CONTINUITY_MS = 6000;
  WAIT_LONG_MS = 3000;
  EXTERNAL_LONG_MS = 2000;
  MAX_OUTSTANDING = 24;
  MAX_PER_POLL = 12;
  MAX_HISTORY = 512;
  MAX_CONTENTION = 256;
  BLOCKED_WINDOW_MS = 3500;
  CONTENTION_WINDOW_MS = 3500;

type
  PWaitRequest = ^TWaitRequest;
  TWaitRequest = record
    Owner: TWaitChainMonitor;
    ThreadID: Cardinal;
    TargetPID: Cardinal;
    Epoch: Cardinal;
    Tick: UInt64;
    Baseline: Boolean;
    Count: Cardinal;
    Cycle: BOOL;
    Nodes: array[0..WCT_MAX_NODE_COUNT - 1] of TWaitChainNode;
    ReusableTick: UInt64;
  end;

{$IFDEF NHW_NATIVE5K_TESTS}
var
  Wait5KFailAt: Integer = 0;
  Wait5KStep: Integer = 0;
  Wait5KAllocated: Integer = 0;
  Wait5KDisposed: Integer = 0;

procedure Wait5KCheckpoint;
begin
  Inc(Wait5KStep);
  if Wait5KStep = Wait5KFailAt then
    raise EOutOfMemory.Create('Synthetic WaitChain allocation failure');
end;
{$ENDIF}

procedure ReleaseWaitRequest(R: PWaitRequest);
begin
  if R = nil then Exit;
  R^.Owner := nil;
  Dispose(R);
{$IFDEF NHW_NATIVE5K_TESTS}
  Inc(Wait5KDisposed);
{$ENDIF}
end;

procedure CallbackWCT(Session: THandle; Context: NativeUInt;
  CallbackStatus: Cardinal; NodeCount: PCardinal;
  Nodes: PWaitChainNode; IsCycle: PWindowsBool); stdcall;
var
  R: PWaitRequest;
  N: Cardinal;
  Cycle: Boolean;
begin
  R := PWaitRequest(Context);
  if (R = nil) or (R^.Owner = nil) then Exit;
  N := 0;
  Cycle := False;
  if NodeCount <> nil then N := NodeCount^;
  if IsCycle <> nil then
    if IsCycle^ then Cycle := True;
  try
    R^.Owner.OnWCTResult(R, CallbackStatus, N, Nodes, Cycle);
  except
    // WCT callbacks must not raise exceptions through Windows callbacks.
  end;
end;

procedure UpdateWait(Active: Boolean; Tick: UInt64; Threshold: UInt64;
  var FirstTick: UInt64; var Emitted: Boolean;
  const EventKind: TDetectionKind; var Pending: TDetectionKinds);
begin
  if not Active then
  begin
    FirstTick := 0;
    Emitted := False;
    Exit;
  end;
  if FirstTick = 0 then FirstTick := Tick;
  if (not Emitted) and (Tick >= FirstTick) and
     (Tick - FirstTick >= Threshold) then
  begin
    Include(Pending, EventKind);
    Emitted := True;
  end;
end;

constructor TWaitChainMonitor.Create;
var
  I: Integer;
  R: PWaitRequest;
begin
  inherited Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FGuard := TCriticalSection.Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FRequests := TDictionary<NativeUInt, Pointer>.Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FPool := TList<Pointer>.Create;
  for I := 0 to MAX_OUTSTANDING - 1 do
  begin
{$IFDEF NHW_NATIVE5K_TESTS}
    Wait5KCheckpoint;
{$ENDIF}
    New(R);
{$IFDEF NHW_NATIVE5K_TESTS}
    Inc(Wait5KAllocated);
{$ENDIF}
    try
      FillChar(R^, SizeOf(R^), 0);
      R^.Owner := Self;
{$IFDEF NHW_NATIVE5K_TESTS}
      Wait5KCheckpoint;
{$ENDIF}
      FPool.Add(R); // ownership transfers only after Add succeeds
    except
      ReleaseWaitRequest(R);
      raise;
    end;
  end;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FInFlight := TDictionary<Cardinal, Byte>.Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FStates := TDictionary<Cardinal, TWaitState>.Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FBlocked := TDictionary<Cardinal, UInt64>.Create;
{$IFDEF NHW_NATIVE5K_TESTS}
  Wait5KCheckpoint;
{$ENDIF}
  FOwners := TDictionary<string, TContentionState>.Create;
  FSession := 0;
  FEpoch := 0;
end;

destructor TWaitChainMonitor.Destroy;
var
  I: Integer;
  R: PWaitRequest;
begin
  StopSession;
  if FPool <> nil then
    for I := 0 to FPool.Count - 1 do
    begin
      R := PWaitRequest(FPool[I]);
      ReleaseWaitRequest(R);
    end;
  FPool.Free;
  FOwners.Free;
  FBlocked.Free;
  FStates.Free;
  FInFlight.Free;
  FRequests.Free;
  FGuard.Free;
  inherited Destroy;
end;

procedure TWaitChainMonitor.StopSession;
var
  Old: THandle;
  I: Integer;
  R: PWaitRequest;
begin
  // Delphi invokes Destroy if construction raises, including before FGuard.
  if FGuard = nil then Exit;
  FGuard.Acquire;
  try
    Old := FSession;
    FSession := 0;
    if FEpoch = High(Cardinal) then FEpoch := 0 else Inc(FEpoch);
  finally
    FGuard.Release;
  end;
  // Windows returns only after any asynchronous callbacks have completed.
  // Never hold the lock while closing the WCT session.
  if Old <> 0 then WCTClose(Old);
  FGuard.Acquire;
  try
    if FRequests <> nil then FRequests.Clear;
    if FInFlight <> nil then FInFlight.Clear;
    if FPool <> nil then
      for I := 0 to FPool.Count - 1 do
      begin
        R := PWaitRequest(FPool[I]);
        R^.ReusableTick := 0; // WCTClose waited for all callbacks
      end;
  finally
    FGuard.Release;
  end;
end;

procedure TWaitChainMonitor.Reset(TargetPID: Cardinal);
begin
  StopSession;
  FGuard.Acquire;
  try
    FTargetPID := TargetPID;
    FPending := [];
    FLastSubmit := 0;
    FRoundRobin := 0;
    FStates.Clear;
    FBlocked.Clear;
    FOwners.Clear;
    FBurstActive := False;
  finally
    FGuard.Release;
  end;
  // No auto elevation or SE_DEBUG_NAME privilege modification.
  FSession := WCTOpen(@CallbackWCT);
end;

// Caller owns FGuard. This method neither retires nor frees native requests.
procedure TWaitChainMonitor.ApplyWaitObservation(TID: Cardinal;
  const Facts: TWaitFacts; Baseline: Boolean; Tick: UInt64);
var
  State: TWaitState;
  OwnerState: TContentionState;
  Key: string;
  I: Integer;
  OldIDs: TList<Cardinal>;
  Pair: TPair<Cardinal, UInt64>;
begin
    if not FStates.TryGetValue(TID, State) then State := Default(TWaitState);
    if (State.LastTick <> 0) and (Tick - State.LastTick > CONTINUITY_MS) then
      State := Default(TWaitState);
    State.LastTick := Tick;

    if (not Baseline) and Facts.Cycle and not State.CycleEmitted then
    begin
      Include(FPending, dkDeadlock);
      State.CycleEmitted := True;
    end;
    if not Facts.Cycle then State.CycleEmitted := False;

    if not Baseline then
    begin
      UpdateWait(Facts.SameProcessOwner, Tick, WAIT_LONG_MS,
        State.LocalStart, State.LocalEmitted, dkThreadWait, FPending);
      UpdateWait(Facts.ExternalOwner, Tick, EXTERNAL_LONG_MS,
        State.ExternalStart, State.ExternalEmitted, dkExternalWait, FPending);
      UpdateWait(Facts.CriticalSection and Facts.SameProcessOwner,
        Tick, WAIT_LONG_MS, State.CriticalStart,
        State.CriticalEmitted, dkCriticalSection, FPending);
    end
    else
    begin
      // Baseline requests can prime history but must not alert.
      if Facts.SameProcessOwner then State.LocalStart := Tick;
      if Facts.ExternalOwner then State.ExternalStart := Tick;
      if Facts.CriticalSection and Facts.SameProcessOwner then State.CriticalStart := Tick;
    end;
    FStates.AddOrSetValue(TID, State);

    if (not Baseline) and Facts.HasOwner then
    begin
      Key := IntToStr(Facts.OwnerPID) + ':' + IntToStr(Facts.OwnerTID);
      if not FOwners.TryGetValue(Key, OwnerState) then
        OwnerState := Default(TContentionState);
      if (OwnerState.LastRoot <> 0) and (OwnerState.LastRoot <> TID) and
         (Tick >= OwnerState.LastTick) and
         (Tick - OwnerState.LastTick <= CONTENTION_WINDOW_MS) and
         ((OwnerState.LastEmitted = 0) or
          (Tick - OwnerState.LastEmitted > 12000)) then
      begin
        Include(FPending, dkContention);
        OwnerState.LastEmitted := Tick;
      end;
      OwnerState.LastRoot := TID;
      OwnerState.LastTick := Tick;
      FOwners.AddOrSetValue(Key, OwnerState);
    end;

    if not Baseline then
      FBlocked.AddOrSetValue(TID, Tick)
    else
      FBlocked.Remove(TID);
    OldIDs := TList<Cardinal>.Create;
    try
      for Pair in FBlocked do
        if (Tick >= Pair.Value) and
           (Tick - Pair.Value > BLOCKED_WINDOW_MS) then
          OldIDs.Add(Pair.Key);
      for I := 0 to OldIDs.Count - 1 do FBlocked.Remove(OldIDs[I]);
    finally
      OldIDs.Free;
    end;
    if (FBlocked.Count >= 5) and (not FBurstActive) then
    begin
      Include(FPending, dkWaitBurst);
      FBurstActive := True;
    end
    else if FBlocked.Count < 3 then
      FBurstActive := False;

    if FStates.Count > MAX_HISTORY then FStates.Clear;
    if FOwners.Count > MAX_CONTENTION then FOwners.Clear;
end;

procedure TWaitChainMonitor.OnWCTResult(Context: Pointer;
  Status: Cardinal; Count: Cardinal; Nodes: PWaitChainNode; Cycle: Boolean);
var
  R: PWaitRequest;
  TID: Cardinal;
  Facts: TWaitFacts;
  State: TWaitState;
  Tick: UInt64;
  Valid: Boolean;
begin
  R := PWaitRequest(Context);
  if R = nil then Exit;
  FGuard.Acquire;
  try
    if not FRequests.ContainsKey(NativeUInt(Context)) then Exit;
    TID := R^.ThreadID;
    FRequests.Remove(NativeUInt(Context));
    FInFlight.Remove(TID);
    R^.ReusableTick := WinTick64 + 3000; // keep WCT callback buffer valid
    if (Status <> 0) or (Count = 0) or (Count > WCT_MAX_NODE_COUNT) or
       (R^.Epoch <> FEpoch) or (R^.TargetPID <> FTargetPID) then Exit;
    Tick := WinTick64;
    Valid := ClassifyWait(Nodes, Count, FTargetPID, TID, Cycle, Facts);
    if not Valid then
    begin
      if FStates.TryGetValue(TID, State) then
      begin
        State.LocalStart := 0;
        State.ExternalStart := 0;
        State.CriticalStart := 0;
        State.LocalEmitted := False;
        State.ExternalEmitted := False;
        State.CriticalEmitted := False;
        State.CycleEmitted := False;
        FStates.AddOrSetValue(TID, State);
      end;
      FBlocked.Remove(TID);
      Exit;
    end;

    ApplyWaitObservation(TID, Facts, R^.Baseline, Tick);
  finally
    FGuard.Release;
    // Fixed pool is never freed in a callback. Windows requires WCT
    // output buffers to outlive the callback; StopSession closes WCT first.
  end;
end;

procedure TWaitChainMonitor.Examine(const Threads: TThreadSampleMap;
  Valid: Boolean; TargetPID: Cardinal; Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  ThreadIDs: TList<Cardinal>;
  ThreadId: Cardinal;
  R, Candidate: PWaitRequest;
  I, J, Attempts: Integer;
  Pending: BOOL;
  ErrorCode: Cardinal;
  Session: THandle;
  Pair: TPair<Cardinal, TThreadSample>;
begin
  FGuard.Acquire;
  try
    Detected := Detected + FPending;
    FPending := [];
    Session := FSession;
    if (Session = 0) or not Valid or (Threads = nil) or
       (TargetPID <> FTargetPID) or
       ((FLastSubmit <> 0) and (Tick - FLastSubmit < POLL_MS)) then Exit;
    FLastSubmit := Tick;
  finally
    FGuard.Release;
  end;
  ThreadIDs := TList<Cardinal>.Create;
  try
    for Pair in Threads do
      if (Pair.Key <> 0) and (Pair.Value.ThreadID = Pair.Key) then
        ThreadIDs.Add(Pair.Key);
    if ThreadIDs.Count = 0 then Exit;
    Attempts := ThreadIDs.Count;
    if Attempts > MAX_PER_POLL then Attempts := MAX_PER_POLL;
    for I := 0 to Attempts - 1 do
    begin
      ThreadId := ThreadIDs[(FRoundRobin + I) mod ThreadIDs.Count];
      FGuard.Acquire;
      try
        if (FSession = 0) or FInFlight.ContainsKey(ThreadId) or
           (FRequests.Count >= MAX_OUTSTANDING) then Continue;
        R := nil;
        for J := 0 to FPool.Count - 1 do
        begin
          Candidate := PWaitRequest(FPool[J]);
          if (not FRequests.ContainsKey(NativeUInt(Candidate))) and
             (Tick >= Candidate^.ReusableTick) then
          begin
            R := Candidate;
            Break;
          end;
        end;
        if R = nil then Continue;
        R^.Cycle := False;
        R^.ThreadID := ThreadId;
        R^.TargetPID := TargetPID;
        R^.Tick := Tick;
        R^.Epoch := FEpoch;
        R^.Baseline := Baseline;
        R^.Count := WCT_MAX_NODE_COUNT;
        FRequests.Add(NativeUInt(R), R);
        try
          FInFlight.AddOrSetValue(ThreadId, 1);
        except
          // Nothing was submitted to WCT yet: return this buffer to the pool.
          FRequests.Remove(NativeUInt(R));
          FInFlight.Remove(ThreadId);
          raise;
        end;
      finally
        FGuard.Release;
      end;
      Pending := WCTGet(Session, NativeUInt(R),
        WCT_OUT_OF_PROC_FLAG or WCT_OUT_OF_PROC_CS_FLAG,
        ThreadId, @R^.Count, @R^.Nodes[0], @R^.Cycle);
      if not Pending then
      begin
        ErrorCode := WinGetLastError;
        if ErrorCode = ERROR_ACCESS_DENIED then
        begin
          // Degrade to local-only wait-chain traversal, never elevate.
          R^.Count := WCT_MAX_NODE_COUNT;
          Pending := WCTGet(Session, NativeUInt(R), 0, ThreadId,
            @R^.Count, @R^.Nodes[0], @R^.Cycle);
          if Pending then ErrorCode := ERROR_SUCCESS
          else ErrorCode := WinGetLastError;
        end;
        if (ErrorCode <> ERROR_IO_PENDING) and (not Pending) then
        begin
          FGuard.Acquire;
          try
            if FRequests.ContainsKey(NativeUInt(R)) then
            begin
              FRequests.Remove(NativeUInt(R));
              FInFlight.Remove(ThreadId);
              R^.ReusableTick := Tick;
            end;
          finally
            FGuard.Release;
          end;
        end;
      end;
    end;
    FRoundRobin := (FRoundRobin + Attempts) mod ThreadIDs.Count;
  finally
    ThreadIDs.Free;
  end;
end;

{$IFDEF NHW_NATIVE5K_TESTS}
{$I Cozy.NHW.Native5K.WaitChain.inc}
{$ENDIF}

end.
