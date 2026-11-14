unit Cozy.NHW.SelfGuard;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Logging,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.SelfRules,
  Cozy.NHW.ETW;

type
  TSelfThreadPending = record
    Created: UInt64;
    StartAddress: NativeUInt;
    LastTick: UInt64;
    Count: Byte;
  end;

  TSelfGuardMonitor = class
  private
    FIAT: TStableFingerprint;
    FFunctions: TStableFingerprint;
    FCallbacks: TStableFingerprint;
    FParameters: TStableFingerprint;
    FKnownThreads: TDictionary<Cardinal, UInt64>;
    FThreadPending: TDictionary<Cardinal, TSelfThreadPending>;
    FThreadPrimed: Boolean;
    FEtwCallbacks: Boolean;
    FLastExternalHighTick: UInt64;
    FLastCheck: UInt64;
    FExpectedWorkerID: Cardinal;
    FExpectedWorkerCreated: UInt64;
    procedure BreakFingerprintContinuity;
    procedure CheckThreads(const Threads: TThreadSampleMap;
      SnapshotValid: Boolean; Baseline: Boolean; ExpectedWorkerID: Cardinal;
      Tick: UInt64; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(EtwEnabled: Boolean);
    procedure Examine(const Trace: TETWMonitor; const Threads: TThreadSampleMap;
      ThreadsValid: Boolean; Baseline: Boolean; Tick: UInt64;
      HighExternalAccess: Boolean; ConsoleHandler: NativeUInt;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE5K_TESTS}
function TestSelfGuard5K(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.SelfNative, Cozy.NHW.Native, Cozy.NHW.WinPointers;

const
  SELF_QUERY_INTERVAL_MS = 2000;
  EXTERNAL_CORRELATION_MS = 8000;

{$IFDEF NHW_NATIVE5K_TESTS}
type
  TSelfIdentity5KHook = function(ID: Cardinal; Start: NativeUInt;
    out Created: UInt64): Boolean;
  TSelfPrivate5KHook = function(Address: NativeUInt): Boolean;
var
  SelfIdentity5KHook: TSelfIdentity5KHook = nil;
  SelfPrivate5KHook: TSelfPrivate5KHook = nil;
{$ENDIF}

function ReadSelfThreadIdentity(ID: Cardinal; ExpectedStart: NativeUInt;
  out Created: UInt64): Boolean;
var
  H: THandle;
  C, E, K, U: TFileTime;
begin
  Created := 0;
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(SelfIdentity5KHook) then
    Exit(SelfIdentity5KHook(ID, ExpectedStart, Created));
{$ENDIF}
  Result := False;
  if (ID = 0) or (ExpectedStart = 0) then Exit;
  // NT CLIENT_ID binds both PID and TID. Keep the handle for identity/liveness
  // checks; no suspend, context write, or debug inspection.
  H := OpenNativeThread(WinCurrentProcessId, ID, $0800 or $00100000);
  if H = 0 then Exit;
  try
    // SYSTEM_THREAD_INFORMATION.StartAddress and Win32StartAddress are
    // different observations. Do not reject valid snapshots by equating them.
    if not WinGetThreadTimes(H, C, E, K, U) then Exit;
    if WinWaitForSingleObject(H, 0) <> WAIT_TIMEOUT then Exit;
    Created := (UInt64(C.dwHighDateTime) shl 32) or UInt64(C.dwLowDateTime);
    Result := Created <> 0;
  finally
    CloseNativeProcess(H);
  end;
end;

function SelfPrivateAddress(Address: NativeUInt): Boolean;
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(SelfPrivate5KHook) then Exit(SelfPrivate5KHook(Address));
{$ENDIF}
  Result := ExecutablePrivateAddress(Address);
end;

constructor TSelfGuardMonitor.Create;
begin
  inherited Create;
  FKnownThreads := TDictionary<Cardinal, UInt64>.Create;
  FThreadPending := TDictionary<Cardinal, TSelfThreadPending>.Create;
  Reset(False);
end;

destructor TSelfGuardMonitor.Destroy;
begin
  FThreadPending.Free;
  FKnownThreads.Free;
  inherited Destroy;
end;

procedure TSelfGuardMonitor.Reset(EtwEnabled: Boolean);
begin
  FIAT := Default(TStableFingerprint);
  FFunctions := Default(TStableFingerprint);
  FCallbacks := Default(TStableFingerprint);
  FParameters := Default(TStableFingerprint);
  FKnownThreads.Clear;
  FThreadPending.Clear;
  FThreadPrimed := False;
  FEtwCallbacks := EtwEnabled;
  FLastExternalHighTick := 0;
  FLastCheck := 0;
  FExpectedWorkerID := 0;
  FExpectedWorkerCreated := 0;
end;

procedure TSelfGuardMonitor.BreakFingerprintContinuity;
begin
  ObserveFingerprint(FIAT, 0, False);
  ObserveFingerprint(FFunctions, 0, False);
  ObserveFingerprint(FCallbacks, 0, False);
  ObserveFingerprint(FParameters, 0, False);
end;

procedure TSelfGuardMonitor.CheckThreads(const Threads: TThreadSampleMap;
  SnapshotValid: Boolean; Baseline: Boolean; ExpectedWorkerID: Cardinal;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Pair: TPair<Cardinal, TThreadSample>;

  procedure RetireAbsentIdentities;
  var
    Missing: TList<Cardinal>;
    ID: Cardinal;
  begin
    Missing := TList<Cardinal>.Create;
    try
      for ID in FKnownThreads.Keys do
        if not Threads.ContainsKey(ID) then Missing.Add(ID);
      for ID in Missing do FKnownThreads.Remove(ID);
      Missing.Clear;
      for ID in FThreadPending.Keys do
        if not Threads.ContainsKey(ID) then Missing.Add(ID);
      for ID in Missing do FThreadPending.Remove(ID);
    finally
      Missing.Free;
    end;
  end;

  procedure ObserveThreadIdentities;
  var
    Pair: TPair<Cardinal, TThreadSample>;
    Pending: TSelfThreadPending;
    ID: Cardinal;
    Created, KnownCreated: UInt64;
    Unknown, Reused: Boolean;
  begin
    for Pair in Threads do
    begin
      ID := Pair.Key;
      if not ReadSelfThreadIdentity(ID, Pair.Value.StartAddress, Created) or
        (Created = 0) then
      begin
        FThreadPending.Remove(ID);
        Continue; // unavailable identity is UNKNOWN, never trusted by TID
      end;
      Reused := FKnownThreads.TryGetValue(ID, KnownCreated);
      if (ID = ExpectedWorkerID) and (ExpectedWorkerID <> 0) and
        (FExpectedWorkerCreated = 0) then
      begin
        if Reused then FExpectedWorkerCreated := KnownCreated
        else FExpectedWorkerCreated := Created;
      end;
      if Reused and (KnownCreated = Created) then Continue;
      if Reused then
      begin
        FKnownThreads.Remove(ID);
        FThreadPending.Remove(ID);
      end;
      if Baseline or not FThreadPrimed or
        ((ID = ExpectedWorkerID) and (ExpectedWorkerID <> 0) and
         (FExpectedWorkerCreated = Created) and not Reused) then
      begin
        FKnownThreads.AddOrSetValue(ID, Created);
        FThreadPending.Remove(ID);
        Continue;
      end;
      Unknown := SelfPrivateAddress(Pair.Value.StartAddress) and
        WithinBoundaryWindow(Tick, FLastExternalHighTick, EXTERNAL_CORRELATION_MS);
      if not Unknown then
      begin
        FThreadPending.Remove(ID);
        FKnownThreads.AddOrSetValue(ID, Created);
        Continue;
      end;
      if not FThreadPending.TryGetValue(ID, Pending) then
        Pending := Default(TSelfThreadPending);
      if (Pending.Created <> Created) or
        (Pending.StartAddress <> Pair.Value.StartAddress) or
        (Tick < Pending.LastTick) or
        ((Tick >= Pending.LastTick) and
         (Tick - Pending.LastTick > EXTERNAL_CORRELATION_MS)) then
        Pending := Default(TSelfThreadPending);
      Pending.Created := Created;
      Pending.StartAddress := Pair.Value.StartAddress;
      if (Pending.Count = 0) or (Tick > Pending.LastTick) then
      begin
        if Pending.Count < 2 then Inc(Pending.Count);
        Pending.LastTick := Tick;
      end;
      if Pending.Count >= 2 then
      begin
        Include(Detected, dkThreadProvenance);
        FKnownThreads.AddOrSetValue(ID, Created);
        FThreadPending.Remove(ID);
      end
      else
        FThreadPending.AddOrSetValue(ID, Pending);
    end;
  end;

begin
  if not SnapshotValid or (Threads = nil) then
  begin
    FThreadPending.Clear; // gap is not another successful confirmation
    Exit;
  end;
  for Pair in Threads do
    if (Pair.Key = 0) or (Pair.Key <> Pair.Value.ThreadID) then
    begin
      FThreadPending.Clear;
      Exit; // do not prune known identities using malformed snapshot data
    end;

  // Reclaim departed identities only from a complete snapshot. This bounds
  // history and prevents a reappearing numeric TID inheriting a prior identity.
  RetireAbsentIdentities;

  if FExpectedWorkerID <> ExpectedWorkerID then
  begin
    FExpectedWorkerID := ExpectedWorkerID;
    FExpectedWorkerCreated := 0;
  end;
  if Baseline then FThreadPending.Clear;
  try
    ObserveThreadIdentities;
  except
    FThreadPending.Clear;
    raise;
  end;
  if not Baseline then FThreadPrimed := True;
  if FKnownThreads.Count > 8192 then
  begin
    FKnownThreads.Clear;
    FThreadPending.Clear;
    FThreadPrimed := False;
  end;
end;

procedure TSelfGuardMonitor.Examine(const Trace: TETWMonitor;
  const Threads: TThreadSampleMap; ThreadsValid: Boolean;
  Baseline: Boolean; Tick: UInt64; HighExternalAccess: Boolean;
  ConsoleHandler: NativeUInt; var Detected: TDetectionKinds);
var
  H: UInt64;
  Entries: Cardinal;
  ValidTargets: Boolean;
  Evt, Buf: NativeUInt;
  Internal: TDetectionKinds;
  CallbacksOk: Boolean;
  WorkerID: Cardinal;
begin
  if HighExternalAccess and not Baseline then FLastExternalHighTick := Tick;
  if Baseline then
  begin
    FLastExternalHighTick := 0;
    BreakFingerprintContinuity;
    CheckThreads(Threads, ThreadsValid, True, 0, Tick, Detected);
    Exit;
  end;
  if (FLastCheck <> 0) and (Tick >= FLastCheck) and
     (Tick - FLastCheck < SELF_QUERY_INTERVAL_MS) then Exit;
  FLastCheck := Tick;
  Internal := [];

  try
  if CaptureSelfIAT(H, Entries) then
  begin
    if ObserveFingerprint(FIAT, H, True) then Include(Internal, dkIAT);
  end
  else ObserveFingerprint(FIAT, 0, False);

  if CaptureLiveFunctionPointers(H, ValidTargets) then
  begin
    H := NextFingerprint(H, Ord(ValidTargets));
    if ObserveFingerprint(FFunctions, H, True) then
      Include(Internal, dkFunctionPointer);
  end
  else ObserveFingerprint(FFunctions, 0, False);

  Evt := 0;
  Buf := 0;
  if FEtwCallbacks and (Trace <> nil) then
    Trace.GetCallbackTargets(Evt, Buf);
  // Required callbacks must remain available if they were registered.
  CallbacksOk := (ConsoleHandler <> 0);
  if FEtwCallbacks then CallbacksOk := CallbacksOk and
    (Evt <> 0) and (Buf <> 0);
  if CallbacksOk and CallbackFingerprint(ConsoleHandler, Evt, Buf,
    H, ValidTargets) then
  begin
    H := NextFingerprint(H, Ord(ValidTargets));
    if ObserveFingerprint(FCallbacks, H, True) then
      Include(Internal, dkCallback);
  end
  else ObserveFingerprint(FCallbacks, 0, False);

  if CaptureProcessParameters(H) then
  begin
    if ObserveFingerprint(FParameters, H, True) then
      Include(Internal, dkProcessParameter);
  end
  else ObserveFingerprint(FParameters, 0, False);
  except
    BreakFingerprintContinuity;
    raise;
  end;

  WorkerID := 0;
  if Trace <> nil then WorkerID := Trace.ConsumerThreadID;
  CheckThreads(Threads, ThreadsValid, False,
    WorkerID, Tick, Internal);

  Detected := Detected + Internal;
  if (Internal <> []) and
    WithinBoundaryWindow(Tick, FLastExternalHighTick,
      EXTERNAL_CORRELATION_MS) then
    Include(Detected, dkBoundary);
end;

{$IFDEF NHW_NATIVE5K_TESTS}
{$I Cozy.NHW.Native5K.SelfGuard.inc}
{$ENDIF}

end.
