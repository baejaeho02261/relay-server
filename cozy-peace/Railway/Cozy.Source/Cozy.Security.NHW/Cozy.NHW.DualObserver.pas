unit Cozy.NHW.DualObserver;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SyncObjs, Cozy.NHW.Logging, Cozy.NHW.ObserverAuthenticator,
  Cozy.NHW.Observer.Protocol;

{$A8}
type
  TObserverShared = Cozy.NHW.Observer.Protocol.TObserverShared;
  PObserverShared = Cozy.NHW.Observer.Protocol.PObserverShared;
  TObserverShutdownStatus = Cozy.NHW.Observer.Protocol.TObserverShutdownStatus;

  // v66. Same EXE can run an optional short-lived independent observer.
  // Cross-process shared memory is PAGE-FILE backed, not a disk log.
  // Observer does not modify or inject into the watched process.
  TDualObserver = class
  private
    FLock: TCriticalSection;
    FStopRequested: LongInt;
    FMapping: THandle;
    FChildJob: THandle;
    FView: PObserverShared;
    FChildProcess: THandle;
    FChildPID: Cardinal;
    FLastReport: UInt64;
    FLastStartAttempt: UInt64;
    FShutdownStatus: TObserverShutdownStatus;
    FAnomalyConfirm: Integer;
    FLastProofRevision: UInt64;
    FLastProofTick: UInt64;
    FExpectedOwnerPID: Cardinal;
    FExpectedOwnerCreated: UInt64;
    FSessionKey: TObserverSessionKey;
    procedure MergeShutdownStatus(const Status: TObserverShutdownStatus);
    function ReadProof(Tick: UInt64; out Evidence: TObserverSessionEvidence): Boolean;
    function AcceptEvidence(const Evidence: TObserverSessionEvidence;
      IndependentEvidence: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds): Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure RequestStop;
    procedure Stop;
    function ReadShutdownStatus(out Status: TObserverShutdownStatus): Boolean;
    function Start: Boolean;
    function Examine(IndependentEvidence: Boolean; Tick: UInt64;
      var Detected: TDetectionKinds): Boolean;
    function Ready: Boolean;
    function AuthenticatedReport(Tick: UInt64): Boolean;
    function SnapshotReport(Tick: UInt64;
      out Evidence: TObserverSessionEvidence; out Available: Boolean): Boolean;
    property ObserverPID: Cardinal read FChildPID;
  end;

function TryRunObserverMode: Boolean;
function ObserverIdentityMatches(ExpectedPID: Cardinal;
  ExpectedCreated: UInt64; ActualPID: Cardinal;
  ActualCreated: UInt64): Boolean;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestDualObserver10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils,
  Cozy.NHW.Observer.ChildRuntime, Cozy.NHW.Observer.Launch;

function ObserverIdentityMatches(ExpectedPID: Cardinal;
  ExpectedCreated: UInt64; ActualPID: Cardinal;
  ActualCreated: UInt64): Boolean;
begin
  Result := Cozy.NHW.Observer.Protocol.ObserverIdentityMatches(ExpectedPID,
    ExpectedCreated, ActualPID, ActualCreated);
end;

function TryRunObserverMode: Boolean;
begin
  Result := Cozy.NHW.Observer.ChildRuntime.TryRunObserverMode;
end;

constructor TDualObserver.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FMapping := 0;
  FView := nil;
  FChildProcess := 0;
  FChildPID := 0;
  FLastReport := 0;
  FAnomalyConfirm := 0;
  FLastProofRevision := 0;
  FLastProofTick := 0;
  FExpectedOwnerPID := 0;
  FExpectedOwnerCreated := 0;
  FillChar(FSessionKey, SizeOf(FSessionKey), 0);
end;

destructor TDualObserver.Destroy;
begin
  Stop;
  FLock.Free;
  inherited Destroy;
end;

procedure TDualObserver.RequestStop;
begin
  TInterlocked.Exchange(FStopRequested, 1);
end;

procedure TDualObserver.MergeShutdownStatus(const Status: TObserverShutdownStatus);
begin
  if not Status.HadChild then Exit;
  if not FShutdownStatus.HadChild then FShutdownStatus.ExitObserved := True;
  FShutdownStatus.HadChild := True;
  FShutdownStatus.ForcedTerminationRequested :=
    FShutdownStatus.ForcedTerminationRequested or Status.ForcedTerminationRequested;
  FShutdownStatus.ExitObserved := FShutdownStatus.ExitObserved and Status.ExitObserved;
  if Status.ElapsedMs > FShutdownStatus.ElapsedMs then
    FShutdownStatus.ElapsedMs := Status.ElapsedMs;
end;

function TDualObserver.ReadShutdownStatus(out Status: TObserverShutdownStatus): Boolean;
begin
  Status := Default(TObserverShutdownStatus);
  if FLock = nil then Exit(False);
  FLock.Acquire;
  try Status := FShutdownStatus;
  finally FLock.Release; end;
  Result := Status.HadChild;
end;

procedure TDualObserver.Stop;
var ChildStopped: Boolean; Started: UInt64; Status: TObserverShutdownStatus;
begin
  if FLock = nil then Exit;
  FLock.Acquire;
  try
    Started := ObserverClockTick;
    Status := Default(TObserverShutdownStatus);
    Status.HadChild := FChildProcess <> 0;
    ChildStopped := FChildProcess = 0;
    if FView <> nil then
      TInterlocked.Exchange(PInteger(@FView^.StopFlag)^, 1);
    if FChildProcess <> 0 then
      ChildStopped := Winapi.Windows.WaitForSingleObject(FChildProcess, 1000) = WAIT_OBJECT_0;
    Status.ForcedTerminationRequested := Status.HadChild and not ChildStopped;
    { The job contains only this exact child. Closing it also bounds a
      nonresponsive observer; no foreign PID or thread is terminated. }
    if FChildJob <> 0 then
    begin Winapi.Windows.CloseHandle(FChildJob); FChildJob := 0; end;
    if FChildProcess <> 0 then
    begin
      if not ChildStopped then
        ChildStopped := Winapi.Windows.WaitForSingleObject(FChildProcess, 500) = WAIT_OBJECT_0;
      Winapi.Windows.CloseHandle(FChildProcess);
      FChildProcess := 0;
    end;
    Status.ExitObserved := ChildStopped;
    Status.ElapsedMs := ObserverClockTick - Started;
    MergeShutdownStatus(Status);
    FChildPID := 0;
    if FView <> nil then
    begin
      if ChildStopped then
      begin
        FillChar(FView^.SessionKey, SizeOf(FView^.SessionKey), 0);
        FillChar(FView^.ProofMAC, SizeOf(FView^.ProofMAC), 0);
      end;
      Winapi.Windows.UnmapViewOfFile(FView);
      FView := nil;
    end;
    if FMapping <> 0 then
    begin Winapi.Windows.CloseHandle(FMapping); FMapping := 0; end;
    FillChar(FSessionKey, SizeOf(FSessionKey), 0);
    FExpectedOwnerPID := 0;
    FExpectedOwnerCreated := 0;
    FLastProofRevision := 0;
    FLastProofTick := 0;
    FAnomalyConfirm := 0;
    FLastReport := 0;
  finally FLock.Release; end;
end;

function TDualObserver.Start: Boolean;
var Created: UInt64; Cleanup: TObserverShutdownStatus;
begin
  Result := False;
  FLock.Acquire;
  try
    Stop;
    if TInterlocked.CompareExchange(FStopRequested, 0, 0) <> 0 then Exit;
    FLastStartAttempt := ObserverClockTick;
    if not QueryProcessCreation(Winapi.Windows.GetCurrentProcess, Created) then Exit;
    { Unnamed mapping: a guessed name cannot expose the session MAC key. }
    FMapping := Winapi.Windows.CreateFileMapping(INVALID_HANDLE_VALUE,
      nil, PAGE_READWRITE, 0, SizeOf(TObserverShared), nil);
    if FMapping = 0 then Exit;
    FView := PObserverShared(Winapi.Windows.MapViewOfFile(FMapping,
      FILE_MAP_ALL_ACCESS, 0, 0, SizeOf(TObserverShared)));
    if FView = nil then
    begin Stop; Exit; end;
    FillChar(FView^, SizeOf(TObserverShared), 0);
    FView^.Magic := OBSERVER_MAGIC;
    FView^.Version := OBSERVER_VERSION;
    FView^.OwnerPID := Winapi.Windows.GetCurrentProcessId;
    FView^.OwnerCreated := Created;
    ObserverStore64(FView^.OwnerTick, ObserverClockTick);
    FExpectedOwnerPID := FView^.OwnerPID;
    FExpectedOwnerCreated := Created;
    if not NHWCreateSessionKey(FSessionKey) then
    begin Stop; Exit; end;
    FView^.SessionKey := FSessionKey;
    if TInterlocked.CompareExchange(FStopRequested, 0, 0) <> 0 then
    begin Stop; Exit; end;
    if not LaunchOwnedObserver(FMapping, FView, FChildProcess, FChildJob,
      FChildPID, Cleanup) then
    begin MergeShutdownStatus(Cleanup); Stop; Exit; end;
    Result := True;
  finally FLock.Release; end;
end;

function TDualObserver.ReadProof(Tick: UInt64;
  out Evidence: TObserverSessionEvidence): Boolean;
var
  FirstRevision, LastRevision: UInt64;
  LocalEvidence: TObserverSessionEvidence;
  LocalMAC: TObserverSessionMAC;
begin
  Result := False;
  Evidence := Default(TObserverSessionEvidence);
  if (FView = nil) or (FChildProcess = 0) or (FChildPID = 0) or
     (FExpectedOwnerPID = 0) or (FExpectedOwnerCreated = 0) then Exit;
  if (FView^.Magic <> OBSERVER_MAGIC) or (FView^.Version <> OBSERVER_VERSION) or
     ((NativeUInt(@FView^.ProofRevision) and 7) <> 0) then Exit;
  if Winapi.Windows.WaitForSingleObject(FChildProcess, 0) <> WAIT_TIMEOUT then Exit;
  FirstRevision := ObserverLoad64(FView^.ProofRevision);
  if (FirstRevision = 0) or ((FirstRevision and 1) <> 0) or
     (FirstRevision < FLastProofRevision) then Exit;
  LocalEvidence := FView^.ProofEvidence;
  LocalMAC := FView^.ProofMAC;
  LastRevision := ObserverLoad64(FView^.ProofRevision);
  if FirstRevision <> LastRevision then Exit;
  if (LocalEvidence.Sequence <> FirstRevision) or
     (LocalEvidence.OwnerPID <> FExpectedOwnerPID) or
     (LocalEvidence.OwnerCreated <> FExpectedOwnerCreated) or
     (LocalEvidence.ObserverPID <> FChildPID) or
     (LocalEvidence.State > 2) or (LocalEvidence.ObservedTick = 0) or
     (Tick < LocalEvidence.ObservedTick) or
     (Tick - LocalEvidence.ObservedTick > 3000) then Exit;
  if (LocalEvidence.State <> 0) and (LocalEvidence.ObservedCreation = 0) then Exit;
  if (LocalEvidence.State = 1) and
     (LocalEvidence.ObservedCreation <> FExpectedOwnerCreated) then Exit;
  if (LocalEvidence.State = 2) and
     (LocalEvidence.ObservedCreation = FExpectedOwnerCreated) then Exit;
  if not NHWVerifySessionMAC(FSessionKey, LocalEvidence, LocalMAC) then Exit;
  Evidence := LocalEvidence;
  FShutdownStatus.AuthenticatedReportObserved := True;
  Result := True;
end;

function TDualObserver.Ready: Boolean;
var E: TObserverSessionEvidence;
begin
  FLock.Acquire;
  try
  Result := ReadProof(ObserverClockTick, E) and (E.State = 1);
  finally FLock.Release; end;
end;

function TDualObserver.AcceptEvidence(const Evidence: TObserverSessionEvidence;
  IndependentEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds): Boolean;
begin
  Result := False;
  if not IndependentEvidence then FAnomalyConfirm := 0;
  if Evidence.Sequence <= FLastProofRevision then Exit;
  FLastProofRevision := Evidence.Sequence; // consume even non-correlated reports
  if (Evidence.ObservedTick <= FLastProofTick) then
  begin
    FAnomalyConfirm := 0;
    Exit;
  end;
  FLastProofTick := Evidence.ObservedTick;
  Result := Evidence.State = 2;
  if Result and IndependentEvidence then
  begin
    if FAnomalyConfirm < 3 then Inc(FAnomalyConfirm);
  end
  else FAnomalyConfirm := 0;
  if (FAnomalyConfirm >= 3) and
     ((FLastReport = 0) or ((Tick >= FLastReport) and
       (Tick - FLastReport >= 60000))) then
  begin
    Include(Detected, dkObserverMismatch);
    FLastReport := Tick;
  end;
end;

function TDualObserver.Examine(IndependentEvidence: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds): Boolean;
var E: TObserverSessionEvidence;
begin
  FLock.Acquire;
  try
  Result := False;
  if TInterlocked.CompareExchange(FStopRequested, 0, 0) <> 0 then Exit;
  { A slow native observation can expire the separate child's heartbeat.
    Retry only a missing/exited owned child, at most once per 30 seconds.
    Missing/stale evidence remains UNKNOWN and never becomes a vote. }
  if ((FChildProcess = 0) or
      (Winapi.Windows.WaitForSingleObject(FChildProcess, 0) = WAIT_OBJECT_0)) and
     ((FLastStartAttempt = 0) or ((Tick >= FLastStartAttempt) and
       (Tick - FLastStartAttempt >= 30000))) then Start;
  if FView = nil then
  begin
    FAnomalyConfirm := 0;
    Exit;
  end;
  if TInterlocked.CompareExchange(FStopRequested, 0, 0) <> 0 then
  begin
    TInterlocked.Exchange(PInteger(@FView^.StopFlag)^, 1);
    Exit;
  end;
  ObserverStore64(FView^.OwnerTick, Tick);
  if not ReadProof(Tick, E) then
  begin
    FAnomalyConfirm := 0;
    Exit;
  end;
  Result := AcceptEvidence(E, IndependentEvidence, Tick, Detected);
  finally FLock.Release; end;
end;

function TDualObserver.SnapshotReport(Tick: UInt64;
  out Evidence: TObserverSessionEvidence; out Available: Boolean): Boolean;
begin
  FLock.Acquire;
  try
  Evidence := Default(TObserverSessionEvidence);
  Available := (FView <> nil) and (FChildProcess <> 0) and (FChildPID <> 0);
  if Available then
    Available := Winapi.Windows.WaitForSingleObject(FChildProcess, 0) = WAIT_TIMEOUT;
  Result := False;
  // ReadProof validates one seqlock copy and its MAC. The caller uses this
  // single immutable local result for grade, sequence and observation tick.
  if Available then Result := ReadProof(Tick, Evidence);
  finally FLock.Release; end;
end;

function TDualObserver.AuthenticatedReport(Tick: UInt64): Boolean;
var E: TObserverSessionEvidence;
begin
  FLock.Acquire;
  try
  // Health polling may reread a fresh report, but only Examine consumes it
  // for anomaly confirmation. Health reads cannot increment the counter.
  Result := ReadProof(Tick, E) and (E.State = 1);
  finally FLock.Release; end;
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.DualObserver.inc}
{$ENDIF}

end.
